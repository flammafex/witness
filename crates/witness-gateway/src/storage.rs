use anyhow::Result;
use rand::{rngs::OsRng, RngCore};
use sqlx::{
    sqlite::{
        SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqliteSynchronous,
    },
    Row,
};
use std::{str::FromStr, time::Duration};
use witness_core::types::{AttestationJobResponse, AttestationJobStatus};
use witness_core::{
    signature_scheme::AttestationSignatures, Attestation, AttestationBatch, CrossAnchor,
    ExternalAnchorProof, MerkleTree, SignedAttestation, SignedTreeHead, TreeHead, WitnessSignature,
};

use crate::epoch::epoch_secs;

pub struct Storage {
    pool: SqlitePool,
}

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_JOB_ERROR_CHARS: usize = 512;
const MAX_RETRY_DELAY_SECS: u64 = 300;

/// Result of reserving the globally canonical tuple for a hash.
#[derive(Debug, Clone)]
pub struct JobReservation {
    pub job: AttestationJobResponse,
    pub created: bool,
}

/// Exclusive, expiring ownership returned to an attestation worker.
#[derive(Debug, Clone)]
pub struct JobClaim {
    pub attestation: Attestation,
    pub lease_token: String,
    pub lease_expires_at: u64,
    pub attempts: u32,
}

/// Cached log state for O(1) STH computation.
#[derive(Debug, Clone)]
pub struct LogState {
    pub network_id: String,
    pub current_root: [u8; 32],
    pub tree_size: u64,
    pub updated_at: u64,
}

impl Storage {
    pub async fn new(database_url: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(SQLITE_BUSY_TIMEOUT)
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| anyhow::anyhow!("Database migration failed: {}", e))?;
        self.migrate_bls_legacy_rows().await?;
        Ok(())
    }

    /// One-time data migration: move legacy "BLS_AGGREGATED:a,b,c" rows from the
    /// `signatures` table into the new `aggregated_signatures` / `aggregated_signers`
    /// tables.  Safe to run repeatedly — uses INSERT OR IGNORE and only deletes rows
    /// that were successfully moved.
    async fn migrate_bls_legacy_rows(&self) -> Result<()> {
        let rows = sqlx::query(
            r#"
            SELECT hash, witness_id, signature
            FROM signatures
            WHERE witness_id LIKE 'BLS_AGGREGATED:%'
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "Migrating {} legacy BLS_AGGREGATED rows to dedicated tables",
            rows.len()
        );

        for row in &rows {
            let hash: String = row.get("hash");
            let witness_id: String = row.get("witness_id");
            let signature: Vec<u8> = row.get("signature");

            let signers_str = witness_id
                .strip_prefix("BLS_AGGREGATED:")
                .unwrap_or_default();
            let signers: Vec<&str> = signers_str.split(',').filter(|s| !s.is_empty()).collect();

            let mut tx = self.pool.begin().await?;

            sqlx::query(
                r#"INSERT INTO aggregated_signatures (hash, signature, scheme)
                   VALUES (?1, ?2, 'bls')
                   ON CONFLICT(hash) DO NOTHING"#,
            )
            .bind(&hash)
            .bind(&signature)
            .execute(&mut *tx)
            .await?;

            for (position, signer) in signers.iter().enumerate() {
                sqlx::query(
                    r#"INSERT INTO aggregated_signers (hash, witness_id, position)
                       VALUES (?1, ?2, ?3)
                       ON CONFLICT(hash, witness_id) DO NOTHING"#,
                )
                .bind(&hash)
                .bind(signer)
                .bind(position as i64)
                .execute(&mut *tx)
                .await?;
            }

            sqlx::query(
                r#"DELETE FROM signatures WHERE hash = ?1 AND witness_id LIKE 'BLS_AGGREGATED:%'"#,
            )
            .bind(&hash)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
        }

        tracing::info!("BLS legacy row migration complete");
        Ok(())
    }

    /// Read signatures for a hash — checks the aggregated tables first, falls back to
    /// the multi-sig `signatures` table.
    async fn read_signatures_on(
        conn: &mut SqliteConnection,
        hash_hex: &str,
    ) -> Result<AttestationSignatures> {
        let agg_row = sqlx::query(r#"SELECT signature FROM aggregated_signatures WHERE hash = ?1"#)
            .bind(hash_hex)
            .fetch_optional(&mut *conn)
            .await?;

        if let Some(agg_row) = agg_row {
            let signature: Vec<u8> = agg_row.get("signature");
            let signer_rows = sqlx::query(
                r#"SELECT witness_id FROM aggregated_signers
                   WHERE hash = ?1 ORDER BY position ASC"#,
            )
            .bind(hash_hex)
            .fetch_all(&mut *conn)
            .await?;
            let signers: Vec<String> = signer_rows.iter().map(|r| r.get("witness_id")).collect();
            return Ok(AttestationSignatures::Aggregated { signature, signers });
        }

        let sig_rows = sqlx::query(
            r#"SELECT witness_id, signature FROM signatures
                   WHERE hash = ?1 ORDER BY witness_id ASC"#,
        )
        .bind(hash_hex)
        .fetch_all(&mut *conn)
        .await?;

        let witness_sigs: Vec<WitnessSignature> = sig_rows
            .iter()
            .map(|row| WitnessSignature {
                witness_id: row.get("witness_id"),
                signature: row.get("signature"),
            })
            .collect();

        Ok(AttestationSignatures::MultiSig {
            signatures: witness_sigs,
        })
    }

    async fn read_signatures(&self, hash_hex: &str) -> Result<AttestationSignatures> {
        let mut conn = self.pool.acquire().await?;
        Self::read_signatures_on(&mut conn, hash_hex).await
    }

    /// Atomically reserve the one canonical tuple for `hash` across all
    /// networks in this database. Sequence allocation and insertion share a
    /// short RAII transaction. The sequence upsert is the first statement and
    /// acquires SQLite's writer lock before insertion; a duplicate explicitly
    /// rolls the allocation back and returns the existing tuple unchanged.
    pub async fn reserve_job(
        &self,
        hash: &[u8; 32],
        network_id: &str,
        now: u64,
    ) -> Result<JobReservation> {
        let hash_hex = hex::encode(hash);
        let now_db = Self::u64_to_i64(now, "reservation time")?;
        let mut tx = self.pool.begin().await?;

        let sequence_row = sqlx::query(
            r#"
            INSERT INTO sequences (network_id, next_val) VALUES (?1, 2)
            ON CONFLICT(network_id) DO UPDATE SET next_val = next_val + 1
                WHERE next_val < 9223372036854775807
            RETURNING next_val - 1 AS sequence
            "#,
        )
        .bind(network_id)
        .fetch_one(&mut *tx)
        .await?;
        let sequence_db: i64 = sequence_row.get("sequence");
        let sequence = Self::nonnegative_i64_to_u64(sequence_db, "sequence")?;

        let inserted = sqlx::query(
            r#"
            INSERT INTO attestations (
                hash, timestamp, network_id, sequence, created_at, status,
                attempts, next_attempt_at
            )
            VALUES (?1, ?2, ?3, ?4, ?2, 'pending', 0, ?2)
            ON CONFLICT(hash) DO NOTHING
            "#,
        )
        .bind(&hash_hex)
        .bind(now_db)
        .bind(network_id)
        .bind(sequence_db)
        .execute(&mut *tx)
        .await?;

        if inserted.rows_affected() == 0 {
            tx.rollback().await?;
            let job = self.get_job(hash).await?.ok_or_else(|| {
                anyhow::anyhow!("canonical attestation disappeared after reservation conflict")
            })?;
            Ok(JobReservation {
                job,
                created: false,
            })
        } else {
            tx.commit().await?;
            Ok(JobReservation {
                job: AttestationJobResponse {
                    attestation: Attestation {
                        hash: *hash,
                        timestamp: now,
                        network_id: network_id.to_string(),
                        sequence,
                    },
                    status: AttestationJobStatus::Pending,
                    signed_attestation: None,
                    attempts: 0,
                    next_attempt_at: Some(now),
                    last_error: None,
                },
                created: true,
            })
        }
    }

    /// Claim one due job without introducing a durable `running` state.
    pub async fn claim_job(
        &self,
        network_id: &str,
        now: u64,
        lease_duration_secs: u64,
    ) -> Result<Option<JobClaim>> {
        if lease_duration_secs == 0 {
            return Err(anyhow::anyhow!("job lease duration must be nonzero"));
        }
        let now_db = Self::u64_to_i64(now, "claim time")?;
        let lease_expires_at = now
            .checked_add(lease_duration_secs)
            .ok_or_else(|| anyhow::anyhow!("job lease expiry overflow"))?;
        let lease_expires_at_db = Self::u64_to_i64(lease_expires_at, "job lease expiry")?;
        let mut token_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let lease_token = hex::encode(token_bytes);

        let row = sqlx::query(
            r#"
            UPDATE attestations
            SET lease_token = ?1,
                lease_expires_at = ?2,
                attempts = attempts + 1
            WHERE hash = (
                SELECT hash
                FROM attestations
                WHERE network_id = ?3
                  AND status IN ('pending', 'retryable')
                  AND next_attempt_at <= ?4
                  AND (lease_expires_at IS NULL OR lease_expires_at <= ?4)
                  AND attempts < 4294967295
                ORDER BY next_attempt_at ASC, sequence ASC, hash ASC
                LIMIT 1
            )
              AND status IN ('pending', 'retryable')
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?4)
            RETURNING hash, timestamp, network_id, sequence, attempts
            "#,
        )
        .bind(&lease_token)
        .bind(lease_expires_at_db)
        .bind(network_id)
        .bind(now_db)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let attempts: i64 = row.get("attempts");

        Ok(Some(JobClaim {
            attestation: Self::attestation_from_row(&row)?,
            lease_token,
            lease_expires_at,
            attempts: u32::try_from(attempts)
                .map_err(|_| anyhow::anyhow!("invalid job attempt count"))?,
        }))
    }

    /// Atomically replace any unconfirmed signature fragments and persist the
    /// immutable verified result under the current lease.
    ///
    /// The caller is responsible for threshold verification. Returning `false`
    /// means that the lease is stale/expired, the tuple differs, or the job is
    /// no longer eligible; no signature data is changed in that case.
    pub async fn complete_verified_job(
        &self,
        signed: &SignedAttestation,
        lease_token: &str,
        now: u64,
    ) -> Result<bool> {
        let hash_hex = hex::encode(signed.attestation.hash);
        let now_db = Self::u64_to_i64(now, "completion time")?;
        let timestamp_db = Self::u64_to_i64(signed.attestation.timestamp, "attestation timestamp")?;
        let sequence_db = Self::u64_to_i64(signed.attestation.sequence, "attestation sequence")?;
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE attestations
            SET status = 'confirmed',
                lease_token = NULL,
                lease_expires_at = NULL,
                next_attempt_at = NULL,
                last_error = NULL,
                completed_at = ?1
            WHERE hash = ?2
              AND timestamp = ?3
              AND network_id = ?4
              AND sequence = ?5
              AND status IN ('pending', 'retryable')
              AND lease_token = ?6
              AND lease_expires_at > ?1
            "#,
        )
        .bind(now_db)
        .bind(&hash_hex)
        .bind(timestamp_db)
        .bind(&signed.attestation.network_id)
        .bind(sequence_db)
        .bind(lease_token)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() == 0 {
            tx.rollback().await?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM signatures WHERE hash = ?1")
            .bind(&hash_hex)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM aggregated_signers WHERE hash = ?1")
            .bind(&hash_hex)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM aggregated_signatures WHERE hash = ?1")
            .bind(&hash_hex)
            .execute(&mut *tx)
            .await?;

        match &signed.signatures {
            AttestationSignatures::MultiSig { signatures } => {
                for signature in signatures {
                    sqlx::query(
                        "INSERT INTO signatures(hash, witness_id, signature) VALUES (?1, ?2, ?3)",
                    )
                    .bind(&hash_hex)
                    .bind(&signature.witness_id)
                    .bind(&signature.signature)
                    .execute(&mut *tx)
                    .await?;
                }
            }
            AttestationSignatures::Aggregated { signature, signers } => {
                sqlx::query(
                    "INSERT INTO aggregated_signatures(hash, signature, scheme) VALUES (?1, ?2, 'bls')",
                )
                .bind(&hash_hex)
                .bind(signature)
                .execute(&mut *tx)
                .await?;
                for (position, signer) in signers.iter().enumerate() {
                    sqlx::query(
                        "INSERT INTO aggregated_signers(hash, witness_id, position) VALUES (?1, ?2, ?3)",
                    )
                    .bind(&hash_hex)
                    .bind(signer)
                    .bind(position as i64)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        tx.commit().await?;
        Ok(true)
    }

    /// Release a current lease and schedule an exponential retry.
    pub async fn reschedule_job(
        &self,
        hash: &[u8; 32],
        lease_token: &str,
        now: u64,
        error: &str,
    ) -> Result<bool> {
        let hash_hex = hex::encode(hash);
        let latest_retry = now
            .checked_add(MAX_RETRY_DELAY_SECS)
            .ok_or_else(|| anyhow::anyhow!("job retry time overflow"))?;
        Self::u64_to_i64(latest_retry, "job retry time")?;
        let now_db = Self::u64_to_i64(now, "reschedule time")?;
        let error = Self::sanitize_job_error(error);
        let result = sqlx::query(
            r#"
            UPDATE attestations
            SET status = 'retryable',
                lease_token = NULL,
                lease_expires_at = NULL,
                next_attempt_at = ?1 + MIN(300, (1 << MIN(attempts - 1, 8))),
                last_error = ?2
            WHERE hash = ?3
              AND status IN ('pending', 'retryable')
              AND lease_token = ?4
              AND lease_expires_at > ?1
            "#,
        )
        .bind(now_db)
        .bind(&error)
        .bind(&hash_hex)
        .bind(lease_token)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Mark a currently leased job as terminally failed.
    pub async fn fail_job(
        &self,
        hash: &[u8; 32],
        lease_token: &str,
        now: u64,
        error: &str,
    ) -> Result<bool> {
        let hash_hex = hex::encode(hash);
        let now_db = Self::u64_to_i64(now, "failure time")?;
        let error = Self::sanitize_job_error(error);
        let result = sqlx::query(
            r#"
            UPDATE attestations
            SET status = 'failed',
                lease_token = NULL,
                lease_expires_at = NULL,
                next_attempt_at = NULL,
                last_error = ?1
            WHERE hash = ?2
              AND status IN ('pending', 'retryable')
              AND lease_token = ?3
              AND lease_expires_at > ?4
            "#,
        )
        .bind(&error)
        .bind(&hash_hex)
        .bind(lease_token)
        .bind(now_db)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Read one consistent job snapshot. Signature rows are read in the same
    /// SQLite snapshot as the status, and are exposed only for confirmed jobs.
    pub async fn get_job(&self, hash: &[u8; 32]) -> Result<Option<AttestationJobResponse>> {
        let hash_hex = hex::encode(hash);
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT hash, timestamp, network_id, sequence, status, attempts,
                   next_attempt_at, last_error
            FROM attestations
            WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let attestation = Self::attestation_from_row(&row)?;
        let status_text: String = row.get("status");
        let status = Self::job_status_from_db(&status_text)?;
        let attempts: i64 = row.get("attempts");
        let signed_attestation = if status == AttestationJobStatus::Confirmed {
            let signatures = Self::read_signatures_on(&mut tx, &hash_hex).await?;
            Some(SignedAttestation {
                attestation: attestation.clone(),
                signatures,
            })
        } else {
            None
        };
        let response = AttestationJobResponse {
            attestation,
            status,
            signed_attestation,
            attempts: u32::try_from(attempts)
                .map_err(|_| anyhow::anyhow!("invalid job attempt count"))?,
            next_attempt_at: row
                .get::<Option<i64>, _>("next_attempt_at")
                .map(|value| Self::nonnegative_i64_to_u64(value, "next attempt time"))
                .transpose()?,
            last_error: row
                .get::<Option<String>, _>("last_error")
                .map(|error| Self::sanitize_job_error(&error)),
        };
        tx.commit().await?;
        Ok(Some(response))
    }

    fn attestation_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Attestation> {
        let hash_hex: String = row.get("hash");
        let hash: [u8; 32] = hex::decode(hash_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid hash length in database"))?;
        Ok(Attestation {
            hash,
            timestamp: Self::nonnegative_i64_to_u64(
                row.get::<i64, _>("timestamp"),
                "attestation timestamp",
            )?,
            network_id: row.get("network_id"),
            sequence: Self::nonnegative_i64_to_u64(
                row.get::<i64, _>("sequence"),
                "attestation sequence",
            )?,
        })
    }

    fn u64_to_i64(value: u64, field: &str) -> Result<i64> {
        i64::try_from(value).map_err(|_| anyhow::anyhow!("{field} exceeds SQLite integer range"))
    }

    fn nonnegative_i64_to_u64(value: i64, field: &str) -> Result<u64> {
        u64::try_from(value).map_err(|_| anyhow::anyhow!("invalid negative {field} in database"))
    }

    fn sanitize_job_error(error: &str) -> String {
        let bounded: String = error
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .take(MAX_JOB_ERROR_CHARS)
            .collect();
        let sanitized = bounded.split_whitespace().collect::<Vec<_>>().join(" ");
        if sanitized.is_empty() {
            "unspecified job error".to_string()
        } else {
            sanitized
        }
    }

    fn job_status_from_db(status: &str) -> Result<AttestationJobStatus> {
        match status {
            "pending" => Ok(AttestationJobStatus::Pending),
            "retryable" => Ok(AttestationJobStatus::Retryable),
            "confirmed" => Ok(AttestationJobStatus::Confirmed),
            "failed" => Ok(AttestationJobStatus::Failed),
            _ => Err(anyhow::anyhow!("invalid attestation job status: {status}")),
        }
    }

    /// Disabled compatibility surface for the pre-job server flow.
    ///
    /// Production writes must use `reserve_job` and
    /// `complete_verified_job`; this method remains only so the Phase 1 crate
    /// compiles until those call sites are removed in Phase 2.
    #[cfg(not(test))]
    pub async fn store_attestation(
        &self,
        _signed: &SignedAttestation,
        _status: Option<&str>,
    ) -> Result<()> {
        Err(anyhow::anyhow!(
            "legacy attestation writes are disabled; use leased job operations"
        ))
    }

    /// Test-only fixture writer for storage tests predating durable jobs.
    #[cfg(test)]
    pub(crate) async fn store_attestation(
        &self,
        signed: &SignedAttestation,
        status: Option<&str>,
    ) -> Result<()> {
        let hash_hex = hex::encode(signed.attestation.hash);
        let status = status.unwrap_or("confirmed");

        // Store attestation
        sqlx::query(
            r#"
            INSERT INTO attestations (hash, timestamp, network_id, sequence, created_at, status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(hash) DO NOTHING
            "#,
        )
        .bind(&hash_hex)
        .bind(signed.attestation.timestamp as i64)
        .bind(&signed.attestation.network_id)
        .bind(signed.attestation.sequence as i64)
        .bind(epoch_secs() as i64)
        .bind(status)
        .execute(&self.pool)
        .await?;

        // Store signatures based on type
        match &signed.signatures {
            AttestationSignatures::MultiSig { signatures } => {
                // Store individual signatures
                for sig in signatures {
                    sqlx::query(
                        r#"
                        INSERT INTO signatures (hash, witness_id, signature)
                        VALUES (?1, ?2, ?3)
                        ON CONFLICT(hash, witness_id) DO NOTHING
                        "#,
                    )
                    .bind(&hash_hex)
                    .bind(&sig.witness_id)
                    .bind(&sig.signature)
                    .execute(&self.pool)
                    .await?;
                }
            }
            AttestationSignatures::Aggregated { signature, signers } => {
                sqlx::query(
                    r#"INSERT INTO aggregated_signatures (hash, signature, scheme)
                       VALUES (?1, ?2, 'bls')
                       ON CONFLICT(hash) DO NOTHING"#,
                )
                .bind(&hash_hex)
                .bind(signature)
                .execute(&self.pool)
                .await?;

                for (position, signer) in signers.iter().enumerate() {
                    sqlx::query(
                        r#"INSERT INTO aggregated_signers (hash, witness_id, position)
                           VALUES (?1, ?2, ?3)
                           ON CONFLICT(hash, witness_id) DO NOTHING"#,
                    )
                    .bind(&hash_hex)
                    .bind(signer)
                    .bind(position as i64)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        Ok(())
    }

    pub async fn get_attestation(&self, hash: &[u8; 32]) -> Result<Option<SignedAttestation>> {
        Ok(self
            .get_job(hash)
            .await?
            .and_then(|job| job.signed_attestation))
    }

    pub async fn get_attestation_status(&self, hash: &[u8; 32]) -> Result<Option<String>> {
        let hash_hex = hex::encode(hash);

        let row = sqlx::query(
            r#"
            SELECT status FROM attestations WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.get::<String, _>("status")))
    }

    /// Test-only compatibility reader. Production pending reads use `get_job`
    /// so an unsigned `SignedAttestation` is never constructed.
    #[cfg(test)]
    pub(crate) async fn get_pending_attestations(&self) -> Result<Vec<SignedAttestation>> {
        let rows = sqlx::query(
            r#"
            SELECT hash, timestamp, network_id, sequence
            FROM attestations
            WHERE status = 'pending'
            ORDER BY sequence ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut attestations = Vec::new();

        for row in rows {
            let hash_str: String = row.get("hash");
            let hash_bytes = hex::decode(&hash_str)?;
            let hash_array: [u8; 32] = hash_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid hash length in database"))?;

            let attestation = Attestation {
                hash: hash_array,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                network_id: row.get("network_id"),
                sequence: row.get::<i64, _>("sequence") as u64,
            };

            let signatures = self.read_signatures(&hash_str).await?;

            attestations.push(SignedAttestation {
                attestation,
                signatures,
            });
        }

        Ok(attestations)
    }

    /// Disabled compatibility surface; confirmation requires a verified result
    /// and a live opaque lease token.
    #[cfg(not(test))]
    pub async fn confirm_attestation(&self, _hash: &[u8; 32]) -> Result<()> {
        Err(anyhow::anyhow!(
            "legacy confirmation is disabled; use complete_verified_job"
        ))
    }

    /// Test-only fixture transition for storage tests predating durable jobs.
    #[cfg(test)]
    pub(crate) async fn confirm_attestation(&self, hash: &[u8; 32]) -> Result<()> {
        let hash_hex = hex::encode(hash);

        sqlx::query(
            r#"
            UPDATE attestations SET status = 'confirmed' WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_log_state(&self, network_id: &str) -> Result<Option<LogState>> {
        let row = sqlx::query(
            r#"
            SELECT current_root, tree_size, updated_at
            FROM log_state
            WHERE network_id = ?1
            "#,
        )
        .bind(network_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let root_vec: Vec<u8> = row.get("current_root");
        let current_root: [u8; 32] = root_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid root length in database"))?;

        Ok(Some(LogState {
            network_id: network_id.to_string(),
            current_root,
            tree_size: row.get::<i64, _>("tree_size") as u64,
            updated_at: row.get::<i64, _>("updated_at") as u64,
        }))
    }

    pub async fn update_log_state(
        &self,
        network_id: &str,
        root: &[u8; 32],
        tree_size: u64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO log_state (network_id, current_root, tree_size, updated_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(network_id)
        .bind(&root[..])
        .bind(tree_size as i64)
        .bind(epoch_secs() as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Disabled compatibility surface. Sequences may only be consumed by an
    /// atomic canonical reservation.
    #[cfg(not(test))]
    pub async fn get_next_sequence(&self, _network_id: &str) -> Result<u64> {
        Err(anyhow::anyhow!(
            "standalone sequence allocation is disabled; use reserve_job"
        ))
    }

    /// Test-only compatibility allocator for storage tests predating jobs.
    #[cfg(test)]
    pub(crate) async fn get_next_sequence(&self, network_id: &str) -> Result<u64> {
        // Atomic increment using INSERT ... ON CONFLICT to prevent race conditions.
        // Two concurrent callers will serialize on the row lock and get distinct values.
        let row = sqlx::query(
            r#"
            INSERT INTO sequences (network_id, next_val) VALUES (?1, 2)
            ON CONFLICT(network_id) DO UPDATE SET next_val = next_val + 1
            RETURNING next_val - 1 as seq
            "#,
        )
        .bind(network_id)
        .fetch_one(&self.pool)
        .await?;

        let seq: i64 = row.get("seq");
        Ok(seq as u64)
    }

    pub async fn check_duplicate(&self, hash: &[u8; 32]) -> Result<bool> {
        let hash_hex = hex::encode(hash);

        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM attestations
            WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = row.get("count");
        Ok(count > 0)
    }

    // ========== Phase 2: Batch Management ==========

    /// Get every complete confirmed result not yet linked to a batch.
    ///
    /// There is deliberately no timestamp watermark: a job confirmed after a
    /// long retry must remain eligible. Within a closing batch, canonical
    /// candidates are ordered by `(sequence, hash)`.
    pub async fn get_unbatched_attestations(
        &self,
        network_id: &str,
    ) -> Result<Vec<SignedAttestation>> {
        let rows = sqlx::query(
            r#"
            SELECT a.hash, a.timestamp, a.network_id, a.sequence, a.status,
                   s.witness_id, s.signature
            FROM attestations a
            LEFT JOIN signatures s ON s.hash = a.hash
            WHERE a.network_id = ?1
              AND a.batch_id IS NULL
              AND a.status = 'confirmed'
              AND (
                  EXISTS (SELECT 1 FROM signatures ms WHERE ms.hash = a.hash)
                  OR (
                      EXISTS (SELECT 1 FROM aggregated_signatures ag WHERE ag.hash = a.hash)
                      AND EXISTS (SELECT 1 FROM aggregated_signers asi WHERE asi.hash = a.hash)
                  )
              )
            ORDER BY a.sequence ASC, a.hash ASC, s.witness_id ASC
            "#,
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await?;

        let mut groups: Vec<(Attestation, Vec<WitnessSignature>, String)> = Vec::new();
        let mut hash_to_index: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for row in &rows {
            let hash_str: String = row.get("hash");
            if let Some(&idx) = hash_to_index.get(&hash_str) {
                if let Some(witness_id) = row.try_get::<Option<String>, _>("witness_id")? {
                    let signature: Vec<u8> = row.get("signature");
                    groups[idx].1.push(WitnessSignature {
                        witness_id,
                        signature,
                    });
                }
            } else {
                let hash_bytes = hex::decode(&hash_str)?;
                let hash_array: [u8; 32] = hash_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid hash length in database"))?;
                let attestation = Attestation {
                    hash: hash_array,
                    timestamp: row.get::<i64, _>("timestamp") as u64,
                    network_id: row.get("network_id"),
                    sequence: row.get::<i64, _>("sequence") as u64,
                };
                let mut sigs = Vec::new();
                if let Some(witness_id) = row.try_get::<Option<String>, _>("witness_id")? {
                    let signature: Vec<u8> = row.get("signature");
                    sigs.push(WitnessSignature {
                        witness_id,
                        signature,
                    });
                }
                hash_to_index.insert(hash_str.clone(), groups.len());
                groups.push((attestation, sigs, hash_str));
            }
        }

        let mut attestations = Vec::new();
        for (attestation, sigs, hash_str) in groups {
            let signatures = if sigs.is_empty() {
                self.read_signatures(&hash_str).await?
            } else {
                AttestationSignatures::MultiSig { signatures: sigs }
            };
            attestations.push(SignedAttestation {
                attestation,
                signatures,
            });
        }

        Ok(attestations)
    }

    /// Store a batch and associate attestations with it.
    /// Wrapped in a transaction so a crash mid-write can't leave orphaned batches
    /// or unlinked attestations.
    pub async fn store_batch(
        &self,
        batch: &AttestationBatch,
        attestation_hashes: &[[u8; 32]],
    ) -> Result<i64> {
        if attestation_hashes.is_empty() {
            anyhow::bail!("cannot store an empty attestation batch");
        }
        if batch.attestation_count != attestation_hashes.len() as u64 {
            anyhow::bail!("batch attestation count does not match candidate count");
        }
        let unique_hashes: std::collections::HashSet<_> = attestation_hashes.iter().collect();
        if unique_hashes.len() != attestation_hashes.len() {
            anyhow::bail!("batch contains duplicate attestation hashes");
        }
        let computed_root = MerkleTree::new(attestation_hashes.to_vec()).root();
        if computed_root != batch.merkle_root {
            anyhow::bail!("batch merkle root does not match candidate order");
        }

        let mut tx = self.pool.begin().await?;

        let result = sqlx::query(
            r#"
            INSERT INTO batches (network_id, merkle_root, period_start, period_end, attestation_count, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(&batch.network_id)
        .bind(&batch.merkle_root[..])
        .bind(batch.period_start as i64)
        .bind(batch.period_end as i64)
        .bind(batch.attestation_count as i64)
        .bind(epoch_secs() as i64)
        .execute(&mut *tx)
        .await?;

        let batch_id = result.last_insert_rowid();
        let mut previous_order: Option<(i64, String)> = None;

        for (index, hash) in attestation_hashes.iter().enumerate() {
            let hash_hex = hex::encode(hash);

            let candidate = sqlx::query(
                r#"
                SELECT sequence
                FROM attestations a
                WHERE a.hash = ?1
                  AND a.network_id = ?2
                  AND a.status = 'confirmed'
                  AND a.batch_id IS NULL
                  AND (
                      EXISTS (SELECT 1 FROM signatures ms WHERE ms.hash = a.hash)
                      OR (
                          EXISTS (SELECT 1 FROM aggregated_signatures ag WHERE ag.hash = a.hash)
                          AND EXISTS (SELECT 1 FROM aggregated_signers asi WHERE asi.hash = a.hash)
                      )
                  )
                "#,
            )
            .bind(&hash_hex)
            .bind(&batch.network_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(candidate) = candidate else {
                anyhow::bail!("batch candidate is no longer confirmed and unbatched");
            };
            let sequence: i64 = candidate.get("sequence");
            let order = (sequence, hash_hex.clone());
            if previous_order
                .as_ref()
                .is_some_and(|previous| previous >= &order)
            {
                anyhow::bail!("batch candidates are not ordered by sequence and hash");
            }
            previous_order = Some(order);

            let linked = sqlx::query(
                r#"
                UPDATE attestations
                SET batch_id = ?1
                WHERE hash = ?2
                  AND network_id = ?3
                  AND status = 'confirmed'
                  AND batch_id IS NULL
                "#,
            )
            .bind(batch_id)
            .bind(&hash_hex)
            .bind(&batch.network_id)
            .execute(&mut *tx)
            .await?;
            if linked.rows_affected() != 1 {
                anyhow::bail!("batch candidate was concurrently linked");
            }

            let positioned = sqlx::query(
                r#"
                INSERT INTO batch_attestations (batch_id, hash, merkle_index)
                SELECT ?1, ?2, ?3
                WHERE NOT EXISTS (
                    SELECT 1 FROM batch_attestations WHERE hash = ?2
                )
                  AND NOT EXISTS (
                    SELECT 1 FROM batch_attestations
                    WHERE batch_id = ?1 AND merkle_index = ?3
                  )
                "#,
            )
            .bind(batch_id)
            .bind(&hash_hex)
            .bind(index as i64)
            .execute(&mut *tx)
            .await?;
            if positioned.rows_affected() != 1 {
                anyhow::bail!("batch hash or merkle position is already linked");
            }
        }

        let linked_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM batch_attestations WHERE batch_id = ?1")
                .bind(batch_id)
                .fetch_one(&mut *tx)
                .await?;
        if linked_count != attestation_hashes.len() as i64 {
            anyhow::bail!("batch linking was partial");
        }

        tx.commit().await?;
        Ok(batch_id)
    }

    /// Get a batch by ID
    pub async fn get_batch(&self, batch_id: i64) -> Result<Option<AttestationBatch>> {
        let row = sqlx::query(
            r#"
            SELECT id, network_id, merkle_root, period_start, period_end, attestation_count
            FROM batches
            WHERE id = ?1
            "#,
        )
        .bind(batch_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let merkle_root_vec: Vec<u8> = row.get("merkle_root");
        let merkle_root: [u8; 32] = merkle_root_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid merkle_root length in database"))?;

        Ok(Some(AttestationBatch {
            id: row.get::<i64, _>("id") as u64,
            network_id: row.get("network_id"),
            merkle_root,
            period_start: row.get::<i64, _>("period_start") as u64,
            period_end: row.get::<i64, _>("period_end") as u64,
            attestation_count: row.get::<i64, _>("attestation_count") as u64,
        }))
    }

    /// Get batch ID for an attestation hash
    pub async fn get_batch_id_for_attestation(&self, hash: &[u8; 32]) -> Result<Option<i64>> {
        let hash_hex = hex::encode(hash);

        let row = sqlx::query(
            r#"
            SELECT batch_id FROM attestations WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| r.get("batch_id")))
    }

    /// Get all attestation hashes for a batch, ordered by merkle index
    pub async fn get_batch_attestation_hashes(&self, batch_id: i64) -> Result<Vec<[u8; 32]>> {
        let rows = sqlx::query(
            r#"
            SELECT ba.hash
            FROM batch_attestations ba
            JOIN attestations a ON a.hash = ba.hash AND a.batch_id = ba.batch_id
            WHERE ba.batch_id = ?1 AND a.status = 'confirmed'
            ORDER BY ba.merkle_index ASC
            "#,
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;

        let mut hashes = Vec::new();
        for row in rows {
            let hash_hex: String = row.get("hash");
            let hash_bytes = hex::decode(&hash_hex)?;
            let hash_array: [u8; 32] = hash_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid hash length"))?;
            hashes.push(hash_array);
        }

        Ok(hashes)
    }

    /// Get batch info for an attestation (batch_id, merkle_index, merkle_root)
    pub async fn get_attestation_batch_info(
        &self,
        hash: &str,
    ) -> Result<Option<(i64, usize, [u8; 32])>> {
        let row = sqlx::query(
            r#"
            SELECT ba.batch_id, ba.merkle_index, b.merkle_root
            FROM batch_attestations ba
            JOIN batches b ON ba.batch_id = b.id
            JOIN attestations a ON a.hash = ba.hash AND a.batch_id = ba.batch_id
            WHERE ba.hash = ?1 AND a.status = 'confirmed'
            "#,
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let batch_id: i64 = row.get("batch_id");
        let merkle_index: i64 = row.get("merkle_index");
        let merkle_root_vec: Vec<u8> = row.get("merkle_root");
        let merkle_root: [u8; 32] = merkle_root_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid merkle root length"))?;

        Ok(Some((batch_id, merkle_index as usize, merkle_root)))
    }

    /// Store a cross-anchor.  The peer's [`SignedAttestation`] is serialized
    /// as JSON so the row is a self-contained, independently verifiable
    /// witness over the batch's merkle root.
    pub async fn store_cross_anchor(&self, cross_anchor: &CrossAnchor) -> Result<()> {
        let witness_attestation_json = serde_json::to_string(&cross_anchor.witness_attestation)?;

        sqlx::query(
            r#"
            INSERT INTO cross_anchors (batch_id, witnessing_network, witness_attestation_json, timestamp, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(cross_anchor.batch.id as i64)
        .bind(&cross_anchor.witnessing_network)
        .bind(&witness_attestation_json)
        .bind(cross_anchor.timestamp as i64)
        .bind(epoch_secs() as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get cross-anchors for a batch
    pub async fn get_cross_anchors(&self, batch_id: i64) -> Result<Vec<CrossAnchor>> {
        let rows = sqlx::query(
            r#"
            SELECT witnessing_network, witness_attestation_json, timestamp
            FROM cross_anchors
            WHERE batch_id = ?1
            ORDER BY id ASC
            "#,
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let batch = self
            .get_batch(batch_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Batch not found"))?;

        let mut cross_anchors = Vec::with_capacity(rows.len());

        for row in rows {
            let witness_attestation_json: String = row.get("witness_attestation_json");
            let witness_attestation: SignedAttestation =
                serde_json::from_str(&witness_attestation_json)?;

            cross_anchors.push(CrossAnchor {
                batch: batch.clone(),
                witnessing_network: row.get("witnessing_network"),
                witness_attestation,
                timestamp: row.get::<i64, _>("timestamp") as u64,
            });
        }

        Ok(cross_anchors)
    }

    // ========== RFC 9162 Signed Tree Heads ==========

    /// Persist a [`SignedTreeHead`] alongside the batch it was issued for.
    /// `tree_size` is the global log size after `batch_id` was appended;
    /// each closed batch produces exactly one STH.
    pub async fn store_sth(&self, sth: &SignedTreeHead, batch_id: i64) -> Result<()> {
        let signed_json = serde_json::to_string(&sth.signed_attestation)?;

        sqlx::query(
            r#"
            INSERT INTO signed_tree_heads (
                tree_size, network_id, timestamp, root_hash,
                batch_id, signed_attestation_json, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(sth.tree_head.tree_size as i64)
        .bind(&sth.tree_head.network_id)
        .bind(sth.tree_head.timestamp as i64)
        .bind(&sth.tree_head.root_hash[..])
        .bind(batch_id)
        .bind(&signed_json)
        .bind(epoch_secs() as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Most-recent STH for `network_id`, or `None` if no batches have closed
    /// yet (the log is empty).
    pub async fn get_latest_sth(&self, network_id: &str) -> Result<Option<SignedTreeHead>> {
        let row = sqlx::query(
            r#"
            SELECT tree_size, timestamp, root_hash, signed_attestation_json
            FROM signed_tree_heads
            WHERE network_id = ?1
            ORDER BY tree_size DESC
            LIMIT 1
            "#,
        )
        .bind(network_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Self::row_to_sth(network_id, row)
    }

    /// Look up the STH for a specific `tree_size` (one per closed batch).
    pub async fn get_sth(
        &self,
        network_id: &str,
        tree_size: u64,
    ) -> Result<Option<SignedTreeHead>> {
        let row = sqlx::query(
            r#"
            SELECT tree_size, timestamp, root_hash, signed_attestation_json
            FROM signed_tree_heads
            WHERE network_id = ?1 AND tree_size = ?2
            "#,
        )
        .bind(network_id)
        .bind(tree_size as i64)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Self::row_to_sth(network_id, row)
    }

    fn row_to_sth(
        network_id: &str,
        row: sqlx::sqlite::SqliteRow,
    ) -> Result<Option<SignedTreeHead>> {
        let tree_size: i64 = row.get("tree_size");
        let timestamp: i64 = row.get("timestamp");
        let root_vec: Vec<u8> = row.get("root_hash");
        let root_hash: [u8; 32] = root_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid root_hash length"))?;

        let signed_json: String = row.get("signed_attestation_json");
        let signed_attestation: SignedAttestation = serde_json::from_str(&signed_json)?;

        Ok(Some(SignedTreeHead {
            tree_head: TreeHead {
                network_id: network_id.to_string(),
                tree_size: tree_size as u64,
                timestamp: timestamp as u64,
                root_hash,
            },
            signed_attestation,
        }))
    }

    /// All log leaves for `network_id` in append order
    /// `(batch_id ASC, merkle_index ASC)`. This is confirmation/batch order,
    /// not global reservation-sequence order: a recovered lower sequence may
    /// append in a later batch. Used to compute the global Merkle Tree Hash and
    /// inclusion / consistency proofs.
    pub async fn get_log_leaves(&self, network_id: &str) -> Result<Vec<[u8; 32]>> {
        let rows = sqlx::query(
            r#"
            SELECT ba.hash AS hash
            FROM batch_attestations ba
            JOIN batches b ON ba.batch_id = b.id
            JOIN attestations a ON a.hash = ba.hash AND a.batch_id = ba.batch_id
            WHERE b.network_id = ?1 AND a.status = 'confirmed'
            ORDER BY ba.batch_id ASC, ba.merkle_index ASC
            "#,
        )
        .bind(network_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let hash_hex: String = row.get("hash");
            let bytes = hex::decode(&hash_hex)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid leaf hash length"))?;
            out.push(arr);
        }
        Ok(out)
    }

    /// Position of `attestation_hash` in the global log, if it has been
    /// included in a closed batch.
    pub async fn get_log_index(
        &self,
        network_id: &str,
        attestation_hash: &[u8; 32],
    ) -> Result<Option<u64>> {
        let hash_hex = hex::encode(attestation_hash);
        let row = sqlx::query(
            r#"
            SELECT (
                SELECT COUNT(*)
                FROM batch_attestations ba2
                JOIN batches b2 ON ba2.batch_id = b2.id
                JOIN attestations a2 ON a2.hash = ba2.hash AND a2.batch_id = ba2.batch_id
                WHERE b2.network_id = ?1
                  AND a2.status = 'confirmed'
                  AND (
                    ba2.batch_id < ba.batch_id
                    OR (ba2.batch_id = ba.batch_id AND ba2.merkle_index < ba.merkle_index)
                  )
            ) AS log_index
            FROM batch_attestations ba
            JOIN batches b ON ba.batch_id = b.id
            JOIN attestations a ON a.hash = ba.hash AND a.batch_id = ba.batch_id
            WHERE b.network_id = ?1 AND ba.hash = ?2 AND a.status = 'confirmed'
            "#,
        )
        .bind(network_id)
        .bind(&hash_hex)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.get::<i64, _>("log_index") as u64))
    }

    // ========== Phase 3: External Anchor Proofs ==========

    /// Store an external anchor proof for a batch
    pub async fn store_anchor_proof(
        &self,
        batch_id: u64,
        proof: &ExternalAnchorProof,
    ) -> Result<()> {
        let provider_str = format!("{}", proof.provider);
        let proof_json = serde_json::to_string(&proof.proof)?;

        sqlx::query(
            r#"
            INSERT INTO external_anchor_proofs (batch_id, provider, timestamp, proof_json, anchored_data, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
        )
        .bind(batch_id as i64)
        .bind(&provider_str)
        .bind(proof.timestamp as i64)
        .bind(&proof_json)
        .bind(proof.anchored_data.as_deref())
        .bind(epoch_secs() as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all external anchor proofs for a batch
    pub async fn get_anchor_proofs(&self, batch_id: u64) -> Result<Vec<ExternalAnchorProof>> {
        let rows = sqlx::query(
            r#"
            SELECT provider, timestamp, proof_json, anchored_data
            FROM external_anchor_proofs
            WHERE batch_id = ?1
            ORDER BY created_at ASC
            "#,
        )
        .bind(batch_id as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut proofs = Vec::new();

        for row in rows {
            let provider_str: String = row.get("provider");
            let provider = match provider_str.as_str() {
                "internet_archive" => witness_core::AnchorProviderType::InternetArchive,
                "trillian" => witness_core::AnchorProviderType::Trillian,
                "dns_txt" => witness_core::AnchorProviderType::DnsTxt,
                "blockchain" => witness_core::AnchorProviderType::Blockchain,
                _ => continue, // Skip unknown providers
            };

            let proof_json: String = row.get("proof_json");
            let proof_value: serde_json::Value = serde_json::from_str(&proof_json)?;

            let anchored_data: Option<Vec<u8>> = row.get("anchored_data");

            proofs.push(ExternalAnchorProof {
                provider,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                proof: proof_value,
                anchored_data,
            });
        }

        Ok(proofs)
    }

    // ========== Admin Dashboard Stats ==========

    /// Count total attestations
    pub async fn count_attestations(&self) -> Result<u64> {
        let row = sqlx::query(r#"SELECT COUNT(*) as count FROM attestations"#)
            .fetch_one(&self.pool)
            .await?;

        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    /// Count attestations since a given timestamp
    pub async fn count_attestations_since(&self, since: u64) -> Result<u64> {
        let row =
            sqlx::query(r#"SELECT COUNT(*) as count FROM attestations WHERE timestamp >= ?1"#)
                .bind(since as i64)
                .fetch_one(&self.pool)
                .await?;

        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    /// Count total batches
    pub async fn count_batches(&self) -> Result<u64> {
        let row = sqlx::query(r#"SELECT COUNT(*) as count FROM batches"#)
            .fetch_one(&self.pool)
            .await?;

        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    /// Get recent attestations for the dashboard
    pub async fn get_recent_attestations(&self, limit: usize) -> Result<Vec<SignedAttestation>> {
        let rows = sqlx::query(
            r#"
            SELECT a.hash, a.timestamp, a.network_id, a.sequence, a.status,
                   s.witness_id, s.signature
            FROM attestations a
            LEFT JOIN signatures s ON s.hash = a.hash
            ORDER BY a.timestamp DESC, a.sequence DESC
            LIMIT ?1
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut groups: Vec<(Attestation, Vec<WitnessSignature>, String)> = Vec::new();
        let mut hash_to_index: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        for row in &rows {
            let hash_str: String = row.get("hash");
            if let Some(&idx) = hash_to_index.get(&hash_str) {
                if let Some(witness_id) = row.try_get::<Option<String>, _>("witness_id")? {
                    let signature: Vec<u8> = row.get("signature");
                    groups[idx].1.push(WitnessSignature {
                        witness_id,
                        signature,
                    });
                }
            } else {
                let hash_bytes = hex::decode(&hash_str)?;
                let hash_array: [u8; 32] = hash_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid hash length in database"))?;
                let attestation = Attestation {
                    hash: hash_array,
                    timestamp: row.get::<i64, _>("timestamp") as u64,
                    network_id: row.get("network_id"),
                    sequence: row.get::<i64, _>("sequence") as u64,
                };
                let mut sigs = Vec::new();
                if let Some(witness_id) = row.try_get::<Option<String>, _>("witness_id")? {
                    let signature: Vec<u8> = row.get("signature");
                    sigs.push(WitnessSignature {
                        witness_id,
                        signature,
                    });
                }
                hash_to_index.insert(hash_str.clone(), groups.len());
                groups.push((attestation, sigs, hash_str));
            }
        }

        let mut attestations = Vec::new();
        for (attestation, sigs, hash_str) in groups {
            let signatures = if sigs.is_empty() {
                self.read_signatures(&hash_str).await?
            } else {
                AttestationSignatures::MultiSig { signatures: sigs }
            };
            attestations.push(SignedAttestation {
                attestation,
                signatures,
            });
        }

        Ok(attestations)
    }

    /// Get anchor stats for a provider
    pub async fn get_anchor_stats(&self, provider: &str) -> Result<(Option<u64>, u64)> {
        let row = sqlx::query(
            r#"
            SELECT MAX(timestamp) as last_time, COUNT(*) as total
            FROM external_anchor_proofs
            WHERE provider = ?1
            "#,
        )
        .bind(provider)
        .fetch_one(&self.pool)
        .await?;

        let last_time: Option<i64> = row.get("last_time");
        let total: i64 = row.get("total");

        Ok((last_time.map(|t| t as u64), total as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    async fn setup_test_db() -> Storage {
        let storage = Storage::new("sqlite::memory:").await.unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn file_test_db(label: &str) -> (String, PathBuf) {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let path = std::env::temp_dir().join(format!(
            "witness-{label}-{}-{}.sqlite",
            std::process::id(),
            hex::encode(random)
        ));
        (format!("sqlite://{}", path.display()), path)
    }

    fn remove_test_db(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    }

    fn create_test_attestation(hash: [u8; 32], sequence: u64) -> SignedAttestation {
        let attestation = Attestation {
            hash,
            timestamp: 1700000000 + sequence,
            network_id: "test-network".to_string(),
            sequence,
        };

        let signatures = AttestationSignatures::MultiSig {
            signatures: vec![
                WitnessSignature {
                    witness_id: "witness-1".to_string(),
                    signature: vec![1, 2, 3, 4],
                },
                WitnessSignature {
                    witness_id: "witness-2".to_string(),
                    signature: vec![5, 6, 7, 8],
                },
            ],
        };

        SignedAttestation {
            attestation,
            signatures,
        }
    }

    fn signed_job(attestation: Attestation, witness_id: &str) -> SignedAttestation {
        SignedAttestation {
            attestation,
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: witness_id.to_string(),
                    signature: vec![7; 64],
                }],
            },
        }
    }

    #[tokio::test]
    async fn file_sqlite_uses_nonzero_busy_timeout() {
        let (url, path) = file_test_db("busy-timeout");
        let storage = Storage::new(&url).await.unwrap();
        storage.migrate().await.unwrap();

        let row = sqlx::query("PRAGMA busy_timeout")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert!(row.get::<i64, _>(0) > 0);

        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn concurrent_file_pools_reserve_one_hash_without_consuming_duplicate_sequence() {
        let (url, path) = file_test_db("reservation-race");
        let first = Storage::new(&url).await.unwrap();
        first.migrate().await.unwrap();
        let second = Storage::new(&url).await.unwrap();
        let hash = [21u8; 32];

        let (left, right) = tokio::join!(
            first.reserve_job(&hash, "network-a", 100),
            second.reserve_job(&hash, "network-b", 200)
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(usize::from(left.created) + usize::from(right.created), 1);
        assert_eq!(left.job.attestation, right.job.attestation);
        assert_eq!(left.job.status, AttestationJobStatus::Pending);
        assert!(left.job.signed_attestation.is_none());
        let winning_network = left.job.attestation.network_id.clone();
        let losing_network = if winning_network == "network-a" {
            "network-b"
        } else {
            "network-a"
        };

        let next = second
            .reserve_job(&[22u8; 32], &winning_network, 300)
            .await
            .unwrap();
        assert!(next.created);
        assert_eq!(next.job.attestation.sequence, 2);
        let losing_network_first = first
            .reserve_job(&[25u8; 32], losing_network, 300)
            .await
            .unwrap();
        assert_eq!(losing_network_first.job.attestation.sequence, 1);

        let (third, fourth) = tokio::join!(
            first.reserve_job(&[23u8; 32], &winning_network, 301),
            second.reserve_job(&[24u8; 32], &winning_network, 302)
        );
        let mut sequences = vec![
            next.job.attestation.sequence,
            third.unwrap().job.attestation.sequence,
            fourth.unwrap().job.attestation.sequence,
        ];
        sequences.sort_unstable();
        assert_eq!(sequences, vec![2, 3, 4]);

        first.pool.close().await;
        second.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn independent_file_pools_claim_job_once() {
        let (url, path) = file_test_db("claim-race");
        let first = Storage::new(&url).await.unwrap();
        first.migrate().await.unwrap();
        let second = Storage::new(&url).await.unwrap();
        first
            .reserve_job(&[26u8; 32], "network", 100)
            .await
            .unwrap();

        let (left, right) = tokio::join!(
            first.claim_job("network", 100, 30),
            second.claim_job("network", 100, 30)
        );
        let claims = [left.unwrap(), right.unwrap()];
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);

        first.pool.close().await;
        second.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn duplicate_reservation_retains_retry_metadata() {
        let (url, path) = file_test_db("duplicate-metadata");
        let first = Storage::new(&url).await.unwrap();
        first.migrate().await.unwrap();
        let second = Storage::new(&url).await.unwrap();
        let hash = [27u8; 32];
        let original = first
            .reserve_job(&hash, "canonical-network", 100)
            .await
            .unwrap();
        let claim = first
            .claim_job("canonical-network", 100, 30)
            .await
            .unwrap()
            .unwrap();
        first
            .reschedule_job(&hash, &claim.lease_token, 101, " retry\nmetadata ")
            .await
            .unwrap();

        let duplicate = second
            .reserve_job(&hash, "other-network", 999)
            .await
            .unwrap();
        assert!(!duplicate.created);
        assert_eq!(duplicate.job.attestation, original.job.attestation);
        assert_eq!(duplicate.job.status, AttestationJobStatus::Retryable);
        assert_eq!(duplicate.job.attempts, 1);
        assert_eq!(duplicate.job.next_attempt_at, Some(102));
        assert_eq!(duplicate.job.last_error.as_deref(), Some("retry metadata"));
        assert!(duplicate.job.signed_attestation.is_none());

        first.pool.close().await;
        second.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn cancelled_raii_transaction_rolls_back_sequence_allocation() {
        let (url, path) = file_test_db("cancelled-transaction");
        let storage = Storage::new(&url).await.unwrap();
        storage.migrate().await.unwrap();
        let pool = storage.pool.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("INSERT INTO sequences(network_id, next_val) VALUES ('network', 2)")
                .execute(&mut *tx)
                .await
                .unwrap();
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            tx.commit().await.unwrap();
        });
        started_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let reservation = storage
            .reserve_job(&[28u8; 32], "network", 100)
            .await
            .unwrap();
        assert_eq!(reservation.job.attestation.sequence, 1);

        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn stale_lease_cannot_transition_reclaimed_job() {
        let (url, path) = file_test_db("stale-lease");
        let storage = Storage::new(&url).await.unwrap();
        storage.migrate().await.unwrap();
        let hash = [31u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();

        let stale = storage
            .claim_job("network", 100, 10)
            .await
            .unwrap()
            .unwrap();
        let current = storage
            .claim_job("network", 111, 20)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stale.lease_token, current.lease_token);
        assert_eq!(current.attempts, 2);

        let signed = SignedAttestation {
            attestation: current.attestation.clone(),
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: "current".to_string(),
                    signature: vec![1, 2, 3],
                }],
            },
        };
        assert!(!storage
            .complete_verified_job(&signed, &stale.lease_token, 112)
            .await
            .unwrap());
        assert!(!storage
            .reschedule_job(&hash, &stale.lease_token, 112, "stale")
            .await
            .unwrap());
        assert!(!storage
            .fail_job(&hash, &stale.lease_token, 112, "stale")
            .await
            .unwrap());
        assert!(storage
            .complete_verified_job(&signed, &current.lease_token, 112)
            .await
            .unwrap());

        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn expired_or_tuple_mismatched_finalization_is_a_noop() {
        let storage = setup_test_db().await;
        let hash = [32u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let claim = storage
            .claim_job("network", 100, 10)
            .await
            .unwrap()
            .unwrap();
        let mut mismatched = SignedAttestation {
            attestation: claim.attestation.clone(),
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: "verified".to_string(),
                    signature: vec![1],
                }],
            },
        };
        mismatched.attestation.sequence += 1;
        assert!(!storage
            .complete_verified_job(&mismatched, &claim.lease_token, 109)
            .await
            .unwrap());

        let valid = SignedAttestation {
            attestation: claim.attestation,
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: "verified".to_string(),
                    signature: vec![1],
                }],
            },
        };
        assert!(!storage
            .complete_verified_job(&valid, &claim.lease_token, 110)
            .await
            .unwrap());
        assert!(!storage
            .reschedule_job(&hash, &claim.lease_token, 110, "expired")
            .await
            .unwrap());
        assert!(!storage
            .fail_job(&hash, &claim.lease_token, 110, "expired")
            .await
            .unwrap());
        let pending = storage.get_job(&hash).await.unwrap().unwrap();
        assert_eq!(pending.status, AttestationJobStatus::Pending);
        assert!(pending.signed_attestation.is_none());
        let signature_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signatures WHERE hash = ?1")
                .bind(hex::encode(hash))
                .fetch_one(&storage.pool)
                .await
                .unwrap();
        assert_eq!(signature_count, 0);
    }

    #[tokio::test]
    async fn invalid_integer_ranges_and_lease_overflow_are_rejected() {
        let storage = setup_test_db().await;
        assert!(storage
            .reserve_job(&[33u8; 32], "network", u64::MAX)
            .await
            .is_err());
        let latest_db_time = i64::MAX as u64;
        storage
            .reserve_job(&[34u8; 32], "network", latest_db_time)
            .await
            .unwrap();
        assert!(storage
            .claim_job("network", latest_db_time, 1)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn finalization_is_atomic_and_confirmed_result_is_immutable() {
        let (url, path) = file_test_db("atomic-finalization");
        let storage = Storage::new(&url).await.unwrap();
        storage.migrate().await.unwrap();
        let hash = [41u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let claim = storage
            .claim_job("network", 100, 30)
            .await
            .unwrap()
            .unwrap();
        let hash_hex = hex::encode(hash);

        // Simulate a signature fragment left by the legacy pending flow.
        sqlx::query(
            "INSERT INTO signatures(hash, witness_id, signature) VALUES (?1, 'legacy', X'00')",
        )
        .bind(&hash_hex)
        .execute(&storage.pool)
        .await
        .unwrap();

        // A constraint failure after the status update must roll back the whole
        // transaction, including deletion of the legacy fragment.
        let invalid = SignedAttestation {
            attestation: claim.attestation.clone(),
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![
                    WitnessSignature {
                        witness_id: "duplicate".to_string(),
                        signature: vec![1],
                    },
                    WitnessSignature {
                        witness_id: "duplicate".to_string(),
                        signature: vec![2],
                    },
                ],
            },
        };
        assert!(storage
            .complete_verified_job(&invalid, &claim.lease_token, 101)
            .await
            .is_err());
        let pending = storage.get_job(&hash).await.unwrap().unwrap();
        assert_eq!(pending.status, AttestationJobStatus::Pending);
        assert!(pending.signed_attestation.is_none());
        let fragment_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM signatures WHERE hash = ?1 AND witness_id = 'legacy'",
        )
        .bind(&hash_hex)
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert_eq!(fragment_count, 1);

        let valid = SignedAttestation {
            attestation: claim.attestation.clone(),
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: "verified".to_string(),
                    signature: vec![9, 8, 7],
                }],
            },
        };
        assert!(storage
            .complete_verified_job(&valid, &claim.lease_token, 102)
            .await
            .unwrap());
        let confirmed = storage.get_job(&hash).await.unwrap().unwrap();
        assert_eq!(confirmed.status, AttestationJobStatus::Confirmed);
        let result = confirmed.signed_attestation.unwrap();
        assert_eq!(result.signature_count(), 1);

        let replacement = SignedAttestation {
            attestation: claim.attestation,
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: "replacement".to_string(),
                    signature: vec![6],
                }],
            },
        };
        assert!(!storage
            .complete_verified_job(&replacement, &claim.lease_token, 103)
            .await
            .unwrap());
        let unchanged = storage.get_job(&hash).await.unwrap().unwrap();
        let unchanged = unchanged.signed_attestation.unwrap();
        match unchanged.signatures {
            AttestationSignatures::MultiSig { signatures } => {
                assert_eq!(signatures[0].witness_id, "verified");
                assert_eq!(signatures[0].signature, vec![9, 8, 7]);
            }
            _ => panic!("expected multisig"),
        }

        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn bls_finalization_replaces_all_pending_signature_representations() {
        let storage = setup_test_db().await;
        let hash = [42u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let claim = storage
            .claim_job("network", 100, 30)
            .await
            .unwrap()
            .unwrap();
        let hash_hex = hex::encode(hash);
        sqlx::query(
            "INSERT INTO signatures(hash, witness_id, signature) VALUES (?1, 'legacy-ed', X'01')",
        )
        .bind(&hash_hex)
        .execute(&storage.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO aggregated_signatures(hash, signature, scheme) VALUES (?1, X'02', 'bls')",
        )
        .bind(&hash_hex)
        .execute(&storage.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO aggregated_signers(hash, witness_id, position) VALUES (?1, 'legacy-bls', 0)",
        )
        .bind(&hash_hex)
        .execute(&storage.pool)
        .await
        .unwrap();

        let signed = SignedAttestation::new_with_aggregated(
            claim.attestation,
            vec![9, 9],
            vec!["new-a".to_string(), "new-b".to_string()],
        );
        assert!(storage
            .complete_verified_job(&signed, &claim.lease_token, 101)
            .await
            .unwrap());
        let ed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signatures WHERE hash = ?1")
            .bind(&hash_hex)
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(ed_count, 0);
        let aggregate: Vec<u8> =
            sqlx::query_scalar("SELECT signature FROM aggregated_signatures WHERE hash = ?1")
                .bind(&hash_hex)
                .fetch_one(&storage.pool)
                .await
                .unwrap();
        assert_eq!(aggregate, vec![9, 9]);
        let signers: Vec<String> = sqlx::query_scalar(
            "SELECT witness_id FROM aggregated_signers WHERE hash = ?1 ORDER BY position",
        )
        .bind(&hash_hex)
        .fetch_all(&storage.pool)
        .await
        .unwrap();
        assert_eq!(signers, vec!["new-a", "new-b"]);
    }

    #[tokio::test]
    async fn concurrent_snapshot_and_finalization_never_mix_status_and_result() {
        let (url, path) = file_test_db("snapshot-finalization");
        let reader = Storage::new(&url).await.unwrap();
        reader.migrate().await.unwrap();
        let writer = Storage::new(&url).await.unwrap();
        let hash = [43u8; 32];
        reader.reserve_job(&hash, "network", 100).await.unwrap();
        let claim = reader.claim_job("network", 100, 30).await.unwrap().unwrap();
        let signed = SignedAttestation {
            attestation: claim.attestation,
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: "verified".to_string(),
                    signature: vec![7, 7],
                }],
            },
        };

        let read_snapshots = async {
            for _ in 0..100 {
                let snapshot = reader.get_job(&hash).await.unwrap().unwrap();
                match snapshot.status {
                    AttestationJobStatus::Pending => {
                        assert!(snapshot.signed_attestation.is_none());
                    }
                    AttestationJobStatus::Confirmed => {
                        let result = snapshot.signed_attestation.unwrap();
                        assert_eq!(result.attestation, signed.attestation);
                        match result.signatures {
                            AttestationSignatures::MultiSig { signatures } => {
                                assert_eq!(signatures.len(), 1);
                                assert_eq!(signatures[0].witness_id, "verified");
                                assert_eq!(signatures[0].signature, vec![7, 7]);
                            }
                            _ => panic!("expected multisig"),
                        }
                    }
                    status => panic!("unexpected status: {status:?}"),
                }
                tokio::task::yield_now().await;
            }
        };
        let finalize = async {
            tokio::task::yield_now().await;
            assert!(writer
                .complete_verified_job(&signed, &claim.lease_token, 101)
                .await
                .unwrap());
        };
        tokio::join!(read_snapshots, finalize);

        reader.pool.close().await;
        writer.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn retry_schedule_is_durable_and_exponential() {
        let storage = setup_test_db().await;
        let hash = [51u8; 32];
        storage.reserve_job(&hash, "network", 100).await.unwrap();
        let first = storage
            .claim_job("network", 100, 20)
            .await
            .unwrap()
            .unwrap();
        assert!(storage
            .reschedule_job(&hash, &first.lease_token, 101, "quorum unavailable")
            .await
            .unwrap());
        let retry = storage.get_job(&hash).await.unwrap().unwrap();
        assert_eq!(retry.status, AttestationJobStatus::Retryable);
        assert_eq!(retry.attempts, 1);
        assert_eq!(retry.next_attempt_at, Some(102));
        assert_eq!(retry.last_error.as_deref(), Some("quorum unavailable"));
        assert!(storage
            .claim_job("network", 101, 20)
            .await
            .unwrap()
            .is_none());

        let second = storage
            .claim_job("network", 102, 20)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.attempts, 2);
        assert!(storage
            .reschedule_job(&hash, &second.lease_token, 103, "still unavailable")
            .await
            .unwrap());
        assert_eq!(
            storage
                .get_job(&hash)
                .await
                .unwrap()
                .unwrap()
                .next_attempt_at,
            Some(105)
        );

        let failed_hash = [52u8; 32];
        storage
            .reserve_job(&failed_hash, "failed-network", 200)
            .await
            .unwrap();
        let failed_claim = storage
            .claim_job("failed-network", 200, 20)
            .await
            .unwrap()
            .unwrap();
        let unsafe_error = format!(" permanent\n\0failure {}", "x".repeat(1_000));
        assert!(storage
            .fail_job(&failed_hash, &failed_claim.lease_token, 201, &unsafe_error,)
            .await
            .unwrap());
        let failed = storage.get_job(&failed_hash).await.unwrap().unwrap();
        assert_eq!(failed.status, AttestationJobStatus::Failed);
        assert_eq!(failed.next_attempt_at, None);
        let stored_error = failed.last_error.unwrap();
        assert!(!stored_error.chars().any(char::is_control));
        assert!(stored_error.chars().count() <= MAX_JOB_ERROR_CHARS);
        assert!(stored_error.starts_with("permanent failure"));
    }

    #[tokio::test]
    async fn migration_recovers_legacy_jobs_and_sequence_counter() {
        use sqlx::migrate::Migrate;

        let (url, path) = file_test_db("legacy-migration");
        let storage = Storage::new(&url).await.unwrap();
        let migrator = sqlx::migrate!("./migrations");
        let mut conn = storage.pool.acquire().await.unwrap();
        conn.ensure_migrations_table().await.unwrap();
        for migration in migrator.iter().filter(|migration| migration.version <= 7) {
            conn.apply(migration).await.unwrap();
        }

        sqlx::query(
            r#"
            INSERT INTO attestations(hash, timestamp, network_id, sequence, created_at, status)
            VALUES
                (?1, 10, 'network', 7, 10, 'pending'),
                (?2, 11, 'network', 9, 11, 'confirmed'),
                (?3, 12, 'network', 10, 12, 'confirmed'),
                (?4, 13, 'network', 11, 13, 'mystery'),
                (?5, 14, 'network', 12, 14, 'confirmed'),
                (?6, 15, 'network', 13, 15, 'confirmed'),
                (?7, 16, 'lagging-network', 20, 16, 'confirmed')
            "#,
        )
        .bind(hex::encode([61u8; 32]))
        .bind(hex::encode([62u8; 32]))
        .bind(hex::encode([63u8; 32]))
        .bind(hex::encode([64u8; 32]))
        .bind(hex::encode([65u8; 32]))
        .bind(hex::encode([66u8; 32]))
        .bind(hex::encode([67u8; 32]))
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO signatures(hash, witness_id, signature) VALUES
                (?1, 'ed25519-witness', zeroblob(64)),
                (?2, 'unknown-state-witness', zeroblob(64)),
                (?3, 'BLS_AGGREGATED:bls-one,bls-two', zeroblob(96)),
                (?4, 'lagging-witness', zeroblob(64)),
                (?5, 'partial-pending', X'00')
            "#,
        )
        .bind(hex::encode([62u8; 32]))
        .bind(hex::encode([64u8; 32]))
        .bind(hex::encode([65u8; 32]))
        .bind(hex::encode([67u8; 32]))
        .bind(hex::encode([61u8; 32]))
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO aggregated_signatures(hash, signature, scheme) VALUES (?1, zeroblob(96), 'bls')",
        )
        .bind(hex::encode([66u8; 32]))
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO aggregated_signers(hash, witness_id, position) VALUES (?1, 'bls-dedicated', 0)",
        )
        .bind(hex::encode([66u8; 32]))
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("INSERT INTO sequences(network_id, next_val) VALUES ('network', 99)")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sequences(network_id, next_val) VALUES ('empty-network', 99)")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sequences(network_id, next_val) VALUES ('lagging-network', 1)")
            .execute(&mut *conn)
            .await
            .unwrap();
        let migration = migrator
            .iter()
            .find(|migration| migration.version == 8)
            .unwrap();
        conn.apply(migration).await.unwrap();
        drop(conn);

        let pending = storage.get_job(&[61u8; 32]).await.unwrap().unwrap();
        assert_eq!(pending.status, AttestationJobStatus::Pending);
        assert_eq!(pending.next_attempt_at, Some(0));
        assert_eq!(pending.attempts, 0);
        assert!(pending.signed_attestation.is_none());
        let confirmed = storage.get_job(&[62u8; 32]).await.unwrap().unwrap();
        assert_eq!(confirmed.status, AttestationJobStatus::Confirmed);
        assert!(confirmed.signed_attestation.is_some());
        let unsigned = storage.get_job(&[63u8; 32]).await.unwrap().unwrap();
        assert_eq!(unsigned.status, AttestationJobStatus::Failed);
        assert_eq!(
            unsigned.last_error.as_deref(),
            Some("legacy confirmed row has no signatures")
        );
        assert!(unsigned.signed_attestation.is_none());
        let unknown = storage.get_job(&[64u8; 32]).await.unwrap().unwrap();
        assert_eq!(unknown.status, AttestationJobStatus::Failed);
        assert_eq!(
            unknown.last_error.as_deref(),
            Some("unsupported legacy attestation status")
        );
        let legacy_bls = storage.get_job(&[65u8; 32]).await.unwrap().unwrap();
        assert_eq!(legacy_bls.status, AttestationJobStatus::Confirmed);
        storage.migrate_bls_legacy_rows().await.unwrap();
        let legacy_bls = storage
            .get_job(&[65u8; 32])
            .await
            .unwrap()
            .unwrap()
            .signed_attestation
            .unwrap();
        assert!(legacy_bls.is_aggregated());
        assert_eq!(legacy_bls.signature_count(), 2);
        let dedicated_bls = storage.get_job(&[66u8; 32]).await.unwrap().unwrap();
        assert_eq!(dedicated_bls.status, AttestationJobStatus::Confirmed);
        assert!(dedicated_bls.signed_attestation.unwrap().is_aggregated());
        let next_val: i64 =
            sqlx::query_scalar("SELECT next_val FROM sequences WHERE network_id = 'network'")
                .fetch_one(&storage.pool)
                .await
                .unwrap();
        assert_eq!(next_val, 99);
        let empty_next_val: i64 =
            sqlx::query_scalar("SELECT next_val FROM sequences WHERE network_id = 'empty-network'")
                .fetch_one(&storage.pool)
                .await
                .unwrap();
        assert_eq!(empty_next_val, 99);
        let lagging_next_val: i64 = sqlx::query_scalar(
            "SELECT next_val FROM sequences WHERE network_id = 'lagging-network'",
        )
        .fetch_one(&storage.pool)
        .await
        .unwrap();
        assert_eq!(lagging_next_val, 21);
        assert!(sqlx::query(
            "INSERT INTO attestations(hash, timestamp, network_id, sequence, created_at, status, attempts) VALUES (?1, 17, 'network', 9, 17, 'pending', 0)",
        )
        .bind(hex::encode([68u8; 32]))
        .execute(&storage.pool)
        .await
        .is_err());

        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn migration_rejects_duplicate_network_sequences_without_rewriting_tuples() {
        use sqlx::migrate::Migrate;

        let (url, path) = file_test_db("duplicate-sequence-migration");
        let storage = Storage::new(&url).await.unwrap();
        let migrator = sqlx::migrate!("./migrations");
        let mut conn = storage.pool.acquire().await.unwrap();
        conn.ensure_migrations_table().await.unwrap();
        for migration in migrator.iter().filter(|migration| migration.version <= 7) {
            conn.apply(migration).await.unwrap();
        }
        sqlx::query(
            r#"
            INSERT INTO attestations(hash, timestamp, network_id, sequence, created_at, status)
            VALUES
                (?1, 10, 'network', 1, 10, 'pending'),
                (?2, 11, 'network', 1, 11, 'pending')
            "#,
        )
        .bind(hex::encode([69u8; 32]))
        .bind(hex::encode([70u8; 32]))
        .execute(&mut *conn)
        .await
        .unwrap();
        let migration = migrator
            .iter()
            .find(|migration| migration.version == 8)
            .unwrap();
        assert!(conn.apply(migration).await.is_err());

        let sequences: Vec<i64> =
            sqlx::query_scalar("SELECT sequence FROM attestations ORDER BY hash")
                .fetch_all(&mut *conn)
                .await
                .unwrap();
        assert_eq!(sequences, vec![1, 1]);
        drop(conn);
        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn test_store_and_get_attestation() {
        let storage = setup_test_db().await;

        let hash = [0u8; 32];
        let signed = create_test_attestation(hash, 1);

        // Store
        storage.store_attestation(&signed, None).await.unwrap();

        // Retrieve
        let retrieved = storage.get_attestation(&hash).await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.attestation.hash, hash);
        assert_eq!(retrieved.attestation.sequence, 1);
        assert_eq!(retrieved.attestation.network_id, "test-network");

        // Check signatures
        match &retrieved.signatures {
            AttestationSignatures::MultiSig { signatures } => {
                assert_eq!(signatures.len(), 2);
                assert_eq!(signatures[0].witness_id, "witness-1");
                assert_eq!(signatures[1].witness_id, "witness-2");
            }
            _ => panic!("Expected MultiSig"),
        }
    }

    #[tokio::test]
    async fn test_store_and_get_attestation_bls() {
        let storage = setup_test_db().await;

        let hash = [1u8; 32];
        let attestation = Attestation {
            hash,
            timestamp: 1700000000,
            network_id: "test-network".to_string(),
            sequence: 1,
        };

        let signed = SignedAttestation {
            attestation,
            signatures: AttestationSignatures::Aggregated {
                signature: vec![10, 20, 30, 40],
                signers: vec!["witness-1".to_string(), "witness-2".to_string()],
            },
        };

        // Store
        storage.store_attestation(&signed, None).await.unwrap();

        // Retrieve
        let retrieved = storage.get_attestation(&hash).await.unwrap().unwrap();

        match &retrieved.signatures {
            AttestationSignatures::Aggregated { signature, signers } => {
                assert_eq!(signature, &vec![10, 20, 30, 40]);
                assert_eq!(signers.len(), 2);
                assert_eq!(signers[0], "witness-1");
                assert_eq!(signers[1], "witness-2");
            }
            _ => panic!("Expected Aggregated"),
        }
    }

    #[tokio::test]
    async fn test_check_duplicate() {
        let storage = setup_test_db().await;

        let hash = [2u8; 32];

        // Not a duplicate initially
        assert!(!storage.check_duplicate(&hash).await.unwrap());

        // Store attestation
        let signed = create_test_attestation(hash, 1);
        storage.store_attestation(&signed, None).await.unwrap();

        // Now it's a duplicate
        assert!(storage.check_duplicate(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_next_sequence() {
        let storage = setup_test_db().await;

        // First sequence should be 1
        let seq = storage.get_next_sequence("test-network").await.unwrap();
        assert_eq!(seq, 1);

        // Subsequent calls return monotonically increasing values
        for expected in 2..=6 {
            let seq = storage.get_next_sequence("test-network").await.unwrap();
            assert_eq!(seq, expected);
        }

        // Different network has independent counter
        let seq = storage.get_next_sequence("other-network").await.unwrap();
        assert_eq!(seq, 1);
    }

    #[tokio::test]
    async fn test_count_attestations_since() {
        let storage = setup_test_db().await;

        // Store attestations with different timestamps
        for i in 0..5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            let mut signed = create_test_attestation(hash, i as u64);
            signed.attestation.timestamp = 1700000000 + (i as u64 * 100);
            storage.store_attestation(&signed, None).await.unwrap();
        }

        // Count all
        let count = storage.count_attestations_since(0).await.unwrap();
        assert_eq!(count, 5);

        // Count since middle
        let count = storage.count_attestations_since(1700000200).await.unwrap();
        assert_eq!(count, 3); // timestamps 200, 300, 400
    }

    #[tokio::test]
    async fn test_store_batch_with_attestations() {
        let storage = setup_test_db().await;

        // Store some attestations first
        let mut hashes = Vec::new();
        for i in 0..3 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            hashes.push(hash);
            let signed = create_test_attestation(hash, i as u64);
            storage.store_attestation(&signed, None).await.unwrap();
        }

        // Create batch
        let batch = AttestationBatch {
            id: 0, // Will be assigned
            network_id: "test-network".to_string(),
            merkle_root: MerkleTree::new(hashes.clone()).root(),
            period_start: 1700000000,
            period_end: 1700003600,
            attestation_count: 3,
        };

        let batch_id = storage.store_batch(&batch, &hashes).await.unwrap();
        assert!(batch_id > 0);

        // Verify batch was stored
        let retrieved = storage.get_batch(batch_id).await.unwrap().unwrap();
        assert_eq!(
            retrieved.merkle_root,
            MerkleTree::new(hashes.clone()).root()
        );
        assert_eq!(retrieved.attestation_count, 3);

        // Verify attestations are linked to batch
        let batch_hashes = storage
            .get_batch_attestation_hashes(batch_id)
            .await
            .unwrap();
        assert_eq!(batch_hashes.len(), 3);
        assert_eq!(batch_hashes[0], hashes[0]);
    }

    #[tokio::test]
    async fn resumed_old_confirmation_is_selected_without_timestamp_cutoff() {
        let (url, path) = file_test_db("resumed-batch-candidate");
        let old_hash = [71u8; 32];
        let old_attestation = {
            let storage = Storage::new(&url).await.unwrap();
            storage.migrate().await.unwrap();
            let reserved = storage
                .reserve_job(&old_hash, "test-network", 1)
                .await
                .unwrap();
            let claim = storage
                .claim_job("test-network", 1, 100)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(claim.attestation, reserved.job.attestation);
            storage.pool.close().await;
            reserved.job.attestation
        };

        let storage = Storage::new(&url).await.unwrap();
        storage.migrate().await.unwrap();
        let new_hash = [72u8; 32];
        storage
            .reserve_job(&new_hash, "test-network", 2)
            .await
            .unwrap();
        let new_claim = storage
            .claim_job("test-network", 2, 10)
            .await
            .unwrap()
            .unwrap();
        assert!(storage
            .complete_verified_job(
                &signed_job(new_claim.attestation.clone(), "new-witness"),
                &new_claim.lease_token,
                3,
            )
            .await
            .unwrap());
        let first_candidates = storage
            .get_unbatched_attestations("test-network")
            .await
            .unwrap();
        assert_eq!(first_candidates.len(), 1);
        assert_eq!(first_candidates[0].attestation.hash, new_hash);
        let first_leaves = vec![new_hash];
        let first_batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: MerkleTree::new(first_leaves.clone()).root(),
            period_start: 1,
            period_end: 3,
            attestation_count: 1,
        };
        storage
            .store_batch(&first_batch, &first_leaves)
            .await
            .unwrap();
        storage.pool.close().await;

        let storage = Storage::new(&url).await.unwrap();
        storage.migrate().await.unwrap();
        let resumed = storage
            .claim_job("test-network", 101, 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resumed.attestation, old_attestation);
        assert!(storage
            .complete_verified_job(
                &signed_job(resumed.attestation, "old-witness"),
                &resumed.lease_token,
                102,
            )
            .await
            .unwrap());

        let retryable_hash = [73u8; 32];
        storage
            .reserve_job(&retryable_hash, "test-network", 200)
            .await
            .unwrap();
        let retryable_claim = storage
            .claim_job("test-network", 200, 10)
            .await
            .unwrap()
            .unwrap();
        assert!(storage
            .reschedule_job(&retryable_hash, &retryable_claim.lease_token, 201, "retry",)
            .await
            .unwrap());

        let failed_hash = [74u8; 32];
        storage
            .reserve_job(&failed_hash, "test-network", 201)
            .await
            .unwrap();
        let failed_claim = storage
            .claim_job("test-network", 201, 10)
            .await
            .unwrap()
            .unwrap();
        assert!(storage
            .fail_job(&failed_hash, &failed_claim.lease_token, 202, "terminal",)
            .await
            .unwrap());

        let pending_hash = [75u8; 32];
        storage
            .reserve_job(&pending_hash, "test-network", 203)
            .await
            .unwrap();

        let candidates = storage
            .get_unbatched_attestations("test-network")
            .await
            .unwrap();
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.attestation.hash)
                .collect::<Vec<_>>(),
            vec![old_hash]
        );
        assert_eq!(candidates[0].attestation.timestamp, 1);
        let second_leaves = vec![old_hash];
        let second_batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: MerkleTree::new(second_leaves.clone()).root(),
            period_start: 3,
            period_end: 203,
            attestation_count: 1,
        };
        storage
            .store_batch(&second_batch, &second_leaves)
            .await
            .unwrap();
        assert_eq!(
            storage.get_log_leaves("test-network").await.unwrap(),
            vec![new_hash, old_hash]
        );

        storage.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn competing_batch_attempts_link_each_hash_once_transactionally() {
        let (url, path) = file_test_db("competing-batches");
        let first = Storage::new(&url).await.unwrap();
        first.migrate().await.unwrap();
        let second = Storage::new(&url).await.unwrap();
        let hashes = [[81u8; 32], [82u8; 32]];
        for (index, hash) in hashes.iter().enumerate() {
            first
                .store_attestation(
                    &create_test_attestation(*hash, index as u64 + 1),
                    Some("confirmed"),
                )
                .await
                .unwrap();
        }
        let root = MerkleTree::new(hashes.to_vec()).root();
        let batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: root,
            period_start: 1,
            period_end: 2,
            attestation_count: hashes.len() as u64,
        };

        let (left, right) = tokio::join!(
            first.store_batch(&batch, &hashes),
            second.store_batch(&batch, &hashes)
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let batch_id = left.ok().or_else(|| right.ok()).unwrap();
        assert_eq!(first.count_batches().await.unwrap(), 1);
        assert_eq!(
            first.get_batch_attestation_hashes(batch_id).await.unwrap(),
            hashes
        );
        let positions: Vec<i64> = sqlx::query_scalar(
            "SELECT merkle_index FROM batch_attestations WHERE batch_id = ?1 ORDER BY merkle_index",
        )
        .bind(batch_id)
        .fetch_all(&first.pool)
        .await
        .unwrap();
        assert_eq!(positions, vec![0, 1]);
        assert!(first.store_batch(&batch, &hashes).await.is_err());
        assert_eq!(first.count_batches().await.unwrap(), 1);

        first.pool.close().await;
        second.pool.close().await;
        remove_test_db(&path);
    }

    #[tokio::test]
    async fn batch_linking_rejects_pending_candidate_without_partial_batch() {
        let storage = setup_test_db().await;
        let confirmed_hash = [83u8; 32];
        let pending_hash = [84u8; 32];
        storage
            .store_attestation(
                &create_test_attestation(confirmed_hash, 1),
                Some("confirmed"),
            )
            .await
            .unwrap();
        storage
            .store_attestation(&create_test_attestation(pending_hash, 2), Some("pending"))
            .await
            .unwrap();
        let hashes = [confirmed_hash, pending_hash];
        let batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: MerkleTree::new(hashes.to_vec()).root(),
            period_start: 1,
            period_end: 2,
            attestation_count: 2,
        };

        assert!(storage.store_batch(&batch, &hashes).await.is_err());
        assert_eq!(storage.count_batches().await.unwrap(), 0);
        assert_eq!(
            storage
                .get_batch_id_for_attestation(&confirmed_hash)
                .await
                .unwrap(),
            None
        );
        assert!(storage
            .get_batch_attestation_hashes(1)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_get_attestation_batch_info() {
        let storage = setup_test_db().await;

        // Store attestation
        let hash = [99u8; 32];
        let signed = create_test_attestation(hash, 1);
        storage.store_attestation(&signed, None).await.unwrap();

        // Not batched yet
        let info = storage
            .get_attestation_batch_info(&hex::encode(hash))
            .await
            .unwrap();
        assert!(info.is_none());

        // Create batch
        let batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: MerkleTree::new(vec![hash]).root(),
            period_start: 1700000000,
            period_end: 1700003600,
            attestation_count: 1,
        };

        let batch_id = storage.store_batch(&batch, &[hash]).await.unwrap();

        // Now batched
        let info = storage
            .get_attestation_batch_info(&hex::encode(hash))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(info.0, batch_id);
        assert_eq!(info.1, 0); // merkle_index
        assert_eq!(info.2, MerkleTree::new(vec![hash]).root()); // merkle_root
    }

    #[tokio::test]
    async fn test_get_attestation_not_found() {
        let storage = setup_test_db().await;

        let hash = [123u8; 32];
        let retrieved = storage.get_attestation(&hash).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_count_attestations() {
        let storage = setup_test_db().await;

        assert_eq!(storage.count_attestations().await.unwrap(), 0);

        // Store some
        for i in 0..3 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            let signed = create_test_attestation(hash, i as u64);
            storage.store_attestation(&signed, None).await.unwrap();
        }

        assert_eq!(storage.count_attestations().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_count_batches() {
        let storage = setup_test_db().await;

        assert_eq!(storage.count_batches().await.unwrap(), 0);

        // Store attestation and batch
        let hash = [1u8; 32];
        let signed = create_test_attestation(hash, 1);
        storage.store_attestation(&signed, None).await.unwrap();

        let batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: MerkleTree::new(vec![hash]).root(),
            period_start: 1700000000,
            period_end: 1700003600,
            attestation_count: 1,
        };
        storage.store_batch(&batch, &[hash]).await.unwrap();

        assert_eq!(storage.count_batches().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_store_attestation_with_pending_status() {
        let storage = setup_test_db().await;

        let hash = [7u8; 32];
        let signed = create_test_attestation(hash, 1);

        storage
            .store_attestation(&signed, Some("pending"))
            .await
            .unwrap();

        let status = storage.get_attestation_status(&hash).await.unwrap();
        assert_eq!(status, Some("pending".to_string()));
    }

    #[tokio::test]
    async fn test_confirm_attestation() {
        let storage = setup_test_db().await;

        let hash = [8u8; 32];
        let signed = create_test_attestation(hash, 1);

        storage
            .store_attestation(&signed, Some("pending"))
            .await
            .unwrap();
        let status = storage.get_attestation_status(&hash).await.unwrap();
        assert_eq!(status, Some("pending".to_string()));

        storage.confirm_attestation(&hash).await.unwrap();
        let status = storage.get_attestation_status(&hash).await.unwrap();
        assert_eq!(status, Some("confirmed".to_string()));
    }

    #[tokio::test]
    async fn test_get_pending_attestations() {
        let storage = setup_test_db().await;

        let pending_hash = [9u8; 32];
        let confirmed_hash = [10u8; 32];

        let pending_signed = create_test_attestation(pending_hash, 1);
        let confirmed_signed = create_test_attestation(confirmed_hash, 2);

        storage
            .store_attestation(&pending_signed, Some("pending"))
            .await
            .unwrap();
        storage
            .store_attestation(&confirmed_signed, Some("confirmed"))
            .await
            .unwrap();

        let pending = storage.get_pending_attestations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attestation.hash, pending_hash);
    }

    #[tokio::test]
    async fn test_get_attestation_status_not_found() {
        let storage = setup_test_db().await;

        let hash = [11u8; 32];
        let status = storage.get_attestation_status(&hash).await.unwrap();
        assert_eq!(status, None);
    }
}
