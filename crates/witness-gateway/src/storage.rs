use anyhow::Result;
use serde::Serialize;
use sqlx::{sqlite::SqlitePool, Row};
use witness_core::{
    signature_scheme::AttestationSignatures, Attestation, AttestationBatch, CrossAnchor,
    ExternalAnchorProof, SignedAttestation, WitnessSignature,
};

/// Throughput metrics for the admin dashboard
#[derive(Serialize, Default)]
pub struct ThroughputMetrics {
    pub attestations_per_minute: f64,
    pub attestations_last_hour: u64,
    pub attestations_last_24h: u64,
    pub peak_rate_last_hour: f64,
}

pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url).await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS attestations (
                hash TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                network_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL,
                witness_id TEXT NOT NULL,
                signature BLOB NOT NULL,
                FOREIGN KEY (hash) REFERENCES attestations(hash),
                UNIQUE(hash, witness_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_attestations_timestamp
            ON attestations(timestamp DESC)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Phase 2: Batch tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network_id TEXT NOT NULL,
                merkle_root BLOB NOT NULL,
                period_start INTEGER NOT NULL,
                period_end INTEGER NOT NULL,
                attestation_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS batch_attestations (
                batch_id INTEGER NOT NULL,
                hash TEXT NOT NULL,
                merkle_index INTEGER NOT NULL,
                FOREIGN KEY (batch_id) REFERENCES batches(id),
                FOREIGN KEY (hash) REFERENCES attestations(hash),
                PRIMARY KEY (batch_id, hash)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cross_anchors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL,
                witnessing_network TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (batch_id) REFERENCES batches(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cross_anchor_signatures (
                cross_anchor_id INTEGER NOT NULL,
                witness_id TEXT NOT NULL,
                signature BLOB NOT NULL,
                FOREIGN KEY (cross_anchor_id) REFERENCES cross_anchors(id),
                PRIMARY KEY (cross_anchor_id, witness_id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add batch_id column to attestations if it doesn't exist
        sqlx::query(
            r#"
            ALTER TABLE attestations ADD COLUMN batch_id INTEGER
            REFERENCES batches(id)
            "#,
        )
        .execute(&self.pool)
        .await
        .ok(); // Ignore error if column already exists

        // Phase 3: External anchor proofs
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS external_anchor_proofs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                proof_json TEXT NOT NULL,
                anchored_data BLOB,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (batch_id) REFERENCES batches(id)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_external_anchors_batch
            ON external_anchor_proofs(batch_id)
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn store_attestation(&self, signed: &SignedAttestation) -> Result<()> {
        let hash_hex = hex::encode(signed.attestation.hash);

        // Store attestation
        sqlx::query(
            r#"
            INSERT OR REPLACE INTO attestations (hash, timestamp, network_id, sequence, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
        )
        .bind(&hash_hex)
        .bind(signed.attestation.timestamp as i64)
        .bind(&signed.attestation.network_id)
        .bind(signed.attestation.sequence as i64)
        .bind(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
        .execute(&self.pool)
        .await?;

        // Store signatures based on type
        match &signed.signatures {
            AttestationSignatures::MultiSig { signatures } => {
                // Store individual signatures
                for sig in signatures {
                    sqlx::query(
                        r#"
                        INSERT OR IGNORE INTO signatures (hash, witness_id, signature)
                        VALUES (?1, ?2, ?3)
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
                // Store aggregated signature with signers list as witness_id
                // Format: "BLS_AGGREGATED:signer1,signer2,signer3"
                let witness_id = format!("BLS_AGGREGATED:{}", signers.join(","));
                sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO signatures (hash, witness_id, signature)
                    VALUES (?1, ?2, ?3)
                    "#,
                )
                .bind(&hash_hex)
                .bind(&witness_id)
                .bind(signature)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    pub async fn get_attestation(&self, hash: &[u8; 32]) -> Result<Option<SignedAttestation>> {
        let hash_hex = hex::encode(hash);

        // Get attestation
        let row = sqlx::query(
            r#"
            SELECT hash, timestamp, network_id, sequence
            FROM attestations
            WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let hash_str: String = row.get("hash");
        let hash_bytes = hex::decode(hash_str)?;
        let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();

        let attestation = Attestation {
            hash: hash_array,
            timestamp: row.get::<i64, _>("timestamp") as u64,
            network_id: row.get("network_id"),
            sequence: row.get::<i64, _>("sequence") as u64,
        };

        // Get signatures
        let sig_rows = sqlx::query(
            r#"
            SELECT witness_id, signature
            FROM signatures
            WHERE hash = ?1
            "#,
        )
        .bind(&hash_hex)
        .fetch_all(&self.pool)
        .await?;

        if sig_rows.is_empty() {
            return Ok(None);
        }

        // Check if this is an aggregated signature
        let first_witness_id: String = sig_rows[0].get("witness_id");

        let signatures = if first_witness_id.starts_with("BLS_AGGREGATED:") {
            // Reconstruct aggregated signature
            let signature: Vec<u8> = sig_rows[0].get("signature");
            let signers_str = first_witness_id.strip_prefix("BLS_AGGREGATED:").unwrap();
            let signers: Vec<String> = signers_str.split(',').map(|s| s.to_string()).collect();

            AttestationSignatures::Aggregated { signature, signers }
        } else {
            // Reconstruct multi-sig
            let witness_sigs: Vec<WitnessSignature> = sig_rows
                .iter()
                .map(|row| WitnessSignature {
                    witness_id: row.get("witness_id"),
                    signature: row.get("signature"),
                })
                .collect();

            AttestationSignatures::MultiSig {
                signatures: witness_sigs,
            }
        };

        Ok(Some(SignedAttestation {
            attestation,
            signatures,
        }))
    }

    pub async fn get_next_sequence(&self, network_id: &str) -> Result<u64> {
        let row = sqlx::query(
            r#"
            SELECT COALESCE(MAX(sequence), 0) as max_seq
            FROM attestations
            WHERE network_id = ?1
            "#,
        )
        .bind(network_id)
        .fetch_one(&self.pool)
        .await?;

        let max_seq: i64 = row.get("max_seq");
        Ok((max_seq + 1) as u64)
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

    /// Get all unbatched attestations since a given time
    pub async fn get_unbatched_attestations(&self, since: u64) -> Result<Vec<SignedAttestation>> {
        let rows = sqlx::query(
            r#"
            SELECT hash, timestamp, network_id, sequence
            FROM attestations
            WHERE batch_id IS NULL AND timestamp >= ?1
            ORDER BY sequence ASC
            "#,
        )
        .bind(since as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut attestations = Vec::new();

        for row in rows {
            let hash_str: String = row.get("hash");
            let hash_bytes = hex::decode(&hash_str)?;
            let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();

            let attestation = Attestation {
                hash: hash_array,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                network_id: row.get("network_id"),
                sequence: row.get::<i64, _>("sequence") as u64,
            };

            // Get signatures
            let sig_rows = sqlx::query(
                r#"
                SELECT witness_id, signature
                FROM signatures
                WHERE hash = ?1
                "#,
            )
            .bind(&hash_str)
            .fetch_all(&self.pool)
            .await?;

            // Reconstruct signatures based on type
            let signatures = if !sig_rows.is_empty() {
                let first_witness_id: String = sig_rows[0].get("witness_id");

                if first_witness_id.starts_with("BLS_AGGREGATED:") {
                    // Aggregated signature
                    let signature: Vec<u8> = sig_rows[0].get("signature");
                    let signers_str = first_witness_id.strip_prefix("BLS_AGGREGATED:").unwrap();
                    let signers: Vec<String> =
                        signers_str.split(',').map(|s| s.to_string()).collect();

                    AttestationSignatures::Aggregated { signature, signers }
                } else {
                    // Multi-sig
                    let witness_sigs: Vec<WitnessSignature> = sig_rows
                        .iter()
                        .map(|row| WitnessSignature {
                            witness_id: row.get("witness_id"),
                            signature: row.get("signature"),
                        })
                        .collect();

                    AttestationSignatures::MultiSig {
                        signatures: witness_sigs,
                    }
                }
            } else {
                AttestationSignatures::MultiSig {
                    signatures: Vec::new(),
                }
            };

            attestations.push(SignedAttestation {
                attestation,
                signatures,
            });
        }

        Ok(attestations)
    }

    /// Store a batch and associate attestations with it
    pub async fn store_batch(
        &self,
        batch: &AttestationBatch,
        attestation_hashes: &[[u8; 32]],
    ) -> Result<i64> {
        // Insert batch
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
        .bind(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
        .execute(&self.pool)
        .await?;

        let batch_id = result.last_insert_rowid();

        // Associate attestations with batch
        for (index, hash) in attestation_hashes.iter().enumerate() {
            let hash_hex = hex::encode(hash);

            sqlx::query(
                r#"
                INSERT INTO batch_attestations (batch_id, hash, merkle_index)
                VALUES (?1, ?2, ?3)
                "#,
            )
            .bind(batch_id)
            .bind(&hash_hex)
            .bind(index as i64)
            .execute(&self.pool)
            .await?;

            // Update attestation with batch_id
            sqlx::query(
                r#"
                UPDATE attestations SET batch_id = ?1 WHERE hash = ?2
                "#,
            )
            .bind(batch_id)
            .bind(&hash_hex)
            .execute(&self.pool)
            .await?;
        }

        Ok(batch_id)
    }

    /// Get a batch by ID
    #[allow(dead_code)] // Used by get_cross_anchors and reserved for batch lookup feature
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
        let merkle_root: [u8; 32] = merkle_root_vec.try_into().unwrap();

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

    /// Store a cross-anchor
    #[allow(dead_code)] // Reserved for cross-network federation feature
    pub async fn store_cross_anchor(&self, cross_anchor: &CrossAnchor) -> Result<()> {
        // Insert cross-anchor
        let result = sqlx::query(
            r#"
            INSERT INTO cross_anchors (batch_id, witnessing_network, timestamp, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
        )
        .bind(cross_anchor.batch.id as i64)
        .bind(&cross_anchor.witnessing_network)
        .bind(cross_anchor.timestamp as i64)
        .bind(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
        .execute(&self.pool)
        .await?;

        let cross_anchor_id = result.last_insert_rowid();

        // Store signatures
        for sig in &cross_anchor.signatures {
            sqlx::query(
                r#"
                INSERT INTO cross_anchor_signatures (cross_anchor_id, witness_id, signature)
                VALUES (?1, ?2, ?3)
                "#,
            )
            .bind(cross_anchor_id)
            .bind(&sig.witness_id)
            .bind(&sig.signature)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Get cross-anchors for a batch
    #[allow(dead_code)] // Reserved for cross-network federation feature
    pub async fn get_cross_anchors(&self, batch_id: i64) -> Result<Vec<CrossAnchor>> {
        let rows = sqlx::query(
            r#"
            SELECT id, witnessing_network, timestamp
            FROM cross_anchors
            WHERE batch_id = ?1
            "#,
        )
        .bind(batch_id)
        .fetch_all(&self.pool)
        .await?;

        let batch = self
            .get_batch(batch_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Batch not found"))?;

        let mut cross_anchors = Vec::new();

        for row in rows {
            let cross_anchor_id: i64 = row.get("id");

            // Get signatures
            let sig_rows = sqlx::query(
                r#"
                SELECT witness_id, signature
                FROM cross_anchor_signatures
                WHERE cross_anchor_id = ?1
                "#,
            )
            .bind(cross_anchor_id)
            .fetch_all(&self.pool)
            .await?;

            let signatures: Vec<WitnessSignature> = sig_rows
                .iter()
                .map(|row| WitnessSignature {
                    witness_id: row.get("witness_id"),
                    signature: row.get("signature"),
                })
                .collect();

            cross_anchors.push(CrossAnchor {
                batch: batch.clone(),
                witnessing_network: row.get("witnessing_network"),
                signatures,
                timestamp: row.get::<i64, _>("timestamp") as u64,
            });
        }

        Ok(cross_anchors)
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
        .bind(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        )
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
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM attestations"#,
        )
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    /// Count attestations since a given timestamp
    pub async fn count_attestations_since(&self, since: u64) -> Result<u64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM attestations WHERE timestamp >= ?1"#,
        )
        .bind(since as i64)
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    /// Count total batches
    pub async fn count_batches(&self) -> Result<u64> {
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM batches"#,
        )
        .fetch_one(&self.pool)
        .await?;

        let count: i64 = row.get("count");
        Ok(count as u64)
    }

    /// Get recent attestations for the dashboard
    pub async fn get_recent_attestations(&self, limit: usize) -> Result<Vec<SignedAttestation>> {
        let rows = sqlx::query(
            r#"
            SELECT hash, timestamp, network_id, sequence
            FROM attestations
            ORDER BY timestamp DESC, sequence DESC
            LIMIT ?1
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut attestations = Vec::new();

        for row in rows {
            let hash_str: String = row.get("hash");
            let hash_bytes = hex::decode(&hash_str)?;
            let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();

            let attestation = Attestation {
                hash: hash_array,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                network_id: row.get("network_id"),
                sequence: row.get::<i64, _>("sequence") as u64,
            };

            // Get signatures
            let sig_rows = sqlx::query(
                r#"
                SELECT witness_id, signature
                FROM signatures
                WHERE hash = ?1
                "#,
            )
            .bind(&hash_str)
            .fetch_all(&self.pool)
            .await?;

            let signatures = if !sig_rows.is_empty() {
                let first_witness_id: String = sig_rows[0].get("witness_id");

                if first_witness_id.starts_with("BLS_AGGREGATED:") {
                    let signature: Vec<u8> = sig_rows[0].get("signature");
                    let signers_str = first_witness_id.strip_prefix("BLS_AGGREGATED:").unwrap();
                    let signers: Vec<String> =
                        signers_str.split(',').map(|s| s.to_string()).collect();

                    AttestationSignatures::Aggregated { signature, signers }
                } else {
                    let witness_sigs: Vec<WitnessSignature> = sig_rows
                        .iter()
                        .map(|row| WitnessSignature {
                            witness_id: row.get("witness_id"),
                            signature: row.get("signature"),
                        })
                        .collect();

                    AttestationSignatures::MultiSig {
                        signatures: witness_sigs,
                    }
                }
            } else {
                AttestationSignatures::MultiSig {
                    signatures: Vec::new(),
                }
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

    // ========== Admin Dashboard - New Methods ==========

    /// Get attestation by hash prefix (minimum 8 characters)
    pub async fn get_attestation_by_prefix(
        &self,
        hash_prefix: &str,
    ) -> Result<Option<(SignedAttestation, Option<i64>)>> {
        let row = sqlx::query(
            r#"
            SELECT hash, timestamp, network_id, sequence, batch_id
            FROM attestations
            WHERE hash LIKE ?1
            LIMIT 1
            "#,
        )
        .bind(format!("{}%", hash_prefix))
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let hash_str: String = row.get("hash");
        let hash_bytes = hex::decode(&hash_str)?;
        let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();
        let batch_id: Option<i64> = row.get("batch_id");

        let attestation = Attestation {
            hash: hash_array,
            timestamp: row.get::<i64, _>("timestamp") as u64,
            network_id: row.get("network_id"),
            sequence: row.get::<i64, _>("sequence") as u64,
        };

        // Get signatures
        let sig_rows = sqlx::query(
            r#"
            SELECT witness_id, signature
            FROM signatures
            WHERE hash = ?1
            "#,
        )
        .bind(&hash_str)
        .fetch_all(&self.pool)
        .await?;

        let signatures = if !sig_rows.is_empty() {
            let first_witness_id: String = sig_rows[0].get("witness_id");

            if first_witness_id.starts_with("BLS_AGGREGATED:") {
                let signature: Vec<u8> = sig_rows[0].get("signature");
                let signers_str = first_witness_id.strip_prefix("BLS_AGGREGATED:").unwrap();
                let signers: Vec<String> =
                    signers_str.split(',').map(|s| s.to_string()).collect();

                AttestationSignatures::Aggregated { signature, signers }
            } else {
                let witness_sigs: Vec<WitnessSignature> = sig_rows
                    .iter()
                    .map(|row| WitnessSignature {
                        witness_id: row.get("witness_id"),
                        signature: row.get("signature"),
                    })
                    .collect();

                AttestationSignatures::MultiSig {
                    signatures: witness_sigs,
                }
            }
        } else {
            AttestationSignatures::MultiSig {
                signatures: Vec::new(),
            }
        };

        Ok(Some((
            SignedAttestation {
                attestation,
                signatures,
            },
            batch_id,
        )))
    }

    /// Get attestations with pagination and optional hash prefix search
    pub async fn get_attestations_paginated(
        &self,
        page: u64,
        limit: u64,
        hash_prefix: Option<&str>,
    ) -> Result<(Vec<(SignedAttestation, Option<i64>)>, u64)> {
        let offset = (page - 1) * limit;

        // Get total count
        let count_row = if let Some(prefix) = hash_prefix {
            sqlx::query(
                r#"SELECT COUNT(*) as count FROM attestations WHERE hash LIKE ?1"#,
            )
            .bind(format!("{}%", prefix))
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query(r#"SELECT COUNT(*) as count FROM attestations"#)
                .fetch_one(&self.pool)
                .await?
        };
        let total: i64 = count_row.get("count");

        // Get paginated results
        let rows = if let Some(prefix) = hash_prefix {
            sqlx::query(
                r#"
                SELECT hash, timestamp, network_id, sequence, batch_id
                FROM attestations
                WHERE hash LIKE ?1
                ORDER BY timestamp DESC, sequence DESC
                LIMIT ?2 OFFSET ?3
                "#,
            )
            .bind(format!("{}%", prefix))
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT hash, timestamp, network_id, sequence, batch_id
                FROM attestations
                ORDER BY timestamp DESC, sequence DESC
                LIMIT ?1 OFFSET ?2
                "#,
            )
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let mut attestations = Vec::new();

        for row in rows {
            let hash_str: String = row.get("hash");
            let hash_bytes = hex::decode(&hash_str)?;
            let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();
            let batch_id: Option<i64> = row.get("batch_id");

            let attestation = Attestation {
                hash: hash_array,
                timestamp: row.get::<i64, _>("timestamp") as u64,
                network_id: row.get("network_id"),
                sequence: row.get::<i64, _>("sequence") as u64,
            };

            // Get signatures
            let sig_rows = sqlx::query(
                r#"
                SELECT witness_id, signature
                FROM signatures
                WHERE hash = ?1
                "#,
            )
            .bind(&hash_str)
            .fetch_all(&self.pool)
            .await?;

            let signatures = if !sig_rows.is_empty() {
                let first_witness_id: String = sig_rows[0].get("witness_id");

                if first_witness_id.starts_with("BLS_AGGREGATED:") {
                    let signature: Vec<u8> = sig_rows[0].get("signature");
                    let signers_str = first_witness_id.strip_prefix("BLS_AGGREGATED:").unwrap();
                    let signers: Vec<String> =
                        signers_str.split(',').map(|s| s.to_string()).collect();

                    AttestationSignatures::Aggregated { signature, signers }
                } else {
                    let witness_sigs: Vec<WitnessSignature> = sig_rows
                        .iter()
                        .map(|row| WitnessSignature {
                            witness_id: row.get("witness_id"),
                            signature: row.get("signature"),
                        })
                        .collect();

                    AttestationSignatures::MultiSig {
                        signatures: witness_sigs,
                    }
                }
            } else {
                AttestationSignatures::MultiSig {
                    signatures: Vec::new(),
                }
            };

            attestations.push((
                SignedAttestation {
                    attestation,
                    signatures,
                },
                batch_id,
            ));
        }

        Ok((attestations, total as u64))
    }

    /// Get batches with pagination
    pub async fn get_batches_paginated(
        &self,
        page: u64,
        limit: u64,
    ) -> Result<(Vec<(AttestationBatch, bool)>, u64)> {
        let offset = (page - 1) * limit;

        // Get total count
        let count_row = sqlx::query(r#"SELECT COUNT(*) as count FROM batches"#)
            .fetch_one(&self.pool)
            .await?;
        let total: i64 = count_row.get("count");

        // Get paginated results with anchor status
        let rows = sqlx::query(
            r#"
            SELECT b.id, b.network_id, b.merkle_root, b.period_start, b.period_end, b.attestation_count,
                   (SELECT COUNT(*) FROM external_anchor_proofs WHERE batch_id = b.id) as anchor_count
            FROM batches b
            ORDER BY b.id DESC
            LIMIT ?1 OFFSET ?2
            "#,
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        let batches: Vec<(AttestationBatch, bool)> = rows
            .into_iter()
            .map(|row| {
                let merkle_root_vec: Vec<u8> = row.get("merkle_root");
                let merkle_root: [u8; 32] = merkle_root_vec.try_into().unwrap();
                let anchor_count: i64 = row.get("anchor_count");

                (
                    AttestationBatch {
                        id: row.get::<i64, _>("id") as u64,
                        network_id: row.get("network_id"),
                        merkle_root,
                        period_start: row.get::<i64, _>("period_start") as u64,
                        period_end: row.get::<i64, _>("period_end") as u64,
                        attestation_count: row.get::<i64, _>("attestation_count") as u64,
                    },
                    anchor_count > 0,
                )
            })
            .collect();

        Ok((batches, total as u64))
    }

    /// Get throughput metrics
    pub async fn get_throughput_metrics(&self) -> Result<ThroughputMetrics> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let one_minute_ago = now - 60;
        let one_hour_ago = now - 3600;
        let one_day_ago = now - 86400;

        // Get attestations in the last minute
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM attestations WHERE timestamp >= ?1"#,
        )
        .bind(one_minute_ago as i64)
        .fetch_one(&self.pool)
        .await?;
        let last_minute: i64 = row.get("count");

        // Get attestations in the last hour
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM attestations WHERE timestamp >= ?1"#,
        )
        .bind(one_hour_ago as i64)
        .fetch_one(&self.pool)
        .await?;
        let last_hour: i64 = row.get("count");

        // Get attestations in the last 24 hours
        let row = sqlx::query(
            r#"SELECT COUNT(*) as count FROM attestations WHERE timestamp >= ?1"#,
        )
        .bind(one_day_ago as i64)
        .fetch_one(&self.pool)
        .await?;
        let last_24h: i64 = row.get("count");

        // Calculate peak rate in the last hour (attestations per minute, max across 5-minute windows)
        let peak_rate = if last_hour > 0 {
            // Get counts per 5-minute window in the last hour
            let rows = sqlx::query(
                r#"
                SELECT (timestamp / 300) as window, COUNT(*) as count
                FROM attestations
                WHERE timestamp >= ?1
                GROUP BY window
                ORDER BY count DESC
                LIMIT 1
                "#,
            )
            .bind(one_hour_ago as i64)
            .fetch_all(&self.pool)
            .await?;

            if let Some(row) = rows.first() {
                let max_in_window: i64 = row.get("count");
                (max_in_window as f64) / 5.0 // Convert 5-minute count to per-minute rate
            } else {
                0.0
            }
        } else {
            0.0
        };

        Ok(ThroughputMetrics {
            attestations_per_minute: last_minute as f64,
            attestations_last_hour: last_hour as u64,
            attestations_last_24h: last_24h as u64,
            peak_rate_last_hour: peak_rate,
        })
    }
}
