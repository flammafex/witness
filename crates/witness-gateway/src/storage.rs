use anyhow::Result;
use sqlx::{sqlite::SqlitePool, Row};
use witness_core::{
    signature_scheme::AttestationSignatures, Attestation, AttestationBatch, CrossAnchor,
    ExternalAnchorProof, SignedAttestation, WitnessSignature,
};

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
    #[allow(dead_code)]
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

    /// Get all attestation hashes for a batch, ordered by merkle index
    pub async fn get_batch_attestation_hashes(&self, batch_id: i64) -> Result<Vec<[u8; 32]>> {
        let rows = sqlx::query(
            r#"
            SELECT hash FROM batch_attestations
            WHERE batch_id = ?1
            ORDER BY merkle_index ASC
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
            WHERE ba.hash = ?1
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

    /// Store a cross-anchor
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> Storage {
        let storage = Storage::new("sqlite::memory:").await.unwrap();
        storage.migrate().await.unwrap();
        storage
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

    #[tokio::test]
    async fn test_store_and_get_attestation() {
        let storage = setup_test_db().await;

        let hash = [0u8; 32];
        let signed = create_test_attestation(hash, 1);

        // Store
        storage.store_attestation(&signed).await.unwrap();

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
        storage.store_attestation(&signed).await.unwrap();

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
        storage.store_attestation(&signed).await.unwrap();

        // Now it's a duplicate
        assert!(storage.check_duplicate(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_next_sequence() {
        let storage = setup_test_db().await;

        // First sequence should be 1
        let seq = storage.get_next_sequence("test-network").await.unwrap();
        assert_eq!(seq, 1);

        // Store some attestations
        for i in 1..=5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            let signed = create_test_attestation(hash, i as u64);
            storage.store_attestation(&signed).await.unwrap();
        }

        // Next sequence should be 6
        let seq = storage.get_next_sequence("test-network").await.unwrap();
        assert_eq!(seq, 6);
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
            storage.store_attestation(&signed).await.unwrap();
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
            storage.store_attestation(&signed).await.unwrap();
        }

        // Create batch
        let batch = AttestationBatch {
            id: 0, // Will be assigned
            network_id: "test-network".to_string(),
            merkle_root: [42u8; 32],
            period_start: 1700000000,
            period_end: 1700003600,
            attestation_count: 3,
        };

        let batch_id = storage.store_batch(&batch, &hashes).await.unwrap();
        assert!(batch_id > 0);

        // Verify batch was stored
        let retrieved = storage.get_batch(batch_id).await.unwrap().unwrap();
        assert_eq!(retrieved.merkle_root, [42u8; 32]);
        assert_eq!(retrieved.attestation_count, 3);

        // Verify attestations are linked to batch
        let batch_hashes = storage.get_batch_attestation_hashes(batch_id).await.unwrap();
        assert_eq!(batch_hashes.len(), 3);
        assert_eq!(batch_hashes[0], hashes[0]);
    }

    #[tokio::test]
    async fn test_get_attestation_batch_info() {
        let storage = setup_test_db().await;

        // Store attestation
        let hash = [99u8; 32];
        let signed = create_test_attestation(hash, 1);
        storage.store_attestation(&signed).await.unwrap();

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
            merkle_root: [55u8; 32],
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
        assert_eq!(info.2, [55u8; 32]); // merkle_root
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
            storage.store_attestation(&signed).await.unwrap();
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
        storage.store_attestation(&signed).await.unwrap();

        let batch = AttestationBatch {
            id: 0,
            network_id: "test-network".to_string(),
            merkle_root: [0u8; 32],
            period_start: 1700000000,
            period_end: 1700003600,
            attestation_count: 1,
        };
        storage.store_batch(&batch, &[hash]).await.unwrap();

        assert_eq!(storage.count_batches().await.unwrap(), 1);
    }
}
