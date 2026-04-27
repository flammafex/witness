use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use witness_core::{
    log::TreeHead, merkle::merkle_tree_hash, signature_scheme::AttestationSignatures,
    AttestationBatch, MerkleTree, NetworkConfig, SignatureScheme, SignedAttestation,
    SignedTreeHead,
};

use crate::anchor_manager::AnchorManager;
use crate::epoch::epoch_secs;
use crate::federation_client::FederationClient;
use crate::metrics;
use crate::server::collect_signatures_until_threshold;
use crate::storage::Storage;
use crate::witness_client::WitnessClient;

/// Manages periodic batch closing for federation
pub struct BatchManager {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<WitnessClient>,
    last_batch_time: Arc<tokio::sync::Mutex<u64>>,
    anchor_manager: Option<Arc<AnchorManager>>,
    federation_client: Option<Arc<FederationClient>>,
}

impl BatchManager {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        witness_client: Arc<WitnessClient>,
    ) -> Self {
        let now = epoch_secs();

        Self {
            config,
            storage,
            witness_client,
            last_batch_time: Arc::new(tokio::sync::Mutex::new(now)),
            anchor_manager: None,
            federation_client: None,
        }
    }

    /// Set the anchor manager (must be called before start)
    pub fn with_anchor_manager(mut self, anchor_manager: Arc<AnchorManager>) -> Self {
        self.anchor_manager = Some(anchor_manager);
        self
    }

    /// Set the federation client for cross-anchoring (must be called before start)
    pub fn with_federation_client(mut self, federation_client: Arc<FederationClient>) -> Self {
        self.federation_client = Some(federation_client);
        self
    }

    /// Start the batch manager background task
    pub fn start(self: Arc<Self>) {
        let batch_period = self.config.federation.batch_period;

        if !self.config.federation.enabled || batch_period == 0 {
            tracing::info!("Batch manager disabled (federation not enabled)");
            return;
        }

        tracing::info!(
            "Starting batch manager with period: {} seconds",
            batch_period
        );

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(batch_period));

            loop {
                interval.tick().await;

                if let Err(e) = self.close_batch().await {
                    tracing::error!("Failed to close batch: {}", e);
                }
            }
        });
    }

    /// Close the current batch and create a new one
    async fn close_batch(&self) -> anyhow::Result<Option<AttestationBatch>> {
        let mut last_batch_time = self.last_batch_time.lock().await;
        let now = epoch_secs();

        // Get all unbatched attestations since last batch
        let attestations = self
            .storage
            .get_unbatched_attestations(*last_batch_time)
            .await?;

        if attestations.is_empty() {
            tracing::debug!("No attestations to batch");
            return Ok(None);
        }

        tracing::info!(
            "Closing batch with {} attestations (period: {} - {})",
            attestations.len(),
            *last_batch_time,
            now
        );

        // Build merkle tree from attestation hashes
        let leaves: Vec<[u8; 32]> = attestations.iter().map(|a| a.attestation.hash).collect();

        let merkle_tree = MerkleTree::new(leaves.clone());
        let merkle_root = merkle_tree.root();

        // Create batch
        let batch = AttestationBatch {
            id: 0, // Will be set by database
            network_id: self.config.id.clone(),
            merkle_root,
            period_start: *last_batch_time,
            period_end: now,
            attestation_count: attestations.len() as u64,
        };

        // Store batch
        let batch_id = self.storage.store_batch(&batch, &leaves).await?;

        // Confirm all attestations in the batch (defensive: they should already be confirmed)
        for attestation in &attestations {
            if let Err(e) = self.storage.confirm_attestation(&attestation.attestation.hash).await {
                tracing::warn!(
                    "Failed to confirm attestation {} in batch: {}",
                    hex::encode(&attestation.attestation.hash),
                    e
                );
            }
        }

        // Record metrics
        metrics::record_batch();

        tracing::info!(
            "Batch {} created: {} attestations, root: {}",
            batch_id,
            attestations.len(),
            hex::encode(merkle_root)
        );

        // Update last batch time
        *last_batch_time = now;

        let final_batch = AttestationBatch {
            id: batch_id as u64,
            ..batch
        };

        // RFC 9162: produce a Signed Tree Head over the entire log up to and
        // including this batch.  The STH is a synthetic Attestation signed
        // by the same witness threshold, so failures here log loudly but do
        // not roll back the batch — clients can still verify per-batch
        // proofs without an STH, and the next batch closure will catch up.
        if let Err(e) = self.sign_and_store_sth(batch_id, now).await {
            tracing::error!("Failed to produce STH for batch {}: {}", batch_id, e);
        }

        // Trigger external anchoring if enabled
        if let Some(anchor_manager) = &self.anchor_manager {
            anchor_manager
                .clone()
                .anchor_batch_async(final_batch.clone());
        }

        // Trigger federation cross-anchoring if enabled
        if let Some(federation_client) = &self.federation_client {
            let fc = federation_client.clone();
            let batch = final_batch.clone();
            tokio::spawn(async move {
                if let Err(e) = fc.cross_anchor_batch(&batch).await {
                    tracing::error!("Cross-anchor failed for batch {}: {}", batch.id, e);
                }
            });
        }

        Ok(Some(final_batch))
    }

    /// Compute the global RFC 9162 Merkle Tree Hash over every closed-batch
    /// leaf in append order, build a [`TreeHead`], collect a witness
    /// threshold of signatures over its digest, and persist the resulting
    /// [`SignedTreeHead`].
    async fn sign_and_store_sth(&self, batch_id: i64, timestamp: u64) -> anyhow::Result<()> {
        let leaves = self.storage.get_log_leaves(&self.config.id).await?;
        if leaves.is_empty() {
            return Ok(());
        }

        let tree_head = TreeHead {
            network_id: self.config.id.clone(),
            tree_size: leaves.len() as u64,
            timestamp,
            root_hash: merkle_tree_hash(&leaves),
        };
        let attestation = tree_head.to_attestation();

        let responses = collect_signatures_until_threshold(
            &self.config.witnesses,
            &attestation,
            &self.witness_client,
            self.config.threshold,
        )
        .await;

        if responses.len() < self.config.threshold {
            anyhow::bail!(
                "STH signing got {} of {} required signatures",
                responses.len(),
                self.config.threshold
            );
        }

        let signed_attestation = match self.config.signature_scheme {
            SignatureScheme::Ed25519 => {
                let mut signed = SignedAttestation::new(attestation.clone());
                for r in responses {
                    signed.add_signature(r.witness_id, r.signature);
                }
                signed
            }
            SignatureScheme::BLS => {
                let signer_ids: Vec<String> =
                    responses.iter().map(|r| r.witness_id.clone()).collect();
                let sigs: Vec<Vec<u8>> = responses.into_iter().map(|r| r.signature).collect();
                let aggregated = witness_core::aggregate_signatures_bls(&sigs)?;
                SignedAttestation {
                    attestation: attestation.clone(),
                    signatures: AttestationSignatures::Aggregated {
                        signature: aggregated,
                        signers: signer_ids,
                    },
                }
            }
        };

        // Defence in depth: refuse to persist an STH whose signatures don't
        // pass the same verifier clients will use.
        witness_core::verify_signed_attestation(&signed_attestation, &self.config)?;

        let sth = SignedTreeHead {
            tree_head,
            signed_attestation,
        };
        self.storage.store_sth(&sth, batch_id).await?;

        tracing::info!(
            "STH issued: tree_size={} root={}",
            sth.tree_head.tree_size,
            hex::encode(sth.tree_head.root_hash)
        );

        Ok(())
    }
}
