use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use witness_core::{AttestationBatch, MerkleTree, NetworkConfig};

use crate::anchor_manager::AnchorManager;
use crate::metrics;
use crate::storage::Storage;

/// Manages periodic batch closing for federation
pub struct BatchManager {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    last_batch_time: Arc<tokio::sync::Mutex<u64>>,
    anchor_manager: Option<Arc<AnchorManager>>,
}

impl BatchManager {
    pub fn new(config: Arc<NetworkConfig>, storage: Arc<Storage>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            config,
            storage,
            last_batch_time: Arc::new(tokio::sync::Mutex::new(now)),
            anchor_manager: None,
        }
    }

    /// Set the anchor manager (must be called before start)
    pub fn with_anchor_manager(mut self, anchor_manager: Arc<AnchorManager>) -> Self {
        self.anchor_manager = Some(anchor_manager);
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
        let leaves: Vec<[u8; 32]> = attestations
            .iter()
            .map(|a| a.attestation.hash)
            .collect();

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

        // Trigger external anchoring if enabled
        if let Some(anchor_manager) = &self.anchor_manager {
            anchor_manager.clone().anchor_batch_async(final_batch.clone());
        }

        Ok(Some(final_batch))
    }
}
