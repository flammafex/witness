use std::sync::Arc;
use anyhow::Result;
use witness_core::{
    AnchorProviderConfig, AnchorProviderType, AnchorRequest, AnchorResponse,
    AttestationBatch, ExternalAnchorProof, NetworkConfig,
};

use crate::anchor_providers::{AnchorProvider, InternetArchiveProvider};
use crate::storage::Storage;

/// Manages external anchoring of batches to public services
pub struct AnchorManager {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    providers: Vec<Arc<dyn AnchorProvider>>,
}

impl AnchorManager {
    pub fn new(config: Arc<NetworkConfig>, storage: Arc<Storage>) -> Self {
        let mut providers: Vec<Arc<dyn AnchorProvider>> = Vec::new();

        // Initialize enabled anchor providers
        if config.external_anchors.enabled {
            for provider_config in &config.external_anchors.providers {
                if !provider_config.enabled {
                    continue;
                }

                match provider_config.provider_type {
                    AnchorProviderType::InternetArchive => {
                        tracing::info!("Initializing Internet Archive anchor provider");
                        providers.push(Arc::new(InternetArchiveProvider::new()));
                    }
                    AnchorProviderType::Trillian => {
                        tracing::warn!("Trillian provider not yet implemented");
                        // TODO: providers.push(Arc::new(TrillianProvider::new()));
                    }
                    AnchorProviderType::DnsTxt => {
                        tracing::warn!("DNS TXT provider not yet implemented");
                        // TODO: providers.push(Arc::new(DnsTxtProvider::new()));
                    }
                    AnchorProviderType::Blockchain => {
                        tracing::warn!("Blockchain provider not yet implemented");
                        // TODO: providers.push(Arc::new(BlockchainProvider::new()));
                    }
                }
            }
        }

        Self {
            config,
            storage,
            providers,
        }
    }

    /// Anchor a batch to all enabled external services
    /// Returns immediately and spawns background tasks for anchoring
    pub fn anchor_batch_async(self: Arc<Self>, batch: AttestationBatch) {
        if !self.config.external_anchors.enabled {
            tracing::debug!("External anchoring disabled");
            return;
        }

        if self.providers.is_empty() {
            tracing::debug!("No anchor providers enabled");
            return;
        }

        tracing::info!(
            "Anchoring batch {} to {} external providers",
            batch.id,
            self.providers.len()
        );

        // Spawn background task for anchoring
        tokio::spawn(async move {
            if let Err(e) = self.anchor_batch_internal(batch).await {
                tracing::error!("Failed to anchor batch: {}", e);
            }
        });
    }

    /// Internal anchoring logic (runs in background)
    async fn anchor_batch_internal(&self, batch: AttestationBatch) -> Result<()> {
        let request = AnchorRequest {
            batch: batch.clone(),
            metadata: None,
        };

        let mut successful_anchors = Vec::new();
        let mut tasks = Vec::new();

        // Launch anchoring tasks in parallel
        for provider in &self.providers {
            let provider_type = provider.provider_type();
            let request_clone = request.clone();
            let provider_clone = Arc::clone(provider);

            let task = tokio::spawn(async move {
                tracing::info!("Submitting batch {} to {:?}", request_clone.batch.id, provider_type);

                match provider_clone.anchor(&request_clone).await {
                    Ok(response) => {
                        if response.success {
                            tracing::info!(
                                "Successfully anchored batch {} to {:?}",
                                request_clone.batch.id,
                                provider_type
                            );
                            Some(response)
                        } else {
                            tracing::warn!(
                                "Failed to anchor batch {} to {:?}: {}",
                                request_clone.batch.id,
                                provider_type,
                                response.error.unwrap_or_else(|| "Unknown error".to_string())
                            );
                            None
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Error anchoring batch {} to {:?}: {}",
                            request_clone.batch.id,
                            provider_type,
                            e
                        );
                        None
                    }
                }
            });

            tasks.push(task);
        }

        // Collect results
        for task in tasks {
            if let Ok(Some(response)) = task.await {
                if let Some(proof) = response.proof {
                    successful_anchors.push(proof);
                }
            }
        }

        // Check if we met the minimum requirement
        let minimum_required = self.config.external_anchors.minimum_required;

        if successful_anchors.len() < minimum_required {
            tracing::error!(
                "Insufficient anchors for batch {}: got {}, required {}",
                batch.id,
                successful_anchors.len(),
                minimum_required
            );
            return Err(anyhow::anyhow!(
                "Insufficient anchors: got {}, required {}",
                successful_anchors.len(),
                minimum_required
            ));
        }

        tracing::info!(
            "Batch {} successfully anchored to {} providers (minimum: {})",
            batch.id,
            successful_anchors.len(),
            minimum_required
        );

        // Store anchor proofs
        self.store_anchor_proofs(batch.id, successful_anchors).await?;

        Ok(())
    }

    /// Store anchor proofs in the database
    async fn store_anchor_proofs(
        &self,
        batch_id: u64,
        proofs: Vec<ExternalAnchorProof>,
    ) -> Result<()> {
        for proof in proofs {
            self.storage.store_anchor_proof(batch_id, &proof).await?;
        }
        Ok(())
    }

    /// Verify all anchor proofs for a batch
    pub async fn verify_batch_anchors(&self, batch_id: u64) -> Result<Vec<bool>> {
        let proofs = self.storage.get_anchor_proofs(batch_id).await?;
        let mut results = Vec::new();

        for proof in proofs {
            // Find the matching provider
            let provider = self.providers.iter()
                .find(|p| p.provider_type() == proof.provider);

            if let Some(provider) = provider {
                match provider.verify(&proof).await {
                    Ok(valid) => results.push(valid),
                    Err(e) => {
                        tracing::error!("Failed to verify anchor proof: {}", e);
                        results.push(false);
                    }
                }
            } else {
                tracing::warn!("No provider found for proof type: {:?}", proof.provider);
                results.push(false);
            }
        }

        Ok(results)
    }
}
