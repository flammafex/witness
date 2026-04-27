use anyhow::Result;
use tracing::{info, warn};
use witness_core::{verify_log_consistency, verify_signed_tree_head, SignedTreeHead};

use crate::client::GatewayClient;
use crate::storage::{FailureType, Storage};

/// One audit tick result.
pub enum TickResult {
    /// Nothing new — the latest STH matches what we already have.
    NoChange,
    /// A new (or changed) STH was found and verified.
    NewSth(SignedTreeHead),
    /// The tick failed; a failure has been recorded.
    Failed,
}

/// Core auditor logic: poll a gateway, verify STH signatures and consistency
/// proofs, and persist the chain.
pub struct Auditor {
    gateway_url: String,
    client: GatewayClient,
    storage: Storage,
}

impl Auditor {
    pub fn new(gateway_url: &str, storage: Storage) -> Self {
        let client = GatewayClient::new(gateway_url);
        Self {
            gateway_url: gateway_url.to_string(),
            client,
            storage,
        }
    }

    /// Perform a single audit cycle.
    pub async fn tick(&self) -> Result<TickResult> {
        let latest = match self.client.get_latest_sth().await {
            Ok(sth) => sth,
            Err(e) => {
                let detail = format!("Failed to fetch latest STH: {}", e);
                warn!("{}", detail);
                self.storage
                    .record_failure(&self.gateway_url, FailureType::Fetch, None, &detail)
                    .await?;
                return Ok(TickResult::Failed);
            }
        };

        let previous = self.storage.latest_sth(&self.gateway_url).await?;

        let result = if let Some(prev) = previous {
            self.audit_with_previous(&prev, &latest).await?
        } else {
            self.accept_first_sth(&latest).await?
        };

        Ok(result)
    }

    async fn audit_with_previous(
        &self,
        prev: &SignedTreeHead,
        latest: &SignedTreeHead,
    ) -> Result<TickResult> {
        // 1. Tree size regression check
        if latest.tree_head.tree_size < prev.tree_head.tree_size {
            let detail = format!(
                "Tree size regression: {} → {}",
                prev.tree_head.tree_size, latest.tree_head.tree_size
            );
            warn!("{}", detail);
            self.storage
                .record_failure(
                    &self.gateway_url,
                    FailureType::TreeSizeRegression,
                    Some(latest.tree_head.tree_size),
                    &detail,
                )
                .await?;
            return Ok(TickResult::Failed);
        }

        // 2. Same size — root hash must not change
        if latest.tree_head.tree_size == prev.tree_head.tree_size {
            if latest.tree_head.root_hash != prev.tree_head.root_hash {
                let detail = format!(
                    "Root mismatch at tree size {}: expected {} got {}",
                    latest.tree_head.tree_size,
                    hex::encode(prev.tree_head.root_hash),
                    hex::encode(latest.tree_head.root_hash)
                );
                warn!("{}", detail);
                self.storage
                    .record_failure(
                        &self.gateway_url,
                        FailureType::RootMismatch,
                        Some(latest.tree_head.tree_size),
                        &detail,
                    )
                    .await?;
                return Ok(TickResult::Failed);
            }
            // Identical STH — no change
            return Ok(TickResult::NoChange);
        }

        // 3. New larger tree — verify STH signature and consistency proof
        let config = match self.client.get_network_config().await {
            Ok(cfg) => cfg,
            Err(e) => {
                let detail = format!("Failed to fetch network config: {}", e);
                warn!("{}", detail);
                self.storage
                    .record_failure(&self.gateway_url, FailureType::Fetch, None, &detail)
                    .await?;
                return Ok(TickResult::Failed);
            }
        };

        if let Err(e) = verify_signed_tree_head(latest, &config) {
            let detail = format!("STH signature verification failed: {}", e);
            warn!("{}", detail);
            self.storage
                .record_failure(
                    &self.gateway_url,
                    FailureType::SthSignature,
                    Some(latest.tree_head.tree_size),
                    &detail,
                )
                .await?;
            return Ok(TickResult::Failed);
        }

        // 4. Fetch and verify consistency proof
        let proof = match self
            .client
            .get_consistency_proof(prev.tree_head.tree_size, latest.tree_head.tree_size)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                let detail = format!(
                    "Failed to fetch consistency proof {}→{}: {}",
                    prev.tree_head.tree_size, latest.tree_head.tree_size, e
                );
                warn!("{}", detail);
                self.storage
                    .record_failure(
                        &self.gateway_url,
                        FailureType::Fetch,
                        Some(latest.tree_head.tree_size),
                        &detail,
                    )
                    .await?;
                return Ok(TickResult::Failed);
            }
        };

        if let Err(e) = verify_log_consistency(&proof, &config) {
            let detail = format!(
                "Consistency proof {}→{} failed: {}",
                prev.tree_head.tree_size, latest.tree_head.tree_size, e
            );
            warn!("{}", detail);
            self.storage
                .record_failure(
                    &self.gateway_url,
                    FailureType::Consistency,
                    Some(latest.tree_head.tree_size),
                    &detail,
                )
                .await?;
            return Ok(TickResult::Failed);
        }

        info!(
            "Verified consistency {} → {} for {}",
            prev.tree_head.tree_size, latest.tree_head.tree_size, self.gateway_url
        );

        // 5. Persist
        self.storage.record_sth(&self.gateway_url, latest).await?;
        info!(
            "Recorded STH at tree size {} for {}",
            latest.tree_head.tree_size, self.gateway_url
        );

        Ok(TickResult::NewSth(latest.clone()))
    }

    async fn accept_first_sth(&self, latest: &SignedTreeHead) -> Result<TickResult> {
        let config = match self.client.get_network_config().await {
            Ok(cfg) => cfg,
            Err(e) => {
                let detail = format!("Failed to fetch network config: {}", e);
                warn!("{}", detail);
                self.storage
                    .record_failure(&self.gateway_url, FailureType::Fetch, None, &detail)
                    .await?;
                return Ok(TickResult::Failed);
            }
        };

        if let Err(e) = verify_signed_tree_head(latest, &config) {
            let detail = format!("STH signature verification failed: {}", e);
            warn!("{}", detail);
            self.storage
                .record_failure(
                    &self.gateway_url,
                    FailureType::SthSignature,
                    Some(latest.tree_head.tree_size),
                    &detail,
                )
                .await?;
            return Ok(TickResult::Failed);
        }

        self.storage.record_sth(&self.gateway_url, latest).await?;
        info!(
            "Recorded first STH at tree size {} for {}",
            latest.tree_head.tree_size, self.gateway_url
        );

        Ok(TickResult::NewSth(latest.clone()))
    }
}
