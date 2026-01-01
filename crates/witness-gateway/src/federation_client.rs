use anyhow::{Context, Result};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use witness_core::{
    AttestationBatch, CrossAnchor, CrossAnchorRequest, CrossAnchorResponse, NetworkConfig,
    PeerNetworkInfo,
};

use crate::storage::Storage;

/// Client for federation operations with peer networks
#[allow(dead_code)]
pub struct FederationClient {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    http_client: Client,
}

impl FederationClient {
    pub fn new(config: Arc<NetworkConfig>, storage: Arc<Storage>) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            storage,
            http_client,
        }
    }

    /// Submit a batch to all peer networks for cross-anchoring
    #[allow(dead_code)]
    pub async fn cross_anchor_batch(&self, batch: &AttestationBatch) -> Result<Vec<CrossAnchor>> {
        if !self.config.federation.enabled {
            return Ok(Vec::new());
        }

        tracing::info!(
            "Submitting batch {} for cross-anchoring to {} peer networks",
            batch.id,
            self.config.federation.peer_networks.len()
        );

        let mut tasks = Vec::new();

        for peer in &self.config.federation.peer_networks {
            let peer = peer.clone();
            let batch = batch.clone();
            let client = self.http_client.clone();

            let task = tokio::spawn(async move {
                Self::request_cross_anchor(&client, &peer, &batch).await
            });

            tasks.push(task);
        }

        // Collect results
        let mut cross_anchors = Vec::new();

        for task in tasks {
            match task.await {
                Ok(Ok(cross_anchor)) => {
                    tracing::info!(
                        "Received cross-anchor from network: {}",
                        cross_anchor.witnessing_network
                    );
                    cross_anchors.push(cross_anchor);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Failed to get cross-anchor from peer: {}", e);
                }
                Err(e) => {
                    tracing::error!("Task join error: {}", e);
                }
            }
        }

        // Store cross-anchors
        for cross_anchor in &cross_anchors {
            if let Err(e) = self.storage.store_cross_anchor(cross_anchor).await {
                tracing::error!("Failed to store cross-anchor: {}", e);
            }
        }

        tracing::info!(
            "Received {} cross-anchors for batch {} (threshold: {})",
            cross_anchors.len(),
            batch.id,
            self.config.federation.cross_anchor_threshold
        );

        Ok(cross_anchors)
    }

    #[allow(dead_code)]
    async fn request_cross_anchor(
        client: &Client,
        peer: &PeerNetworkInfo,
        batch: &AttestationBatch,
    ) -> Result<CrossAnchor> {
        let url = format!("{}/v1/federation/anchor", peer.gateway);

        let request = CrossAnchorRequest {
            batch: batch.clone(),
        };

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await
            .with_context(|| format!("Failed to connect to peer network: {}", peer.id))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Peer {} returned error {}: {}",
                peer.id,
                status,
                error_text
            );
        }

        let cross_anchor_response: CrossAnchorResponse = response
            .json()
            .await
            .with_context(|| format!("Failed to parse response from peer: {}", peer.id))?;

        Ok(cross_anchor_response.cross_anchor)
    }
}
