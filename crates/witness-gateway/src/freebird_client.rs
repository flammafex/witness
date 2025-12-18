// Phase 6: Freebird Anonymous Submission Client
//
// This module handles communication with the Freebird verifier service
// for anonymous token verification.

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use witness_core::{FreebirdConfig, FreebirdVerifyRequest, FreebirdVerifyResponse};

/// Cached issuer metadata from Freebird
#[derive(Debug, Clone)]
pub struct IssuerMetadata {
    pub issuer_id: String,
    pub pubkey: String,
    pub kid: String,
    pub exp_sec: u64,
    pub current_epoch: u32,
    pub valid_epochs: Vec<u32>,
}

/// Response from Freebird issuer's well-known endpoint
#[derive(Debug, Deserialize)]
struct WellKnownResponse {
    issuer_id: String,
    #[serde(default)]
    current_epoch: u32,
    #[serde(default)]
    valid_epochs: Vec<u32>,
    voprf: VoprfInfo,
}

#[derive(Debug, Deserialize)]
struct VoprfInfo {
    #[allow(dead_code)]
    suite: String,
    kid: String,
    pubkey: String,
    exp_sec: u64,
}

/// Client for interacting with Freebird services
pub struct FreebirdClient {
    config: Arc<FreebirdConfig>,
    http_client: Client,
    issuer_metadata: Arc<RwLock<Option<IssuerMetadata>>>,
}

impl FreebirdClient {
    /// Create a new Freebird client
    pub fn new(config: Arc<FreebirdConfig>) -> Self {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            http_client,
            issuer_metadata: Arc::new(RwLock::new(None)),
        }
    }

    /// Check if Freebird is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Refresh issuer metadata from the well-known endpoint
    pub async fn refresh_metadata(&self) -> Result<()> {
        if !self.config.enabled || self.config.issuer_url.is_empty() {
            return Ok(());
        }

        tracing::info!("Refreshing Freebird issuer metadata from {}", self.config.issuer_url);

        let response = self
            .http_client
            .get(&self.config.issuer_url)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch issuer metadata: HTTP {}",
                response.status()
            ));
        }

        let well_known: WellKnownResponse = response.json().await?;

        let metadata = IssuerMetadata {
            issuer_id: well_known.issuer_id,
            pubkey: well_known.voprf.pubkey,
            kid: well_known.voprf.kid,
            exp_sec: well_known.voprf.exp_sec,
            current_epoch: well_known.current_epoch,
            valid_epochs: well_known.valid_epochs,
        };

        tracing::info!(
            "Updated Freebird issuer metadata: issuer_id={}, kid={}, exp_sec={}",
            metadata.issuer_id,
            metadata.kid,
            metadata.exp_sec
        );

        let mut lock = self.issuer_metadata.write().await;
        *lock = Some(metadata);

        Ok(())
    }

    /// Get cached issuer metadata
    pub async fn get_metadata(&self) -> Option<IssuerMetadata> {
        let lock = self.issuer_metadata.read().await;
        lock.clone()
    }

    /// Verify a Freebird token with the verifier service
    pub async fn verify_token(
        &self,
        token_b64: &str,
        exp: i64,
        epoch: u32,
    ) -> Result<FreebirdVerifyResponse> {
        if !self.config.enabled {
            return Err(anyhow!("Freebird is not enabled"));
        }

        if self.config.verifier_url.is_empty() {
            return Err(anyhow!("Freebird verifier URL not configured"));
        }

        // Get issuer ID from config or cached metadata
        let issuer_id = if !self.config.issuer_id.is_empty() {
            self.config.issuer_id.clone()
        } else {
            let metadata = self.get_metadata().await;
            metadata
                .map(|m| m.issuer_id)
                .ok_or_else(|| anyhow!("No issuer metadata available"))?
        };

        let verify_url = format!("{}/v1/verify", self.config.verifier_url.trim_end_matches('/'));

        let request = FreebirdVerifyRequest {
            token_b64: token_b64.to_string(),
            issuer_id,
            exp: Some(exp),
            epoch,
        };

        tracing::debug!(
            "Sending Freebird verification request to {}: epoch={}, exp={}",
            verify_url,
            epoch,
            exp
        );

        let response = self
            .http_client
            .post(&verify_url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let response_text = response.text().await?;

        tracing::debug!("Freebird verifier response ({}): {}", status, response_text);

        if status.is_success() {
            let verify_response: FreebirdVerifyResponse = serde_json::from_str(&response_text)
                .map_err(|e| anyhow!("Failed to parse verifier response: {}", e))?;
            Ok(verify_response)
        } else if status.as_u16() == 401 {
            // Token verification failed (invalid, expired, or replay)
            Ok(FreebirdVerifyResponse {
                ok: false,
                error: Some("Token verification failed".to_string()),
                verified_at: 0,
            })
        } else {
            Err(anyhow!(
                "Freebird verifier error: HTTP {} - {}",
                status,
                response_text
            ))
        }
    }

    /// Start background metadata refresh task
    pub fn start_metadata_refresh(self: Arc<Self>) {
        if !self.config.enabled || self.config.issuer_url.is_empty() {
            return;
        }

        let refresh_interval = Duration::from_secs(self.config.refresh_interval_min * 60);

        tokio::spawn(async move {
            // Initial fetch
            if let Err(e) = self.refresh_metadata().await {
                tracing::warn!("Initial Freebird metadata fetch failed: {}", e);
            }

            // Periodic refresh
            let mut interval = tokio::time::interval(refresh_interval);
            interval.tick().await; // Skip the first immediate tick

            loop {
                interval.tick().await;
                if let Err(e) = self.refresh_metadata().await {
                    tracing::warn!("Freebird metadata refresh failed: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freebird_config_default() {
        let config = FreebirdConfig::default();
        assert!(!config.enabled);
        assert!(config.verifier_url.is_empty());
        assert!(config.issuer_url.is_empty());
        assert_eq!(config.max_clock_skew_secs, 300);
        assert_eq!(config.refresh_interval_min, 10);
    }
}
