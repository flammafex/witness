//! HTTP client for polling a witness gateway's RFC 9162 endpoints.

use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use witness_core::{LogConsistencyProof, NetworkVerificationConfig, SignedTreeHead};

pub struct GatewayClient {
    client: Client,
    gateway_url: String,
}

impl GatewayClient {
    pub fn new(gateway_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        let gateway_url = gateway_url.trim_end_matches('/').to_string();
        Self {
            client,
            gateway_url,
        }
    }

    /// Fetch the gateway's current secret-free verification configuration.
    pub async fn get_network_config(&self) -> Result<NetworkVerificationConfig> {
        let url = format!("{}/v1/network", self.gateway_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to connect to gateway: {}", self.gateway_url))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        response
            .json()
            .await
            .with_context(|| format!("Failed to parse network config from {}", self.gateway_url))
    }

    /// Fetch the latest signed tree head.
    pub async fn get_latest_sth(&self) -> Result<SignedTreeHead> {
        let url = format!("{}/v1/log/sth", self.gateway_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to connect to gateway: {}", self.gateway_url))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        response
            .json()
            .await
            .context("Failed to parse STH response")
    }

    /// Fetch a consistency proof between two tree sizes.
    pub async fn get_consistency_proof(
        &self,
        first: u64,
        second: u64,
    ) -> Result<LogConsistencyProof> {
        let url = format!(
            "{}/v1/log/consistency?first={}&second={}",
            self.gateway_url, first, second
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to connect to gateway: {}", self.gateway_url))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        response
            .json()
            .await
            .context("Failed to parse consistency proof response")
    }
}
