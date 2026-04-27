use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use witness_core::{
    ExternalAnchorProof, FreebirdToken, LogConsistencyProof, NetworkConfig, ProofBundle,
    SignedAttestation, SignedTreeHead, TimestampRequest, TimestampResponse,
};

pub struct WitnessClient {
    client: Client,
    gateway_url: String,
}

impl WitnessClient {
    pub fn new(gateway_url: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            gateway_url: gateway_url.to_string(),
        }
    }

    pub async fn timestamp(
        &self,
        hash: &str,
        freebird_token: Option<FreebirdToken>,
    ) -> Result<SignedAttestation> {
        let url = format!("{}/v1/timestamp", self.gateway_url);

        let request = TimestampRequest {
            hash: hash.to_string(),
            freebird_token,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        let timestamp_response: TimestampResponse = response
            .json()
            .await
            .context("Failed to parse gateway response")?;

        Ok(timestamp_response.attestation)
    }

    pub async fn get_timestamp(&self, hash: &str) -> Result<SignedAttestation> {
        let url = format!("{}/v1/timestamp/{}", self.gateway_url, hash);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        let timestamp_response: TimestampResponse = response
            .json()
            .await
            .context("Failed to parse gateway response")?;

        Ok(timestamp_response.attestation)
    }

    pub async fn get_config(&self) -> Result<serde_json::Value> {
        let url = format!("{}/v1/config", self.gateway_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        let config: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse gateway response")?;

        Ok(config)
    }

    /// Fetch the full [`NetworkConfig`] (witnesses + pubkeys + federation peers).
    /// Used by offline verifiers to check threshold signatures and cross-anchors.
    pub async fn get_network_config(&self) -> Result<NetworkConfig> {
        self.get_network_config_from(&self.gateway_url).await
    }

    /// Fetch a [`NetworkConfig`] from an arbitrary gateway URL — used to fetch
    /// peer network configs for cross-anchor verification.
    pub async fn get_network_config_from(&self, gateway_url: &str) -> Result<NetworkConfig> {
        let url = format!("{}/v1/network", gateway_url.trim_end_matches('/'));

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to connect to gateway: {}", gateway_url))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Gateway {} returned error {}: {}",
                gateway_url,
                status,
                error_text
            );
        }

        let config: NetworkConfig = response
            .json()
            .await
            .with_context(|| format!("Failed to parse network config from {}", gateway_url))?;

        Ok(config)
    }

    /// Fetch a self-contained [`ProofBundle`] for a hash.
    pub async fn get_proof_bundle(&self, hash: &str) -> Result<ProofBundle> {
        let url = format!("{}/v1/bundle/{}", self.gateway_url, hash);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        let bundle: ProofBundle = response
            .json()
            .await
            .context("Failed to parse proof bundle")?;

        Ok(bundle)
    }

    /// Latest signed tree head from the gateway's log.
    pub async fn get_latest_sth(&self) -> Result<SignedTreeHead> {
        let url = format!("{}/v1/log/sth", self.gateway_url);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        response.json().await.context("Failed to parse STH response")
    }

    /// Consistency proof linking two prior STHs in the gateway's log.
    pub async fn get_log_consistency(
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
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        response
            .json()
            .await
            .context("Failed to parse consistency proof")
    }

    pub async fn get_batch_anchors(&self, hash: &str) -> Result<Vec<ExternalAnchorProof>> {
        let url = format!("{}/v1/anchors/{}", self.gateway_url, hash);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to gateway")?;

        if !response.status().is_success() {
            if response.status() == 404 {
                // Not found - return empty list
                return Ok(Vec::new());
            }

            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("Gateway returned error {}: {}", status, error_text);
        }

        let anchors: Vec<ExternalAnchorProof> = response
            .json()
            .await
            .context("Failed to parse gateway response")?;

        Ok(anchors)
    }
}
