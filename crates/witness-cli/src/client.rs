use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use witness_core::{
    ExternalAnchorProof, FreebirdToken, NetworkConfig, SignedAttestation, TimestampRequest,
    TimestampResponse, VerifyRequest, VerifyResponse,
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

    pub async fn verify(&self, attestation: &SignedAttestation) -> Result<VerifyResponse> {
        let url = format!("{}/v1/verify", self.gateway_url);

        let request = VerifyRequest {
            attestation: attestation.clone(),
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

        let verify_response: VerifyResponse = response
            .json()
            .await
            .context("Failed to parse gateway response")?;

        Ok(verify_response)
    }

    pub async fn get_config(&self) -> Result<NetworkConfig> {
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

        let config: NetworkConfig = response
            .json()
            .await
            .context("Failed to parse gateway response")?;

        Ok(config)
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
