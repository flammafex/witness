use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use witness_core::{Attestation, SignRequest, SignResponse, WitnessInfo};

pub struct WitnessClient {
    client: Client,
}

impl WitnessClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    pub async fn request_signature(
        &self,
        witness: &WitnessInfo,
        attestation: &Attestation,
    ) -> Result<SignResponse> {
        let url = format!("{}/v1/sign", witness.endpoint);

        let request = SignRequest {
            attestation: attestation.clone(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .with_context(|| format!("Failed to connect to witness: {}", witness.id))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Witness {} returned error {}: {}",
                witness.id,
                status,
                error_text
            );
        }

        let sign_response: SignResponse = response
            .json()
            .await
            .with_context(|| format!("Failed to parse response from witness: {}", witness.id))?;

        Ok(sign_response)
    }

    pub async fn health_check(&self, witness: &WitnessInfo) -> bool {
        let url = format!("{}/health", witness.endpoint);

        self.client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}
