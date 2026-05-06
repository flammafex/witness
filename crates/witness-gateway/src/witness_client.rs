use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use witness_core::{Attestation, SignRequest, SignResponse, WitnessInfo};

pub struct WitnessClient {
    client: Client,
}

impl WitnessClient {
    pub fn new() -> Self {
        Self {
            client: crate::http_client::build_client(true),
        }
    }

    pub async fn request_signature(
        &self,
        witness: &WitnessInfo,
        attestation: &Attestation,
    ) -> Result<SignResponse> {
        let auth_token = witness
            .auth_token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Missing auth token for witness: {}", witness.id))?;

        let url = format!("{}/v1/sign", witness.endpoint);

        let request = SignRequest {
            attestation: attestation.clone(),
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(auth_token)
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

impl Default for WitnessClient {
    fn default() -> Self {
        Self::new()
    }
}
