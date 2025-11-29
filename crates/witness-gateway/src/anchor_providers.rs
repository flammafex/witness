use anyhow::Result;
use reqwest::Client;
use witness_core::{
    AnchorProviderType, AnchorRequest, AnchorResponse, ExternalAnchorProof,
};

/// Trait for external anchor providers
#[async_trait::async_trait]
pub trait AnchorProvider: Send + Sync {
    /// Submit a batch to be anchored
    async fn anchor(&self, request: &AnchorRequest) -> Result<AnchorResponse>;

    /// Get the provider type
    fn provider_type(&self) -> AnchorProviderType;

    /// Verify an anchor proof
    async fn verify(&self, proof: &ExternalAnchorProof) -> Result<bool>;
}

/// Internet Archive anchor provider
pub struct InternetArchiveProvider {
    client: Client,
    base_url: String,
}

impl InternetArchiveProvider {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            base_url: "https://web.archive.org".to_string(),
        }
    }

    pub fn with_url(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }

    /// Create a data URL for the batch
    fn create_data_url(&self, request: &AnchorRequest) -> String {
        // Create a deterministic URL for this batch
        let batch_id = request.batch.id;
        let network_id = &request.batch.network_id;
        let merkle_root_hex = hex::encode(request.batch.merkle_root);

        format!(
            "data:text/plain;charset=utf-8,Witness%20Batch%20Anchor%0A\
             Network:%20{}%0A\
             Batch%20ID:%20{}%0A\
             Merkle%20Root:%20{}%0A\
             Period:%20{}%20-%20{}%0A\
             Attestations:%20{}",
            network_id,
            batch_id,
            merkle_root_hex,
            request.batch.period_start,
            request.batch.period_end,
            request.batch.attestation_count
        )
    }
}

impl Default for InternetArchiveProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AnchorProvider for InternetArchiveProvider {
    async fn anchor(&self, request: &AnchorRequest) -> Result<AnchorResponse> {
        // Create data URL with batch information
        let data_url = self.create_data_url(request);

        // Submit to Internet Archive's Save API
        let save_url = format!("{}/save/{}", self.base_url, data_url);

        tracing::info!(
            "Submitting batch {} to Internet Archive: {}",
            request.batch.id,
            save_url
        );

        match self.client
            .get(&save_url)
            .header("User-Agent", "Witness-Timestamping/0.1.0")
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let final_url = response.url().to_string();

                if status.is_success() {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let proof = ExternalAnchorProof {
                        provider: AnchorProviderType::InternetArchive,
                        timestamp,
                        proof: serde_json::json!({
                            "archive_url": final_url,
                            "batch_id": request.batch.id,
                            "merkle_root": hex::encode(request.batch.merkle_root),
                        }),
                        anchored_data: Some(data_url.as_bytes().to_vec()),
                    };

                    tracing::info!(
                        "Successfully archived batch {} at: {}",
                        request.batch.id,
                        final_url
                    );

                    Ok(AnchorResponse {
                        success: true,
                        proof: Some(proof),
                        error: None,
                    })
                } else {
                    let error = format!(
                        "Internet Archive returned status {}: {}",
                        status,
                        response.text().await.unwrap_or_default()
                    );

                    tracing::warn!("Failed to archive batch {}: {}", request.batch.id, error);

                    Ok(AnchorResponse {
                        success: false,
                        proof: None,
                        error: Some(error),
                    })
                }
            }
            Err(e) => {
                let error = format!("Failed to connect to Internet Archive: {}", e);
                tracing::error!("{}", error);

                Ok(AnchorResponse {
                    success: false,
                    proof: None,
                    error: Some(error),
                })
            }
        }
    }

    fn provider_type(&self) -> AnchorProviderType {
        AnchorProviderType::InternetArchive
    }

    async fn verify(&self, proof: &ExternalAnchorProof) -> Result<bool> {
        // Extract archive URL from proof
        let archive_url = proof
            .proof
            .get("archive_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing archive_url in proof"))?;

        // Try to fetch the archived page
        match self.client
            .get(archive_url)
            .header("User-Agent", "Witness-Timestamping/0.1.0")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    // Optionally: verify the content matches what we anchored
                    Ok(true)
                } else {
                    tracing::warn!(
                        "Archive verification failed: status {}",
                        response.status()
                    );
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::error!("Failed to verify archive: {}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use witness_core::AttestationBatch;

    #[test]
    fn test_create_data_url() {
        let provider = InternetArchiveProvider::new();
        let batch = AttestationBatch {
            id: 1,
            network_id: "test-network".to_string(),
            merkle_root: [1u8; 32],
            period_start: 1000,
            period_end: 2000,
            attestation_count: 42,
        };

        let request = AnchorRequest {
            batch,
            metadata: None,
        };

        let url = provider.create_data_url(&request);
        assert!(url.contains("test-network"));
        assert!(url.contains("Batch%20ID:%201"));
        assert!(url.contains("Attestations:%2042"));
    }

    #[tokio::test]
    async fn test_provider_type() {
        let provider = InternetArchiveProvider::new();
        assert_eq!(
            provider.provider_type(),
            AnchorProviderType::InternetArchive
        );
    }
}
