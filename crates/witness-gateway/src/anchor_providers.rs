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

/// Trillian/Tessera transparency log anchor provider
pub struct TrillianProvider {
    client: Client,
    log_url: String,
}

impl TrillianProvider {
    pub fn new(log_url: String) -> Self {
        Self {
            client: Client::new(),
            log_url,
        }
    }

    /// Create a log entry for the batch
    fn create_log_entry(&self, request: &AnchorRequest) -> serde_json::Value {
        serde_json::json!({
            "batch_id": request.batch.id,
            "network_id": request.batch.network_id,
            "merkle_root": hex::encode(request.batch.merkle_root),
            "period_start": request.batch.period_start,
            "period_end": request.batch.period_end,
            "attestation_count": request.batch.attestation_count,
        })
    }
}

#[async_trait::async_trait]
impl AnchorProvider for TrillianProvider {
    async fn anchor(&self, request: &AnchorRequest) -> Result<AnchorResponse> {
        // Create log entry
        let entry = self.create_log_entry(request);
        let entry_bytes = serde_json::to_vec(&entry)?;

        // Submit to Trillian/Tessera log
        let add_url = format!("{}/add", self.log_url);

        tracing::info!(
            "Submitting batch {} to Trillian log: {}",
            request.batch.id,
            add_url
        );

        match self.client
            .post(&add_url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &entry_bytes),
            }))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();

                if status.is_success() {
                    let result: serde_json::Value = response.json().await?;

                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let proof = ExternalAnchorProof {
                        provider: AnchorProviderType::Trillian,
                        timestamp,
                        proof: serde_json::json!({
                            "log_url": self.log_url,
                            "tree_size": result.get("tree_size"),
                            "log_index": result.get("log_index"),
                            "inclusion_proof": result.get("inclusion_proof"),
                            "batch_id": request.batch.id,
                            "merkle_root": hex::encode(request.batch.merkle_root),
                        }),
                        anchored_data: Some(entry_bytes),
                    };

                    tracing::info!(
                        "Successfully added batch {} to Trillian log",
                        request.batch.id
                    );

                    Ok(AnchorResponse {
                        success: true,
                        proof: Some(proof),
                        error: None,
                    })
                } else {
                    let error = format!(
                        "Trillian log returned status {}: {}",
                        status,
                        response.text().await.unwrap_or_default()
                    );

                    tracing::warn!("Failed to add batch {} to Trillian log: {}", request.batch.id, error);

                    Ok(AnchorResponse {
                        success: false,
                        proof: None,
                        error: Some(error),
                    })
                }
            }
            Err(e) => {
                let error = format!("Failed to connect to Trillian log: {}", e);
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
        AnchorProviderType::Trillian
    }

    async fn verify(&self, proof: &ExternalAnchorProof) -> Result<bool> {
        // Extract log index from proof
        let log_index = proof
            .proof
            .get("log_index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing log_index in proof"))?;

        let log_url = proof
            .proof
            .get("log_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing log_url in proof"))?;

        // Query the log entry
        let get_url = format!("{}/entries/{}", log_url, log_index);

        match self.client
            .get(&get_url)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    // Optionally: verify the entry matches what we anchored
                    Ok(true)
                } else {
                    tracing::warn!(
                        "Trillian verification failed: status {}",
                        response.status()
                    );
                    Ok(false)
                }
            }
            Err(e) => {
                tracing::error!("Failed to verify Trillian entry: {}", e);
                Ok(false)
            }
        }
    }
}

/// DNS TXT record anchor provider
pub struct DnsTxtProvider {
    client: Client,
    api_url: String,
    domain: String,
    api_key: Option<String>,
}

impl DnsTxtProvider {
    pub fn new(api_url: String, domain: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            api_url,
            domain,
            api_key,
        }
    }

    /// Create DNS TXT record name for a batch
    fn create_record_name(&self, batch_id: u64) -> String {
        format!("_witness-{}.{}", batch_id, self.domain)
    }

    /// Create DNS TXT record value for a batch
    fn create_record_value(&self, request: &AnchorRequest) -> String {
        format!(
            "v=witness1;id={};root={};network={};start={};end={};count={}",
            request.batch.id,
            hex::encode(request.batch.merkle_root),
            request.batch.network_id,
            request.batch.period_start,
            request.batch.period_end,
            request.batch.attestation_count
        )
    }
}

#[async_trait::async_trait]
impl AnchorProvider for DnsTxtProvider {
    async fn anchor(&self, request: &AnchorRequest) -> Result<AnchorResponse> {
        let record_name = self.create_record_name(request.batch.id);
        let record_value = self.create_record_value(request);

        tracing::info!(
            "Creating DNS TXT record for batch {}: {}",
            request.batch.id,
            record_name
        );

        // Build DNS API request
        let mut req = self.client
            .post(&self.api_url)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "name": record_name,
                "type": "TXT",
                "value": record_value,
                "ttl": 3600,
            }));

        // Add API key if provided
        if let Some(api_key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        }

        match req.send().await {
            Ok(response) => {
                let status = response.status();

                if status.is_success() {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let proof = ExternalAnchorProof {
                        provider: AnchorProviderType::DnsTxt,
                        timestamp,
                        proof: serde_json::json!({
                            "record_name": record_name,
                            "record_value": record_value,
                            "domain": self.domain,
                            "batch_id": request.batch.id,
                            "merkle_root": hex::encode(request.batch.merkle_root),
                        }),
                        anchored_data: Some(record_value.as_bytes().to_vec()),
                    };

                    tracing::info!(
                        "Successfully created DNS TXT record for batch {}: {}",
                        request.batch.id,
                        record_name
                    );

                    Ok(AnchorResponse {
                        success: true,
                        proof: Some(proof),
                        error: None,
                    })
                } else {
                    let error = format!(
                        "DNS API returned status {}: {}",
                        status,
                        response.text().await.unwrap_or_default()
                    );

                    tracing::warn!("Failed to create DNS TXT record for batch {}: {}", request.batch.id, error);

                    Ok(AnchorResponse {
                        success: false,
                        proof: None,
                        error: Some(error),
                    })
                }
            }
            Err(e) => {
                let error = format!("Failed to connect to DNS API: {}", e);
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
        AnchorProviderType::DnsTxt
    }

    async fn verify(&self, proof: &ExternalAnchorProof) -> Result<bool> {
        // Extract record name from proof
        let record_name = proof
            .proof
            .get("record_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing record_name in proof"))?;

        // Note: In a real implementation, you would use a DNS resolver to query the TXT record
        // For now, we'll just verify the proof structure is valid
        tracing::info!("Verifying DNS TXT record: {}", record_name);

        // TODO: Implement actual DNS resolution using trust-dns-resolver or similar
        // For now, return true if the proof has the required fields
        let has_required_fields = proof.proof.get("record_value").is_some()
            && proof.proof.get("domain").is_some()
            && proof.proof.get("merkle_root").is_some();

        Ok(has_required_fields)
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
