use anyhow::Result;
use reqwest::Client;
use witness_core::{
    AnchorProviderType, AnchorRequest, AnchorResponse, ExternalAnchorProof,
};
use ethers::prelude::*;
use std::str::FromStr;
use std::convert::TryFrom;

/// Trait for external anchor providers
#[async_trait::async_trait]
pub trait AnchorProvider: Send + Sync {
    /// Submit a batch to be anchored
    async fn anchor(&self, request: &AnchorRequest) -> Result<AnchorResponse>;

    /// Get the provider type
    fn provider_type(&self) -> AnchorProviderType;
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
}

/// Ethereum/EVM anchor provider
/// Anchors batch roots by sending a 0-value transaction with the root in input data.
pub struct EthereumProvider {
    client: SignerMiddleware<Provider<Http>, LocalWallet>,
}

impl EthereumProvider {
    pub async fn new(rpc_url: &str, private_key: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let chain_id = provider.get_chainid().await?;
        
        let wallet = LocalWallet::from_str(private_key)?
            .with_chain_id(chain_id.as_u64());

        let client = SignerMiddleware::new(provider, wallet);

        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl AnchorProvider for EthereumProvider {
    async fn anchor(&self, request: &AnchorRequest) -> Result<AnchorResponse> {
        // 1. Prepare the payload (The Merkle Root)
        // We use the raw bytes of the root as the transaction data
        let data = Bytes::from(request.batch.merkle_root.to_vec());

        // 2. Construct the transaction
        // We send 0 ETH to ourselves (the sender), just to carry the data payload.
        let tx = TransactionRequest::new()
            .to(self.client.address()) 
            .value(0)
            .data(data.clone());

        tracing::info!(
            "Submitting batch {} anchor to Ethereum (Chain ID: {})",
            request.batch.id,
            self.client.signer().chain_id()
        );

        // 3. Send and wait for receipt
        // In production, you might want to wait for fewer confirmations to return faster,
        // but for an anchor, 1 confirmation is usually enough to get the hash.
        match self.client.send_transaction(tx, None).await {
            Ok(pending_tx) => {
                let tx_hash = pending_tx.tx_hash();
                tracing::info!("Ethereum Tx sent: {:?}", tx_hash);

                // Wait for mining (optional, but good for verification certainty)
                let receipt = pending_tx.await?;

                if let Some(receipt) = receipt {
                    if receipt.status == Some(U64::from(1)) {
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();

                        let proof = ExternalAnchorProof {
                            provider: AnchorProviderType::Blockchain,
                            timestamp,
                            proof: serde_json::json!({
                                "network": "ethereum", // or polygon, optimism, etc.
                                "chain_id": self.client.signer().chain_id(),
                                "tx_hash": format!("{:?}", tx_hash),
                                "block_number": receipt.block_number,
                                "batch_id": request.batch.id,
                                "merkle_root": hex::encode(request.batch.merkle_root),
                            }),
                            anchored_data: Some(data.to_vec()),
                        };

                        Ok(AnchorResponse {
                            success: true,
                            proof: Some(proof),
                            error: None,
                        })
                    } else {
                        // Reverted
                        let error = "Ethereum transaction reverted".to_string();
                        tracing::error!("{}", error);
                        Ok(AnchorResponse { success: false, proof: None, error: Some(error) })
                    }
                } else {
                    // Dropped?
                    let error = "Ethereum transaction dropped".to_string();
                    Ok(AnchorResponse { success: false, proof: None, error: Some(error) })
                }
            }
            Err(e) => {
                let error = format!("Failed to send Ethereum transaction: {}", e);
                tracing::error!("{}", error);
                Ok(AnchorResponse { success: false, proof: None, error: Some(error) })
            }
        }
    }

    fn provider_type(&self) -> AnchorProviderType {
        AnchorProviderType::Blockchain
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
