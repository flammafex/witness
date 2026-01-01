use serde::{Deserialize, Serialize};
use crate::federation::AttestationBatch;

/// External anchor provider types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnchorProviderType {
    /// Internet Archive (archive.org)
    InternetArchive,

    /// Trillian/Tessera transparency log
    Trillian,

    /// DNS TXT record
    DnsTxt,

    /// Blockchain (various chains)
    Blockchain,
}

impl std::fmt::Display for AnchorProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorProviderType::InternetArchive => write!(f, "internet_archive"),
            AnchorProviderType::Trillian => write!(f, "trillian"),
            AnchorProviderType::DnsTxt => write!(f, "dns_txt"),
            AnchorProviderType::Blockchain => write!(f, "blockchain"),
        }
    }
}

/// Configuration for an external anchor provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProviderConfig {
    /// Type of anchor provider
    #[serde(rename = "type")]
    pub provider_type: AnchorProviderType,

    /// Whether this provider is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Priority (lower = higher priority, providers tried in order)
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Provider-specific configuration (URL, credentials, etc.)
    #[serde(flatten)]
    pub config: serde_json::Value,
}

fn default_enabled() -> bool {
    true
}

fn default_priority() -> u32 {
    100
}

/// Configuration for external anchoring
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExternalAnchorsConfig {
    /// Whether external anchoring is enabled
    #[serde(default)]
    pub enabled: bool,

    /// How often to anchor batches (seconds)
    #[serde(default = "default_anchor_period")]
    pub anchor_period: u64,

    /// Minimum number of successful anchors required
    #[serde(default = "default_minimum_required")]
    pub minimum_required: usize,

    /// List of anchor providers
    #[serde(default)]
    pub providers: Vec<AnchorProviderConfig>,
}

fn default_anchor_period() -> u64 {
    3600 // 1 hour
}

fn default_minimum_required() -> usize {
    1
}

/// Proof that data was anchored to an external service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAnchorProof {
    /// Type of anchor provider
    pub provider: AnchorProviderType,

    /// When this anchor was created
    pub timestamp: u64,

    /// Provider-specific proof data (URL, transaction hash, etc.)
    pub proof: serde_json::Value,

    /// Optional: the actual data that was anchored (for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchored_data: Option<Vec<u8>>,
}

/// A batch with external anchor proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchoredBatch {
    /// The original batch
    pub batch: AttestationBatch,

    /// External anchor proofs
    pub external_anchors: Vec<ExternalAnchorProof>,
}

/// Request to anchor a batch externally
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRequest {
    /// The batch to anchor
    pub batch: AttestationBatch,

    /// Optional: additional metadata to include
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Response from anchoring a batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorResponse {
    /// Whether the anchor was successful
    pub success: bool,

    /// The anchor proof (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<ExternalAnchorProof>,

    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_serialization() {
        let config = AnchorProviderConfig {
            provider_type: AnchorProviderType::InternetArchive,
            enabled: true,
            priority: 1,
            config: serde_json::json!({
                "submit_url": "https://web.archive.org/save/"
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("internet_archive"));

        let deserialized: AnchorProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider_type, AnchorProviderType::InternetArchive);
    }

    #[test]
    fn test_external_anchors_config_defaults() {
        // Test serde defaults by deserializing empty JSON
        let config: ExternalAnchorsConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled);
        assert_eq!(config.anchor_period, 3600);
        assert_eq!(config.minimum_required, 1);
        assert_eq!(config.providers.len(), 0);
    }

    #[test]
    fn test_anchor_response() {
        let response = AnchorResponse {
            success: true,
            proof: Some(ExternalAnchorProof {
                provider: AnchorProviderType::InternetArchive,
                timestamp: 1234567890,
                proof: serde_json::json!({
                    "url": "https://web.archive.org/web/20231215/..."
                }),
                anchored_data: None,
            }),
            error: None,
        };

        assert!(response.success);
        assert!(response.proof.is_some());
    }
}
