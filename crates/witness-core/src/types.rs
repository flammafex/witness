use serde::{Deserialize, Serialize};
use std::fmt;

/// Core attestation: what gets signed by witnesses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    /// SHA-256 hash of the content being timestamped
    pub hash: [u8; 32],

    /// Unix timestamp in seconds
    pub timestamp: u64,

    /// Which Witness network this attestation is from
    pub network_id: String,

    /// Monotonic sequence number for ordering
    pub sequence: u64,
}

impl Attestation {
    pub fn new(hash: [u8; 32], network_id: String, sequence: u64) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            hash,
            timestamp,
            network_id,
            sequence,
        }
    }

    /// Get canonical bytes for signing
    pub fn to_bytes(&self) -> Vec<u8> {
        // Deterministic serialization for signing
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.hash);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(self.network_id.as_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Attestation(hash={}, ts={}, net={}, seq={})",
            hex::encode(self.hash),
            self.timestamp,
            self.network_id,
            self.sequence
        )
    }
}

/// A single witness's signature on an attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    /// ID of the witness that signed
    pub witness_id: String,

    /// Signature bytes (Ed25519 64 bytes or BLS 96 bytes, depending on network configuration)
    pub signature: Vec<u8>,
}

/// Complete signed attestation with all witness signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub attestation: Attestation,

    /// Signatures (multi-sig or aggregated)
    pub signatures: crate::signature_scheme::AttestationSignatures,
}

impl SignedAttestation {
    /// Create new attestation with Ed25519 multi-sig
    pub fn new(attestation: Attestation) -> Self {
        Self {
            attestation,
            signatures: crate::signature_scheme::AttestationSignatures::new_multisig(),
        }
    }

    /// Create new attestation with BLS aggregated signature
    pub fn new_with_aggregated(
        attestation: Attestation,
        signature: Vec<u8>,
        signers: Vec<String>,
    ) -> Self {
        Self {
            attestation,
            signatures: crate::signature_scheme::AttestationSignatures::new_aggregated(
                signature, signers,
            ),
        }
    }

    /// Add a signature (only works for multi-sig)
    pub fn add_signature(&mut self, witness_id: String, signature: Vec<u8>) {
        self.signatures.add_signature_multisig(witness_id, signature);
    }

    /// Get count of signers
    pub fn signature_count(&self) -> usize {
        self.signatures.signer_count()
    }

    /// Check if using aggregated signatures
    pub fn is_aggregated(&self) -> bool {
        self.signatures.is_aggregated()
    }
}

/// Information about a witness node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessInfo {
    /// Unique identifier for this witness
    pub id: String,

    /// Ed25519 public key (hex encoded)
    pub pubkey: String,

    /// HTTP endpoint for this witness
    pub endpoint: String,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network identifier
    pub id: String,

    /// List of witnesses in this network
    pub witnesses: Vec<WitnessInfo>,

    /// Minimum number of signatures required
    pub threshold: usize,

    /// Signature scheme (ed25519 or bls)
    #[serde(default)]
    pub signature_scheme: crate::signature_scheme::SignatureScheme,

    /// Federation configuration (Phase 2)
    #[serde(default)]
    pub federation: crate::federation::FederationConfig,

    /// External anchors configuration (Phase 3)
    #[serde(default)]
    pub external_anchors: crate::external_anchors::ExternalAnchorsConfig,

    /// Deprecated: Use federation.peer_networks instead
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federation_peers: Vec<String>,
}

impl NetworkConfig {
    pub fn validate(&self) -> crate::Result<()> {
        if self.witnesses.is_empty() {
            return Err(crate::WitnessError::InvalidPublicKey(
                "No witnesses configured".to_string()
            ));
        }

        if self.threshold == 0 || self.threshold > self.witnesses.len() {
            return Err(crate::WitnessError::InsufficientSignatures {
                got: 0,
                required: self.threshold,
            });
        }

        Ok(())
    }

    pub fn find_witness(&self, id: &str) -> Option<&WitnessInfo> {
        self.witnesses.iter().find(|w| w.id == id)
    }
}

/// Request to timestamp a hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampRequest {
    /// SHA-256 hash to timestamp (hex encoded)
    pub hash: String,

    /// Optional Freebird token for Sybil resistance
    #[serde(default)]
    pub freebird_token: Option<FreebirdToken>,
}

/// Freebird token for anonymous authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreebirdToken {
    /// Base64-encoded token (131 or 195 bytes)
    pub token_b64: String,

    /// Issuer ID that created this token
    pub issuer_id: String,

    /// Token expiration (Unix timestamp)
    pub exp: u64,

    /// Epoch used for MAC key derivation
    pub epoch: u32,
}

/// Configuration for Freebird integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreebirdConfig {
    /// Freebird verifier URL (e.g., "http://localhost:8082")
    pub verifier_url: Option<String>,

    /// Trusted issuer ID(s)
    pub issuer_ids: Vec<String>,

    /// Whether Freebird is required (false = permissive mode for dev)
    #[serde(default)]
    pub required: bool,

    /// Whether to consume tokens on verification (default: false)
    ///
    /// If true, uses /v1/verify which records the nullifier and prevents reuse.
    /// If false, uses /v1/check which validates without consumption, allowing
    /// tokens (like Day Passes) to be reused elsewhere (e.g., in Clout).
    #[serde(default)]
    pub consume_tokens: bool,
}

/// Response from successful timestamp request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampResponse {
    pub attestation: SignedAttestation,
}

/// Request to verify an attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub attestation: SignedAttestation,
}

/// Response from verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub verified_signatures: usize,
    pub required_signatures: usize,
    pub message: String,
}

/// Internal request from gateway to witness for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub attestation: Attestation,
}

/// Response from witness with signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    pub witness_id: String,
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_serialization_roundtrip() {
        let attestation = Attestation {
            hash: [0u8; 32],
            timestamp: 1700000000,
            network_id: "test-network".to_string(),
            sequence: 42,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&attestation).unwrap();

        // Deserialize back
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();

        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_attestation_to_bytes_deterministic() {
        let attestation = Attestation {
            hash: [1u8; 32],
            timestamp: 1700000000,
            network_id: "test".to_string(),
            sequence: 1,
        };

        let bytes1 = attestation.to_bytes();
        let bytes2 = attestation.to_bytes();

        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_signed_attestation_with_multisig() {
        let attestation = Attestation {
            hash: [2u8; 32],
            timestamp: 1700000000,
            network_id: "test".to_string(),
            sequence: 1,
        };

        let mut signed = SignedAttestation::new(attestation);
        signed.add_signature("witness-1".to_string(), vec![1, 2, 3, 4]);
        signed.add_signature("witness-2".to_string(), vec![5, 6, 7, 8]);

        assert_eq!(signed.signature_count(), 2);
        assert!(!signed.is_aggregated());

        // Serialize and deserialize
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.signature_count(), 2);
        assert!(!deserialized.is_aggregated());
    }

    #[test]
    fn test_signed_attestation_with_aggregated() {
        let attestation = Attestation {
            hash: [3u8; 32],
            timestamp: 1700000000,
            network_id: "test".to_string(),
            sequence: 1,
        };

        let signed = SignedAttestation::new_with_aggregated(
            attestation,
            vec![10, 20, 30, 40],
            vec!["witness-1".to_string(), "witness-2".to_string()],
        );

        assert_eq!(signed.signature_count(), 2);
        assert!(signed.is_aggregated());

        // Serialize and deserialize
        let json = serde_json::to_string(&signed).unwrap();
        let deserialized: SignedAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.signature_count(), 2);
        assert!(deserialized.is_aggregated());
    }

    #[test]
    fn test_network_config_validation() {
        // Valid config
        let config = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![WitnessInfo {
                id: "w1".to_string(),
                pubkey: "abc123".to_string(),
                endpoint: "http://localhost:3001".to_string(),
            }],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(config.validate().is_ok());

        // Empty witnesses
        let bad_config = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(bad_config.validate().is_err());

        // Threshold too high
        let bad_threshold = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![WitnessInfo {
                id: "w1".to_string(),
                pubkey: "abc123".to_string(),
                endpoint: "http://localhost:3001".to_string(),
            }],
            threshold: 5, // Only 1 witness
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(bad_threshold.validate().is_err());
    }

    #[test]
    fn test_find_witness() {
        let config = NetworkConfig {
            id: "test".to_string(),
            witnesses: vec![
                WitnessInfo {
                    id: "w1".to_string(),
                    pubkey: "key1".to_string(),
                    endpoint: "http://localhost:3001".to_string(),
                },
                WitnessInfo {
                    id: "w2".to_string(),
                    pubkey: "key2".to_string(),
                    endpoint: "http://localhost:3002".to_string(),
                },
            ],
            threshold: 1,
            signature_scheme: Default::default(),
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        assert!(config.find_witness("w1").is_some());
        assert!(config.find_witness("w2").is_some());
        assert!(config.find_witness("w3").is_none());
    }
}
