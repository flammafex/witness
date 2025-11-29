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

    /// Ed25519 signature bytes
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
