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

    /// Freebird anonymous submission configuration (Phase 6)
    #[serde(default)]
    pub freebird: FreebirdConfig,

    /// Deprecated: Use federation.peer_networks instead
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub federation_peers: Vec<String>,
}

/// Freebird anonymous submission configuration (Phase 6)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreebirdConfig {
    /// Whether Freebird anonymous submissions are enabled
    #[serde(default)]
    pub enabled: bool,

    /// URL of the Freebird verifier service (e.g., "http://localhost:8082")
    #[serde(default)]
    pub verifier_url: String,

    /// URL of the Freebird issuer for metadata discovery (e.g., "http://localhost:8081/.well-known/issuer")
    #[serde(default)]
    pub issuer_url: String,

    /// Expected issuer ID for token validation
    #[serde(default)]
    pub issuer_id: String,

    /// Maximum acceptable clock skew in seconds (default: 300 = 5 minutes)
    #[serde(default = "default_clock_skew")]
    pub max_clock_skew_secs: i64,

    /// How often to refresh issuer metadata in minutes (default: 10)
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_min: u64,
}

fn default_clock_skew() -> i64 {
    300
}

fn default_refresh_interval() -> u64 {
    10
}

impl Default for FreebirdConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verifier_url: String::new(),
            issuer_url: String::new(),
            issuer_id: String::new(),
            max_clock_skew_secs: default_clock_skew(),
            refresh_interval_min: default_refresh_interval(),
        }
    }
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

// ============================================================================
// Phase 6: Freebird Anonymous Submission Types
// ============================================================================

/// Request for anonymous timestamping using Freebird token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousTimestampRequest {
    /// SHA-256 hash to timestamp (hex encoded)
    pub hash: String,

    /// Freebird VOPRF token (base64url encoded, 195 bytes)
    pub token_b64: String,

    /// Token expiration timestamp (Unix seconds)
    pub exp: i64,

    /// Epoch used for token MAC key derivation
    pub epoch: u32,
}

/// Response from anonymous timestamp request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousTimestampResponse {
    /// The signed attestation
    pub attestation: SignedAttestation,

    /// Indicates this was an anonymous submission
    pub anonymous: bool,

    /// Freebird verification timestamp
    pub freebird_verified_at: i64,
}

/// Freebird token verification request (sent to Freebird verifier)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreebirdVerifyRequest {
    pub token_b64: String,
    pub issuer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    pub epoch: u32,
}

/// Freebird token verification response (from Freebird verifier)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreebirdVerifyResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub verified_at: i64,
}

// ============================================================================
// Light Client Support: Merkle Proof Types
// ============================================================================

/// Response containing a merkle proof for offline verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResponse {
    /// The signed attestation
    pub attestation: SignedAttestation,

    /// Merkle proof showing inclusion in a batch
    pub merkle_proof: crate::MerkleProof,

    /// Batch information
    pub batch: crate::AttestationBatch,

    /// External anchor proofs for this batch (if available)
    #[serde(default)]
    pub external_anchors: Vec<crate::ExternalAnchorProof>,
}
