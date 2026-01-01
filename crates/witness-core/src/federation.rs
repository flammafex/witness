use serde::{Deserialize, Serialize};

use crate::merkle::MerkleProof;
use crate::WitnessSignature;

/// A batch of attestations with their merkle root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBatch {
    /// Unique batch ID
    pub id: u64,

    /// Network that created this batch
    pub network_id: String,

    /// Merkle root of all attestations in this batch
    pub merkle_root: [u8; 32],

    /// Start of batch period (Unix seconds)
    pub period_start: u64,

    /// End of batch period (Unix seconds)
    pub period_end: u64,

    /// Number of attestations in this batch
    pub attestation_count: u64,
}

/// Cross-anchor attestation from a peer network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossAnchor {
    /// The batch being witnessed
    pub batch: AttestationBatch,

    /// ID of the network that witnessed this batch
    pub witnessing_network: String,

    /// Signatures from the witnessing network's witnesses
    pub signatures: Vec<WitnessSignature>,

    /// When this cross-anchor was created
    pub timestamp: u64,
}

/// Configuration for federation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FederationConfig {
    /// Whether federation is enabled
    #[serde(default)]
    pub enabled: bool,

    /// How often to close batches (seconds)
    #[serde(default = "default_batch_period")]
    pub batch_period: u64,

    /// Peer networks to federate with
    #[serde(default)]
    pub peer_networks: Vec<PeerNetworkInfo>,

    /// Minimum number of peer networks that must cross-anchor
    #[serde(default)]
    pub cross_anchor_threshold: usize,
}

fn default_batch_period() -> u64 {
    3600 // 1 hour
}

/// Information about a peer network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNetworkInfo {
    /// Peer network ID
    pub id: String,

    /// Gateway URL for this peer network
    pub gateway: String,

    /// Minimum number of witnesses required from this peer
    #[serde(default = "default_min_witnesses")]
    pub min_witnesses: usize,
}

fn default_min_witnesses() -> usize {
    2
}

/// Request to cross-anchor a batch (sent to peer network)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossAnchorRequest {
    pub batch: AttestationBatch,
}

/// Response from peer network after cross-anchoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossAnchorResponse {
    pub cross_anchor: CrossAnchor,
}

/// Enhanced attestation with merkle proof and cross-anchors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedAttestation {
    /// The base signed attestation
    pub attestation: crate::SignedAttestation,

    /// Merkle proof of inclusion in a batch (if available)
    pub merkle_proof: Option<MerkleProof>,

    /// Cross-anchors from peer networks (if available)
    pub cross_anchors: Vec<CrossAnchor>,
}

/// Request to get federated verification info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedVerifyRequest {
    /// Hash to verify
    pub hash: [u8; 32],
}

/// Response with federated verification info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedVerifyResponse {
    pub federated_attestation: Option<FederatedAttestation>,
    pub verified: bool,
    pub verification_level: VerificationLevel,
    pub message: String,
}

/// Level of verification achieved
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationLevel {
    /// No attestation found
    None,

    /// Basic: Threshold signatures from witnesses (Phase 1)
    Basic,

    /// Batched: Included in merkle tree batch
    Batched,

    /// Federated: Cross-anchored by peer networks (Phase 2)
    Federated { peer_count: usize },
}

impl std::fmt::Display for VerificationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationLevel::None => write!(f, "None"),
            VerificationLevel::Basic => write!(f, "Basic (threshold signatures)"),
            VerificationLevel::Batched => write!(f, "Batched (merkle tree)"),
            VerificationLevel::Federated { peer_count } => {
                write!(f, "Federated ({} peer networks)", peer_count)
            }
        }
    }
}
