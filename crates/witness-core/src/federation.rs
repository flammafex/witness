use serde::{Deserialize, Serialize};

use crate::external_anchors::ExternalAnchorProof;
use crate::merkle::MerkleProof;
use crate::{NetworkConfig, Result, SignedAttestation, WitnessError};

/// A batch of attestations with their merkle root
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttestationBatch {
    /// Unique batch ID
    pub id: u64,

    /// Network that created this batch
    pub network_id: String,

    /// Merkle root of all attestations in this batch
    #[serde(with = "crate::serde_hex::array32")]
    #[schemars(with = "String")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub merkle_root: [u8; 32],

    /// Start of batch period (Unix seconds)
    pub period_start: u64,

    /// End of batch period (Unix seconds)
    pub period_end: u64,

    /// Number of attestations in this batch
    pub attestation_count: u64,
}

/// Cross-anchor attestation from a peer network.
///
/// The peer network signs an [`Attestation`](crate::Attestation) whose `hash`
/// is the cross-anchored batch's merkle root and whose `network_id` is the
/// peer's own network ID.  This makes the cross-anchor a self-contained,
/// independently verifiable threshold signature — clients can verify it
/// against the peer's published [`NetworkConfig`] without trusting the
/// originating gateway.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CrossAnchor {
    /// The batch being witnessed
    pub batch: AttestationBatch,

    /// ID of the network that witnessed this batch
    pub witnessing_network: String,

    /// Signed attestation from the peer network over `batch.merkle_root`
    pub witness_attestation: SignedAttestation,

    /// When this cross-anchor was created (Unix seconds)
    pub timestamp: u64,
}

/// Verify a cross-anchor against the peer network's configuration.
///
/// Checks that:
/// 1. The witness attestation's hash equals the batch's merkle root.
/// 2. The witness attestation's network_id matches `witnessing_network`.
/// 3. `peer_config.id` matches `witnessing_network`.
/// 4. The threshold signature verifies against `peer_config`.
///
/// Returns the number of verified signatures on success.
pub fn verify_cross_anchor(
    cross_anchor: &CrossAnchor,
    peer_config: &NetworkConfig,
) -> Result<usize> {
    let attestation = &cross_anchor.witness_attestation.attestation;

    if attestation.hash != cross_anchor.batch.merkle_root {
        return Err(WitnessError::InvalidSignature);
    }

    if attestation.network_id != cross_anchor.witnessing_network {
        return Err(WitnessError::InvalidSignature);
    }

    if peer_config.id != cross_anchor.witnessing_network {
        return Err(WitnessError::WitnessNotFound(
            cross_anchor.witnessing_network.clone(),
        ));
    }

    crate::verify_signed_attestation(&cross_anchor.witness_attestation, peer_config)
}

/// Configuration for federation
#[derive(Debug, Clone, Serialize, Deserialize, Default, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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

    /// Token that peers must present when calling our federation anchor endpoint
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub inbound_auth_token: Option<String>,

    /// Previous inbound auth token (accepted during rotation)
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub previous_inbound_auth_token: Option<String>,
}

fn default_batch_period() -> u64 {
    3600 // 1 hour
}

/// Information about a peer network
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PeerNetworkInfo {
    /// Peer network ID
    pub id: String,

    /// Gateway URL for this peer network
    pub gateway: String,

    /// Minimum number of witnesses required from this peer
    #[serde(default = "default_min_witnesses")]
    pub min_witnesses: usize,

    /// Bearer token to send when calling this peer's federation endpoint
    #[serde(default, skip_serializing)]
    #[schemars(skip)]
    pub auth_token: Option<String>,
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
    #[serde(with = "crate::serde_hex::array32")]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
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

/// Inclusion of an attestation in a batch's merkle tree.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct BatchInclusion {
    pub batch: AttestationBatch,
    pub merkle_proof: MerkleProof,
}

/// Self-contained bundle proving the full chain of trust for a hash.
///
/// All four layers are independently verifiable, so a client can confirm:
/// - **Threshold signature** — the home network's witnesses signed the attestation.
/// - **Batch inclusion** — the attestation was committed to a merkle root.
/// - **Cross-anchors** — peer networks signed that root.
/// - **External anchors** — the root was committed to external systems
///   (Internet Archive, Trillian, DNS, blockchain).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProofBundle {
    /// Threshold-signed attestation from the home network
    pub signed_attestation: SignedAttestation,

    /// Merkle inclusion proof, present once the attestation has been batched
    pub batch_inclusion: Option<BatchInclusion>,

    /// Cross-anchors from peer networks
    #[serde(default)]
    pub cross_anchors: Vec<CrossAnchor>,

    /// External anchor proofs (Internet Archive, Trillian, DNS, blockchain)
    #[serde(default)]
    pub external_anchors: Vec<ExternalAnchorProof>,
}

/// Configuration for verifying a [`ProofBundle`] offline.
#[derive(Debug, Clone, schemars::JsonSchema)]
pub struct ProofVerificationConfig {
    /// The home network's configuration (used to verify the threshold signature)
    pub network: NetworkConfig,
    /// Peer network configurations (used to verify cross-anchors).
    /// Cross-anchors from networks not present here are reported as unverified.
    pub peers: Vec<NetworkConfig>,
}

/// Result of verifying a [`ProofBundle`].
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProofBundleVerification {
    /// Number of valid signatures on the threshold-signed attestation
    pub verified_signatures: usize,
    /// Threshold required by the home network
    pub required_signatures: usize,
    /// Whether the merkle inclusion proof verified, if present
    pub batch_inclusion_verified: Option<bool>,
    /// Per-peer verification status: `(witnessing_network, verified)`
    pub cross_anchors_verified: Vec<(String, bool)>,
    /// Number of external anchor proofs included (not cryptographically verified here)
    pub external_anchors_present: usize,
    /// Highest level of verification achieved
    pub level: VerificationLevel,
}

/// Verify a [`ProofBundle`] offline against the supplied network configurations.
///
/// Returns an error only if the home network's threshold signature is invalid.
/// Other layers (batch inclusion, cross-anchors) are reported per-layer in the
/// result; callers decide what level they require.
pub fn verify_proof_bundle(
    bundle: &ProofBundle,
    config: &ProofVerificationConfig,
) -> Result<ProofBundleVerification> {
    let verified_signatures =
        crate::verify_signed_attestation(&bundle.signed_attestation, &config.network)?;

    let batch_inclusion_verified = bundle.batch_inclusion.as_ref().map(|inclusion| {
        let leaf = bundle.signed_attestation.attestation.hash;
        let proof = &inclusion.merkle_proof;
        proof.leaf == leaf
            && proof.root == inclusion.batch.merkle_root
            && crate::merkle::verify_inclusion(
                &leaf,
                proof.leaf_index,
                proof.tree_size,
                &proof.siblings,
                &proof.root,
            )
    });

    let cross_anchors_verified: Vec<(String, bool)> = bundle
        .cross_anchors
        .iter()
        .map(|ca| {
            let ok = config
                .peers
                .iter()
                .find(|p| p.id == ca.witnessing_network)
                .is_some_and(|peer| verify_cross_anchor(ca, peer).is_ok());
            (ca.witnessing_network.clone(), ok)
        })
        .collect();

    let verified_peer_count = cross_anchors_verified.iter().filter(|(_, ok)| *ok).count();

    let level = if verified_peer_count > 0 {
        VerificationLevel::Federated {
            peer_count: verified_peer_count,
        }
    } else if batch_inclusion_verified == Some(true) {
        VerificationLevel::Batched
    } else {
        VerificationLevel::Basic
    };

    Ok(ProofBundleVerification {
        verified_signatures,
        required_signatures: config.network.threshold,
        batch_inclusion_verified,
        cross_anchors_verified,
        external_anchors_present: bundle.external_anchors.len(),
        level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signature_scheme::AttestationSignatures, Attestation, MerkleTree, SignatureScheme,
        WitnessInfo, WitnessSignature,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn ed25519_network(id: &str) -> (NetworkConfig, SigningKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = hex::encode(signing_key.verifying_key().as_bytes());
        let cfg = NetworkConfig {
            id: id.to_string(),
            witnesses: vec![WitnessInfo {
                id: "w1".to_string(),
                pubkey,
                endpoint: "http://localhost".to_string(),
                auth_token: None,
            }],
            threshold: 1,
            signature_scheme: SignatureScheme::Ed25519,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };
        (cfg, signing_key)
    }

    fn sign_with(
        network: &NetworkConfig,
        key: &SigningKey,
        attestation: Attestation,
    ) -> SignedAttestation {
        let signature = key.sign(&attestation.to_bytes()).to_bytes().to_vec();
        SignedAttestation {
            attestation,
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![WitnessSignature {
                    witness_id: network.witnesses[0].id.clone(),
                    signature,
                }],
            },
        }
    }

    #[test]
    fn cross_anchor_verifies_with_correct_peer_config() {
        let (peer_cfg, peer_key) = ed25519_network("peer-net");

        let merkle_root = [7u8; 32];
        let attestation = Attestation::new(merkle_root, peer_cfg.id.clone(), 1);
        let signed = sign_with(&peer_cfg, &peer_key, attestation);

        let cross_anchor = CrossAnchor {
            batch: AttestationBatch {
                id: 1,
                network_id: "home".to_string(),
                merkle_root,
                period_start: 0,
                period_end: 100,
                attestation_count: 3,
            },
            witnessing_network: peer_cfg.id.clone(),
            witness_attestation: signed,
            timestamp: 1,
        };

        assert_eq!(verify_cross_anchor(&cross_anchor, &peer_cfg).unwrap(), 1);
    }

    #[test]
    fn cross_anchor_rejects_root_mismatch() {
        let (peer_cfg, peer_key) = ed25519_network("peer-net");

        // SignedAttestation has a different hash than batch.merkle_root
        let attestation = Attestation::new([1u8; 32], peer_cfg.id.clone(), 1);
        let signed = sign_with(&peer_cfg, &peer_key, attestation);

        let cross_anchor = CrossAnchor {
            batch: AttestationBatch {
                id: 1,
                network_id: "home".to_string(),
                merkle_root: [2u8; 32],
                period_start: 0,
                period_end: 100,
                attestation_count: 3,
            },
            witnessing_network: peer_cfg.id.clone(),
            witness_attestation: signed,
            timestamp: 1,
        };

        assert!(verify_cross_anchor(&cross_anchor, &peer_cfg).is_err());
    }

    #[test]
    fn cross_anchor_rejects_wrong_peer_config() {
        let (peer_cfg, peer_key) = ed25519_network("peer-net");
        let (other_cfg, _) = ed25519_network("other-net");

        let merkle_root = [9u8; 32];
        let attestation = Attestation::new(merkle_root, peer_cfg.id.clone(), 1);
        let signed = sign_with(&peer_cfg, &peer_key, attestation);

        let cross_anchor = CrossAnchor {
            batch: AttestationBatch {
                id: 1,
                network_id: "home".to_string(),
                merkle_root,
                period_start: 0,
                period_end: 100,
                attestation_count: 3,
            },
            witnessing_network: peer_cfg.id.clone(),
            witness_attestation: signed,
            timestamp: 1,
        };

        // Verifying against a different peer's config must fail
        assert!(verify_cross_anchor(&cross_anchor, &other_cfg).is_err());
    }

    #[test]
    fn proof_bundle_verifies_full_chain() {
        let (home_cfg, home_key) = ed25519_network("home-net");
        let (peer_cfg, peer_key) = ed25519_network("peer-net");

        // Home network signs the original hash
        let leaf_hash = [42u8; 32];
        let attestation = Attestation::new(leaf_hash, home_cfg.id.clone(), 1);
        let signed = sign_with(&home_cfg, &home_key, attestation);

        // Build a small merkle tree with the leaf
        let leaves = vec![leaf_hash, [1u8; 32], [2u8; 32], [3u8; 32]];
        let tree = MerkleTree::new(leaves);
        let merkle_root = tree.root();
        let proof = tree.inclusion_proof(0).unwrap();

        let batch = AttestationBatch {
            id: 1,
            network_id: home_cfg.id.clone(),
            merkle_root,
            period_start: 0,
            period_end: 100,
            attestation_count: 4,
        };

        // Peer cross-anchors the merkle root
        let peer_attestation = Attestation::new(merkle_root, peer_cfg.id.clone(), 1);
        let peer_signed = sign_with(&peer_cfg, &peer_key, peer_attestation);
        let cross_anchor = CrossAnchor {
            batch: batch.clone(),
            witnessing_network: peer_cfg.id.clone(),
            witness_attestation: peer_signed,
            timestamp: 1,
        };

        let bundle = ProofBundle {
            signed_attestation: signed,
            batch_inclusion: Some(BatchInclusion {
                batch,
                merkle_proof: proof,
            }),
            cross_anchors: vec![cross_anchor],
            external_anchors: vec![],
        };

        let cfg = ProofVerificationConfig {
            network: home_cfg,
            peers: vec![peer_cfg],
        };
        let result = verify_proof_bundle(&bundle, &cfg).unwrap();

        assert_eq!(result.verified_signatures, 1);
        assert_eq!(result.batch_inclusion_verified, Some(true));
        assert_eq!(result.cross_anchors_verified.len(), 1);
        assert!(result.cross_anchors_verified[0].1);
        assert!(matches!(
            result.level,
            VerificationLevel::Federated { peer_count: 1 }
        ));
    }
}
