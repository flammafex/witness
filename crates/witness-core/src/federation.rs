use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use url::Url;

use crate::external_anchors::ExternalAnchorProof;
use crate::merkle::MerkleProof;
use crate::{NetworkVerificationConfig, Result, SignedAttestation, WitnessError};

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
/// against the peer's published [`NetworkVerificationConfig`] without trusting the
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
    peer_config: &NetworkVerificationConfig,
) -> Result<usize> {
    peer_config.validate()?;
    let attestation = &cross_anchor.witness_attestation.attestation;

    if attestation.hash != cross_anchor.batch.merkle_root {
        return Err(WitnessError::InvalidSignature);
    }

    if attestation.network_id != cross_anchor.witnessing_network {
        return Err(WitnessError::NetworkIdMismatch {
            expected: cross_anchor.witnessing_network.clone(),
            actual: attestation.network_id.clone(),
        });
    }

    if peer_config.id != cross_anchor.witnessing_network {
        return Err(WitnessError::NetworkIdMismatch {
            expected: cross_anchor.witnessing_network.clone(),
            actual: peer_config.id.clone(),
        });
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

/// Public federation discovery and policy fields used by verifiers.
///
/// This is deliberately separate from [`FederationConfig`]: it contains no
/// batch scheduling state or inbound authentication material.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FederationVerificationConfig {
    /// Whether cross-anchoring is enabled for this network.
    #[serde(default)]
    pub enabled: bool,

    /// Public gateway discovery information for configured peers.
    #[serde(default)]
    pub peer_networks: Vec<PeerNetworkVerificationInfo>,

    /// Number of distinct configured peers required for a federated result.
    #[serde(default)]
    pub cross_anchor_threshold: usize,
}

/// Public discovery and verification policy for one federation peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PeerNetworkVerificationInfo {
    /// Peer network ID.
    pub id: String,

    /// Public gateway URL used to discover the peer's verification config.
    pub gateway: String,

    /// Minimum number of signatures required from this peer network.
    #[serde(default = "default_min_witnesses")]
    pub min_witnesses: usize,
}

/// Compatibility alias for callers that prefer the `Verification*` naming
/// convention for public federation DTOs.
pub type VerificationFederationConfig = FederationVerificationConfig;

/// Compatibility alias for callers that prefer the `Verification*` naming
/// convention for public peer DTOs.
pub type VerificationPeerNetworkInfo = PeerNetworkVerificationInfo;

impl FederationVerificationConfig {
    pub(crate) fn validate(&self, home_id: &str) -> Result<()> {
        let mut ids = HashSet::new();
        for peer in &self.peer_networks {
            if peer.id.trim().is_empty() {
                return Err(WitnessError::InvalidVerificationConfig(
                    "peer network id must be nonempty".to_string(),
                ));
            }
            if peer.id == home_id {
                return Err(WitnessError::InvalidVerificationConfig(format!(
                    "peer network '{}' must be distinct from home network",
                    peer.id
                )));
            }
            if !ids.insert(peer.id.clone()) {
                return Err(WitnessError::InvalidVerificationConfig(format!(
                    "duplicate peer network id '{}'",
                    peer.id
                )));
            }
            if peer.min_witnesses == 0 {
                return Err(WitnessError::InvalidVerificationConfig(format!(
                    "peer '{}' min_witnesses must be at least 1",
                    peer.id
                )));
            }
            validate_peer_gateway_url(&peer.gateway)?;
        }

        if self.cross_anchor_threshold > self.peer_networks.len() {
            return Err(WitnessError::InvalidVerificationConfig(format!(
                "cross_anchor_threshold {} exceeds {} configured peers",
                self.cross_anchor_threshold,
                self.peer_networks.len()
            )));
        }
        if self.enabled && self.cross_anchor_threshold == 0 {
            return Err(WitnessError::InvalidVerificationConfig(
                "enabled federation requires a nonzero cross_anchor_threshold".to_string(),
            ));
        }
        Ok(())
    }
}

/// Validate a public peer-discovery URL without performing network access.
/// HTTPS is required except for explicit loopback HTTP development URLs.
pub(crate) fn validate_peer_gateway_url(value: &str) -> Result<()> {
    let url = Url::parse(value).map_err(|error| {
        WitnessError::InvalidVerificationConfig(format!("invalid peer gateway URL: {error}"))
    })?;

    if url.username() != "" || url.password().is_some() {
        return Err(WitnessError::InvalidVerificationConfig(
            "peer gateway URL must not contain credentials".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(WitnessError::InvalidVerificationConfig(
            "peer gateway URL must not contain a query or fragment".to_string(),
        ));
    }

    match url.scheme() {
        "https" => {}
        "http" if url.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(WitnessError::InvalidVerificationConfig(
                "peer gateway URL must use HTTPS or explicit loopback HTTP for development"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    let normalized = host.trim_start_matches('[').trim_end_matches(']');
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
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
    pub network: NetworkVerificationConfig,
    /// Peer network configurations (used to verify cross-anchors).
    /// Cross-anchors from networks not present here are reported as unverified.
    pub peers: Vec<NetworkVerificationConfig>,
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
/// Returns an error for an invalid home or supplied peer trust configuration,
/// or if the home threshold signature is invalid. Optional proof layers are
/// reported per-layer and downgrade the result when invalid.
pub fn verify_proof_bundle(
    bundle: &ProofBundle,
    config: &ProofVerificationConfig,
) -> Result<ProofBundleVerification> {
    config.network.validate()?;
    let mut peer_ids = HashSet::new();
    for peer in &config.peers {
        peer.validate()?;
        if peer.id == config.network.id || !peer_ids.insert(peer.id.clone()) {
            return Err(WitnessError::InvalidVerificationConfig(format!(
                "peer trust configurations must have unique IDs distinct from home network: {}",
                peer.id
            )));
        }
    }

    let verified_signatures =
        crate::verify_signed_attestation(&bundle.signed_attestation, &config.network)?;

    let batch_inclusion_verified = bundle.batch_inclusion.as_ref().map(|inclusion| {
        let leaf = bundle.signed_attestation.attestation.hash;
        let proof = &inclusion.merkle_proof;
        inclusion.batch.network_id == config.network.id
            && proof.leaf_index < inclusion.batch.attestation_count
            && proof.tree_size == inclusion.batch.attestation_count
            && proof.leaf == leaf
            && proof.root == inclusion.batch.merkle_root
            && crate::merkle::verify_inclusion(
                &leaf,
                proof.leaf_index,
                proof.tree_size,
                &proof.siblings,
                &proof.root,
            )
    });

    let home_batch = config.network.id.as_str();
    let mut verified_peer_ids = HashSet::new();
    let cross_anchors_verified: Vec<(String, bool)> = bundle
        .cross_anchors
        .iter()
        .map(|ca| {
            let already_verified = verified_peer_ids.contains(&ca.witnessing_network);
            let batch_linked = batch_inclusion_verified == Some(true)
                && ca.batch.network_id == home_batch
                && bundle.batch_inclusion.as_ref().is_some_and(|inclusion| {
                    ca.batch.merkle_root == inclusion.batch.merkle_root
                        && ca.batch.network_id == inclusion.batch.network_id
                        && ca.batch.id == inclusion.batch.id
                });
            let ok = !already_verified
                && batch_linked
                && config
                    .network
                    .federation
                    .peer_networks
                    .iter()
                    .find(|policy| policy.id == ca.witnessing_network)
                    .and_then(|policy| {
                        config
                            .peers
                            .iter()
                            .find(|peer| peer.id == policy.id)
                            .map(|peer| {
                                policy.min_witnesses <= peer.witnesses.len()
                                    && verify_cross_anchor(ca, peer)
                                        .is_ok_and(|count| count >= policy.min_witnesses)
                            })
                    })
                    .unwrap_or(false);
            if ok {
                verified_peer_ids.insert(ca.witnessing_network.clone());
            }
            (ca.witnessing_network.clone(), ok)
        })
        .collect();

    let verified_peer_count = verified_peer_ids.len();
    let federation_threshold_met = config.network.federation.enabled
        && batch_inclusion_verified == Some(true)
        && verified_peer_count >= config.network.federation.cross_anchor_threshold;

    let level = if federation_threshold_met {
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
        signature_scheme::AttestationSignatures, Attestation, MerkleTree, NetworkConfig,
        PeerNetworkInfo, SignatureScheme, WitnessInfo, WitnessSignature,
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

        assert_eq!(
            verify_cross_anchor(&cross_anchor, &peer_cfg.verification_config().unwrap()).unwrap(),
            1
        );
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

        assert!(
            verify_cross_anchor(&cross_anchor, &peer_cfg.verification_config().unwrap()).is_err()
        );
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
        assert!(
            verify_cross_anchor(&cross_anchor, &other_cfg.verification_config().unwrap()).is_err()
        );
    }

    #[test]
    fn proof_bundle_verifies_full_chain() {
        let (mut home_cfg, home_key) = ed25519_network("home-net");
        let (peer_cfg, peer_key) = ed25519_network("peer-net");

        home_cfg.federation = FederationConfig {
            enabled: true,
            peer_networks: vec![PeerNetworkInfo {
                id: peer_cfg.id.clone(),
                gateway: "https://peer.example".to_string(),
                min_witnesses: 1,
                auth_token: None,
            }],
            cross_anchor_threshold: 1,
            ..Default::default()
        };

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
            network: home_cfg.verification_config().unwrap(),
            peers: vec![peer_cfg.verification_config().unwrap()],
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

        let valid_anchor = bundle.cross_anchors[0].clone();
        let mut invalid_anchor = valid_anchor.clone();
        invalid_anchor.batch.merkle_root = [0xFF; 32];

        let mut invalid_first = bundle.clone();
        invalid_first.cross_anchors = vec![invalid_anchor.clone(), valid_anchor.clone()];
        let invalid_first_result = verify_proof_bundle(&invalid_first, &cfg).unwrap();

        let mut valid_first = bundle.clone();
        valid_first.cross_anchors = vec![valid_anchor, invalid_anchor];
        let valid_first_result = verify_proof_bundle(&valid_first, &cfg).unwrap();

        assert_eq!(invalid_first_result.level, valid_first_result.level);
        let peer_count = |level: &VerificationLevel| match level {
            VerificationLevel::Federated { peer_count } => *peer_count,
            _ => 0,
        };
        assert_eq!(
            peer_count(&invalid_first_result.level),
            peer_count(&valid_first_result.level)
        );
        assert_eq!(peer_count(&invalid_first_result.level), 1);
        assert!(matches!(
            invalid_first_result.level,
            VerificationLevel::Federated { peer_count: 1 }
        ));
        assert_eq!(
            invalid_first_result.cross_anchors_verified,
            vec![
                ("peer-net".to_string(), false),
                ("peer-net".to_string(), true)
            ]
        );
        assert_eq!(
            valid_first_result.cross_anchors_verified,
            vec![
                ("peer-net".to_string(), true),
                ("peer-net".to_string(), false)
            ]
        );

        // Optional federation evidence must never manufacture a federated
        // result when its home batch/root/source linkage is absent or wrong.
        let mut missing_batch = bundle.clone();
        missing_batch.batch_inclusion = None;
        let missing = verify_proof_bundle(&missing_batch, &cfg).unwrap();
        assert_eq!(missing.level, VerificationLevel::Basic);
        assert!(!missing.cross_anchors_verified[0].1);

        let mut wrong_root = bundle.clone();
        wrong_root.cross_anchors[0].batch.merkle_root = [0xFF; 32];
        let wrong_root_result = verify_proof_bundle(&wrong_root, &cfg).unwrap();
        assert_eq!(wrong_root_result.level, VerificationLevel::Batched);
        assert!(!wrong_root_result.cross_anchors_verified[0].1);

        let mut wrong_network = bundle.clone();
        wrong_network.cross_anchors[0].batch.network_id = "unrelated".to_string();
        let wrong_network_result = verify_proof_bundle(&wrong_network, &cfg).unwrap();
        assert_eq!(wrong_network_result.level, VerificationLevel::Batched);
        assert!(!wrong_network_result.cross_anchors_verified[0].1);

        let mut duplicate = bundle.clone();
        duplicate
            .cross_anchors
            .push(duplicate.cross_anchors[0].clone());
        let duplicate_result = verify_proof_bundle(&duplicate, &cfg).unwrap();
        assert_eq!(
            duplicate_result.cross_anchors_verified,
            vec![
                ("peer-net".to_string(), true),
                ("peer-net".to_string(), false)
            ]
        );
        assert!(matches!(
            duplicate_result.level,
            VerificationLevel::Federated { peer_count: 1 }
        ));

        let mut below_threshold = cfg.clone();
        below_threshold.network.federation.peer_networks[0].min_witnesses = 2;
        let below_result = verify_proof_bundle(&bundle, &below_threshold).unwrap();
        assert_eq!(below_result.level, VerificationLevel::Batched);
        assert!(!below_result.cross_anchors_verified[0].1);
    }
}
