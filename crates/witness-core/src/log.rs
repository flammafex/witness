//! RFC 9162 Signed Tree Head and consistency-proof verification.
//!
//! A [`TreeHead`] is the witness log's commitment at a given size: the root
//! hash, the tree size (number of leaves), and a timestamp.  Witnesses
//! threshold-sign a digest of these fields so anyone — including
//! third-party auditors — can confirm that the operator did publish this
//! state.
//!
//! Auditors monitor a log by fetching successive [`SignedTreeHead`]s and
//! verifying [`LogConsistencyProof`]s between them.  A valid chain of
//! consistency proofs from `STH_old` to `STH_new` proves the operator did
//! not rewrite history: the first `tree_size_old` entries of the new tree
//! are byte-identical to the old tree.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::merkle::{verify_consistency, verify_inclusion};
use crate::{
    Attestation, NetworkConfig, Result, SignedAttestation, WitnessError,
};

/// Domain separator for the STH-signing digest.  Bumping the suffix is a
/// hard fork of the log signature scheme.
const STH_DOMAIN: &[u8] = b"witness-sth-v1\x00";

/// Plaintext fields of a tree head.  The signing digest commits to all of
/// these so a verifier given a [`SignedTreeHead`] can recompute it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeHead {
    /// Network this STH belongs to.
    pub network_id: String,
    /// Number of leaves in the log.
    pub tree_size: u64,
    /// When this STH was issued (Unix seconds).
    pub timestamp: u64,
    /// Merkle root of the log at `tree_size`.
    pub root_hash: [u8; 32],
}

impl TreeHead {
    /// Build the digest signed by witnesses.  Length-prefixes the network
    /// ID so two networks with confusable names can't produce colliding
    /// signatures.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(STH_DOMAIN);
        h.update((self.network_id.len() as u32).to_le_bytes());
        h.update(self.network_id.as_bytes());
        h.update(self.tree_size.to_le_bytes());
        h.update(self.timestamp.to_le_bytes());
        h.update(self.root_hash);
        h.finalize().into()
    }

    /// Construct the synthetic [`Attestation`] that witnesses sign.
    /// `hash` is the STH digest, `sequence` is the tree size, `network_id`
    /// matches the home network.  This lets us reuse the existing per-witness
    /// `/v1/sign` endpoint without adding a parallel signing flow.
    pub fn to_attestation(&self) -> Attestation {
        Attestation {
            hash: self.signing_digest(),
            timestamp: self.timestamp,
            network_id: self.network_id.clone(),
            sequence: self.tree_size,
        }
    }
}

/// A [`TreeHead`] together with witness threshold signatures over its
/// digest.  The same `AttestationSignatures` machinery used for individual
/// timestamps is reused; verification piggybacks on
/// [`crate::verify_signed_attestation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub tree_head: TreeHead,
    pub signed_attestation: SignedAttestation,
}

impl SignedTreeHead {
    pub fn root_hash(&self) -> &[u8; 32] {
        &self.tree_head.root_hash
    }

    pub fn tree_size(&self) -> u64 {
        self.tree_head.tree_size
    }
}

/// Verify a [`SignedTreeHead`] against the issuing network's configuration.
///
/// Returns the number of valid signatures, or an error if any of the
/// structural checks fail or the threshold isn't met.
pub fn verify_signed_tree_head(sth: &SignedTreeHead, config: &NetworkConfig) -> Result<usize> {
    if sth.tree_head.network_id != config.id {
        return Err(WitnessError::WitnessNotFound(format!(
            "STH network_id {} != config.id {}",
            sth.tree_head.network_id, config.id
        )));
    }

    let expected = sth.tree_head.to_attestation();
    if sth.signed_attestation.attestation != expected {
        return Err(WitnessError::InvalidSignature);
    }

    crate::verify_signed_attestation(&sth.signed_attestation, config)
}

/// Consistency proof linking two signed tree heads of the same log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConsistencyProof {
    pub old_sth: SignedTreeHead,
    pub new_sth: SignedTreeHead,
    /// Hashes from RFC 9162 §2.1.4.1 PROOF.
    #[serde(with = "crate::merkle::hex_bytes_vec")]
    pub hashes: Vec<[u8; 32]>,
}

/// Verify that `proof.new_sth` is a consistent extension of `proof.old_sth`.
///
/// Both STHs are checked individually against `config`, then RFC 9162
/// §2.1.4.2 consistency-proof verification is applied to the two roots.
pub fn verify_log_consistency(proof: &LogConsistencyProof, config: &NetworkConfig) -> Result<()> {
    verify_signed_tree_head(&proof.old_sth, config)?;
    verify_signed_tree_head(&proof.new_sth, config)?;

    let ok = verify_consistency(
        proof.old_sth.tree_size(),
        proof.new_sth.tree_size(),
        proof.old_sth.root_hash(),
        proof.new_sth.root_hash(),
        &proof.hashes,
    );
    if !ok {
        return Err(WitnessError::InvalidSignature);
    }
    Ok(())
}

/// Verify an inclusion proof against an STH (rather than a free-standing
/// root).  The leaf is `attestation_hash`, expected at position `leaf_index`
/// in the log of size `sth.tree_size`.
pub fn verify_inclusion_against_sth(
    sth: &SignedTreeHead,
    leaf_index: u64,
    attestation_hash: &[u8; 32],
    audit_path: &[[u8; 32]],
) -> bool {
    verify_inclusion(
        attestation_hash,
        leaf_index,
        sth.tree_size(),
        audit_path,
        sth.root_hash(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{consistency_path, hash_leaf, inclusion_path, merkle_tree_hash};
    use crate::signature_scheme::{AttestationSignatures, SignatureScheme};
    use crate::WitnessInfo;
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

    fn sign_sth(network: &NetworkConfig, key: &SigningKey, head: TreeHead) -> SignedTreeHead {
        let attestation = head.to_attestation();
        let signature = key.sign(&attestation.to_bytes()).to_bytes().to_vec();
        let signed_attestation = SignedAttestation {
            attestation,
            signatures: AttestationSignatures::MultiSig {
                signatures: vec![crate::WitnessSignature {
                    witness_id: network.witnesses[0].id.clone(),
                    signature,
                }],
            },
        };
        SignedTreeHead {
            tree_head: head,
            signed_attestation,
        }
    }

    fn make_head(network: &NetworkConfig, leaves: &[[u8; 32]], timestamp: u64) -> TreeHead {
        TreeHead {
            network_id: network.id.clone(),
            tree_size: leaves.len() as u64,
            timestamp,
            root_hash: merkle_tree_hash(leaves),
        }
    }

    #[test]
    fn signed_tree_head_verifies_against_network() {
        let (cfg, key) = ed25519_network("net-a");
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let head = make_head(&cfg, &leaves, 1000);

        let sth = sign_sth(&cfg, &key, head);
        let count = verify_signed_tree_head(&sth, &cfg).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn sth_with_wrong_network_id_rejected() {
        let (cfg_a, key_a) = ed25519_network("net-a");
        let (cfg_b, _) = ed25519_network("net-b");
        let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let head = make_head(&cfg_a, &leaves, 100);
        let sth = sign_sth(&cfg_a, &key_a, head);

        assert!(verify_signed_tree_head(&sth, &cfg_b).is_err());
    }

    #[test]
    fn sth_with_tampered_root_rejected() {
        let (cfg, key) = ed25519_network("net-a");
        let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let head = make_head(&cfg, &leaves, 100);
        let mut sth = sign_sth(&cfg, &key, head);
        sth.tree_head.root_hash = [0xFFu8; 32];

        assert!(verify_signed_tree_head(&sth, &cfg).is_err());
    }

    #[test]
    fn log_consistency_proof_verifies() {
        let (cfg, key) = ed25519_network("net-a");
        let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| [i; 32]).collect();

        let old_head = make_head(&cfg, &leaves[..3], 100);
        let new_head = make_head(&cfg, &leaves, 200);

        let old_sth = sign_sth(&cfg, &key, old_head);
        let new_sth = sign_sth(&cfg, &key, new_head);

        let hashes = consistency_path(3, &leaves).unwrap();
        let proof = LogConsistencyProof {
            old_sth,
            new_sth,
            hashes,
        };

        verify_log_consistency(&proof, &cfg).unwrap();
    }

    #[test]
    fn log_consistency_proof_rejects_tampered_extension() {
        let (cfg, key) = ed25519_network("net-a");
        let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| [i; 32]).collect();
        let mut tampered_leaves = leaves.clone();
        tampered_leaves[1] = [99u8; 32]; // rewrite history at index 1

        let old_head = make_head(&cfg, &leaves[..3], 100);
        let tampered_new_head = make_head(&cfg, &tampered_leaves, 200);

        let old_sth = sign_sth(&cfg, &key, old_head);
        let new_sth = sign_sth(&cfg, &key, tampered_new_head);

        // Even if the operator generates a "consistency proof" against the
        // tampered tree, the old root no longer reconstructs from it.
        let hashes = consistency_path(3, &tampered_leaves).unwrap();
        let proof = LogConsistencyProof {
            old_sth,
            new_sth,
            hashes,
        };

        assert!(verify_log_consistency(&proof, &cfg).is_err());
    }

    #[test]
    fn inclusion_against_sth_verifies() {
        let (cfg, key) = ed25519_network("net-a");
        let leaves: Vec<[u8; 32]> = (0u8..6).map(|i| [i; 32]).collect();
        let head = make_head(&cfg, &leaves, 500);
        let sth = sign_sth(&cfg, &key, head);

        let path = inclusion_path(2, &leaves).unwrap();
        assert!(verify_inclusion_against_sth(&sth, 2, &leaves[2], &path));

        // Wrong leaf rejected.
        assert!(!verify_inclusion_against_sth(&sth, 2, &[42u8; 32], &path));

        // Hashed leaf passed where raw leaf expected: rejected.
        let hashed = hash_leaf(&leaves[2]);
        assert!(!verify_inclusion_against_sth(&sth, 2, &hashed, &path));
    }

    /// `LogConsistencyProof.hashes` uses a custom serde adapter
    /// (`crate::merkle::hex_bytes_vec`) — a regression here would silently
    /// break the over-the-wire format, so round-trip the whole proof through
    /// JSON and verify the result is still cryptographically valid.
    #[test]
    fn consistency_proof_round_trips_through_json() {
        let (cfg, key) = ed25519_network("net-a");
        let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| [i; 32]).collect();

        let old_head = make_head(&cfg, &leaves[..3], 100);
        let new_head = make_head(&cfg, &leaves, 200);
        let old_sth = sign_sth(&cfg, &key, old_head);
        let new_sth = sign_sth(&cfg, &key, new_head);
        let hashes = consistency_path(3, &leaves).unwrap();
        let proof = LogConsistencyProof {
            old_sth,
            new_sth,
            hashes,
        };

        let json = serde_json::to_string(&proof).unwrap();
        let restored: LogConsistencyProof = serde_json::from_str(&json).unwrap();
        verify_log_consistency(&restored, &cfg).unwrap();
    }
}
