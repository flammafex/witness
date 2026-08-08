//! `witness-core` — shared types and cryptographic primitives for the Witness
//! threshold-signing timestamping network.
//!
//! # Signature schemes
//!
//! Two schemes are supported, selected per-network via `SignatureScheme`:
//!
//! - **Ed25519** (`SignatureScheme::Ed25519`): each witness produces an
//!   independent signature stored in `AttestationSignatures::MultiSig`.
//!   Verification checks that at least `threshold` individual signatures are
//!   valid.
//!
//! - **BLS12-381** (`SignatureScheme::BLS`): individual BLS signatures are
//!   aggregated into a single compact signature stored in
//!   `AttestationSignatures::Aggregated`.  Verification uses the aggregated
//!   public key of the signing subset.

pub mod bls;
pub mod crypto;
pub mod error;
pub mod external_anchors;
pub mod federation;
pub mod log;
pub mod merkle;
pub mod serde_hex;
pub mod signature_scheme;
pub mod types;

// types
pub use types::{
    Attestation, AttestationEvent, FreebirdConfig, FreebirdToken, LogInclusionProofResponse,
    MerkleProofResponse, NetworkConfig, NetworkConfigPublic, NetworkVerificationConfig,
    NetworkVerificationWitness, SignRequest, SignResponse, SignedAttestation, TimestampRequest,
    TimestampResponse, VerificationWitnessInfo, VerifyRequest, VerifyResponse, WitnessInfo,
    WitnessSignature,
};

// crypto
#[cfg(feature = "keygen")]
pub use crypto::generate_keypair;
pub use crypto::{
    constant_time_eq, decode_public_key, encode_public_key, hash_content, sign_attestation,
    verify_signature, verify_signed_attestation,
};

// error
pub use error::{Result, WitnessError};

// merkle
pub use merkle::{MerkleProof, MerkleTree};

// log (RFC 9162 STH / consistency proofs)
pub use log::{
    verify_inclusion_against_sth, verify_log_consistency, verify_signed_tree_head,
    LogConsistencyProof, SignedTreeHead, TreeHead,
};

// federation
pub use federation::{
    verify_cross_anchor, verify_proof_bundle, AttestationBatch, BatchInclusion, CrossAnchor,
    CrossAnchorRequest, CrossAnchorResponse, FederatedAttestation, FederatedVerifyRequest,
    FederatedVerifyResponse, FederationConfig, FederationVerificationConfig, PeerNetworkInfo,
    PeerNetworkVerificationInfo, ProofBundle, ProofBundleVerification, ProofVerificationConfig,
    VerificationFederationConfig, VerificationLevel, VerificationPeerNetworkInfo,
};

// bls
#[cfg(feature = "keygen")]
pub use bls::generate_bls_keypair;
pub use bls::{
    aggregate_signatures_bls, decode_bls_public_key, decode_bls_secret_key, encode_bls_public_key,
    encode_bls_secret_key, sign_attestation_bls, verify_aggregated_signature_bls,
    verify_signature_bls,
};

// signature scheme
pub use signature_scheme::{AttestationSignatures, SignatureScheme};

// external anchors
pub use external_anchors::{
    AnchorProviderConfig, AnchorProviderType, AnchorRequest, AnchorResponse, AnchoredBatch,
    ExternalAnchorProof, ExternalAnchorsConfig,
};
