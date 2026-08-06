//! `witness-client` — a typed client SDK for the Witness timestamping network.
//!
//! This crate covers the full attestation lifecycle (submit, poll, fetch
//! proofs/bundles/anchors), the transparency-log read surface, optional
//! WebSocket push events, and **local** verification.
//!
//! # Local verification is the default
//!
//! The plainly-named [`verify`], [`verify_proof_bundle`], [`verify_sth`],
//! [`verify_consistency`] and [`verify_log_inclusion`] functions run client-side
//! against `witness-core` semantics. They are thin wrappers over `witness-core`
//! — this crate never re-implements any cryptography. Talking to `POST /v1/verify`
//! is available only under the explicitly-labelled [`WitnessClient::verify_remote`]
//! ("the gateway's opinion"), which is **non-authoritative**.
//!
//! # Trust anchors are caller-controlled
//!
//! Verification functions accept a caller-supplied [`NetworkConfig`] (and peer
//! configs). Fetching configs from gateways is a trust-on-first-use (TOFU)
//! convenience ([`WitnessClient::network`] / [`WitnessClient::network_from`]),
//! never a silent default inside a `verify` call. Prefer pinning a
//! `network.json`-derived config.
//!
//! # Pre-1.0 disclaimer
//!
//! This project is pre-1.0 and unaudited, and is not Byzantine-fault-tolerant.
//! Publishing this SDK does **not** constitute a security audit.

mod client;
mod error;
mod verify;
#[cfg(feature = "ws")]
mod ws;

pub use client::{PollConfig, WitnessClient, WitnessClientBuilder};
pub use error::{Error, Result};
pub use verify::{
    verify, verify_consistency, verify_log_inclusion, verify_proof_bundle, verify_sth,
};

// Re-export the wire types used across the public surface for convenience.
pub use witness_core::types::{AttestationJobResponse, AttestationJobStatus};
pub use witness_core::{
    Attestation, AttestationEvent, ExternalAnchorProof, FreebirdToken, LogConsistencyProof,
    LogInclusionProofResponse, MerkleProofResponse, NetworkConfig, NetworkConfigPublic,
    ProofBundle, ProofBundleVerification, ProofVerificationConfig, SignedAttestation,
    SignedTreeHead, VerifyResponse,
};
