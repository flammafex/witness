//! Local verification — the default, trust-minimizing path.
//!
//! These are thin wrappers over `witness-core`; `witness-client` never
//! re-implements any cryptography. Verification functions only take configs as
//! parameters — fetching configs from a gateway is the caller's explicit TOFU
//! choice, never a silent default here.

use witness_core::{
    LogConsistencyProof, LogInclusionProofResponse, NetworkConfig, ProofBundle,
    ProofBundleVerification, ProofVerificationConfig, SignedAttestation, SignedTreeHead,
    WitnessError,
};

use crate::error::{Error, Result};

/// Verify a threshold-signed attestation against a network config.
///
/// Returns the number of valid signatures, or an error if the threshold isn't
/// met or any structural check fails.
pub fn verify(signed: &SignedAttestation, config: &NetworkConfig) -> Result<usize> {
    witness_core::verify_signed_attestation(signed, config).map_err(Error::Verification)
}

/// Verify a self-contained [`ProofBundle`] offline against the supplied
/// network configurations.
///
/// Returns an error only if the home network's threshold signature is invalid;
/// other layers (batch inclusion, cross-anchors) are reported per-layer in the
/// result.
pub fn verify_proof_bundle(
    bundle: &ProofBundle,
    config: &ProofVerificationConfig,
) -> Result<ProofBundleVerification> {
    witness_core::verify_proof_bundle(bundle, config).map_err(Error::Verification)
}

/// Verify a signed tree head against the issuing network's configuration.
///
/// Returns the number of valid signatures.
pub fn verify_sth(sth: &SignedTreeHead, config: &NetworkConfig) -> Result<usize> {
    witness_core::verify_signed_tree_head(sth, config).map_err(Error::Verification)
}

/// Verify that `proof.new_sth` is a consistent extension of `proof.old_sth`.
pub fn verify_consistency(proof: &LogConsistencyProof, config: &NetworkConfig) -> Result<()> {
    witness_core::verify_log_consistency(proof, config).map_err(Error::Verification)
}

/// Verify an RFC 9162 inclusion proof against the STH carried in the response.
///
/// The proof's `tree_size` must match the STH's `tree_size` (position-awareness,
/// §3.6). The audit path is then checked against the STH's committed root.
///
/// Note: this verifies the inclusion proof against the STH's root. Verifying the
/// STH's threshold signature requires a `NetworkConfig` and is done separately
/// via [`verify_sth`].
pub fn verify_log_inclusion(proof: &LogInclusionProofResponse, leaf: [u8; 32]) -> Result<()> {
    if proof.tree_size != proof.sth.tree_head.tree_size {
        return Err(Error::Verification(WitnessError::InvalidSignature));
    }
    let audit_path = proof
        .audit_path
        .iter()
        .map(|h| {
            let b =
                hex::decode(h).map_err(|_| Error::Verification(WitnessError::InvalidSignature))?;
            b.try_into()
                .map_err(|_| Error::Verification(WitnessError::InvalidSignature))
        })
        .collect::<Result<Vec<[u8; 32]>>>()?;
    let ok = witness_core::verify_inclusion_against_sth(
        &proof.sth,
        proof.leaf_index,
        &leaf,
        &audit_path,
    );
    if !ok {
        return Err(Error::Verification(WitnessError::InvalidSignature));
    }
    Ok(())
}
