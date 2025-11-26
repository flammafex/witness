use serde::{Deserialize, Serialize};

/// Signature scheme used by the network
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SignatureScheme {
    /// Ed25519 signatures (Phase 1, multi-sig)
    Ed25519,

    /// BLS signatures (Phase 4, aggregated)
    #[serde(rename = "bls")]
    BLS,
}

impl Default for SignatureScheme {
    fn default() -> Self {
        SignatureScheme::Ed25519
    }
}

impl std::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureScheme::Ed25519 => write!(f, "ed25519"),
            SignatureScheme::BLS => write!(f, "bls"),
        }
    }
}

/// Signatures on an attestation (multi-sig or aggregated)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttestationSignatures {
    /// Ed25519 multi-signature (one signature per witness)
    MultiSig {
        signatures: Vec<crate::WitnessSignature>,
    },

    /// BLS aggregated signature (single signature from multiple witnesses)
    Aggregated {
        /// Aggregated BLS signature
        signature: Vec<u8>,

        /// List of witness IDs that participated
        signers: Vec<String>,
    },
}

impl AttestationSignatures {
    pub fn new_multisig() -> Self {
        AttestationSignatures::MultiSig {
            signatures: Vec::new(),
        }
    }

    pub fn new_aggregated(signature: Vec<u8>, signers: Vec<String>) -> Self {
        AttestationSignatures::Aggregated { signature, signers }
    }

    pub fn add_signature_multisig(&mut self, witness_id: String, signature: Vec<u8>) {
        if let AttestationSignatures::MultiSig { signatures } = self {
            signatures.push(crate::WitnessSignature {
                witness_id,
                signature,
            });
        }
    }

    pub fn signer_count(&self) -> usize {
        match self {
            AttestationSignatures::MultiSig { signatures } => signatures.len(),
            AttestationSignatures::Aggregated { signers, .. } => signers.len(),
        }
    }

    pub fn is_aggregated(&self) -> bool {
        matches!(self, AttestationSignatures::Aggregated { .. })
    }
}
