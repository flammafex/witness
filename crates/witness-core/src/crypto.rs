use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::{
    signature_scheme::AttestationSignatures, Attestation, NetworkConfig, Result,
    SignedAttestation, SignatureScheme, WitnessError,
};

/// Generate a new Ed25519 keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign an attestation
pub fn sign_attestation(attestation: &Attestation, signing_key: &SigningKey) -> Vec<u8> {
    let message = attestation.to_bytes();
    let signature = signing_key.sign(&message);
    signature.to_bytes().to_vec()
}

/// Verify a single signature on an attestation
pub fn verify_signature(
    attestation: &Attestation,
    signature: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<()> {
    let message = attestation.to_bytes();

    let sig = Signature::from_slice(signature)
        .map_err(|_| WitnessError::InvalidSignature)?;

    verifying_key
        .verify(&message, &sig)
        .map_err(|_| WitnessError::InvalidSignature)
}

/// Verify a complete signed attestation against network config
pub fn verify_signed_attestation(
    signed: &SignedAttestation,
    config: &NetworkConfig,
) -> Result<usize> {
    match (&signed.signatures, &config.signature_scheme) {
        // Ed25519 multi-sig verification
        (AttestationSignatures::MultiSig { signatures }, SignatureScheme::Ed25519) => {
            if signatures.is_empty() {
                return Err(WitnessError::InsufficientSignatures {
                    got: 0,
                    required: config.threshold,
                });
            }

            let mut verified_count = 0;

            for witness_sig in signatures {
                // Find witness in config
                let witness_info = config
                    .find_witness(&witness_sig.witness_id)
                    .ok_or_else(|| {
                        WitnessError::WitnessNotFound(witness_sig.witness_id.clone())
                    })?;

                // Decode public key
                let pubkey_bytes = hex::decode(&witness_info.pubkey)
                    .map_err(|e| WitnessError::InvalidPublicKey(e.to_string()))?;

                let verifying_key = VerifyingKey::from_bytes(
                    pubkey_bytes.as_slice().try_into().map_err(|_| {
                        WitnessError::InvalidPublicKey("Invalid key length".to_string())
                    })?,
                )
                .map_err(|e| WitnessError::InvalidPublicKey(e.to_string()))?;

                // Verify signature
                if verify_signature(&signed.attestation, &witness_sig.signature, &verifying_key)
                    .is_ok()
                {
                    verified_count += 1;
                }
            }

            if verified_count < config.threshold {
                return Err(WitnessError::InsufficientSignatures {
                    got: verified_count,
                    required: config.threshold,
                });
            }

            Ok(verified_count)
        }

        // BLS aggregated signature verification
        (AttestationSignatures::Aggregated { signature, signers }, SignatureScheme::BLS) => {
            if signers.is_empty() {
                return Err(WitnessError::InsufficientSignatures {
                    got: 0,
                    required: config.threshold,
                });
            }

            if signers.len() < config.threshold {
                return Err(WitnessError::InsufficientSignatures {
                    got: signers.len(),
                    required: config.threshold,
                });
            }

            // Collect public keys for all signers
            let mut public_keys = Vec::new();

            for signer_id in signers {
                let witness_info = config
                    .find_witness(signer_id)
                    .ok_or_else(|| WitnessError::WitnessNotFound(signer_id.clone()))?;

                let pubkey = crate::decode_bls_public_key(&witness_info.pubkey)?;
                public_keys.push(pubkey);
            }

            // Verify aggregated signature
            crate::verify_aggregated_signature_bls(
                &signed.attestation,
                signature,
                &public_keys,
            )?;

            Ok(signers.len())
        }

        // Mismatch between signature type and network configuration
        _ => Err(WitnessError::InvalidSignature),
    }
}

/// Hash content using SHA-256
pub fn hash_content(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Encode public key to hex
pub fn encode_public_key(key: &VerifyingKey) -> String {
    hex::encode(key.as_bytes())
}

/// Decode public key from hex
pub fn decode_public_key(hex_str: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WitnessError::InvalidPublicKey(e.to_string()))?;

    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| WitnessError::InvalidPublicKey("Invalid key length".to_string()))?;

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| WitnessError::InvalidPublicKey(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (signing_key, verifying_key) = generate_keypair();
        let attestation = Attestation::new([1; 32], "test-net".to_string(), 1);

        let signature = sign_attestation(&attestation, &signing_key);
        assert!(verify_signature(&attestation, &signature, &verifying_key).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let (_, verifying_key) = generate_keypair();
        let attestation = Attestation::new([1; 32], "test-net".to_string(), 1);
        let bad_signature = vec![0u8; 64];

        assert!(verify_signature(&attestation, &bad_signature, &verifying_key).is_err());
    }

    #[test]
    fn test_hash_content() {
        let data = b"hello world";
        let hash = hash_content(data);
        assert_eq!(hash.len(), 32);

        // Same content should produce same hash
        let hash2 = hash_content(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_public_key_encoding() {
        let (_, verifying_key) = generate_keypair();
        let encoded = encode_public_key(&verifying_key);
        let decoded = decode_public_key(&encoded).unwrap();
        assert_eq!(verifying_key, decoded);
    }
}
