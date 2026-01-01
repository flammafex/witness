use blst::min_sig::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::RngCore;

use crate::{Attestation, Result, WitnessError};

const DST: &[u8] = b"WITNESS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_";

/// Generate a new BLS keypair
pub fn generate_bls_keypair() -> (SecretKey, PublicKey) {
    let mut ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ikm);

    let secret_key = SecretKey::key_gen(&ikm, &[]).unwrap();
    let public_key = secret_key.sk_to_pk();

    (secret_key, public_key)
}

/// Sign an attestation using BLS
pub fn sign_attestation_bls(attestation: &Attestation, secret_key: &SecretKey) -> Vec<u8> {
    let message = attestation.to_bytes();
    let signature = secret_key.sign(&message, DST, &[]);
    signature.to_bytes().to_vec()
}

/// Verify a BLS signature on an attestation
pub fn verify_signature_bls(
    attestation: &Attestation,
    signature_bytes: &[u8],
    public_key: &PublicKey,
) -> Result<()> {
    let message = attestation.to_bytes();

    // Parse signature
    let signature = Signature::from_bytes(signature_bytes)
        .map_err(|_| WitnessError::InvalidSignature)?;

    // Verify
    let result = signature.verify(true, &message, DST, &[], public_key, true);

    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(WitnessError::InvalidSignature)
    }
}

/// Aggregate multiple BLS signatures
pub fn aggregate_signatures_bls(signature_bytes_list: &[Vec<u8>]) -> Result<Vec<u8>> {
    if signature_bytes_list.is_empty() {
        return Err(WitnessError::InsufficientSignatures {
            got: 0,
            required: 1,
        });
    }

    // Parse first signature
    let first_sig = Signature::from_bytes(&signature_bytes_list[0])
        .map_err(|_| WitnessError::InvalidSignature)?;

    let mut agg_sig = AggregateSignature::from_signature(&first_sig);

    // Aggregate remaining signatures
    for sig_bytes in &signature_bytes_list[1..] {
        let sig = Signature::from_bytes(sig_bytes)
            .map_err(|_| WitnessError::InvalidSignature)?;

        agg_sig.add_signature(&sig, true)
            .map_err(|_| WitnessError::InvalidSignature)?;
    }

    Ok(agg_sig.to_signature().to_bytes().to_vec())
}

/// Verify an aggregated BLS signature
pub fn verify_aggregated_signature_bls(
    attestation: &Attestation,
    aggregated_signature: &[u8],
    public_keys: &[PublicKey],
) -> Result<()> {
    if public_keys.is_empty() {
        return Err(WitnessError::InsufficientSignatures {
            got: 0,
            required: 1,
        });
    }

    let message = attestation.to_bytes();

    // Parse aggregated signature
    let signature = Signature::from_bytes(aggregated_signature)
        .map_err(|_| WitnessError::InvalidSignature)?;

    // Create aggregated public key
    let mut agg_pubkey = blst::min_sig::AggregatePublicKey::from_public_key(&public_keys[0]);

    // Add remaining public keys (starting from index 1, not 0)
    for pk in &public_keys[1..] {
        agg_pubkey.add_public_key(pk, true)
            .map_err(|_| WitnessError::InvalidPublicKey("Failed to aggregate public keys".to_string()))?;
    }

    // Verify
    let result = signature.verify(
        true,
        &message,
        DST,
        &[],
        &agg_pubkey.to_public_key(),
        true,
    );

    if result == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(WitnessError::InvalidSignature)
    }
}

/// Encode BLS public key to hex
pub fn encode_bls_public_key(key: &PublicKey) -> String {
    hex::encode(key.to_bytes())
}

/// Decode BLS public key from hex
pub fn decode_bls_public_key(hex_str: &str) -> Result<PublicKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WitnessError::InvalidPublicKey(e.to_string()))?;

    PublicKey::from_bytes(&bytes)
        .map_err(|_| WitnessError::InvalidPublicKey("Invalid BLS public key".to_string()))
}

/// Encode BLS secret key to hex
pub fn encode_bls_secret_key(key: &SecretKey) -> String {
    hex::encode(key.to_bytes())
}

/// Decode BLS secret key from hex
pub fn decode_bls_secret_key(hex_str: &str) -> Result<SecretKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WitnessError::InvalidPublicKey(e.to_string()))?;

    SecretKey::from_bytes(&bytes)
        .map_err(|_| WitnessError::InvalidPublicKey("Invalid BLS secret key".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_sign_and_verify() {
        let (secret_key, public_key) = generate_bls_keypair();
        let attestation = Attestation::new([1; 32], "test-net".to_string(), 1);

        let signature = sign_attestation_bls(&attestation, &secret_key);
        assert!(verify_signature_bls(&attestation, &signature, &public_key).is_ok());
    }

    #[test]
    fn test_bls_invalid_signature() {
        let (_, public_key) = generate_bls_keypair();
        let attestation = Attestation::new([1; 32], "test-net".to_string(), 1);
        let bad_signature = vec![0u8; 96];

        assert!(verify_signature_bls(&attestation, &bad_signature, &public_key).is_err());
    }

    #[test]
    fn test_bls_signature_aggregation() {
        let attestation = Attestation::new([1; 32], "test-net".to_string(), 1);

        // Generate 3 keypairs
        let keys: Vec<_> = (0..3).map(|_| generate_bls_keypair()).collect();

        // Sign with each key
        let signatures: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_attestation_bls(&attestation, sk))
            .collect();

        // Aggregate signatures
        let aggregated = aggregate_signatures_bls(&signatures).unwrap();

        // Verify aggregated signature
        let public_keys: Vec<PublicKey> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        assert!(verify_aggregated_signature_bls(&attestation, &aggregated, &public_keys).is_ok());
    }

    #[test]
    fn test_bls_aggregation_wrong_keys() {
        let attestation = Attestation::new([1; 32], "test-net".to_string(), 1);

        // Generate 3 keypairs
        let keys: Vec<_> = (0..3).map(|_| generate_bls_keypair()).collect();

        // Sign with each key
        let signatures: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_attestation_bls(&attestation, sk))
            .collect();

        // Aggregate signatures
        let aggregated = aggregate_signatures_bls(&signatures).unwrap();

        // Try to verify with wrong public keys
        let wrong_keys: Vec<PublicKey> = (0..3)
            .map(|_| generate_bls_keypair().1)
            .collect();

        assert!(verify_aggregated_signature_bls(&attestation, &aggregated, &wrong_keys).is_err());
    }

    #[test]
    fn test_bls_key_encoding() {
        let (secret_key, public_key) = generate_bls_keypair();

        let encoded_sk = encode_bls_secret_key(&secret_key);
        let decoded_sk = decode_bls_secret_key(&encoded_sk).unwrap();
        assert_eq!(secret_key.to_bytes(), decoded_sk.to_bytes());

        let encoded_pk = encode_bls_public_key(&public_key);
        let decoded_pk = decode_bls_public_key(&encoded_pk).unwrap();
        assert_eq!(public_key.to_bytes(), decoded_pk.to_bytes());
    }
}
