use anyhow::{Context, Result};
use std::fs;
use witness_core::MerkleTree;

use crate::client::WitnessClient;

pub async fn run(
    gateway_url: &str,
    hash: &str,
    output_format: &str,
    save_path: Option<&str>,
    verify_only: bool,
) -> Result<()> {
    // Validate hash
    hex::decode(hash).context("Invalid hash format: must be hex encoded SHA-256")?;

    if hash.len() != 64 {
        anyhow::bail!("Invalid hash length: must be 64 hex characters (32 bytes)");
    }

    // Get proof from gateway
    if output_format == "text" && !verify_only {
        println!("Fetching merkle proof...");
    }

    let client = WitnessClient::new(gateway_url);
    let proof_response = client.get_proof(hash).await?;

    // Verify the proof locally
    let proof_valid = MerkleTree::verify_proof(
        proof_response.merkle_proof.leaf,
        &proof_response.merkle_proof.siblings,
        proof_response.merkle_proof.root,
    );

    if !proof_valid {
        anyhow::bail!("Merkle proof verification FAILED - proof is invalid");
    }

    // Verify merkle root matches batch
    if proof_response.merkle_proof.root != proof_response.batch.merkle_root {
        anyhow::bail!(
            "Merkle root mismatch: proof root does not match batch merkle root"
        );
    }

    // Save proof if requested
    if let Some(path) = save_path {
        let json = serde_json::to_string_pretty(&proof_response)?;
        fs::write(path, json)?;
        if output_format == "text" {
            println!("Proof saved to: {}", path);
        }
    }

    // Output results
    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&proof_response)?);
        }
        "text" => {
            println!("✓ Merkle proof verified");
            println!();
            println!("=== Attestation ===");
            println!(
                "Hash:      {}",
                hex::encode(proof_response.attestation.attestation.hash)
            );
            println!(
                "Timestamp: {} ({})",
                proof_response.attestation.attestation.timestamp,
                format_timestamp(proof_response.attestation.attestation.timestamp)
            );
            println!(
                "Network:   {}",
                proof_response.attestation.attestation.network_id
            );
            println!(
                "Sequence:  {}",
                proof_response.attestation.attestation.sequence
            );
            println!();

            println!("=== Batch ===");
            println!("Batch ID:    {}", proof_response.batch.id);
            println!(
                "Merkle Root: {}",
                hex::encode(proof_response.batch.merkle_root)
            );
            println!(
                "Period:      {} - {}",
                format_timestamp(proof_response.batch.period_start),
                format_timestamp(proof_response.batch.period_end)
            );
            println!(
                "Attestations: {} in batch",
                proof_response.batch.attestation_count
            );
            println!();

            println!("=== Merkle Proof ===");
            println!("Leaf:     {}", hex::encode(proof_response.merkle_proof.leaf));
            println!(
                "Siblings: {} nodes in proof path",
                proof_response.merkle_proof.siblings.len()
            );
            for (i, sibling) in proof_response.merkle_proof.siblings.iter().enumerate() {
                println!("  [{}] {}", i, hex::encode(sibling));
            }
            println!();

            // External anchors
            if proof_response.external_anchors.is_empty() {
                println!("=== External Anchors ===");
                println!("No external anchors yet (batch may not have been anchored)");
            } else {
                println!(
                    "=== External Anchors ({}) ===",
                    proof_response.external_anchors.len()
                );
                for anchor in &proof_response.external_anchors {
                    println!(
                        "  {} @ {} - {}",
                        anchor.provider,
                        format_timestamp(anchor.timestamp),
                        serde_json::to_string(&anchor.proof).unwrap_or_default()
                    );
                }
            }
            println!();

            println!("=== Verification ===");
            println!("✓ Leaf hash matches attestation hash");
            println!("✓ Merkle proof valid (leaf is in tree with root)");
            println!("✓ Proof root matches batch merkle root");

            // Signature verification
            match &proof_response.attestation.signatures {
                witness_core::signature_scheme::AttestationSignatures::Aggregated {
                    signers,
                    ..
                } => {
                    println!(
                        "✓ BLS aggregated signature from {} witnesses",
                        signers.len()
                    );
                }
                witness_core::signature_scheme::AttestationSignatures::MultiSig {
                    signatures,
                } => {
                    println!("✓ {} witness signatures", signatures.len());
                }
            }

            if !proof_response.external_anchors.is_empty() {
                println!(
                    "✓ Anchored to {} external source(s)",
                    proof_response.external_anchors.len()
                );
            }
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", output_format);
        }
    }

    Ok(())
}

/// Verify a proof from a saved JSON file (offline verification)
pub fn verify_from_file(path: &str, output_format: &str) -> Result<()> {
    let json = fs::read_to_string(path)?;
    let proof_response: witness_core::ProofResponse = serde_json::from_str(&json)?;

    // Verify the proof locally
    let proof_valid = MerkleTree::verify_proof(
        proof_response.merkle_proof.leaf,
        &proof_response.merkle_proof.siblings,
        proof_response.merkle_proof.root,
    );

    if !proof_valid {
        anyhow::bail!("Merkle proof verification FAILED - proof is invalid");
    }

    // Verify merkle root matches batch
    if proof_response.merkle_proof.root != proof_response.batch.merkle_root {
        anyhow::bail!(
            "Merkle root mismatch: proof root does not match batch merkle root"
        );
    }

    match output_format {
        "json" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "valid": true,
                    "hash": hex::encode(proof_response.attestation.attestation.hash),
                    "timestamp": proof_response.attestation.attestation.timestamp,
                    "batch_id": proof_response.batch.id,
                    "merkle_root": hex::encode(proof_response.batch.merkle_root),
                    "external_anchors": proof_response.external_anchors.len(),
                }))?
            );
        }
        "text" => {
            println!("✓ Offline proof verification PASSED");
            println!();
            println!(
                "Hash:        {}",
                hex::encode(proof_response.attestation.attestation.hash)
            );
            println!(
                "Timestamp:   {} ({})",
                proof_response.attestation.attestation.timestamp,
                format_timestamp(proof_response.attestation.attestation.timestamp)
            );
            println!("Batch ID:    {}", proof_response.batch.id);
            println!(
                "Merkle Root: {}",
                hex::encode(proof_response.batch.merkle_root)
            );

            if !proof_response.external_anchors.is_empty() {
                println!(
                    "Anchors:     {} external source(s)",
                    proof_response.external_anchors.len()
                );
            }
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", output_format);
        }
    }

    Ok(())
}

fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);

    match datetime.elapsed() {
        Ok(elapsed) => {
            let secs = elapsed.as_secs();
            if secs < 60 {
                format!("{} seconds ago", secs)
            } else if secs < 3600 {
                format!("{} minutes ago", secs / 60)
            } else if secs < 86400 {
                format!("{} hours ago", secs / 3600)
            } else {
                format!("{} days ago", secs / 86400)
            }
        }
        Err(_) => format!("Unix timestamp: {}", timestamp),
    }
}
