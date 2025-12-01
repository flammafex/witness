use anyhow::Result;
use witness_core::{FederatedVerifyResponse, MerkleTree};

use crate::client::WitnessClient;

pub async fn run(gateway_url: &str, hash: &str, output_format: &str) -> Result<()> {
    let client = WitnessClient::new(gateway_url);

    // Call the federation verification endpoint
    let url = format!("{}/v1/federation/verify/{}", gateway_url, hash);
    let response = reqwest::get(&url).await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to verify: {}", response.status());
    }

    let verify_response: FederatedVerifyResponse = response.json().await?;

    if output_format == "json" {
        println!("{}", serde_json::to_string_pretty(&verify_response)?);
        return Ok(());
    }

    // Text output with visual trust chain
    println!("================================================================");
    println!("         WITNESS FEDERATED VERIFICATION REPORT                  ");
    println!("================================================================");
    println!();

    if let Some(ref federated_attestation) = verify_response.federated_attestation {
        let attestation = &federated_attestation.attestation;

        // Basic attestation info
        println!("ATTESTATION");
        println!("  Hash:      {}", hex::encode(attestation.attestation.hash));
        println!("  Network:   {}", attestation.attestation.network_id);
        println!("  Timestamp: {} ({})",
            attestation.attestation.timestamp,
            format_timestamp(attestation.attestation.timestamp)
        );
        println!("  Sequence:  {}", attestation.attestation.sequence);
        println!();

        // Witness signatures
        match &attestation.signatures {
            witness_core::signature_scheme::AttestationSignatures::MultiSig { signatures } => {
                println!("WITNESS SIGNATURES ({} witnesses)", signatures.len());
                for (i, sig) in signatures.iter().enumerate() {
                    println!("  {}. {}", i + 1, sig.witness_id);
                }
                println!();
            }
            witness_core::signature_scheme::AttestationSignatures::Aggregated { .. } => {
                println!("WITNESS SIGNATURES (BLS aggregate)");
                println!();
            }
        }

        // Merkle proof (batching)
        if let Some(ref merkle_proof) = federated_attestation.merkle_proof {
            println!("MERKLE PROOF (Batched)");
            println!("  Root:     {}", hex::encode(merkle_proof.root));
            println!("  Siblings: {}", merkle_proof.siblings.len());

            // Verify the merkle proof
            let verified = MerkleTree::verify_proof(
                merkle_proof.leaf,
                &merkle_proof.siblings,
                merkle_proof.root,
            );

            if verified {
                println!("  Status:   [VALID]");
            } else {
                println!("  Status:   [INVALID]");
            }
            println!();
        }

        // Cross-anchors (federation)
        if !federated_attestation.cross_anchors.is_empty() {
            println!("CROSS-ANCHORS ({} peer networks)", federated_attestation.cross_anchors.len());
            for (i, cross_anchor) in federated_attestation.cross_anchors.iter().enumerate() {
                println!("  {}. Network: {}", i + 1, cross_anchor.witnessing_network);
                println!("     Witnesses: {}", cross_anchor.signatures.len());
                println!("     Timestamp: {} ({})",
                    cross_anchor.timestamp,
                    format_timestamp(cross_anchor.timestamp)
                );
            }
            println!();
        }
    }

    // Verification level summary
    println!("================================================================");
    println!("VERIFICATION LEVEL: {}", verify_response.verification_level);
    println!("================================================================");
    println!();

    // Trust ladder visualization
    print_trust_ladder(&verify_response);

    Ok(())
}

fn format_timestamp(timestamp: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| Utc::now());
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn print_trust_ladder(response: &FederatedVerifyResponse) {
    println!("TRUST LADDER:");
    println!();

    // Phase 1: Basic
    println!("  Phase 1: Threshold Signatures");
    println!("  |");
    if matches!(response.verification_level, witness_core::VerificationLevel::None) {
        println!("  +-- [NOT VERIFIED]");
        return;
    } else {
        println!("  +-- [VERIFIED]");
    }
    println!("  |");

    // Phase 2: Batched
    println!("  Phase 2: Merkle Batching");
    println!("  |");
    if matches!(response.verification_level, witness_core::VerificationLevel::Batched | witness_core::VerificationLevel::Federated { .. }) {
        println!("  +-- [BATCHED]");
    } else {
        println!("  +-- [PENDING] (not batched yet)");
        return;
    }
    println!("  |");

    // Phase 2.5: Federation
    println!("  Phase 2.5: Cross-Network Federation");
    println!("  |");
    if let witness_core::VerificationLevel::Federated { peer_count } = response.verification_level {
        if peer_count > 0 {
            println!("  +-- [FEDERATED] ({} peer networks)", peer_count);
        } else {
            println!("  +-- [BATCHED] (no federation configured)");
        }
    } else {
        println!("  +-- [PENDING] (batch not yet cross-anchored)");
    }
    println!("  |");

    // Phase 3: External Anchors
    println!("  Phase 3: External Anchors");
    println!("  |");
    if let Some(ref federated_attestation) = response.federated_attestation {
        // Check if there are external anchors (we need to call the anchors endpoint)
        println!("  +-- [CHECK /v1/anchors/<hash> for external anchor proofs]");
    } else {
        println!("  +-- [PENDING]");
    }
    println!();
}
