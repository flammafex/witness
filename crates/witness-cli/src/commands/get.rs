use anyhow::{Context, Result};

use crate::client::WitnessClient;

pub async fn run(gateway_url: &str, hash: &str, output_format: &str) -> Result<()> {
    // Validate hash
    hex::decode(hash)
        .context("Invalid hash format: must be hex encoded SHA-256")?;

    if hash.len() != 64 {
        anyhow::bail!("Invalid hash length: must be 64 hex characters (32 bytes)");
    }

    // Get timestamp
    if output_format == "text" {
        println!("Looking up timestamp...");
    }

    let client = WitnessClient::new(gateway_url);
    let attestation = client.get_timestamp(hash).await?;

    // Output results
    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&attestation)?);
        }
        "text" => {
            println!("✓ Found timestamp");
            println!();
            println!("Hash:      {}", hex::encode(attestation.attestation.hash));
            println!("Timestamp: {} ({})",
                attestation.attestation.timestamp,
                format_timestamp(attestation.attestation.timestamp)
            );
            println!("Network:   {}", attestation.attestation.network_id);
            println!("Sequence:  {}", attestation.attestation.sequence);
            println!();

            // Display signature information based on type
            if attestation.is_aggregated() {
                println!("Signatures: BLS aggregated signature from {} witnesses", attestation.signature_count());
                match &attestation.signatures {
                    witness_core::signature_scheme::AttestationSignatures::Aggregated { signers, .. } => {
                        for signer in signers {
                            println!("  - {}", signer);
                        }
                    }
                    _ => {}
                }
            } else {
                println!("Signatures: {} witnesses signed", attestation.signature_count());
                match &attestation.signatures {
                    witness_core::signature_scheme::AttestationSignatures::MultiSig { signatures } => {
                        for sig in signatures {
                            println!("  - {}", sig.witness_id);
                        }
                    }
                    _ => {}
                }
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
