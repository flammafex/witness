use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;

use crate::client::WitnessClient;

pub async fn run(
    gateway_url: &str,
    file_path: Option<String>,
    hash_hex: Option<String>,
    token_b64: String,
    exp: i64,
    epoch: u32,
    output_format: &str,
    save_path: Option<String>,
) -> Result<()> {
    // Determine the hash to timestamp
    let hash = if let Some(path) = file_path {
        // Read file and compute hash
        let content = fs::read(&path)
            .with_context(|| format!("Failed to read file: {}", path))?;

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash_bytes = hasher.finalize();

        let hash_hex = hex::encode(hash_bytes);

        if output_format == "text" {
            println!("File: {}", path);
            println!("SHA-256: {}", hash_hex);
            println!();
        }

        hash_hex
    } else if let Some(hash) = hash_hex {
        // Validate hash format
        hex::decode(&hash)
            .context("Invalid hash format: must be hex encoded SHA-256")?;

        if hash.len() != 64 {
            anyhow::bail!("Invalid hash length: must be 64 hex characters (32 bytes)");
        }

        hash
    } else {
        anyhow::bail!("Must provide either --file or --hash");
    };

    // Validate token
    if token_b64.is_empty() {
        anyhow::bail!("Freebird token is required for anonymous submissions");
    }

    // Request anonymous timestamp
    if output_format == "text" {
        println!("Requesting anonymous timestamp from gateway...");
        println!("  Using Freebird token (epoch={}, exp={})", epoch, exp);
    }

    let client = WitnessClient::new(gateway_url);
    let response = client.anonymous_timestamp(&hash, &token_b64, exp, epoch).await?;

    // Output results
    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        "text" => {
            println!("✓ Anonymous timestamp successful!");
            println!();
            println!("Hash:      {}", hex::encode(response.attestation.attestation.hash));
            println!("Timestamp: {} ({})",
                response.attestation.attestation.timestamp,
                format_timestamp(response.attestation.attestation.timestamp)
            );
            println!("Network:   {}", response.attestation.attestation.network_id);
            println!("Sequence:  {}", response.attestation.attestation.sequence);
            println!();
            println!("Anonymous: ✓ Yes");
            println!("Freebird verified at: {}", response.freebird_verified_at);
            println!();

            // Display signature information based on type
            if response.attestation.is_aggregated() {
                println!("Signatures: BLS aggregated signature from {} witnesses", response.attestation.signature_count());
                match &response.attestation.signatures {
                    witness_core::signature_scheme::AttestationSignatures::Aggregated { signers, .. } => {
                        for signer in signers {
                            println!("  - {}", signer);
                        }
                    }
                    _ => {}
                }
            } else {
                println!("Signatures: {} witnesses signed", response.attestation.signature_count());
                match &response.attestation.signatures {
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

    // Save attestation if requested
    if let Some(save_path) = save_path {
        let json = serde_json::to_string_pretty(&response)?;
        fs::write(&save_path, json)
            .with_context(|| format!("Failed to write attestation to: {}", save_path))?;

        if output_format == "text" {
            println!();
            println!("Attestation saved to: {}", save_path);
        }
    }

    Ok(())
}

fn format_timestamp(timestamp: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(timestamp);

    // Simple formatting
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
