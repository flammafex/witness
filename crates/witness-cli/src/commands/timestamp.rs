use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use witness_core::FreebirdToken;

use crate::client::WitnessClient;

pub async fn run(
    gateway_url: &str,
    file_path: Option<String>,
    hash_hex: Option<String>,
    output_format: &str,
    save_path: Option<String>,
    freebird_token_path: Option<String>,
) -> Result<()> {
    // Determine the hash to timestamp
    let hash = if let Some(path) = file_path {
        // Read file and compute hash
        let content = fs::read(&path).with_context(|| format!("Failed to read file: {}", path))?;

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
        hex::decode(&hash).context("Invalid hash format: must be hex encoded SHA-256")?;

        if hash.len() != 64 {
            anyhow::bail!("Invalid hash length: must be 64 hex characters (32 bytes)");
        }

        hash
    } else {
        anyhow::bail!("Must provide either --file or --hash");
    };

    // Load Freebird token from file if provided
    let freebird_token = if let Some(token_path) = freebird_token_path {
        let token_content = fs::read_to_string(&token_path)
            .with_context(|| format!("Failed to read Freebird token file: {}", token_path))?;
        let token: FreebirdToken = serde_json::from_str(&token_content)
            .with_context(|| "Failed to parse Freebird token JSON")?;
        Some(token)
    } else {
        None
    };

    // Reserve the canonical attestation job.
    if output_format == "text" {
        if freebird_token.is_some() {
            println!("Submitting attestation job with Freebird token...");
        } else {
            println!("Submitting attestation job...");
        }
    }

    let client = WitnessClient::new(gateway_url);
    let job = client.create_attestation(&hash, freebird_token).await?;

    // Output results
    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&job)?);
        }
        "text" => {
            println!("Attestation job accepted.");
            println!();
            println!("Status:    {:?}", job.status);
            println!("Hash:      {}", hex::encode(job.attestation.hash));
            println!(
                "Timestamp: {} ({})",
                job.attestation.timestamp,
                format_timestamp(job.attestation.timestamp)
            );
            println!("Network:   {}", job.attestation.network_id);
            println!("Sequence:  {}", job.attestation.sequence);
            println!("Attempts:  {}", job.attempts);
            if let Some(next_attempt_at) = job.next_attempt_at {
                println!("Next try:  {}", next_attempt_at);
            }
            if let Some(error) = &job.last_error {
                println!("Last error: {}", error);
            }
            if let Some(attestation) = &job.signed_attestation {
                println!("Signatures: {} verified", attestation.signature_count());
            } else {
                println!("Poll with: witness status {}", hash);
            }
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", output_format);
        }
    }

    // Save the durable job snapshot if requested.
    if let Some(save_path) = save_path {
        let json = serde_json::to_string_pretty(&job)?;
        fs::write(&save_path, json)
            .with_context(|| format!("Failed to write attestation to: {}", save_path))?;

        if output_format == "text" {
            println!();
            println!("Attestation job saved to: {}", save_path);
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
