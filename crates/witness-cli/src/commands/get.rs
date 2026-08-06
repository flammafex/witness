use anyhow::{Context, Result};

use witness_client::WitnessClient;

pub async fn run(gateway_url: &str, hash: &str, output_format: &str) -> Result<()> {
    // Validate hash
    let hash_bytes = decode_hash(hash)?;

    // Get durable attestation job status.
    if output_format == "text" {
        println!("Looking up attestation job...");
    }

    let client = WitnessClient::new(gateway_url)?;
    let job = client.get_attestation(hash_bytes).await?;

    // Output results
    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&job)?);
        }
        "text" => {
            println!("Found attestation job");
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

fn decode_hash(hash_hex: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hash_hex).context("Invalid hash format: must be hex encoded SHA-256")?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("Invalid hash length: must be 64 hex characters (32 bytes)")
    })?;
    Ok(arr)
}
