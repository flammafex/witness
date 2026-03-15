use anyhow::{Context, Result};
use std::fs;
use witness_core::SignedAttestation;

use crate::client::WitnessClient;

pub async fn run(gateway_url: &str, file_path: &str, output_format: &str) -> Result<()> {
    // Load attestation from file
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read attestation file: {}", file_path))?;

    let attestation: SignedAttestation = serde_json::from_str(&content)
        .context("Failed to parse attestation JSON")?;

    if output_format == "text" {
        println!("Verifying attestation...");
        println!("Hash: {}", hex::encode(attestation.attestation.hash));
        println!();
    }

    // Fetch network config (contains public keys) for local verification
    let client = WitnessClient::new(gateway_url);
    let config = client.get_config().await?;

    // Verify locally using witness-core cryptographic verification
    let result = witness_core::verify_signed_attestation(&attestation, &config);

    // Output results
    match output_format {
        "json" => {
            let (valid, verified_signatures, message) = match &result {
                Ok(count) => (true, *count, format!(
                    "Valid: {} of {} signatures verified, {} required",
                    count, config.witnesses.len(), config.threshold
                )),
                Err(e) => (false, 0, format!("Invalid: {}", e)),
            };
            let response = serde_json::json!({
                "valid": valid,
                "verified_signatures": verified_signatures,
                "required_signatures": config.threshold,
                "message": message,
            });
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        "text" => {
            match result {
                Ok(count) => {
                    println!("VALID");
                    println!();
                    println!(
                        "{} of {} signatures verified, {} required",
                        count, config.witnesses.len(), config.threshold
                    );
                }
                Err(e) => {
                    println!("INVALID");
                    println!();
                    println!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", output_format);
        }
    }

    Ok(())
}
