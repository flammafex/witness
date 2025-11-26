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

    // Verify with gateway
    let client = WitnessClient::new(gateway_url);
    let result = client.verify(&attestation).await?;

    // Output results
    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        "text" => {
            if result.valid {
                println!("✓ VALID");
                println!();
                println!("{}", result.message);
            } else {
                println!("✗ INVALID");
                println!();
                println!("{}", result.message);
                std::process::exit(1);
            }
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", output_format);
        }
    }

    Ok(())
}
