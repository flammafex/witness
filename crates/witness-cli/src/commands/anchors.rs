use anyhow::Result;

use crate::client::WitnessClient;

pub async fn run(gateway_url: &str, hash: &str, output_format: &str) -> Result<()> {
    let client = WitnessClient::new(gateway_url);

    // Get batch anchors for this hash
    let anchors = client.get_batch_anchors(hash).await?;

    if anchors.is_empty() {
        if output_format == "text" {
            println!("No external anchors found for this attestation");
            println!();
            println!("This means either:");
            println!("  - External anchoring is not enabled");
            println!("  - The attestation hasn't been batched yet");
            println!("  - The batch hasn't been anchored yet");
        } else {
            println!("[]");
        }
        return Ok(());
    }

    match output_format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&anchors)?);
        }
        "text" => {
            println!("External Anchor Proofs ({} found)", anchors.len());
            println!("═══════════════════════════════════════════════════");
            println!();

            for (i, anchor) in anchors.iter().enumerate() {
                println!("Anchor #{}: {:?}", i + 1, anchor.provider);
                println!("  Timestamp: {} ({})",
                    anchor.timestamp,
                    format_timestamp(anchor.timestamp)
                );

                // Display provider-specific proof data
                match anchor.provider {
                    witness_core::AnchorProviderType::InternetArchive => {
                        if let Some(url) = anchor.proof.get("archive_url").and_then(|v| v.as_str()) {
                            println!("  Archive URL: {}", url);
                        }
                        if let Some(root) = anchor.proof.get("merkle_root").and_then(|v| v.as_str()) {
                            println!("  Merkle Root: {}", root);
                        }
                    }
                    witness_core::AnchorProviderType::Trillian => {
                        println!("  Proof: {}", serde_json::to_string_pretty(&anchor.proof)?);
                    }
                    witness_core::AnchorProviderType::DnsTxt => {
                        println!("  Proof: {}", serde_json::to_string_pretty(&anchor.proof)?);
                    }
                    witness_core::AnchorProviderType::Blockchain => {
                        println!("  Proof: {}", serde_json::to_string_pretty(&anchor.proof)?);
                    }
                }

                if i < anchors.len() - 1 {
                    println!();
                }
            }

            println!();
            println!("✓ Attestation is anchored to {} external service(s)", anchors.len());
        }
        _ => {
            anyhow::bail!("Invalid output format: {}", output_format);
        }
    }

    Ok(())
}

fn format_timestamp(unix_secs: u64) -> String {
    use std::time::{UNIX_EPOCH, Duration};

    let timestamp = UNIX_EPOCH + Duration::from_secs(unix_secs);
    let datetime = chrono::DateTime::<chrono::Utc>::from(timestamp);
    datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}
