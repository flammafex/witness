use anyhow::{Context, Result};
use std::fs;
use witness_core::{NetworkConfig, ProofBundle, ProofVerificationConfig};

use crate::client::WitnessClient;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    gateway_url: &str,
    bundle_path: Option<String>,
    hash: Option<String>,
    network_config_path: Option<String>,
    peer_config_paths: Vec<String>,
    online: bool,
    output_format: &str,
) -> Result<()> {
    // 1. Load the proof bundle: from file or by fetching from the gateway.
    let bundle: ProofBundle = if let Some(path) = bundle_path {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read bundle file: {}", path))?;
        serde_json::from_str(&content).context("Failed to parse bundle JSON")?
    } else if let Some(hash) = hash {
        let client = WitnessClient::new(gateway_url);
        client.get_proof_bundle(&hash).await?
    } else {
        anyhow::bail!("Must provide either --bundle <path> or --hash <hex>");
    };

    // 2. Resolve the home network's config: from file (offline) or fetched (online).
    let network: NetworkConfig = if let Some(path) = network_config_path {
        load_network_config(&path)?
    } else if online {
        let client = WitnessClient::new(gateway_url);
        client.get_network_config().await?
    } else {
        anyhow::bail!(
            "Provide --network-config <path> for offline verification, or pass --online to \
             fetch the home network's config from the gateway"
        );
    };

    // 3. Resolve peer configs (each --peer-config path) plus, in online mode,
    //    fetch any peer referenced by the bundle's cross-anchors that we don't
    //    already have a local config for.
    let mut peers: Vec<NetworkConfig> = peer_config_paths
        .iter()
        .map(|p| load_network_config(p))
        .collect::<Result<Vec<_>>>()?;

    if online {
        let client = WitnessClient::new(gateway_url);
        for cross_anchor in &bundle.cross_anchors {
            if peers
                .iter()
                .any(|p| p.id == cross_anchor.witnessing_network)
            {
                continue;
            }
            // Look up peer's gateway URL in the home network config
            let peer_info = network
                .federation
                .peer_networks
                .iter()
                .find(|p| p.id == cross_anchor.witnessing_network);
            match peer_info {
                Some(peer) => match client.get_network_config_from(&peer.gateway).await {
                    Ok(cfg) => peers.push(cfg),
                    Err(e) => {
                        if output_format == "text" {
                            eprintln!(
                                "Warning: failed to fetch peer config for {}: {}",
                                cross_anchor.witnessing_network, e
                            );
                        }
                    }
                },
                None => {
                    if output_format == "text" {
                        eprintln!(
                            "Warning: cross-anchor from unknown peer network: {}",
                            cross_anchor.witnessing_network
                        );
                    }
                }
            }
        }
    }

    let config = ProofVerificationConfig { network, peers };

    let result = witness_core::verify_proof_bundle(&bundle, &config);

    match output_format {
        "json" => match result {
            Ok(verification) => {
                let response = serde_json::json!({
                    "valid": true,
                    "verified_signatures": verification.verified_signatures,
                    "required_signatures": verification.required_signatures,
                    "batch_inclusion_verified": verification.batch_inclusion_verified,
                    "cross_anchors_verified": verification.cross_anchors_verified,
                    "external_anchors_present": verification.external_anchors_present,
                    "level": verification.level.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&response)?);
            }
            Err(e) => {
                let response = serde_json::json!({
                    "valid": false,
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&response)?);
                std::process::exit(1);
            }
        },
        "text" => match result {
            Ok(verification) => {
                println!("VALID");
                println!();
                println!(
                    "Hash:         {}",
                    hex::encode(bundle.signed_attestation.attestation.hash)
                );
                println!(
                    "Network:      {}",
                    bundle.signed_attestation.attestation.network_id
                );
                println!(
                    "Threshold:    {} of {} signatures verified ({} required)",
                    verification.verified_signatures,
                    bundle.signed_attestation.signature_count(),
                    verification.required_signatures
                );
                match verification.batch_inclusion_verified {
                    Some(true) => println!("Batch:        merkle inclusion verified"),
                    Some(false) => println!("Batch:        merkle inclusion FAILED"),
                    None => println!("Batch:        not yet batched"),
                }
                if verification.cross_anchors_verified.is_empty() {
                    println!("Cross-anchors: none");
                } else {
                    println!("Cross-anchors:");
                    for (peer, ok) in &verification.cross_anchors_verified {
                        println!("  - {} {}", peer, if *ok { "OK" } else { "FAILED" });
                    }
                }
                println!(
                    "External anchors: {}",
                    verification.external_anchors_present
                );
                println!("Level:        {}", verification.level);
            }
            Err(e) => {
                println!("INVALID");
                println!();
                println!("{}", e);
                std::process::exit(1);
            }
        },
        _ => anyhow::bail!("Invalid output format: {}", output_format),
    }

    Ok(())
}

fn load_network_config(path: &str) -> Result<NetworkConfig> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read network config: {}", path))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse network config: {}", path))
}
