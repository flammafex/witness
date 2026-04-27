//! `witness log` subcommands: fetch STHs and verify RFC 9162 consistency
//! proofs against a network's published [`NetworkConfig`].

use anyhow::{Context, Result};
use witness_core::{verify_log_consistency, verify_signed_tree_head, NetworkConfig};

use crate::client::WitnessClient;

/// Fetch and display the gateway's latest STH.  When `--verify` is set, also
/// check the threshold signatures against the gateway's network config.
pub async fn sth(gateway: &str, output: &str, verify: bool) -> Result<()> {
    let client = WitnessClient::new(gateway);
    let sth = client.get_latest_sth().await?;

    if verify {
        let config: NetworkConfig = client.get_network_config().await?;
        let count = verify_signed_tree_head(&sth, &config)
            .context("STH signature verification failed")?;
        eprintln!(
            "STH verified: {} of {} signatures valid (threshold: {})",
            count,
            config.witnesses.len(),
            config.threshold
        );
    }

    match output {
        "json" => println!("{}", serde_json::to_string_pretty(&sth)?),
        _ => {
            println!("Tree size:    {}", sth.tree_head.tree_size);
            println!("Timestamp:    {}", sth.tree_head.timestamp);
            println!("Network:      {}", sth.tree_head.network_id);
            println!("Root hash:    {}", hex::encode(sth.tree_head.root_hash));
        }
    }
    Ok(())
}

/// Fetch a consistency proof between two STHs and verify the RFC 9162 chain.
pub async fn consistency(
    gateway: &str,
    first: u64,
    second: u64,
    output: &str,
    verify: bool,
) -> Result<()> {
    let client = WitnessClient::new(gateway);
    let proof = client.get_log_consistency(first, second).await?;

    if verify {
        let config = client.get_network_config().await?;
        verify_log_consistency(&proof, &config)
            .context("Consistency proof verification failed")?;
        eprintln!(
            "Consistency proof verified: tree[{}] is a prefix of tree[{}]",
            first, second
        );
    }

    match output {
        "json" => println!("{}", serde_json::to_string_pretty(&proof)?),
        _ => {
            println!("Old tree size: {}", proof.old_sth.tree_head.tree_size);
            println!("New tree size: {}", proof.new_sth.tree_head.tree_size);
            println!("Old root:      {}", hex::encode(proof.old_sth.tree_head.root_hash));
            println!("New root:      {}", hex::encode(proof.new_sth.tree_head.root_hash));
            println!("Proof hashes:  {}", proof.hashes.len());
            for (i, h) in proof.hashes.iter().enumerate() {
                println!("  [{}] {}", i, hex::encode(h));
            }
        }
    }
    Ok(())
}
