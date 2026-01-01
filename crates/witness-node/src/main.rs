mod server;
mod config;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber;

use config::WitnessNodeConfig;
use server::WitnessServer;

#[derive(Parser, Debug)]
#[command(name = "witness-node")]
#[command(about = "Witness node for signing attestations", long_about = None)]
struct Args {
    /// Path to witness configuration file
    #[arg(short, long, default_value = "witness.json")]
    config: PathBuf,

    /// HTTP port to listen on
    #[arg(short, long)]
    port: Option<u16>,

    /// Generate a new keypair and exit
    #[arg(long)]
    generate_key: bool,

    /// Use BLS signatures instead of Ed25519 (for --generate-key)
    #[arg(long)]
    bls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "witness_node=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();

    // Handle key generation
    if args.generate_key {
        if args.bls {
            let (secret_key, public_key) = witness_core::generate_bls_keypair();

            println!("Generated new BLS keypair:");
            println!("Public key:  {}", witness_core::encode_bls_public_key(&public_key));
            println!("Private key: {}", witness_core::encode_bls_secret_key(&secret_key));
            println!("\nStore the private key securely in your witness configuration.");
            println!("Share the public key with the network coordinator.");
            println!("\nIn your witness config, set:");
            println!("  \"signature_scheme\": \"bls\"");
        } else {
            let (signing_key, verifying_key) = witness_core::generate_keypair();

            println!("Generated new Ed25519 keypair:");
            println!("Public key:  {}", witness_core::encode_public_key(&verifying_key));
            println!("Private key: {}", hex::encode(signing_key.to_bytes()));
            println!("\nStore the private key securely in your witness configuration.");
            println!("Share the public key with the network coordinator.");
            println!("\nIn your witness config, set:");
            println!("  \"signature_scheme\": \"ed25519\"");
        }
        return Ok(());
    }

    // Load configuration
    let config = WitnessNodeConfig::load(&args.config)?;
    let port = args.port.unwrap_or(config.port);

    tracing::info!("Starting witness node: {}", config.id);
    tracing::info!("Public key: {}", config.public_key());
    tracing::info!("Listening on port: {}", port);

    // Start server
    let server = WitnessServer::new(config);
    server.run(port).await?;

    Ok(())
}
