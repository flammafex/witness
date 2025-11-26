mod server;
mod storage;
mod witness_client;
mod batch_manager;
mod federation_client;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber;
use witness_core::NetworkConfig;

use batch_manager::BatchManager;
use federation_client::FederationClient;
use server::GatewayServer;
use storage::Storage;

#[derive(Parser, Debug)]
#[command(name = "witness-gateway")]
#[command(about = "Gateway for aggregating witness signatures", long_about = None)]
struct Args {
    /// Path to network configuration file
    #[arg(short, long, default_value = "network.json")]
    config: PathBuf,

    /// HTTP port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Path to SQLite database
    #[arg(short, long, default_value = "gateway.db")]
    database: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "witness_gateway=info,tower_http=info".into()),
        )
        .init();

    let args = Args::parse();

    // Load network configuration
    let config_content = std::fs::read_to_string(&args.config)?;
    let network_config: NetworkConfig = serde_json::from_str(&config_content)?;

    // Validate configuration
    network_config.validate()?;

    tracing::info!("Loaded network configuration: {}", network_config.id);
    tracing::info!("Witnesses: {}", network_config.witnesses.len());
    tracing::info!("Threshold: {}", network_config.threshold);

    // Check if federation is enabled
    if network_config.federation.enabled {
        tracing::info!("Federation enabled with {} peer networks",
            network_config.federation.peer_networks.len());
        tracing::info!("Batch period: {} seconds",
            network_config.federation.batch_period);
    } else {
        tracing::info!("Federation disabled (Phase 1 mode)");
    }

    // Initialize storage
    let db_url = format!("sqlite:{}", args.database.display());
    let storage = Storage::new(&db_url).await?;
    storage.migrate().await?;

    tracing::info!("Database initialized: {:?}", args.database);

    // Wrap in Arc for sharing
    let network_config = Arc::new(network_config);
    let storage = Arc::new(storage);

    // Initialize batch manager (Phase 2)
    let batch_manager = Arc::new(BatchManager::new(
        network_config.clone(),
        storage.clone(),
    ));

    // Initialize federation client (Phase 2)
    let federation_client = Arc::new(FederationClient::new(
        network_config.clone(),
        storage.clone(),
    ));

    // Start batch manager background task
    batch_manager.clone().start();

    // Start server
    let server = GatewayServer::new(
        network_config,
        storage,
        batch_manager,
        federation_client,
    );
    server.run(args.port).await?;

    Ok(())
}
