mod admin;
mod anchor_manager;
mod anchor_providers;
mod batch_manager;
mod federation_client;
mod freebird_client;
mod notifications;
mod server;
mod storage;
mod witness_client;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber;
use witness_core::NetworkConfig;

use admin::AdminState;
use anchor_manager::AnchorManager;
use batch_manager::BatchManager;
use federation_client::FederationClient;
use freebird_client::FreebirdClient;
use notifications::NotificationBroadcaster;
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

    /// Enable admin dashboard UI at /admin
    #[arg(long, default_value = "false")]
    admin_ui: bool,
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

    // Check if external anchoring is enabled (Phase 3)
    if network_config.external_anchors.enabled {
        tracing::info!("External anchoring enabled with {} providers",
            network_config.external_anchors.providers.len());
        tracing::info!("Anchor period: {} seconds",
            network_config.external_anchors.anchor_period);
        tracing::info!("Minimum required anchors: {}",
            network_config.external_anchors.minimum_required);
    }

    // Initialize storage
    // For sqlx-sqlite: sqlite:path?mode=rwc (read-write-create)
    // The ?mode=rwc tells SQLite to create the database file if it doesn't exist
    let db_url = format!("sqlite:{}?mode=rwc", args.database.display());
    let storage = Storage::new(&db_url).await?;
    storage.migrate().await?;

    tracing::info!("Database initialized: {:?}", args.database);

    // Wrap in Arc for sharing
    let network_config = Arc::new(network_config);
    let storage = Arc::new(storage);

    // Initialize anchor manager (Phase 3)
    let anchor_manager = Arc::new(AnchorManager::new(
        network_config.clone(),
        storage.clone(),
    ));

    // Initialize batch manager (Phase 2) with anchor manager
    let batch_manager = Arc::new(
        BatchManager::new(network_config.clone(), storage.clone())
            .with_anchor_manager(anchor_manager.clone())
    );

    // Initialize federation client (Phase 2)
    let federation_client = Arc::new(FederationClient::new(
        network_config.clone(),
        storage.clone(),
    ));

    // Initialize Freebird client (Phase 6)
    let freebird_client = Arc::new(FreebirdClient::new(
        Arc::new(network_config.freebird.clone()),
    ));

    // Check if Freebird is enabled
    if network_config.freebird.enabled {
        tracing::info!("Freebird anonymous submissions enabled");
        tracing::info!("  Verifier URL: {}", network_config.freebird.verifier_url);
        tracing::info!("  Issuer URL: {}", network_config.freebird.issuer_url);

        // Start background metadata refresh
        freebird_client.clone().start_metadata_refresh();
    } else {
        tracing::info!("Freebird anonymous submissions disabled");
    }

    // Start batch manager background task
    batch_manager.clone().start();

    // Initialize notification broadcaster (Phase 6)
    let broadcaster = Arc::new(NotificationBroadcaster::new(network_config.id.clone()));
    tracing::info!("WebSocket notifications enabled at /v1/ws");

    // Create admin state if admin UI is enabled
    let admin_state = if args.admin_ui {
        tracing::info!("Admin dashboard enabled at /admin");
        Some(AdminState::new(network_config.clone(), storage.clone()))
    } else {
        None
    };

    // Start server
    let server = GatewayServer::new(
        network_config,
        storage,
        batch_manager,
        federation_client,
        freebird_client,
        broadcaster,
    );
    server.run(args.port, admin_state).await?;

    Ok(())
}
