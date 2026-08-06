use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use witness_core::NetworkConfig;
use witness_gateway::{
    admin::AdminState,
    anchor_manager::AnchorManager,
    batch_manager::BatchManager,
    federation_client::FederationClient,
    freebird::FreebirdClient,
    metrics,
    node_client::NodeClient,
    reconciler::{AttestationWorker, Reconciler},
    server::GatewayServer,
    storage::Storage,
};

fn is_non_loopback_host(host: &str) -> bool {
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" {
        return false;
    }
    if host_lower == "127.0.0.1" || host_lower == "::1" {
        return false;
    }
    if let Ok(ip) = host.parse() {
        return !is_loopback_ip(&ip);
    }
    true
}

fn is_loopback_ip(ip: &std::net::IpAddr) -> bool {
    ip.is_loopback()
}

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

    /// Host/interface to bind to (secure default: localhost)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Path to SQLite database
    #[arg(short, long, default_value = "gateway.db")]
    database: PathBuf,

    /// Enable admin dashboard UI at /admin
    #[arg(long, default_value = "false")]
    admin_ui: bool,

    /// Admin API key required to access /admin (or set WITNESS_ADMIN_API_KEY)
    #[arg(long, env = "WITNESS_ADMIN_API_KEY")]
    admin_api_key: Option<String>,

    /// Token required for WebSocket connections (or set WITNESS_WS_AUTH_TOKEN)
    #[arg(long, env = "WITNESS_WS_AUTH_TOKEN")]
    ws_auth_token: Option<String>,

    /// Bearer token required to access /metrics (or set WITNESS_METRICS_TOKEN)
    #[arg(long, env = "WITNESS_METRICS_TOKEN")]
    metrics_token: Option<String>,

    /// Trust X-Forwarded-For header for real client IP (set when behind a reverse proxy)
    #[arg(long, env = "WITNESS_BEHIND_PROXY", default_value = "false")]
    behind_proxy: bool,
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

    // Initialize Prometheus metrics
    let metrics_handle = metrics::init_metrics();
    tracing::info!("Prometheus metrics initialized");

    let args = Args::parse();

    // Load network configuration
    let config_content = std::fs::read_to_string(&args.config)?;
    let network_config: NetworkConfig = serde_json::from_str(&config_content)?;

    // Validate configuration
    network_config.validate()?;

    for witness in &network_config.witnesses {
        if witness.auth_token.as_deref().unwrap_or("").is_empty() {
            anyhow::bail!(
                "witness '{}' is missing auth_token in network config",
                witness.id
            );
        }
    }

    tracing::info!("Loaded network configuration: {}", network_config.id);
    tracing::info!("Witnesses: {}", network_config.witnesses.len());
    tracing::info!("Threshold: {}", network_config.threshold);

    // Check if federation is enabled
    if network_config.federation.enabled {
        tracing::info!(
            "Federation enabled with {} peer networks",
            network_config.federation.peer_networks.len()
        );
        tracing::info!(
            "Batch period: {} seconds",
            network_config.federation.batch_period
        );
    } else {
        tracing::info!("Federation disabled (Phase 1 mode)");
    }

    // Check if external anchoring is enabled (Phase 3)
    if network_config.external_anchors.enabled {
        tracing::info!(
            "External anchoring enabled with {} providers",
            network_config.external_anchors.providers.len()
        );
        tracing::info!(
            "Anchor period: {} seconds",
            network_config.external_anchors.anchor_period
        );
        tracing::info!(
            "Minimum required anchors: {}",
            network_config.external_anchors.minimum_required
        );
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
    let anchor_manager =
        Arc::new(AnchorManager::new(network_config.clone(), storage.clone()).await);

    // Initialize federation client (Phase 2)
    let federation_client = Arc::new(FederationClient::new(
        network_config.clone(),
        storage.clone(),
    ));

    // Witness HTTP client shared between the leased attestation worker and
    // batch-manager STH signing.
    let witness_client = Arc::new(NodeClient::new());

    // Initialize batch manager (Phase 2) with anchor manager and federation client
    let batch_manager = Arc::new(
        BatchManager::new(
            network_config.clone(),
            storage.clone(),
            witness_client.clone(),
        )
        .with_anchor_manager(anchor_manager.clone())
        .with_federation_client(federation_client.clone()),
    );

    // Start batch manager background task
    batch_manager.clone().start();

    // Create admin state if admin UI is enabled
    let admin_api_key = if args.admin_ui {
        let key = args
            .admin_api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("--admin-ui requires --admin-api-key (or WITNESS_ADMIN_API_KEY)")
            })?
            .to_string();

        tracing::info!("Admin dashboard enabled at /admin (auth required)");
        Some(key)
    } else {
        None
    };
    let admin_state = admin_api_key
        .as_ref()
        .map(|_| AdminState::new(network_config.clone(), storage.clone()));

    // Initialize Freebird client from environment variables
    let freebird_client = FreebirdClient::from_env().map(Arc::new);
    if let Some(ref client) = freebird_client {
        let config = client.config();
        let mode = if config.consume_tokens {
            "/v1/verify (consuming)"
        } else {
            "/v1/check (non-consuming)"
        };
        tracing::info!(
            "Freebird enabled: verifier={}, required={}, mode={}",
            config.verifier_url.as_deref().unwrap_or("none"),
            config.required,
            mode
        );
        if !config.consume_tokens {
            tracing::warn!(
                "Freebird non-consuming mode is enabled (FREEBIRD_CONSUME_TOKENS=false). \
                 Tokens can be reused until expiry; use only for explicit proof-of-possession flows."
            );
        }
    } else {
        tracing::info!("Freebird disabled (no FREEBIRD_VERIFIER_URL set)");
    }

    // Security startup warnings
    if freebird_client.is_none() {
        tracing::warn!(
            "SECURITY: Freebird is disabled (no FREEBIRD_VERIFIER_URL). \
             Attestation endpoint has no proof-of-work/humanity protection."
        );
    }
    if network_config.federation.enabled && network_config.federation.inbound_auth_token.is_none() {
        tracing::warn!(
            "SECURITY: Federation is enabled but inbound_auth_token is not set. \
             Federation anchor endpoint accepts unauthenticated requests."
        );
    }

    // Start background metrics tasks
    let start_time = Instant::now();

    // Uptime metric updater (every 60 seconds)
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let uptime = start_time.elapsed().as_secs();
            metrics::set_uptime(uptime);
        }
    });

    // Witness health checker (every 30 seconds)
    let health_config = network_config.clone();
    tokio::spawn(async move {
        let client = NodeClient::new();
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            for witness in &health_config.witnesses {
                let healthy = client.health_check(witness).await;
                metrics::set_witness_health(&witness.id, healthy);
            }
        }
    });

    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let reconciler_cancel = cancel.clone();
    let worker = AttestationWorker::new(
        network_config.clone(),
        storage.clone(),
        witness_client.clone(),
    );
    let reconciler = Reconciler::new(worker, reconciler_cancel);
    let reconciler_handle = tokio::spawn(reconciler.run());

    // Start server
    let server = GatewayServer::new(
        network_config,
        storage,
        freebird_client,
        metrics_handle,
        args.ws_auth_token,
        args.metrics_token,
        args.behind_proxy,
    );

    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install SIGTERM handler");

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received SIGINT, initiating graceful shutdown");
                }
                _ = sigterm.recv() => {
                    tracing::info!("Received SIGTERM, initiating graceful shutdown");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await;
            tracing::info!("Received SIGINT, initiating graceful shutdown");
        }

        cancel_clone.cancel();
    });

    if is_non_loopback_host(&args.host) {
        tracing::warn!(
            "Gateway listening on non-loopback address {}. Traffic is unencrypted HTTP - ensure a TLS terminator (nginx, traefik, cloud load balancer) is in front.",
            args.host
        );
        if !args.behind_proxy {
            tracing::warn!(
                "SECURITY: Gateway is not behind a proxy (--behind-proxy=false) and listening on non-loopback address {}. \
                 X-Forwarded-For headers will not be trusted - clients may appear as 127.0.0.1.",
                args.host
            );
        }
    }

    let server_result = server
        .run(
            &args.host,
            args.port,
            admin_state,
            admin_api_key,
            cancel.clone(),
        )
        .await;
    cancel.cancel();
    if let Err(error) = reconciler_handle.await {
        tracing::warn!("Attestation worker task ended unexpectedly: {error}");
    }
    server_result?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    use crate::is_non_loopback_host;

    #[tokio::test]
    async fn cancellation_token_triggers_on_signal() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_clone.cancel();
        });

        tokio::time::timeout(Duration::from_secs(5), cancel.cancelled())
            .await
            .expect("timed out waiting for cancellation");

        assert!(cancel.is_cancelled());
    }

    #[test]
    fn test_is_non_loopback_host() {
        assert!(!is_non_loopback_host("127.0.0.1"));
        assert!(!is_non_loopback_host("::1"));
        assert!(!is_non_loopback_host("localhost"));
        assert!(!is_non_loopback_host("LOCALHOST"));

        assert!(is_non_loopback_host("0.0.0.0"));
        assert!(is_non_loopback_host("::"));
        assert!(is_non_loopback_host("192.168.1.1"));
        assert!(is_non_loopback_host("10.0.0.1"));
        assert!(is_non_loopback_host("172.16.0.1"));
        assert!(is_non_loopback_host("public.example.com"));
    }
}
