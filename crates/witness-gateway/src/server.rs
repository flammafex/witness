use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use witness_core::{
    Attestation, CrossAnchorRequest, CrossAnchorResponse, ExternalAnchorProof, NetworkConfig,
    SignatureScheme, SignedAttestation, TimestampRequest, TimestampResponse, VerifyRequest,
    VerifyResponse,
};

use crate::admin::{admin_router, AdminState};
use crate::batch_manager::BatchManager;
use crate::federation_client::FederationClient;
use crate::freebird::{FreebirdClient, FreebirdError};
use crate::storage::Storage;
use crate::witness_client::WitnessClient;

/// Event broadcast to WebSocket clients when an attestation is created
#[derive(Clone, Debug, serde::Serialize)]
pub struct AttestationEvent {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Clone)]
pub struct GatewayServer {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<WitnessClient>,
    batch_manager: Arc<BatchManager>,
    federation_client: Arc<FederationClient>,
    freebird_client: Option<Arc<FreebirdClient>>,
    event_tx: broadcast::Sender<AttestationEvent>,
}

impl GatewayServer {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        batch_manager: Arc<BatchManager>,
        federation_client: Arc<FederationClient>,
        freebird_client: Option<Arc<FreebirdClient>>,
    ) -> Self {
        // Create broadcast channel for WebSocket events with capacity 256
        let (event_tx, _) = broadcast::channel(256);

        Self {
            config,
            storage,
            witness_client: Arc::new(WitnessClient::new()),
            batch_manager,
            federation_client,
            freebird_client,
            event_tx,
        }
    }

    pub async fn run(self, port: u16, admin_state: Option<AdminState>) -> anyhow::Result<()> {
        let mut app = Router::new()
            // Visualizer page at root
            .route("/", get(visualizer_page))
            .route("/health", get(health_handler))
            .route("/v1/config", get(config_handler))
            .route("/v1/timestamp", post(timestamp_handler))
            .route("/v1/timestamp/:hash", get(get_timestamp_handler))
            .route("/v1/verify", post(verify_handler))
            // Phase 2: Federation endpoints
            .route("/v1/federation/anchor", post(federation_anchor_handler))
            // Phase 3: External anchor endpoints
            .route("/v1/anchors/:hash", get(get_anchors_handler))
            // WebSocket events endpoint
            .route("/ws/events", get(ws_events_handler))
            .layer(CorsLayer::permissive())
            .with_state(self);

        // Add admin dashboard if enabled
        if let Some(admin) = admin_state {
            app = app.nest("/admin", admin_router(admin));
        }

        let addr = format!("0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;

        tracing::info!("Gateway listening on {}", addr);

        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn config_handler(State(server): State<GatewayServer>) -> impl IntoResponse {
    Json(server.config.as_ref().clone())
}

async fn timestamp_handler(
    State(server): State<GatewayServer>,
    Json(request): Json<TimestampRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Received timestamp request for hash: {}", request.hash);

    // Check Freebird token if configured
    if let Some(ref freebird) = server.freebird_client {
        match &request.freebird_token {
            Some(token) => {
                // Verify token with Freebird verifier
                freebird.verify(token).await?;
                // Token is consumed by verifier (nullifier recorded)
                tracing::info!("Freebird token verified for hash: {}", request.hash);
            }
            None if freebird.is_required() => {
                return Err(AppError::FreebirdTokenRequired);
            }
            None => {
                // Permissive mode - allow without token
                tracing::debug!("No Freebird token provided (permissive mode)");
            }
        }
    }

    // Parse hash
    let hash_bytes = hex::decode(&request.hash)
        .map_err(|_| AppError::InvalidHash)?;

    let hash: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| AppError::InvalidHash)?;

    // Check for duplicate
    if server.storage.check_duplicate(&hash).await? {
        tracing::info!("Hash already timestamped: {}", request.hash);

        // Return existing attestation
        let existing = server.storage.get_attestation(&hash).await?
            .ok_or(AppError::InternalError)?;

        return Ok(Json(TimestampResponse {
            attestation: existing,
        }));
    }

    // Get next sequence number
    let sequence = server.storage.get_next_sequence(&server.config.id).await?;

    // Create attestation
    let attestation = Attestation::new(hash, server.config.id.clone(), sequence);

    tracing::debug!("Created attestation: {}", attestation);

    // Request signatures from all witnesses concurrently
    let mut tasks = Vec::new();

    for witness in &server.config.witnesses {
        let witness = witness.clone();
        let attestation = attestation.clone();
        let client = server.witness_client.clone();

        let task = tokio::spawn(async move {
            match client.request_signature(&witness, &attestation).await {
                Ok(response) => {
                    tracing::info!("Got signature from witness: {}", witness.id);
                    Some(response)
                }
                Err(e) => {
                    tracing::warn!("Failed to get signature from {}: {}", witness.id, e);
                    None
                }
            }
        });

        tasks.push(task);
    }

    // Collect results and create signed attestation based on signature scheme
    let signed = match server.config.signature_scheme {
        SignatureScheme::Ed25519 => {
            // Ed25519: Collect individual signatures
            let mut signed = SignedAttestation::new(attestation.clone());

            for task in tasks {
                if let Ok(Some(response)) = task.await {
                    signed.add_signature(response.witness_id, response.signature);
                }
            }

            tracing::info!(
                "Collected {} Ed25519 signatures (threshold: {})",
                signed.signature_count(),
                server.config.threshold
            );

            if signed.signature_count() < server.config.threshold {
                return Err(AppError::InsufficientSignatures {
                    got: signed.signature_count(),
                    required: server.config.threshold,
                });
            }

            signed
        }

        SignatureScheme::BLS => {
            // BLS: Collect individual signatures and aggregate
            let mut individual_signatures = Vec::new();
            let mut signer_ids = Vec::new();

            for task in tasks {
                if let Ok(Some(response)) = task.await {
                    individual_signatures.push(response.signature);
                    signer_ids.push(response.witness_id);
                }
            }

            tracing::info!(
                "Collected {} BLS signatures to aggregate (threshold: {})",
                individual_signatures.len(),
                server.config.threshold
            );

            if individual_signatures.len() < server.config.threshold {
                return Err(AppError::InsufficientSignatures {
                    got: individual_signatures.len(),
                    required: server.config.threshold,
                });
            }

            // Aggregate BLS signatures
            let aggregated_signature = witness_core::aggregate_signatures_bls(&individual_signatures)
                .map_err(|e| {
                    tracing::error!("BLS aggregation failed: {}", e);
                    AppError::InvalidSignature
                })?;

            tracing::info!(
                "Aggregated {} BLS signatures into single signature",
                individual_signatures.len()
            );

            SignedAttestation::new_with_aggregated(
                attestation.clone(),
                aggregated_signature,
                signer_ids,
            )
        }
    };

    // Verify signatures
    let verified_count = witness_core::verify_signed_attestation(&signed, &server.config)
        .map_err(|e| {
            tracing::error!("Signature verification failed: {}", e);
            AppError::InvalidSignature
        })?;

    tracing::info!("Verified {} signatures", verified_count);

    // Store attestation
    server.storage.store_attestation(&signed).await?;

    tracing::info!(
        "Successfully timestamped hash {} with sequence {}",
        request.hash,
        signed.attestation.sequence
    );

    // Broadcast event to WebSocket clients (non-blocking)
    let event = AttestationEvent {
        event_type: "attestation",
        hash: request.hash.clone(),
        timestamp: signed.attestation.timestamp,
    };
    // Ignore send errors (no receivers is ok)
    let _ = server.event_tx.send(event);

    Ok(Json(TimestampResponse {
        attestation: signed,
    }))
}

async fn get_timestamp_handler(
    State(server): State<GatewayServer>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up timestamp for hash: {}", hash);

    let hash_bytes = hex::decode(&hash)
        .map_err(|_| AppError::InvalidHash)?;

    let hash_array: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| AppError::InvalidHash)?;

    let attestation = server
        .storage
        .get_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(TimestampResponse { attestation }))
}

async fn verify_handler(
    State(server): State<GatewayServer>,
    Json(request): Json<VerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Verifying attestation for hash: {}", hex::encode(request.attestation.attestation.hash));

    match witness_core::verify_signed_attestation(&request.attestation, &server.config) {
        Ok(verified_count) => {
            let message = format!(
                "Valid: {} of {} signatures verified, {} required",
                verified_count,
                server.config.witnesses.len(),
                server.config.threshold
            );

            Ok(Json(VerifyResponse {
                valid: true,
                verified_signatures: verified_count,
                required_signatures: server.config.threshold,
                message,
            }))
        }
        Err(e) => {
            let message = format!("Invalid: {}", e);

            Ok(Json(VerifyResponse {
                valid: false,
                verified_signatures: 0,
                required_signatures: server.config.threshold,
                message,
            }))
        }
    }
}

// Phase 2: Federation anchor handler
async fn federation_anchor_handler(
    State(server): State<GatewayServer>,
    Json(request): Json<CrossAnchorRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "Received cross-anchor request from network: {}",
        request.batch.network_id
    );

    // Create an attestation for this batch's merkle root
    let sequence = server.storage.get_next_sequence(&server.config.id).await?;

    let attestation = Attestation::new(
        request.batch.merkle_root,
        server.config.id.clone(),
        sequence,
    );

    tracing::debug!("Created attestation for batch cross-anchor: {}", attestation);

    // Request signatures from all witnesses
    let mut tasks = Vec::new();

    for witness in &server.config.witnesses {
        let witness = witness.clone();
        let attestation = attestation.clone();
        let client = server.witness_client.clone();

        let task = tokio::spawn(async move {
            match client.request_signature(&witness, &attestation).await {
                Ok(response) => {
                    tracing::info!("Got signature from witness: {}", witness.id);
                    Some(response)
                }
                Err(e) => {
                    tracing::warn!("Failed to get signature from {}: {}", witness.id, e);
                    None
                }
            }
        });

        tasks.push(task);
    }

    // Collect signatures
    let mut signatures = Vec::new();

    for task in tasks {
        if let Ok(Some(response)) = task.await {
            signatures.push(witness_core::WitnessSignature {
                witness_id: response.witness_id,
                signature: response.signature,
            });
        }
    }

    tracing::info!(
        "Collected {} signatures for cross-anchor (threshold: {})",
        signatures.len(),
        server.config.threshold
    );

    // Verify we have enough signatures
    if signatures.len() < server.config.threshold {
        return Err(AppError::InsufficientSignatures {
            got: signatures.len(),
            required: server.config.threshold,
        });
    }

    // Create cross-anchor
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let cross_anchor = witness_core::CrossAnchor {
        batch: request.batch,
        witnessing_network: server.config.id.clone(),
        signatures,
        timestamp,
    };

    tracing::info!(
        "Created cross-anchor for network: {}",
        cross_anchor.batch.network_id
    );

    Ok(Json(CrossAnchorResponse { cross_anchor }))
}

// Phase 3: Get external anchor proofs for an attestation
async fn get_anchors_handler(
    State(server): State<GatewayServer>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up external anchors for hash: {}", hash);

    let hash_bytes = hex::decode(&hash)
        .map_err(|_| AppError::InvalidHash)?;

    let hash_array: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| AppError::InvalidHash)?;

    // First, check if the attestation exists
    let attestation = server
        .storage
        .get_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;

    // Check if it's in a batch
    let batch_id = server
        .storage
        .get_batch_id_for_attestation(&hash_array)
        .await?;

    match batch_id {
        Some(batch_id) => {
            // Get anchor proofs for this batch
            let proofs: Vec<ExternalAnchorProof> = server
                .storage
                .get_anchor_proofs(batch_id as u64)
                .await?;

            Ok(Json(proofs))
        }
        None => {
            // Attestation exists but not batched yet
            Ok(Json(Vec::<ExternalAnchorProof>::new()))
        }
    }
}

// Error handling
enum AppError {
    InvalidHash,
    NotFound,
    InvalidSignature,
    InsufficientSignatures { got: usize, required: usize },
    InternalError,
    DatabaseError(sqlx::Error),
    Other(anyhow::Error),
    // Freebird errors
    FreebirdTokenRequired,
    FreebirdTokenInvalid,
    FreebirdVerificationFailed(String),
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::DatabaseError(e)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Other(e)
    }
}

impl From<FreebirdError> for AppError {
    fn from(e: FreebirdError) -> Self {
        match e {
            FreebirdError::TokenRequired => AppError::FreebirdTokenRequired,
            FreebirdError::TokenInvalid | FreebirdError::TokenExpired => AppError::FreebirdTokenInvalid,
            FreebirdError::UntrustedIssuer(issuer) => {
                AppError::FreebirdVerificationFailed(format!("Untrusted issuer: {}", issuer))
            }
            FreebirdError::VerificationFailed(msg) => AppError::FreebirdVerificationFailed(msg),
            FreebirdError::HttpError(e) => {
                AppError::FreebirdVerificationFailed(format!("HTTP error: {}", e))
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::InvalidHash => (StatusCode::BAD_REQUEST, "Invalid hash format".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Attestation not found".to_string()),
            AppError::InvalidSignature => (StatusCode::BAD_REQUEST, "Invalid signature".to_string()),
            AppError::InsufficientSignatures { got, required } => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Insufficient signatures: got {}, required {}", got, required),
            ),
            AppError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
            AppError::DatabaseError(e) => {
                tracing::error!("Database error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            }
            AppError::Other(e) => {
                tracing::error!("Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
            }
            // Freebird errors
            AppError::FreebirdTokenRequired => {
                (StatusCode::UNAUTHORIZED, "Freebird token required".to_string())
            }
            AppError::FreebirdTokenInvalid => {
                (StatusCode::FORBIDDEN, "Freebird token invalid or already used".to_string())
            }
            AppError::FreebirdVerificationFailed(msg) => {
                tracing::error!("Freebird verification failed: {}", msg);
                (StatusCode::BAD_GATEWAY, format!("Freebird verification failed: {}", msg))
            }
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

// ============================================================================
// WebSocket Events Handler
// ============================================================================

async fn ws_events_handler(
    ws: WebSocketUpgrade,
    State(server): State<GatewayServer>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, server.event_tx.subscribe()))
}

async fn handle_ws_connection(
    socket: WebSocket,
    mut event_rx: broadcast::Receiver<AttestationEvent>,
) {
    let (mut sender, mut receiver) = socket.split();

    tracing::info!("WebSocket client connected");

    // Spawn a task to forward events to the client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match serde_json::to_string(&event) {
                Ok(json) => {
                    if sender.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to serialize event: {}", e);
                }
            }
        }
    });

    // Handle incoming messages (for ping/pong and close detection)
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Close(_)) => {
                tracing::info!("WebSocket client sent close frame");
                break;
            }
            Ok(Message::Ping(data)) => {
                // Pong is handled automatically by axum
                tracing::debug!("Received ping: {:?}", data);
            }
            Err(e) => {
                tracing::debug!("WebSocket receive error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Abort the send task when the client disconnects
    send_task.abort();
    tracing::info!("WebSocket client disconnected");
}

// ============================================================================
// Visualizer Page
// ============================================================================

async fn visualizer_page() -> impl IntoResponse {
    Html(VISUALIZER_HTML)
}

const VISUALIZER_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Witness Visualizer</title>
    <style>
        :root {
            --bg: #0a0a0a;
            --card-bg: #141414;
            --border: #2a2a2a;
            --text: #e0e0e0;
            --text-dim: #888;
            --accent: #4a9eff;
            --success: #4ade80;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, monospace;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 2rem;
        }
        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }
        h1 span { color: var(--accent); }
        .subtitle {
            color: var(--text-dim);
            font-size: 0.875rem;
            margin-bottom: 2rem;
        }
        .status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 2rem;
            font-size: 0.875rem;
        }
        .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--text-dim);
        }
        .dot.connected { background: var(--success); }
        .dot.connecting { background: #fbbf24; animation: pulse 1s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .events {
            width: 100%;
            max-width: 800px;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }
        .event {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .event-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .event-type {
            color: var(--accent);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }
        .event-time {
            color: var(--text-dim);
            font-size: 0.75rem;
        }
        .event-hash {
            font-size: 0.875rem;
            word-break: break-all;
            color: var(--success);
        }
        .empty {
            color: var(--text-dim);
            text-align: center;
            padding: 2rem;
        }
        .counter {
            font-size: 3rem;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 2rem;
        }
    </style>
</head>
<body>
    <h1><span>Witness</span> Visualizer</h1>
    <p class="subtitle">Real-time attestation events</p>

    <div class="status">
        <span class="dot" id="status-dot"></span>
        <span id="status-text">Connecting...</span>
    </div>

    <div class="counter" id="counter">0</div>

    <div class="events" id="events">
        <div class="empty">Waiting for attestations...</div>
    </div>

    <audio id="chime" preload="auto">
        <source src="data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdH2Onp6WgXBjYXKBjpqfmIx+cGZqd4WSmp2WjH5wZmp3hZKanZaMfnBmaneFlJqdlox+cGZqd4WUmp2Wi35wZWl2hZSanZaLfnBlaXaFlJqdm4t+cGVpdoWUmpybi35wZWl2hZOam5qLfnBlaXaFk5qbmot+cGVpdoWTmpuai35wZWl2hZOam5qLfnBlaXaFk5qbmop+cGVpdoWTmpuain5wZWl2hZOam5qKfnBlaXaFk5qbmop9cGRodYWTmpuZin1wZGh1hZKZm5mKfXBkaHWFkpmamYl9cGRodIWSmZqZiX1wZGh0hZKZmpmJfXBkaHSFkpmamYl9cGRodIWSmZmYiH1vY2d0hJKZmZiIfW9jZ3SEkpiZmId9b2NndISSmJmYh31vY2d0hJKYmZiHfW9jZ3SEkpiZmId9b2NndISSmJiXh31vY2d0hJKYmJeHfW9jZ3SElJiYl4d9b2NndISSmJiXh31vY2Z0hJKYmJeHfG5iZnOEkpiYl4d8bmJmc4SSmJeWhnxuYmZzhJKYl5aGfG5iZnOEkpiXloZ8bmJmc4OSmJeWhnxuYmZzg5KYl5aGfG5iZnODkpiXloV8bmJmc4OSmJeVhXxuYWVyg5KXlpWFfG5hZXKDkpeWlYV8bmFlcoOSl5aVhXxuYWVyg5GXlpWFfG5hZXKDkZeWlYV8bmFlcoORl5WUhHxuYGRxg5GXlZSEfG5gZHGDkZeVlIR8bWBkcYORlpWUhHttYGRxg5GWlZSEe21gZHGDkZaVlIN7bV9jcIOQlpSUg3ttX2Nwg5CWlJSDe21fY3CDkJaUk4N7bV9jcIOQlpSTg3ttX2Nwg5CVlJODe21fY3CDkJWUk4N7bV9jcIOQlZSTg3tsXmJvgo+Vk5KCe2xeYm+Cj5WTkoJ7bF5ib4KPlZOSgntsXmJvgo+VkpKCe2xeYm+Cj5WSkYJ7a11hboKPlZKRgXtrXWFugo+UkpGBe2tdYW6Cj5SRkYF7al1hboKPlJGRgXtqXWBtgo6UkZGAe2pdYG2CjpSRkIB6aVxgbYKOk5GQgHppXGBtgo6TkZCAemlcYG2CjpORkIB6aVxgbYKOk5GQgHppXGBtgo6TkI+AemhbX2yCjpOQj4B6aFtfbIKNk5CPf3poW19sgo2SkI9/emhbX2yCjZKQj396aFtfbIKNkpCPf3poW19sgo2SkI9/emhbX2yCjZKQj396aFtfbIKNkpCPf3poW19sgo2SkI9/emhbX2yCjZKQj396aFtfbIKNkpCPfnlnWl5rgY2SkI9+eWdaXmuBjZKQjn55Z1pea4GNko+OfnlnWl5rgY2Sj45+eWdaXmuBjZKPjn55Z1peaoGMko+OfnhnWV5qgYySj419eGdZXmqBjJGPjX14Z1lean+MkY+NfXhnWV5qf4yRj418eGdZXmp/jJGOjXx4ZlhcaX+MkY6NfHhmWFxpf4yQjo18eGZYXGl/jJCOjHx4ZlhcaX+MkI6MfHhmWFxpf4yQjYx8eGZYXGl/jJCNjHx4ZlhcaX+MkI2MfHhmWFxpf4yQjYx8eGZYXGl/jJCNi3x3ZVdbaH6LkI2Le3dlV1tofouPjYt7d2VXW2h+i4+Ni3t3ZVdbaH6Lj42Le3dlV1tofouPjYt7d2VXW2h+i4+Mi3t3ZVdbaH6Lj4yLe3dlV1tofouPjIt7d2VXW2h+i4+Mi3t3ZVdbaH6Lj4yLe3dlV1tnfouPjIt7d2RWVmd9io6LindnZVZWZn2KjYt6d2ZlVlZmfYqMi3p3ZmVWVmZ9ioyKendlVFVlfIqMint3ZVRVZX2Ki4p6d2VUVmV8ioqKendlVFZlfIqKinp3ZVRVZX2Kiop6d2VUVmV8ioqKendkU1RkfImKiXl2ZFRUZHyJiYl5dmRUVGR8iYmJeXZkVFRkfImJiXl2ZFRUZHyJiYl5dmRUVGR8iYmIeXZkVFRjfImJiHl2ZFRTYnyIiYh4dWNTU2J8iIiId3VjU1NifIiIiHd1Y1NTYnyIiIh3dWNTU2J8iIiId3VjU1NifIiIiHd1Y1NTYnyIiIh3dWNTU2J8iIeHd3VjU1NifIiHh3d1Y1NTYnyIh4d3dWNTU2J8iIeHd3U=" type="audio/wav">
    </audio>

    <script>
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('status-text');
        const eventsContainer = document.getElementById('events');
        const counterEl = document.getElementById('counter');
        const chime = document.getElementById('chime');

        let eventCount = 0;
        let ws;
        let reconnectTimeout;

        function connect() {
            statusDot.className = 'dot connecting';
            statusText.textContent = 'Connecting...';

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            ws = new WebSocket(`${protocol}//${window.location.host}/ws/events`);

            ws.onopen = () => {
                statusDot.className = 'dot connected';
                statusText.textContent = 'Connected';
            };

            ws.onclose = () => {
                statusDot.className = 'dot';
                statusText.textContent = 'Disconnected - reconnecting...';
                reconnectTimeout = setTimeout(connect, 3000);
            };

            ws.onerror = () => {
                ws.close();
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    addEvent(data);
                    playChime();
                } catch (e) {
                    console.error('Failed to parse event:', e);
                }
            };
        }

        function addEvent(data) {
            eventCount++;
            counterEl.textContent = eventCount;

            // Remove empty message if present
            const empty = eventsContainer.querySelector('.empty');
            if (empty) empty.remove();

            const eventEl = document.createElement('div');
            eventEl.className = 'event';
            eventEl.innerHTML = `
                <div class="event-header">
                    <span class="event-type">${data.type}</span>
                    <span class="event-time">${new Date(data.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
                <div class="event-hash">${data.hash}</div>
            `;

            eventsContainer.insertBefore(eventEl, eventsContainer.firstChild);

            // Keep only last 50 events
            while (eventsContainer.children.length > 50) {
                eventsContainer.removeChild(eventsContainer.lastChild);
            }
        }

        function playChime() {
            chime.currentTime = 0;
            chime.play().catch(() => {});
        }

        connect();
    </script>
</body>
</html>
"##;
