use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use witness_core::{
    Attestation, CrossAnchorRequest, CrossAnchorResponse, ExternalAnchorProof, MerkleTree,
    NetworkConfig, SignatureScheme, SignedAttestation, TimestampRequest, TimestampResponse,
    VerifyRequest, VerifyResponse,
};

use crate::admin::{admin_router, AdminState};
use crate::batch_manager::BatchManager;
use crate::federation_client::FederationClient;
use crate::freebird::{FreebirdClient, FreebirdError};
use crate::metrics::{self, RequestTimer};
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
#[allow(dead_code)]
pub struct GatewayServer {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<WitnessClient>,
    batch_manager: Arc<BatchManager>,
    federation_client: Arc<FederationClient>,
    freebird_client: Option<Arc<FreebirdClient>>,
    event_tx: broadcast::Sender<AttestationEvent>,
    metrics_handle: PrometheusHandle,
}

impl GatewayServer {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        batch_manager: Arc<BatchManager>,
        federation_client: Arc<FederationClient>,
        freebird_client: Option<Arc<FreebirdClient>>,
        metrics_handle: PrometheusHandle,
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
            metrics_handle,
        }
    }

    pub async fn run(self, port: u16, admin_state: Option<AdminState>) -> anyhow::Result<()> {
        let mut app = Router::new()
            .route("/", get(root_handler))
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route("/v1/config", get(config_handler))
            .route("/v1/timestamp", post(timestamp_handler))
            .route("/v1/timestamp/:hash", get(get_timestamp_handler))
            .route("/v1/verify", post(verify_handler))
            // Phase 2: Federation endpoints
            .route("/v1/federation/anchor", post(federation_anchor_handler))
            // Phase 3: External anchor endpoints
            .route("/v1/anchors/:hash", get(get_anchors_handler))
            // Phase 6: Light client proof endpoint
            .route("/v1/proof/:hash", get(get_proof_handler))
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

async fn metrics_handler(State(server): State<GatewayServer>) -> impl IntoResponse {
    server.metrics_handle.render()
}

async fn config_handler(State(server): State<GatewayServer>) -> impl IntoResponse {
    Json(server.config.as_ref().clone())
}

async fn timestamp_handler(
    State(server): State<GatewayServer>,
    Json(request): Json<TimestampRequest>,
) -> Result<impl IntoResponse, AppError> {
    let _timer = RequestTimer::new("timestamp");
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
                    metrics::record_signatures(&response.witness_id);
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
                    metrics::record_signatures(&response.witness_id);
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

    // Record metrics
    metrics::record_attestation();

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
    let _attestation = server
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

// ============================================================================
// Phase 6: Light Client Proof Handler
// ============================================================================

/// Response for merkle inclusion proof
#[derive(serde::Serialize)]
struct ProofResponse {
    /// The attestation hash
    hash: String,
    /// Merkle proof siblings (hex-encoded)
    proof: Vec<String>,
    /// Index of the leaf in the merkle tree
    index: usize,
    /// Merkle root of the batch (hex-encoded)
    merkle_root: String,
    /// Batch ID
    batch_id: u64,
}

async fn get_proof_handler(
    State(server): State<GatewayServer>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up merkle proof for hash: {}", hash);

    // Validate hash format
    let hash_bytes = hex::decode(&hash).map_err(|_| AppError::InvalidHash)?;
    let _: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| AppError::InvalidHash)?;

    // Get batch info for this attestation
    let batch_info = server
        .storage
        .get_attestation_batch_info(&hash)
        .await?
        .ok_or(AppError::NotBatched)?;

    let (batch_id, merkle_index, merkle_root) = batch_info;

    // Get all attestation hashes for this batch to rebuild the merkle tree
    let batch_hashes = server
        .storage
        .get_batch_attestation_hashes(batch_id)
        .await?;

    // Build merkle tree and generate proof
    let tree = MerkleTree::new(batch_hashes);
    let proof = tree
        .proof(merkle_index)
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("Failed to generate merkle proof")))?;

    Ok(Json(ProofResponse {
        hash,
        proof: proof.iter().map(hex::encode).collect(),
        index: merkle_index,
        merkle_root: hex::encode(merkle_root),
        batch_id: batch_id as u64,
    }))
}

// Error handling
enum AppError {
    InvalidHash,
    NotFound,
    NotBatched,
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
            AppError::NotBatched => (StatusCode::NOT_FOUND, "Attestation not yet batched".to_string()),
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

async fn root_handler() -> impl IntoResponse {
    axum::response::Redirect::temporary("/admin")
}
