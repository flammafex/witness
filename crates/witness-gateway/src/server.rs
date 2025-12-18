use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use witness_core::{
    AnonymousTimestampRequest, AnonymousTimestampResponse, Attestation, CrossAnchorRequest,
    CrossAnchorResponse, ExternalAnchorProof, NetworkConfig, ProofResponse, SignatureScheme,
    SignedAttestation, TimestampRequest, TimestampResponse, VerifyRequest, VerifyResponse,
    WsSubscription,
};

use crate::admin::{admin_router, AdminState};
use crate::batch_manager::BatchManager;
use crate::federation_client::FederationClient;
use crate::freebird_client::FreebirdClient;
use crate::notifications::{ClientSubscription, NotificationBroadcaster};
use crate::storage::Storage;
use crate::witness_client::WitnessClient;

#[derive(Clone)]
pub struct GatewayServer {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<WitnessClient>,
    batch_manager: Arc<BatchManager>,
    federation_client: Arc<FederationClient>,
    freebird_client: Arc<FreebirdClient>,
    broadcaster: Arc<NotificationBroadcaster>,
}

impl GatewayServer {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        batch_manager: Arc<BatchManager>,
        federation_client: Arc<FederationClient>,
        freebird_client: Arc<FreebirdClient>,
        broadcaster: Arc<NotificationBroadcaster>,
    ) -> Self {
        Self {
            config,
            storage,
            witness_client: Arc::new(WitnessClient::new()),
            batch_manager,
            federation_client,
            freebird_client,
            broadcaster,
        }
    }

    pub async fn run(self, port: u16, admin_state: Option<AdminState>) -> anyhow::Result<()> {
        let mut app = Router::new()
            .route("/health", get(health_handler))
            .route("/v1/config", get(config_handler))
            .route("/v1/timestamp", post(timestamp_handler))
            .route("/v1/timestamp/:hash", get(get_timestamp_handler))
            .route("/v1/verify", post(verify_handler))
            // Phase 2: Federation endpoints
            .route("/v1/federation/anchor", post(federation_anchor_handler))
            // Phase 3: External anchor endpoints
            .route("/v1/anchors/:hash", get(get_anchors_handler))
            // Light client: Merkle proof endpoint
            .route("/v1/proof/:hash", get(get_proof_handler))
            // Phase 6: Freebird anonymous submission
            .route("/v1/anonymous/timestamp", post(anonymous_timestamp_handler))
            // Phase 6: WebSocket notifications
            .route("/v1/ws", get(ws_handler))
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

    // Broadcast notification
    server.broadcaster.notify_attestation(
        &signed.attestation.hash,
        signed.attestation.sequence,
        false, // not anonymous
    );

    tracing::info!(
        "Successfully timestamped hash {} with sequence {}",
        request.hash,
        signed.attestation.sequence
    );

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

// Light client: Merkle proof handler for offline verification
async fn get_proof_handler(
    State(server): State<GatewayServer>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up merkle proof for hash: {}", hash);

    let hash_bytes = hex::decode(&hash).map_err(|_| AppError::InvalidHash)?;

    let hash_array: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| AppError::InvalidHash)?;

    // Get the attestation
    let attestation = server
        .storage
        .get_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;

    // Get the merkle proof
    let merkle_proof = server
        .storage
        .get_merkle_proof_for_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotBatched)?;

    // Get the batch ID to retrieve batch info and external anchors
    let batch_id = server
        .storage
        .get_batch_id_for_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotBatched)?;

    let batch = server
        .storage
        .get_batch(batch_id)
        .await?
        .ok_or(AppError::InternalError)?;

    // Get external anchor proofs for this batch
    let external_anchors = server
        .storage
        .get_anchor_proofs(batch_id as u64)
        .await?;

    Ok(Json(ProofResponse {
        attestation,
        merkle_proof,
        batch,
        external_anchors,
    }))
}

// Phase 6: Freebird anonymous submission handler
async fn anonymous_timestamp_handler(
    State(server): State<GatewayServer>,
    Json(request): Json<AnonymousTimestampRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "Received anonymous timestamp request for hash: {}",
        request.hash
    );

    // Check if Freebird is enabled
    if !server.freebird_client.is_enabled() {
        tracing::warn!("Anonymous submission rejected: Freebird is not enabled");
        return Err(AppError::FreebirdDisabled);
    }

    // Verify the Freebird token first
    tracing::debug!(
        "Verifying Freebird token: epoch={}, exp={}",
        request.epoch,
        request.exp
    );

    let verify_result = server
        .freebird_client
        .verify_token(&request.token_b64, request.exp, request.epoch)
        .await
        .map_err(|e| {
            tracing::error!("Freebird verification error: {}", e);
            AppError::FreebirdVerificationError(e.to_string())
        })?;

    if !verify_result.ok {
        tracing::warn!(
            "Freebird token verification failed: {:?}",
            verify_result.error
        );
        return Err(AppError::FreebirdTokenInvalid(
            verify_result.error.unwrap_or_else(|| "Unknown error".to_string()),
        ));
    }

    tracing::info!(
        "Freebird token verified at timestamp: {}",
        verify_result.verified_at
    );

    // Parse hash
    let hash_bytes = hex::decode(&request.hash).map_err(|_| AppError::InvalidHash)?;

    let hash: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    // Check for duplicate
    if server.storage.check_duplicate(&hash).await? {
        tracing::info!("Hash already timestamped (anonymous): {}", request.hash);

        // Return existing attestation
        let existing = server
            .storage
            .get_attestation(&hash)
            .await?
            .ok_or(AppError::InternalError)?;

        return Ok(Json(AnonymousTimestampResponse {
            attestation: existing,
            anonymous: true,
            freebird_verified_at: verify_result.verified_at,
        }));
    }

    // Get next sequence number
    let sequence = server.storage.get_next_sequence(&server.config.id).await?;

    // Create attestation
    let attestation = Attestation::new(hash, server.config.id.clone(), sequence);

    tracing::debug!("Created anonymous attestation: {}", attestation);

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
                "Collected {} Ed25519 signatures for anonymous submission (threshold: {})",
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
                "Collected {} BLS signatures to aggregate for anonymous submission (threshold: {})",
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
            let aggregated_signature =
                witness_core::aggregate_signatures_bls(&individual_signatures).map_err(|e| {
                    tracing::error!("BLS aggregation failed: {}", e);
                    AppError::InvalidSignature
                })?;

            tracing::info!(
                "Aggregated {} BLS signatures into single signature",
                individual_signatures.len()
            );

            SignedAttestation::new_with_aggregated(attestation.clone(), aggregated_signature, signer_ids)
        }
    };

    // Verify signatures
    let verified_count = witness_core::verify_signed_attestation(&signed, &server.config).map_err(|e| {
        tracing::error!("Signature verification failed: {}", e);
        AppError::InvalidSignature
    })?;

    tracing::info!("Verified {} signatures for anonymous submission", verified_count);

    // Store attestation (marked as anonymous)
    server.storage.store_attestation(&signed).await?;
    server
        .storage
        .mark_anonymous(&hash, verify_result.verified_at)
        .await?;

    // Broadcast notification (anonymous flag = true)
    server.broadcaster.notify_attestation(
        &signed.attestation.hash,
        signed.attestation.sequence,
        true, // anonymous submission
    );

    tracing::info!(
        "Successfully timestamped hash {} anonymously with sequence {}",
        request.hash,
        signed.attestation.sequence
    );

    Ok(Json(AnonymousTimestampResponse {
        attestation: signed,
        anonymous: true,
        freebird_verified_at: verify_result.verified_at,
    }))
}

// Phase 6: WebSocket handler for real-time notifications
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(server): State<GatewayServer>,
) -> impl IntoResponse {
    tracing::info!("New WebSocket connection request");
    ws.on_upgrade(move |socket| handle_ws_connection(socket, server))
}

async fn handle_ws_connection(socket: WebSocket, server: GatewayServer) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to notifications
    let mut broadcast_rx = server.broadcaster.subscribe();

    // Track client subscriptions (default: all enabled)
    let mut subscription = ClientSubscription::new();

    // Send connected message
    let connected_notification = server
        .broadcaster
        .create_connected_notification(subscription.list());

    if let Ok(json) = serde_json::to_string(&connected_notification) {
        if sender.send(Message::Text(json)).await.is_err() {
            tracing::debug!("Failed to send connected message, client disconnected");
            return;
        }
    }

    tracing::info!(
        "WebSocket client connected, subscribers={}",
        server.broadcaster.subscriber_count()
    );

    // Handle both incoming messages and broadcast notifications
    loop {
        tokio::select! {
            // Handle incoming messages from client (subscription management)
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        // Try to parse as subscription request
                        if let Ok(sub_request) = serde_json::from_str::<WsSubscription>(&text) {
                            if !sub_request.subscribe.is_empty() {
                                subscription.subscribe(&sub_request.subscribe);
                                tracing::debug!("Client subscribed to: {:?}", sub_request.subscribe);
                            }
                            if !sub_request.unsubscribe.is_empty() {
                                subscription.unsubscribe(&sub_request.unsubscribe);
                                tracing::debug!("Client unsubscribed from: {:?}", sub_request.unsubscribe);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::debug!("WebSocket client sent close frame");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Err(e)) => {
                        tracing::debug!("WebSocket error: {}", e);
                        break;
                    }
                    None => {
                        tracing::debug!("WebSocket stream ended");
                        break;
                    }
                    _ => {}
                }
            }

            // Forward broadcast notifications to client
            notification = broadcast_rx.recv() => {
                match notification {
                    Ok(notif) => {
                        // Check if client is subscribed to this notification type
                        if subscription.is_subscribed(&notif.notification_type) {
                            if let Ok(json) = serde_json::to_string(&notif) {
                                if sender.send(Message::Text(json)).await.is_err() {
                                    tracing::debug!("Failed to send notification, client disconnected");
                                    break;
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("WebSocket client lagged by {} messages", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("Broadcast channel closed");
                        break;
                    }
                }
            }
        }
    }

    tracing::info!(
        "WebSocket client disconnected, remaining subscribers={}",
        server.broadcaster.subscriber_count().saturating_sub(1)
    );
}

// Error handling
enum AppError {
    InvalidHash,
    NotFound,
    NotBatched,
    InvalidSignature,
    InsufficientSignatures { got: usize, required: usize },
    InternalError,
    FreebirdDisabled,
    FreebirdVerificationError(String),
    FreebirdTokenInvalid(String),
    DatabaseError(sqlx::Error),
    Other(anyhow::Error),
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

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::InvalidHash => (StatusCode::BAD_REQUEST, "Invalid hash format".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Attestation not found".to_string()),
            AppError::NotBatched => (
                StatusCode::NOT_FOUND,
                "Attestation exists but has not been included in a batch yet. Retry after batch period.".to_string(),
            ),
            AppError::InvalidSignature => (StatusCode::BAD_REQUEST, "Invalid signature".to_string()),
            AppError::InsufficientSignatures { got, required } => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Insufficient signatures: got {}, required {}", got, required),
            ),
            AppError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
            AppError::FreebirdDisabled => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Anonymous submissions are not enabled".to_string(),
            ),
            AppError::FreebirdVerificationError(msg) => (
                StatusCode::BAD_GATEWAY,
                format!("Freebird verification service error: {}", msg),
            ),
            AppError::FreebirdTokenInvalid(msg) => (
                StatusCode::UNAUTHORIZED,
                format!("Invalid Freebird token: {}", msg),
            ),
            AppError::DatabaseError(e) => {
                tracing::error!("Database error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            }
            AppError::Other(e) => {
                tracing::error!("Error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string())
            }
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
