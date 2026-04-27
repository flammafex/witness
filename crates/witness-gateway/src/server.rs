use axum::{
    extract::{
        connect_info::ConnectInfo,
        ws::{CloseFrame, Message, WebSocket},
        DefaultBodyLimit, Request, State, WebSocketUpgrade,
    },
    http::{
        header::{AUTHORIZATION, WWW_AUTHENTICATE},
        HeaderValue, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use futures_util::{SinkExt, StreamExt};
use dashmap::DashMap;
use governor::{clock::DefaultClock, state::keyed::DashMapStateStore, Quota, RateLimiter};
use metrics_exporter_prometheus::PrometheusHandle;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use witness_core::{
    merkle::{consistency_path, inclusion_path},
    Attestation, BatchInclusion, CrossAnchorRequest, CrossAnchorResponse, ExternalAnchorProof,
    LogConsistencyProof, MerkleTree, NetworkConfig, ProofBundle, SignResponse, SignatureScheme,
    SignedAttestation, SignedTreeHead, TimestampRequest, TimestampResponse, VerifyRequest,
    VerifyResponse, WitnessInfo,
};

use crate::admin::{admin_router, AdminState};
use crate::epoch::epoch_secs;
use crate::error::AppError;
use crate::freebird::FreebirdClient;
use crate::metrics::{self, RequestTimer};
use crate::real_ip::real_ip;
use crate::storage::Storage;
use crate::witness_client::WitnessClient;

// ============================================================================
// Public types
// ============================================================================

/// Public-facing subset of NetworkConfig — excludes internal endpoints, peer URLs, and auth tokens.
#[derive(serde::Serialize)]
struct NetworkConfigPublic {
    id: String,
    threshold: usize,
    signature_scheme: witness_core::SignatureScheme,
    witness_count: usize,
}

/// Event broadcast to WebSocket clients when an attestation is created.
#[derive(Clone, Debug, serde::Serialize)]
pub struct AttestationEvent {
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub hash: String,
    pub timestamp: u64,
}

// ============================================================================
// Focused state structs
// ============================================================================

/// State for /v1/timestamp POST — includes rate limiter and Freebird.
#[derive(Clone)]
struct TimestampState {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<WitnessClient>,
    freebird_client: Option<Arc<FreebirdClient>>,
    event_tx: broadcast::Sender<AttestationEvent>,
    rate_limiter: Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>,
    behind_proxy: bool,
}

/// State for /v1/federation/anchor POST — includes federation-specific rate limiter.
#[derive(Clone)]
struct FederationState {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    witness_client: Arc<WitnessClient>,
    rate_limiter: Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>,
    behind_proxy: bool,
    auth_store: Arc<FederationAuthStore>,
}

/// State for /metrics GET — only needs the handle and optional auth token.
#[derive(Clone)]
struct MetricsState {
    handle: PrometheusHandle,
    metrics_token: Option<Arc<str>>,
}

/// State for all other routes — config, storage, WebSocket broadcast.
#[derive(Clone)]
struct CoreState {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    event_tx: broadcast::Sender<AttestationEvent>,
    ws_auth_token: Option<Arc<str>>,
}

/// State threaded through the admin auth middleware.
#[derive(Clone)]
struct AdminAuthState {
    api_key: Arc<str>,
    rate_limiter: Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>,
    behind_proxy: bool,
}

// ============================================================================
// Federation auth token store
// ============================================================================

const FEDERATION_TOKEN_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;

/// Entry for a federation auth token with expiry.
#[derive(Clone)]
struct TokenEntry {
    token: String,
    expires_at: u64,
}

/// In-memory store for federation auth tokens.
///
/// Supports per-partner token generation, automatic expiry of previous
/// tokens when rotated, and periodic cleanup.
#[derive(Clone)]
pub struct FederationAuthStore {
    current: DashMap<String, TokenEntry>,
    expired: DashMap<String, TokenEntry>,
}

impl FederationAuthStore {
    pub fn new() -> Self {
        Self {
            current: DashMap::new(),
            expired: DashMap::new(),
        }
    }

    /// Seed a current token from static configuration.
    pub fn seed_current(&self, partner_id: &str, token: String) {
        let entry = TokenEntry {
            token,
            expires_at: u64::MAX,
        };
        self.current.insert(partner_id.to_string(), entry);
    }

    /// Seed a previous (expired) token from static configuration.
    pub fn seed_expired(&self, partner_id: &str, token: String, expires_at: u64) {
        let entry = TokenEntry { token, expires_at };
        self.expired.insert(partner_id.to_string(), entry);
    }

    /// Generate a new auth token for a partner.
    ///
    /// If a current token exists, it is moved to the expired map with
    /// `expires_at = now` (immediately invalid).
    pub fn generate_auth_token(&self, partner_id: &str) -> String {
        let now = epoch_secs();
        let token = generate_random_token();

        if let Some((_, old)) = self.current.remove(partner_id) {
            self.expired.insert(
                partner_id.to_string(),
                TokenEntry {
                    token: old.token,
                    expires_at: now,
                },
            );
        }

        let entry = TokenEntry {
            token: token.clone(),
            expires_at: now.saturating_add(FEDERATION_TOKEN_LIFETIME_SECS),
        };
        self.current.insert(partner_id.to_string(), entry);
        token
    }

    /// Validate whether a token is current and not expired.
    pub fn validate_auth_token(&self, token: &str) -> bool {
        let now = epoch_secs();
        for entry in self.current.iter() {
            if entry.value().token == token && entry.value().expires_at > now {
                return true;
            }
        }
        false
    }

    /// Check if any current tokens are configured.
    pub fn has_current_tokens(&self) -> bool {
        !self.current.is_empty()
    }

    /// Remove all expired entries (both current and expired maps).
    pub fn cleanup_expired(&self, now: u64) {
        let before_current = self.current.len();
        self.current.retain(|_, entry| entry.expires_at > now);
        let after_current = self.current.len();
        if before_current != after_current {
            tracing::info!(
                "Cleaned up {} expired current federation tokens",
                before_current - after_current
            );
        }

        let before_expired = self.expired.len();
        self.expired.retain(|_, entry| entry.expires_at > now);
        let after_expired = self.expired.len();
        if before_expired != after_expired {
            tracing::info!(
                "Cleaned up {} expired previous federation tokens",
                before_expired - after_expired
            );
        }
    }
}

fn generate_random_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const TOKEN_LEN: usize = 64;
    let mut rng = rand::thread_rng();
    (0..TOKEN_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// ============================================================================
// GatewayServer — thin orchestrator
// ============================================================================

pub struct GatewayServer {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    freebird_client: Option<Arc<FreebirdClient>>,
    metrics_handle: PrometheusHandle,
    ws_auth_token: Option<Arc<str>>,
    metrics_token: Option<Arc<str>>,
    behind_proxy: bool,
}

impl GatewayServer {
    pub fn new(
        config: Arc<NetworkConfig>,
        storage: Arc<Storage>,
        freebird_client: Option<Arc<FreebirdClient>>,
        metrics_handle: PrometheusHandle,
        ws_auth_token: Option<String>,
        metrics_token: Option<String>,
        behind_proxy: bool,
    ) -> Self {
        Self {
            config,
            storage,
            freebird_client,
            metrics_handle,
            ws_auth_token: ws_auth_token.map(Arc::<str>::from),
            metrics_token: metrics_token.map(Arc::<str>::from),
            behind_proxy,
        }
    }

    pub async fn run(
        self,
        host: &str,
        port: u16,
        admin_state: Option<AdminState>,
        admin_api_key: Option<String>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<()> {
        let (event_tx, _) = broadcast::channel(256);
        let witness_client = Arc::new(WitnessClient::new());

        let core_state = CoreState {
            config: self.config.clone(),
            storage: self.storage.clone(),
            event_tx: event_tx.clone(),
            ws_auth_token: self.ws_auth_token.clone(),
        };

        let timestamp_state = TimestampState {
            config: self.config.clone(),
            storage: self.storage.clone(),
            witness_client: witness_client.clone(),
            freebird_client: self.freebird_client.clone(),
            event_tx: event_tx.clone(),
            rate_limiter: Arc::new(RateLimiter::dashmap(Quota::per_minute(
                NonZeroU32::new(30).unwrap(),
            ))),
            behind_proxy: self.behind_proxy,
        };

        let auth_store = Arc::new(FederationAuthStore::new());
        if let Some(token) = &self.config.federation.inbound_auth_token {
            auth_store.seed_current("_default", token.clone());
        }
        if let Some(token) = &self.config.federation.previous_inbound_auth_token {
            auth_store.seed_expired("_default", token.clone(), epoch_secs());
        }

        let federation_state = FederationState {
            config: self.config.clone(),
            storage: self.storage.clone(),
            witness_client: witness_client.clone(),
            rate_limiter: Arc::new(RateLimiter::dashmap(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            behind_proxy: self.behind_proxy,
            auth_store: auth_store.clone(),
        };

        let cleanup_store = auth_store;
        let cleanup_cancel = cancel.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = epoch_secs();
                        cleanup_store.cleanup_expired(now);
                    }
                    _ = cleanup_cancel.cancelled() => break,
                }
            }
        });

        let metrics_state = MetricsState {
            handle: self.metrics_handle,
            metrics_token: self.metrics_token.clone(),
        };

        let behind_proxy = self.behind_proxy;

        let mut app = Router::new()
            .route("/", get(root_handler))
            .route("/health", get(health_handler))
            .route("/v1/config", get(config_handler))
            .route("/v1/network", get(network_config_handler))
            .route("/v1/timestamp/:hash", get(get_timestamp_handler))
            .route("/v1/verify", post(verify_handler))
            .route("/v1/anchors/:hash", get(get_anchors_handler))
            .route("/v1/proof/:hash", get(get_proof_handler))
            .route("/v1/bundle/:hash", get(get_proof_bundle_handler))
            .route("/v1/log/sth", get(get_latest_sth_handler))
            .route("/v1/log/sth/:tree_size", get(get_sth_at_size_handler))
            .route("/v1/log/consistency", get(get_consistency_handler))
            .route("/v1/log/proof", get(get_log_proof_handler))
            .route("/ws/events", get(ws_events_handler))
            .with_state(core_state)
            .merge(
                Router::new()
                    .route("/v1/timestamp", post(timestamp_handler))
                    .with_state(timestamp_state),
            )
            .merge(
                Router::new()
                    .route("/v1/federation/anchor", post(federation_anchor_handler))
                    .with_state(federation_state),
            )
            .merge(
                Router::new()
                    .route("/metrics", get(metrics_handler))
                    .with_state(metrics_state),
            )
            .layer(DefaultBodyLimit::max(65_536))
            .layer(CorsLayer::permissive());

        if let Some(admin) = admin_state {
            let api_key = admin_api_key.ok_or_else(|| {
                anyhow::anyhow!("admin_api_key must be set when admin_ui is enabled")
            })?;
            let auth_state = AdminAuthState {
                api_key: Arc::<str>::from(api_key),
                rate_limiter: Arc::new(RateLimiter::dashmap(Quota::per_minute(
                    NonZeroU32::new(5).unwrap(),
                ))),
                behind_proxy,
            };

            app = app.nest(
                "/admin",
                admin_router(admin).layer(middleware::from_fn_with_state(
                    auth_state,
                    admin_auth_middleware,
                )),
            );
        }

        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;

        tracing::info!("Gateway listening on {}", addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { cancel.cancelled().await })
        .await?;
        Ok(())
    }
}

// ============================================================================
// Admin middleware
// ============================================================================

async fn admin_auth_middleware(
    State(state): State<AdminAuthState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    // Authenticate first — rate-limiting before auth leaks state to unauthenticated callers
    if !is_admin_authorized(&request, &state.api_key) {
        return admin_unauthorized_response();
    }

    let client_ip = real_ip(request.headers(), addr, state.behind_proxy);

    // Rate-limit authenticated requests to prevent abuse of expensive admin operations
    if state.rate_limiter.check_key(&client_ip).is_err() {
        tracing::warn!("Admin rate limit exceeded for IP: {}", client_ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "Too many requests" })),
        )
            .into_response();
    }

    next.run(request).await
}

fn is_admin_authorized(request: &Request, expected_key: &str) -> bool {
    if let Some(provided_key) = request
        .headers()
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
    {
        if witness_core::constant_time_eq(provided_key, expected_key) {
            return true;
        }
    }

    if let Some(auth) = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            if witness_core::constant_time_eq(token, expected_key) {
                return true;
            }
        }

        if let Some(encoded) = auth
            .strip_prefix("Basic ")
            .or_else(|| auth.strip_prefix("basic "))
        {
            if basic_password_matches(encoded, expected_key) {
                return true;
            }
        }
    }

    false
}

fn basic_password_matches(encoded_credentials: &str, expected_key: &str) -> bool {
    let Ok(decoded) = BASE64_STANDARD.decode(encoded_credentials) else {
        return false;
    };
    let Ok(decoded_str) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((_, password)) = decoded_str.split_once(':') else {
        return false;
    };

    witness_core::constant_time_eq(password, expected_key)
}

fn admin_unauthorized_response() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="witness-admin", charset="UTF-8""#),
    );
    response
}

// ============================================================================
// Shared signature-collection helper
// ============================================================================

/// Request signatures from all witnesses concurrently, stopping as soon as
/// `threshold` successful responses have been received. Tasks for the
/// remaining witnesses are cancelled via `JoinSet::abort_all`.
pub(crate) async fn collect_signatures_until_threshold(
    witnesses: &[WitnessInfo],
    attestation: &Attestation,
    client: &Arc<WitnessClient>,
    threshold: usize,
) -> Vec<SignResponse> {
    let mut set = tokio::task::JoinSet::new();

    for witness in witnesses {
        let witness = witness.clone();
        let attestation = attestation.clone();
        let client = client.clone();

        set.spawn(async move {
            match client.request_signature(&witness, &attestation).await {
                Ok(resp) => {
                    tracing::info!("Got signature from witness: {}", witness.id);
                    Some(resp)
                }
                Err(e) => {
                    tracing::warn!("Failed to get signature from {}: {}", witness.id, e);
                    None
                }
            }
        });
    }

    let mut responses = Vec::new();

    while let Some(result) = set.join_next().await {
        if let Ok(Some(response)) = result {
            metrics::record_signatures(&response.witness_id);
            responses.push(response);
            if responses.len() >= threshold {
                set.abort_all();
                break;
            }
        }
    }

    responses
}

// ============================================================================
// CoreState handlers
// ============================================================================

async fn root_handler() -> impl IntoResponse {
    axum::response::Redirect::temporary("/admin")
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn config_handler(State(state): State<CoreState>) -> impl IntoResponse {
    Json(NetworkConfigPublic {
        id: state.config.id.clone(),
        threshold: state.config.threshold,
        signature_scheme: state.config.signature_scheme,
        witness_count: state.config.witnesses.len(),
    })
}

/// Return the full [`NetworkConfig`] (witnesses, threshold, signature scheme,
/// federation peers, external anchor providers) for offline verification of
/// proof bundles.  Auth tokens are omitted via `#[serde(skip_serializing)]`
/// on the relevant fields.
async fn network_config_handler(State(state): State<CoreState>) -> impl IntoResponse {
    Json((*state.config).clone())
}

async fn get_timestamp_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up timestamp for hash: {}", hash);

    let hash_bytes = hex::decode(&hash).map_err(|_| AppError::InvalidHash)?;
    let hash_array: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    let attestation = state
        .storage
        .get_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;

    let status = state
        .storage
        .get_attestation_status(&hash_array)
        .await?
        .unwrap_or_else(|| "confirmed".to_string());

    Ok(Json(TimestampResponse {
        attestation,
        status,
    }))
}

async fn verify_handler(
    State(state): State<CoreState>,
    Json(request): Json<VerifyRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "Verifying attestation for hash: {}",
        hex::encode(request.attestation.attestation.hash)
    );

    match witness_core::verify_signed_attestation(&request.attestation, &state.config) {
        Ok(verified_count) => {
            let message = format!(
                "Valid: {} of {} signatures verified, {} required",
                verified_count,
                state.config.witnesses.len(),
                state.config.threshold
            );
            Ok(Json(VerifyResponse {
                valid: true,
                verified_signatures: verified_count,
                required_signatures: state.config.threshold,
                message,
            }))
        }
        Err(e) => {
            tracing::debug!("Attestation verification failed: {}", e);
            Ok(Json(VerifyResponse {
                valid: false,
                verified_signatures: 0,
                required_signatures: state.config.threshold,
                message: "Signature verification failed".to_string(),
            }))
        }
    }
}

async fn get_anchors_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up external anchors for hash: {}", hash);

    let hash_bytes = hex::decode(&hash).map_err(|_| AppError::InvalidHash)?;
    let hash_array: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    let _attestation = state
        .storage
        .get_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;

    let batch_id = state
        .storage
        .get_batch_id_for_attestation(&hash_array)
        .await?;

    match batch_id {
        Some(batch_id) => {
            let proofs: Vec<ExternalAnchorProof> =
                state.storage.get_anchor_proofs(batch_id as u64).await?;
            Ok(Json(proofs))
        }
        None => Ok(Json(Vec::<ExternalAnchorProof>::new())),
    }
}

/// Response for merkle inclusion proof.
#[derive(serde::Serialize)]
struct ProofResponse {
    hash: String,
    proof: Vec<String>,
    index: usize,
    merkle_root: String,
    batch_id: u64,
}

async fn get_proof_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up merkle proof for hash: {}", hash);

    let hash_bytes = hex::decode(&hash).map_err(|_| AppError::InvalidHash)?;
    let _: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    let batch_info = state
        .storage
        .get_attestation_batch_info(&hash)
        .await?
        .ok_or(AppError::NotBatched)?;

    let (batch_id, merkle_index, merkle_root) = batch_info;

    let batch_hashes = state.storage.get_batch_attestation_hashes(batch_id).await?;

    let tree = MerkleTree::new(batch_hashes);
    let proof = tree
        .inclusion_proof(merkle_index)
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("Failed to generate merkle proof")))?;

    Ok(Json(ProofResponse {
        hash,
        proof: proof.siblings.iter().map(hex::encode).collect(),
        index: merkle_index,
        merkle_root: hex::encode(merkle_root),
        batch_id: batch_id as u64,
    }))
}

/// Return a self-contained [`ProofBundle`] for a hash.
///
/// The bundle includes the home network's threshold-signed attestation,
/// merkle inclusion proof (if batched), peer cross-anchors, and external
/// anchor proofs.  Clients can verify the bundle offline against the
/// network configurations using [`witness_core::verify_proof_bundle`].
async fn get_proof_bundle_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Building proof bundle for hash: {}", hash);

    let hash_bytes = hex::decode(&hash).map_err(|_| AppError::InvalidHash)?;
    let hash_array: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    let signed_attestation = state
        .storage
        .get_attestation(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut batch_inclusion = None;
    let mut cross_anchors = Vec::new();
    let mut external_anchors = Vec::new();

    if let Some((batch_id, merkle_index, merkle_root)) =
        state.storage.get_attestation_batch_info(&hash).await?
    {
        let batch = state
            .storage
            .get_batch(batch_id)
            .await?
            .ok_or(AppError::NotFound)?;

        let batch_hashes = state.storage.get_batch_attestation_hashes(batch_id).await?;
        let tree = MerkleTree::new(batch_hashes);
        let mut merkle_proof = tree
            .inclusion_proof(merkle_index)
            .ok_or_else(|| AppError::Other(anyhow::anyhow!("Failed to generate merkle proof")))?;
        // The on-disk merkle_root is authoritative; copy it onto the proof so
        // verifiers don't depend on whatever the in-memory tree just computed.
        merkle_proof.root = merkle_root;

        batch_inclusion = Some(BatchInclusion {
            batch: batch.clone(),
            merkle_proof,
        });

        cross_anchors = state.storage.get_cross_anchors(batch_id).await?;
        external_anchors = state.storage.get_anchor_proofs(batch_id as u64).await?;
    }

    Ok(Json(ProofBundle {
        signed_attestation,
        batch_inclusion,
        cross_anchors,
        external_anchors,
    }))
}

// ============================================================================
// RFC 9162 Certificate Transparency v2 endpoints
// ============================================================================

/// Latest signed tree head for the gateway's home network.  Returns 404 if
/// no batches have closed yet (the log is empty).
async fn get_latest_sth_handler(
    State(state): State<CoreState>,
) -> Result<impl IntoResponse, AppError> {
    let sth = state
        .storage
        .get_latest_sth(&state.config.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(sth))
}

/// Look up a historical STH at a specific tree size.  Auditors use this to
/// pin a known-good snapshot and walk forward via consistency proofs.
async fn get_sth_at_size_handler(
    State(state): State<CoreState>,
    axum::extract::Path(tree_size): axum::extract::Path<u64>,
) -> Result<impl IntoResponse, AppError> {
    let sth = state
        .storage
        .get_sth(&state.config.id, tree_size)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(sth))
}

#[derive(serde::Deserialize)]
struct ConsistencyQuery {
    first: u64,
    second: u64,
}

/// RFC 9162 §4.10 GetConsistency: prove that the log of size `first` is a
/// prefix of the log of size `second`.  Both endpoints are inclusive — they
/// must each correspond to a previously published STH.
async fn get_consistency_handler(
    State(state): State<CoreState>,
    axum::extract::Query(q): axum::extract::Query<ConsistencyQuery>,
) -> Result<impl IntoResponse, AppError> {
    if q.first == 0 || q.first > q.second {
        return Err(AppError::InvalidHash);
    }

    let old_sth = state
        .storage
        .get_sth(&state.config.id, q.first)
        .await?
        .ok_or(AppError::NotFound)?;
    let new_sth = state
        .storage
        .get_sth(&state.config.id, q.second)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut leaves = state.storage.get_log_leaves(&state.config.id).await?;
    if (leaves.len() as u64) < q.second {
        return Err(AppError::InternalError);
    }
    leaves.truncate(q.second as usize);

    let hashes = consistency_path(q.first as usize, &leaves)
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("invalid consistency proof bounds")))?;

    Ok(Json(LogConsistencyProof {
        old_sth,
        new_sth,
        hashes,
    }))
}

#[derive(serde::Deserialize)]
struct LogProofQuery {
    hash: String,
    tree_size: u64,
}

#[derive(serde::Serialize)]
struct LogInclusionProofResponse {
    leaf_index: u64,
    tree_size: u64,
    audit_path: Vec<String>,
    sth: SignedTreeHead,
}

/// RFC 9162 §4.11 GetProofByHash: inclusion proof for `hash` against the
/// STH at `tree_size`.
async fn get_log_proof_handler(
    State(state): State<CoreState>,
    axum::extract::Query(q): axum::extract::Query<LogProofQuery>,
) -> Result<impl IntoResponse, AppError> {
    let hash_bytes = hex::decode(&q.hash).map_err(|_| AppError::InvalidHash)?;
    let hash_array: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    let leaf_index = state
        .storage
        .get_log_index(&state.config.id, &hash_array)
        .await?
        .ok_or(AppError::NotBatched)?;

    if leaf_index >= q.tree_size {
        // Leaf was added after the requested STH — can't prove inclusion.
        return Err(AppError::NotFound);
    }

    let sth = state
        .storage
        .get_sth(&state.config.id, q.tree_size)
        .await?
        .ok_or(AppError::NotFound)?;

    let mut leaves = state.storage.get_log_leaves(&state.config.id).await?;
    if (leaves.len() as u64) < q.tree_size {
        return Err(AppError::InternalError);
    }
    leaves.truncate(q.tree_size as usize);

    let path = inclusion_path(leaf_index as usize, &leaves)
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("inclusion path generation failed")))?;

    Ok(Json(LogInclusionProofResponse {
        leaf_index,
        tree_size: q.tree_size,
        audit_path: path.iter().map(hex::encode).collect(),
        sth,
    }))
}

async fn ws_events_handler(
    ws: WebSocketUpgrade,
    State(state): State<CoreState>,
) -> impl IntoResponse {
    let token = state.ws_auth_token.clone();
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state.event_tx.subscribe(), token))
}

// ============================================================================
// TimestampState handler
// ============================================================================

async fn timestamp_handler(
    State(state): State<TimestampState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<TimestampRequest>,
) -> Result<impl IntoResponse, AppError> {
    let _timer = RequestTimer::new("timestamp");

    let client_ip = real_ip(&headers, addr, state.behind_proxy);

    if state.rate_limiter.check_key(&client_ip).is_err() {
        tracing::warn!("Timestamp rate limit exceeded for IP: {}", client_ip);
        return Err(AppError::RateLimited);
    }

    tracing::info!("Received timestamp request for hash: {}", request.hash);

    if let Some(ref freebird) = state.freebird_client {
        match &request.freebird_token {
            Some(token) => {
                freebird.verify(token).await?;
                tracing::info!("Freebird token verified for hash: {}", request.hash);
            }
            None if freebird.is_required() => {
                return Err(AppError::FreebirdTokenRequired);
            }
            None => {
                tracing::debug!("No Freebird token provided (permissive mode)");
            }
        }
    }

    let hash_bytes = hex::decode(&request.hash).map_err(|_| AppError::InvalidHash)?;
    let hash: [u8; 32] = hash_bytes.try_into().map_err(|_| AppError::InvalidHash)?;

    if state.storage.check_duplicate(&hash).await? {
        tracing::info!("Hash already timestamped: {}", request.hash);
        let existing = state
            .storage
            .get_attestation(&hash)
            .await?
            .ok_or(AppError::InternalError)?;
        let status = state
            .storage
            .get_attestation_status(&hash)
            .await?
            .unwrap_or_else(|| "confirmed".to_string());

        if status == "pending" {
            return Ok((
                StatusCode::ACCEPTED,
                Json(TimestampResponse {
                    attestation: existing,
                    status: "pending".to_string(),
                }),
            ));
        }

        return Ok((
            StatusCode::OK,
            Json(TimestampResponse {
                attestation: existing,
                status: "confirmed".to_string(),
            }),
        ));
    }

    let sequence = state.storage.get_next_sequence(&state.config.id).await?;
    let attestation = Attestation::new(hash, state.config.id.clone(), sequence);
    tracing::debug!("Created attestation: {}", attestation);

    let signed = SignedAttestation::new(attestation.clone());
    state
        .storage
        .store_attestation(&signed, Some("pending"))
        .await?;

    let responses = collect_signatures_until_threshold(
        &state.config.witnesses,
        &attestation,
        &state.witness_client,
        state.config.threshold,
    )
    .await;

    let signed = match state.config.signature_scheme {
        SignatureScheme::Ed25519 => {
            let mut signed = SignedAttestation::new(attestation.clone());
            for response in responses {
                signed.add_signature(response.witness_id, response.signature);
            }
            tracing::info!(
                "Collected {} Ed25519 signatures (threshold: {})",
                signed.signature_count(),
                state.config.threshold
            );
            if signed.signature_count() < state.config.threshold {
                return Err(AppError::InsufficientSignatures {
                    got: signed.signature_count(),
                    required: state.config.threshold,
                });
            }
            signed
        }
        SignatureScheme::BLS => {
            let count = responses.len();
            if count < state.config.threshold {
                return Err(AppError::InsufficientSignatures {
                    got: count,
                    required: state.config.threshold,
                });
            }
            let signer_ids: Vec<String> = responses.iter().map(|r| r.witness_id.clone()).collect();
            let individual_signatures: Vec<Vec<u8>> =
                responses.into_iter().map(|r| r.signature).collect();
            tracing::info!(
                "Collected {} BLS signatures to aggregate (threshold: {})",
                count,
                state.config.threshold
            );
            let aggregated = witness_core::aggregate_signatures_bls(&individual_signatures)
                .map_err(|e| {
                    tracing::error!("BLS aggregation failed: {}", e);
                    AppError::InvalidSignature
                })?;
            tracing::info!("Aggregated {} BLS signatures into single signature", count);
            SignedAttestation::new_with_aggregated(attestation.clone(), aggregated, signer_ids)
        }
    };

    let verified_count =
        witness_core::verify_signed_attestation(&signed, &state.config).map_err(|e| {
            tracing::error!("Signature verification failed: {}", e);
            AppError::InvalidSignature
        })?;
    tracing::info!("Verified {} signatures", verified_count);

    state.storage.store_attestation(&signed, None).await?;
    state.storage.confirm_attestation(&hash).await?;
    metrics::record_attestation();

    tracing::info!(
        "Successfully timestamped hash {} with sequence {}",
        request.hash,
        signed.attestation.sequence
    );

    let event = AttestationEvent {
        event_type: "attestation",
        hash: request.hash.clone(),
        timestamp: signed.attestation.timestamp,
    };
    let _ = state.event_tx.send(event);

    Ok((
        StatusCode::CREATED,
        Json(TimestampResponse {
            attestation: signed,
            status: "confirmed".to_string(),
        }),
    ))
}

// ============================================================================
// FederationState handler
// ============================================================================

async fn federation_anchor_handler(
    State(state): State<FederationState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CrossAnchorRequest>,
) -> Result<impl IntoResponse, AppError> {
    if !state.auth_store.has_current_tokens() {
        tracing::warn!("Rejected federation request: inbound_auth_token not configured");
        return Err(AppError::Unauthorized);
    }

    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match provided {
        Some(token) if state.auth_store.validate_auth_token(token) => {}
        _ => {
            tracing::warn!("Rejected unauthenticated federation anchor request");
            return Err(AppError::Unauthorized);
        }
    }

    let client_ip = real_ip(&headers, addr, state.behind_proxy);
    if state.rate_limiter.check_key(&client_ip).is_err() {
        tracing::warn!("Federation rate limit exceeded for IP: {}", client_ip);
        return Err(AppError::RateLimited);
    }

    tracing::info!(
        "Received cross-anchor request from network: {}",
        request.batch.network_id
    );

    let sequence = state.storage.get_next_sequence(&state.config.id).await?;
    let attestation =
        Attestation::new(request.batch.merkle_root, state.config.id.clone(), sequence);
    tracing::debug!(
        "Created attestation for batch cross-anchor: {}",
        attestation
    );

    let responses = collect_signatures_until_threshold(
        &state.config.witnesses,
        &attestation,
        &state.witness_client,
        state.config.threshold,
    )
    .await;

    if responses.len() < state.config.threshold {
        return Err(AppError::InsufficientSignatures {
            got: responses.len(),
            required: state.config.threshold,
        });
    }

    tracing::info!(
        "Collected {} signatures for cross-anchor (threshold: {})",
        responses.len(),
        state.config.threshold
    );

    let witness_attestation = match state.config.signature_scheme {
        SignatureScheme::Ed25519 => {
            let mut signed = SignedAttestation::new(attestation.clone());
            for response in responses {
                signed.add_signature(response.witness_id, response.signature);
            }
            signed
        }
        SignatureScheme::BLS => {
            let signer_ids: Vec<String> = responses.iter().map(|r| r.witness_id.clone()).collect();
            let individual_signatures: Vec<Vec<u8>> =
                responses.into_iter().map(|r| r.signature).collect();
            let aggregated = witness_core::aggregate_signatures_bls(&individual_signatures)
                .map_err(|e| {
                    tracing::error!("BLS aggregation for cross-anchor failed: {}", e);
                    AppError::InvalidSignature
                })?;
            SignedAttestation::new_with_aggregated(attestation.clone(), aggregated, signer_ids)
        }
    };

    // Sanity check: re-verify the cross-anchor attestation against our own config
    // before sending it to the peer.  Catches any aggregation/signing bugs locally
    // instead of leaking bad cross-anchors into the federation.
    witness_core::verify_signed_attestation(&witness_attestation, &state.config).map_err(|e| {
        tracing::error!(
            "Self-verification of cross-anchor attestation failed: {}",
            e
        );
        AppError::InvalidSignature
    })?;

    let timestamp = epoch_secs();

    let cross_anchor = witness_core::CrossAnchor {
        batch: request.batch,
        witnessing_network: state.config.id.clone(),
        witness_attestation,
        timestamp,
    };

    tracing::info!(
        "Created cross-anchor for network: {}",
        cross_anchor.batch.network_id
    );

    Ok(Json(CrossAnchorResponse { cross_anchor }))
}

// ============================================================================
// MetricsState handler
// ============================================================================

async fn metrics_handler(
    State(state): State<MetricsState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(ref expected_token) = state.metrics_token {
        let auth_ok = headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| witness_core::constant_time_eq(t, expected_token))
            .unwrap_or(false);

        if !auth_ok {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "Unauthorized" })),
            )
                .into_response();
        }
    }
    state.handle.render().into_response()
}

// ============================================================================
// WebSocket handler
// ============================================================================

async fn handle_ws_connection(
    socket: WebSocket,
    mut event_rx: broadcast::Receiver<AttestationEvent>,
    required_token: Option<Arc<str>>,
) {
    let (mut sender, mut receiver) = socket.split();

    tracing::info!("WebSocket client connected");

    // First-message authentication: if a token is configured, challenge the client before
    // forwarding any events.
    if let Some(ref expected_token) = required_token {
        if sender
            .send(Message::Text(r#"{"type":"auth_required"}"#.to_string()))
            .await
            .is_err()
        {
            return;
        }

        let auth_msg = tokio::time::timeout(Duration::from_secs(5), receiver.next()).await;

        match auth_msg {
            Ok(Some(Ok(Message::Text(text)))) => {
                let provided = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("token").and_then(|t| t.as_str()).map(str::to_owned));

                if !provided
                    .as_deref()
                    .map(|t| witness_core::constant_time_eq(t, expected_token))
                    .unwrap_or(false)
                {
                    tracing::warn!("WebSocket client failed authentication");
                    let _ = sender
                        .send(Message::Close(Some(CloseFrame {
                            code: 4001,
                            reason: "Unauthorized".into(),
                        })))
                        .await;
                    return;
                }
                tracing::info!("WebSocket client authenticated");
            }
            _ => {
                tracing::warn!("WebSocket auth timeout or protocol error");
                return;
            }
        }
    }

    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            match serde_json::to_string(&event) {
                Ok(json) => {
                    if sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to serialize event: {}", e);
                }
            }
        }
    });

    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Close(_)) => {
                tracing::info!("WebSocket client sent close frame");
                break;
            }
            Ok(Message::Ping(data)) => {
                tracing::debug!("Received ping: {:?}", data);
            }
            Err(e) => {
                tracing::debug!("WebSocket receive error: {}", e);
                break;
            }
            _ => {}
        }
    }

    send_task.abort();
    tracing::info!("WebSocket client disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::DefaultBodyLimit,
        routing::post,
        Router,
    };
    use tower::Service;

    #[tokio::test]
    async fn body_limit_rejects_oversized_payload() {
        let app = Router::new()
            .route("/test", post(|_body: Json<serde_json::Value>| async { "ok" }))
            .layer(DefaultBodyLimit::max(65_536));

        let large_payload = serde_json::json!({
            "data": "x".repeat(70_000)
        });
        let body = Body::from(large_payload.to_string());

        let mut app = app;
        let response = app
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/test")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn body_limit_accepts_sized_payload() {
        let app = Router::new()
            .route("/test", post(|_body: Json<serde_json::Value>| async { "ok" }))
            .layer(DefaultBodyLimit::max(65_536));

        let small_payload = serde_json::json!({
            "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        });
        let body = Body::from(small_payload.to_string());

        let mut app = app;
        let response = app
            .call(
                Request::builder()
                    .method("POST")
                    .uri("/test")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cors_preflight_returns_allow_origin_header() {
        let app = Router::new()
            .route("/v1/config", get(|| async { "ok" }))
            .layer(CorsLayer::permissive());

        let mut app = app;
        let response = app
            .call(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/config")
                    .header("Access-Control-Request-Method", "GET")
                    .header("Access-Control-Request-Headers", "origin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().contains_key("access-control-allow-origin"),
            "Preflight response must include Access-Control-Allow-Origin header"
        );
    }

    #[tokio::test]
    async fn cors_get_with_origin_returns_allow_origin_header() {
        let app = Router::new()
            .route("/v1/config", get(|| async { "ok" }))
            .layer(CorsLayer::permissive());

        let mut app = app;
        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .uri("/v1/config")
                    .header("Origin", "http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().contains_key("access-control-allow-origin"),
            "GET response with Origin header must include Access-Control-Allow-Origin"
        );
    }

    #[test]
    fn federation_old_token_invalidated_on_rotation() {
        let store = FederationAuthStore::new();
        let partner = "peer-network-1";

        let token_a = store.generate_auth_token(partner);
        assert!(store.validate_auth_token(&token_a), "initial token should be valid");

        let token_b = store.generate_auth_token(partner);
        assert!(
            !store.validate_auth_token(&token_a),
            "old token should be invalidated after rotation"
        );
        assert!(store.validate_auth_token(&token_b), "new token should be valid");
    }

    #[test]
    fn federation_expired_tokens_cleaned_up() {
        let store = FederationAuthStore::new();
        let partner = "peer-network-1";

        let token_a = store.generate_auth_token(partner);
        let _token_b = store.generate_auth_token(partner);

        assert!(store.expired.contains_key(partner), "old token should be in expired map");

        store.cleanup_expired(epoch_secs());

        assert!(
            !store.expired.contains_key(partner),
            "expired token should be cleaned up"
        );
        assert!(
            store.current.contains_key(partner),
            "current token should remain after cleanup"
        );
        assert!(
            !store.validate_auth_token(&token_a),
            "cleaned-up old token should no longer validate"
        );
    }
}
