use axum::{
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, Request, State},
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
use dashmap::DashMap;
use governor::{clock::DefaultClock, state::keyed::DashMapStateStore, Quota, RateLimiter};
use metrics_exporter_prometheus::PrometheusHandle;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;
use witness_core::{Attestation, NetworkConfig, SignResponse, WitnessInfo};

use crate::admin::{admin_router, AdminState};
use crate::epoch::epoch_secs;
use crate::freebird::FreebirdClient;
use crate::metrics;
use crate::real_ip::real_ip;
use crate::storage::Storage;
use crate::traits::WitnessClientTrait;

pub use federation_auth::FederationAuthStore;

mod federation_auth;
mod routes;
mod ws;

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

/// State for `POST /v1/attestations` — includes admission controls.
#[derive(Clone)]
struct AttestationState {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
    freebird_client: Option<Arc<FreebirdClient>>,
    event_tx: broadcast::Sender<AttestationEvent>,
    rate_limiter: Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>,
    creation_locks: Arc<DashMap<[u8; 32], Arc<Mutex<()>>>>,
    behind_proxy: bool,
}

/// State for /v1/federation/anchor POST — includes federation-specific rate limiter.
#[derive(Clone)]
struct FederationState {
    config: Arc<NetworkConfig>,
    storage: Arc<Storage>,
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
        let core_state = CoreState {
            config: self.config.clone(),
            storage: self.storage.clone(),
            event_tx: event_tx.clone(),
            ws_auth_token: self.ws_auth_token.clone(),
        };

        let attestation_state = AttestationState {
            config: self.config.clone(),
            storage: self.storage.clone(),
            freebird_client: self.freebird_client.clone(),
            event_tx: event_tx.clone(),
            rate_limiter: Arc::new(RateLimiter::dashmap(Quota::per_minute(
                NonZeroU32::new(30).unwrap(),
            ))),
            creation_locks: Arc::new(DashMap::new()),
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
            .route("/", get(self::routes::root_handler))
            .route("/health", get(self::routes::health_handler))
            .route("/v1/config", get(self::routes::config_handler))
            .route("/v1/network", get(self::routes::network_config_handler))
            .route(
                "/v1/attestations/:hash",
                get(self::routes::get_attestation_handler),
            )
            .route("/v1/verify", post(self::routes::verify_handler))
            .route("/v1/anchors/:hash", get(self::routes::get_anchors_handler))
            .route("/v1/proof/:hash", get(self::routes::get_proof_handler))
            .route(
                "/v1/bundle/:hash",
                get(self::routes::get_proof_bundle_handler),
            )
            .route("/v1/log/sth", get(self::routes::get_latest_sth_handler))
            .route(
                "/v1/log/sth/:tree_size",
                get(self::routes::get_sth_at_size_handler),
            )
            .route(
                "/v1/log/consistency",
                get(self::routes::get_consistency_handler),
            )
            .route("/v1/log/proof", get(self::routes::get_log_proof_handler))
            .route("/ws/events", get(self::ws::ws_events_handler))
            .with_state(core_state)
            .merge(
                Router::new()
                    .route(
                        "/v1/attestations",
                        post(self::routes::create_attestation_handler),
                    )
                    .with_state(attestation_state),
            )
            .merge(
                Router::new()
                    .route(
                        "/v1/federation/anchor",
                        post(self::routes::federation_anchor_handler),
                    )
                    .with_state(federation_state),
            )
            .merge(
                Router::new()
                    .route("/metrics", get(self::routes::metrics_handler))
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

// Retained for Phase 3 batch/STH signing. Public attestation jobs do not use
// this response-counting helper; their worker validates every signature.
pub(crate) async fn collect_signatures_until_threshold(
    witnesses: &[WitnessInfo],
    attestation: &Attestation,
    client: &Arc<dyn WitnessClientTrait>,
    threshold: usize,
) -> Vec<SignResponse> {
    let mut set = tokio::task::JoinSet::new();

    for witness in witnesses {
        let witness = witness.clone();
        let attestation = attestation.clone();
        let client = client.clone();
        set.spawn(async move {
            match client.request_signature(&witness, &attestation).await {
                Ok(response) => Some(response),
                Err(error) => {
                    tracing::warn!(witness = %witness.id, "Batch signature request failed: {error}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::DefaultBodyLimit, routing::post, Router};
    use tower::Service;

    #[tokio::test]
    async fn body_limit_rejects_oversized_payload() {
        let app = Router::new()
            .route(
                "/test",
                post(|_body: Json<serde_json::Value>| async { "ok" }),
            )
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
            .route(
                "/test",
                post(|_body: Json<serde_json::Value>| async { "ok" }),
            )
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
            response
                .headers()
                .contains_key("access-control-allow-origin"),
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
            response
                .headers()
                .contains_key("access-control-allow-origin"),
            "GET response with Origin header must include Access-Control-Allow-Origin"
        );
    }
}
