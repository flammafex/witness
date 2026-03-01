use axum::{
    extract::{connect_info::ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use governor::{clock::DefaultClock, state::keyed::DashMapStateStore, Quota, RateLimiter};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use witness_core::{SignRequest, SignResponse, SignatureScheme};

use crate::config::WitnessNodeConfig;

#[derive(Clone)]
pub struct WitnessServer {
    config: Arc<WitnessNodeConfig>,
    sign_rate_limiter: Arc<RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>>,
}

impl WitnessServer {
    pub fn new(config: WitnessNodeConfig) -> Self {
        Self {
            config: Arc::new(config),
            sign_rate_limiter: Arc::new(RateLimiter::dashmap(
                Quota::per_minute(NonZeroU32::new(60).unwrap()),
            )),
        }
    }

    pub async fn run(self, host: &str, port: u16) -> anyhow::Result<()> {
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/v1/sign", post(sign_handler))
            .route("/v1/info", get(info_handler))
            .with_state(self);

        let addr = format!("{}:{}", host, port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;

        tracing::info!("Witness node listening on {}", addr);

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn info_handler(State(server): State<WitnessServer>) -> impl IntoResponse {
    Json(serde_json::json!({
        "id": server.config.id,
        "public_key": server.config.public_key(),
        "network_id": server.config.network_id,
    }))
}

async fn sign_handler(
    State(server): State<WitnessServer>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Per-IP rate limiting (defense-in-depth behind bearer auth)
    if server.sign_rate_limiter.check_key(&addr.ip()).is_err() {
        tracing::warn!("Sign rate limit exceeded for IP: {}", addr.ip());
        return Err(AppError::RateLimited);
    }

    let provided_token = bearer_token(&headers).ok_or(AppError::Unauthorized)?;
    let current_matches =
        witness_core::constant_time_eq(provided_token, &server.config.signing_auth_token);
    let previous_matches = server
        .config
        .previous_signing_auth_token
        .as_deref()
        .is_some_and(|prev| witness_core::constant_time_eq(provided_token, prev));

    if !current_matches && !previous_matches {
        tracing::warn!("Rejected unauthorized sign request");
        return Err(AppError::Unauthorized);
    }
    if previous_matches && !current_matches {
        tracing::warn!("Sign request authenticated with previous token — rotate soon");
    }

    tracing::debug!("Received sign request: {}", request.attestation);

    // Validate timestamp (basic sanity check)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let time_diff = if request.attestation.timestamp > now {
        request.attestation.timestamp - now
    } else {
        now - request.attestation.timestamp
    };

    if time_diff > server.config.max_clock_skew {
        tracing::warn!(
            "Timestamp too far from current time: {} vs {}",
            request.attestation.timestamp,
            now
        );
        return Err(AppError::InvalidTimestamp);
    }

    // Validate network ID
    if request.attestation.network_id != server.config.network_id {
        tracing::warn!(
            "Network ID mismatch: expected {}, got {}",
            server.config.network_id,
            request.attestation.network_id
        );
        return Err(AppError::InvalidNetwork);
    }

    // Sign the attestation based on signature scheme
    let signature = match server.config.signature_scheme {
        SignatureScheme::Ed25519 => {
            let signing_key = server.config.ed25519_signing_key().map_err(|e| {
                tracing::error!("Failed to get Ed25519 signing key: {}", e);
                AppError::InternalError
            })?;

            witness_core::sign_attestation(&request.attestation, &signing_key)
        }
        SignatureScheme::BLS => {
            let secret_key = server.config.bls_secret_key().map_err(|e| {
                tracing::error!("Failed to get BLS secret key: {}", e);
                AppError::InternalError
            })?;

            witness_core::sign_attestation_bls(&request.attestation, &secret_key)
        }
    };

    tracing::info!(
        "Signed attestation {} for hash {} using {}",
        request.attestation.sequence,
        hex::encode(request.attestation.hash),
        server.config.signature_scheme
    );

    let response = SignResponse {
        witness_id: server.config.id.clone(),
        signature,
    };

    Ok(Json(response))
}

// Error handling
enum AppError {
    Unauthorized,
    InvalidTimestamp,
    InvalidNetwork,
    InternalError,
    RateLimited,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::InvalidTimestamp => (StatusCode::BAD_REQUEST, "Invalid timestamp"),
            AppError::InvalidNetwork => (StatusCode::BAD_REQUEST, "Invalid network ID"),
            AppError::InternalError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Too many requests"),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    value.strip_prefix("Bearer ")
}

