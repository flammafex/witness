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
            sign_rate_limiter: Arc::new(RateLimiter::dashmap(Quota::per_minute(
                NonZeroU32::new(60).unwrap(),
            ))),
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
    // Authenticate first so unauthenticated callers can't exhaust rate limits
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

    // Per-IP rate limiting (defense-in-depth, after auth)
    if server.sign_rate_limiter.check_key(&addr.ip()).is_err() {
        tracing::warn!("Sign rate limit exceeded for IP: {}", addr.ip());
        return Err(AppError::RateLimited);
    }

    tracing::debug!("Received sign request: {}", request.attestation);

    // Validate timestamp (basic sanity check)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let time_diff = request.attestation.timestamp.abs_diff(now);

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use std::net::SocketAddr;
    use witness_core::{Attestation, NetworkConfig, SignedAttestation, WitnessInfo};

    const NETWORK_ID: &str = "test-net";
    const CURRENT_TOKEN: &str = "current-token";
    const PREVIOUS_TOKEN: &str = "previous-token";

    fn test_config(signature_scheme: SignatureScheme, private_key: String) -> WitnessNodeConfig {
        WitnessNodeConfig {
            id: "witness-1".to_string(),
            signature_scheme,
            private_key,
            port: 3000,
            host: "127.0.0.1".to_string(),
            network_id: NETWORK_ID.to_string(),
            signing_auth_token: CURRENT_TOKEN.to_string(),
            previous_signing_auth_token: Some(PREVIOUS_TOKEN.to_string()),
            max_clock_skew: 300,
        }
    }

    fn ed25519_config() -> WitnessNodeConfig {
        let (signing_key, _) = witness_core::generate_keypair();
        test_config(
            SignatureScheme::Ed25519,
            hex::encode(signing_key.to_bytes()),
        )
    }

    fn bls_config() -> WitnessNodeConfig {
        let (secret_key, _) = witness_core::generate_bls_keypair();
        test_config(
            SignatureScheme::BLS,
            witness_core::encode_bls_secret_key(&secret_key),
        )
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_request(network_id: &str, timestamp: u64) -> SignRequest {
        SignRequest {
            attestation: Attestation {
                hash: [7u8; 32],
                timestamp,
                network_id: network_id.to_string(),
                sequence: 1,
            },
        }
    }

    fn auth_headers(token: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        }
        headers
    }

    /// Call `sign_handler` directly (no Router) and unwrap the success body
    /// back into a concrete `SignResponse`.
    async fn sign_success(
        server: &WitnessServer,
        addr: SocketAddr,
        headers: HeaderMap,
        request: SignRequest,
    ) -> SignResponse {
        let result = sign_handler(
            State(server.clone()),
            ConnectInfo(addr),
            headers,
            Json(request),
        )
        .await;

        match result {
            Ok(response) => {
                let body = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
                    .await
                    .expect("failed to read sign response body");
                serde_json::from_slice(&body).expect("failed to parse SignResponse")
            }
            Err(_) => panic!("expected sign_handler to succeed"),
        }
    }

    /// Call `sign_handler` directly and return the exact `AppError` it produced.
    async fn expect_error(
        server: &WitnessServer,
        addr: SocketAddr,
        headers: HeaderMap,
        request: SignRequest,
    ) -> AppError {
        let result = sign_handler(
            State(server.clone()),
            ConnectInfo(addr),
            headers,
            Json(request),
        )
        .await;

        match result {
            Err(e) => e,
            Ok(_) => panic!("expected sign_handler to fail"),
        }
    }

    #[tokio::test]
    async fn missing_bearer_token_rejected() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4001".parse().unwrap();

        let err = expect_error(
            &server,
            addr,
            auth_headers(None),
            sign_request(NETWORK_ID, now()),
        )
        .await;
        assert!(matches!(err, AppError::Unauthorized));
    }

    #[tokio::test]
    async fn wrong_bearer_token_rejected() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4002".parse().unwrap();

        let err = expect_error(
            &server,
            addr,
            auth_headers(Some("wrong-token")),
            sign_request(NETWORK_ID, now()),
        )
        .await;
        assert!(matches!(err, AppError::Unauthorized));
    }

    #[tokio::test]
    async fn current_token_signs_attestation() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4003".parse().unwrap();
        let request = sign_request(NETWORK_ID, now());

        let response = sign_success(
            &server,
            addr,
            auth_headers(Some(CURRENT_TOKEN)),
            request.clone(),
        )
        .await;

        assert_eq!(response.witness_id, server.config.id);
        let verifying_key = server.config.ed25519_verifying_key().unwrap();
        witness_core::verify_signature(&request.attestation, &response.signature, &verifying_key)
            .expect("signature should verify against the config's public key");
    }

    #[tokio::test]
    async fn previous_token_grace_path_signs() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4004".parse().unwrap();
        let request = sign_request(NETWORK_ID, now());

        // Only the previous token matches; this is the rotation grace path.
        let response = sign_success(
            &server,
            addr,
            auth_headers(Some(PREVIOUS_TOKEN)),
            request.clone(),
        )
        .await;

        assert_eq!(response.witness_id, server.config.id);
        let verifying_key = server.config.ed25519_verifying_key().unwrap();
        witness_core::verify_signature(&request.attestation, &response.signature, &verifying_key)
            .expect("signature should verify against the config's public key");
    }

    #[tokio::test]
    async fn unmatched_token_rejected() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4005".parse().unwrap();

        let err = expect_error(
            &server,
            addr,
            auth_headers(Some("neither-current-nor-previous")),
            sign_request(NETWORK_ID, now()),
        )
        .await;
        assert!(matches!(err, AppError::Unauthorized));
    }

    #[tokio::test]
    async fn timestamp_outside_skew_rejected() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4006".parse().unwrap();

        let future = now() + server.config.max_clock_skew + 60;
        let err = expect_error(
            &server,
            addr,
            auth_headers(Some(CURRENT_TOKEN)),
            sign_request(NETWORK_ID, future),
        )
        .await;
        assert!(matches!(err, AppError::InvalidTimestamp));
    }

    #[tokio::test]
    async fn wrong_network_id_rejected() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4007".parse().unwrap();

        let err = expect_error(
            &server,
            addr,
            auth_headers(Some(CURRENT_TOKEN)),
            sign_request("wrong-net", now()),
        )
        .await;
        assert!(matches!(err, AppError::InvalidNetwork));
    }

    #[tokio::test]
    async fn ed25519_signature_verifies_via_signed_attestation() {
        let server = WitnessServer::new(ed25519_config());
        let addr: SocketAddr = "127.0.0.1:4008".parse().unwrap();
        let request = sign_request(NETWORK_ID, now());

        let response = sign_success(
            &server,
            addr,
            auth_headers(Some(CURRENT_TOKEN)),
            request.clone(),
        )
        .await;

        // Build a NetworkConfig carrying this witness and verify through the
        // full SignedAttestation (multi-sig threshold) path.
        let network = NetworkConfig {
            id: NETWORK_ID.to_string(),
            witnesses: vec![WitnessInfo {
                id: server.config.id.clone(),
                pubkey: server.config.public_key(),
                endpoint: "http://127.0.0.1:3000".to_string(),
                auth_token: None,
            }],
            threshold: 1,
            signature_scheme: SignatureScheme::Ed25519,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        };

        let mut signed = SignedAttestation::new(request.attestation);
        signed.add_signature(response.witness_id, response.signature);
        let verified = witness_core::verify_signed_attestation(&signed, &network).unwrap();
        assert_eq!(verified, 1);
    }

    #[tokio::test]
    async fn bls_configuration_signs_and_verifies() {
        let server = WitnessServer::new(bls_config());
        let addr: SocketAddr = "127.0.0.1:4009".parse().unwrap();
        let request = sign_request(NETWORK_ID, now());

        let response = sign_success(
            &server,
            addr,
            auth_headers(Some(CURRENT_TOKEN)),
            request.clone(),
        )
        .await;

        assert_eq!(response.witness_id, server.config.id);
        let public_key = server.config.bls_public_key().unwrap();
        witness_core::verify_signature_bls(&request.attestation, &response.signature, &public_key)
            .expect("BLS signature should verify against the config's public key");
    }

    #[tokio::test]
    async fn corrupt_ed25519_key_returns_internal_error() {
        // "deadbeef" is valid hex but only 4 bytes — too short to be an
        // Ed25519 seed, so key derivation fails inside the sign handler.
        let server = WitnessServer::new(test_config(
            SignatureScheme::Ed25519,
            "deadbeef".to_string(),
        ));
        let addr: SocketAddr = "127.0.0.1:4010".parse().unwrap();

        let err = expect_error(
            &server,
            addr,
            auth_headers(Some(CURRENT_TOKEN)),
            sign_request(NETWORK_ID, now()),
        )
        .await;
        assert!(matches!(err, AppError::InternalError));
    }
}
