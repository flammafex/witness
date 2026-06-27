use axum::{routing::get, routing::post, Json, Router};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use witness_core::{
    encode_public_key, generate_keypair, sign_attestation, NetworkConfig, SignRequest,
    SignResponse, SignatureScheme, WitnessInfo,
};
use witness_gateway::server::GatewayServer;
use witness_gateway::storage::Storage;

fn get_metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
    static HANDLE: std::sync::OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
        std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install metrics recorder")
        })
        .clone()
}

struct TestApp {
    client: reqwest::Client,
    gateway_url: String,
    cancel: CancellationToken,
}

impl TestApp {
    async fn new() -> Self {
        let (signing_key, verifying_key) = generate_keypair();
        let signing_key = Arc::new(signing_key);

        let witness_cancel = CancellationToken::new();
        let witness_cancel_clone = witness_cancel.clone();
        let sk = signing_key.clone();

        let (port_tx, port_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let app = Router::new()
                .route(
                    "/v1/sign",
                    post(move |Json(req): Json<SignRequest>| {
                        let sk = sk.clone();
                        async move {
                            let signature = sign_attestation(&req.attestation, sk.as_ref());
                            Json(SignResponse {
                                witness_id: "test-witness-1".to_string(),
                                signature,
                            })
                        }
                    }),
                )
                .route("/health", get(|| async { "ok" }));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let _ = port_tx.send(port);

            axum::serve(listener, app)
                .with_graceful_shutdown(async move { witness_cancel_clone.cancelled().await })
                .await
                .unwrap();
        });

        let witness_port = port_rx.await.unwrap();

        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_port = gateway_listener.local_addr().unwrap().port();
        drop(gateway_listener);

        let network_config = Arc::new(NetworkConfig {
            id: "test-network".to_string(),
            witnesses: vec![WitnessInfo {
                id: "test-witness-1".to_string(),
                pubkey: encode_public_key(&verifying_key),
                endpoint: format!("http://127.0.0.1:{}", witness_port),
                auth_token: Some("test-auth-token".to_string()),
            }],
            threshold: 1,
            signature_scheme: SignatureScheme::Ed25519,
            federation: Default::default(),
            external_anchors: Default::default(),
            federation_peers: vec![],
        });

        let storage = Arc::new(
            Storage::new("sqlite::memory:")
                .await
                .expect("failed to create storage"),
        );
        storage.migrate().await.expect("failed to migrate storage");

        let server = GatewayServer::new(
            network_config,
            storage,
            None,
            get_metrics_handle(),
            None,
            None,
            false,
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            server
                .run("127.0.0.1", gateway_port, None, None, cancel_clone)
                .await
        });

        let gateway_url = format!("http://127.0.0.1:{}", gateway_port);
        for _ in 0..100 {
            if handle.is_finished() {
                panic!("Gateway server failed to start on port {}", gateway_port);
            }
            if reqwest::get(format!("{}/health", gateway_url))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Self {
            client: reqwest::Client::new(),
            gateway_url,
            cancel,
        }
    }

    async fn post_timestamp(&self, hash: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/timestamp", self.gateway_url))
            .json(&serde_json::json!({ "hash": hash }))
            .send()
            .await
            .expect("failed to send timestamp request")
    }

    async fn get_timestamp(&self, hash: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/v1/timestamp/{}", self.gateway_url, hash))
            .send()
            .await
            .expect("failed to send get timestamp request")
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[tokio::test]
async fn test_submit_attestation() {
    let app = TestApp::new().await;

    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    let response = app.post_timestamp(hash).await;

    let status = response.status();
    let body_text = response.text().await.unwrap();
    assert_eq!(status, 201, "Expected 201 Created, got {:?}", body_text);
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
    assert_eq!(body["status"], "confirmed");
    assert_eq!(body["attestation"]["attestation"]["hash"], hash);
    assert!(
        body["attestation"]["signatures"]["signatures"][0]["signature"]
            .as_str()
            .is_some_and(|signature| signature
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())),
        "signature should be canonical lowercase hex"
    );
}

#[tokio::test]
async fn test_get_timestamp() {
    let app = TestApp::new().await;
    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let response = app.post_timestamp(hash).await;
    assert_eq!(response.status(), 201);

    let response = app.get_timestamp(hash).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "confirmed");
}

#[tokio::test]
async fn test_submit_duplicate() {
    let app = TestApp::new().await;
    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let response = app.post_timestamp(hash).await;
    assert_eq!(response.status(), 201);

    let response = app.post_timestamp(hash).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "confirmed");
}

#[tokio::test]
async fn test_cors_headers() {
    let app = TestApp::new().await;

    let response = app
        .client
        .get(format!("{}/v1/config", app.gateway_url))
        .header("Origin", "http://example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert!(
        response
            .headers()
            .contains_key("access-control-allow-origin"),
        "Expected CORS Access-Control-Allow-Origin header"
    );
}

#[tokio::test]
async fn test_body_limit() {
    let app = TestApp::new().await;

    let large_payload = serde_json::json!({
        "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "data": "x".repeat(70_000)
    });

    let response = app
        .client
        .post(format!("{}/v1/timestamp", app.gateway_url))
        .json(&large_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
}
