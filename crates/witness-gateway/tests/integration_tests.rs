use axum::{routing::get, routing::post, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use witness_core::{
    encode_public_key, generate_keypair, sign_attestation, FreebirdConfig, NetworkConfig,
    SignRequest, SignResponse, SignatureScheme, WitnessInfo,
};
use witness_gateway::freebird::FreebirdClient;
use witness_gateway::node_client::NodeClient;
use witness_gateway::reconciler::{AttestationWorker, Reconciler};
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
    storage: Arc<Storage>,
}

impl TestApp {
    async fn new() -> Self {
        Self::new_with_worker(true).await
    }

    async fn new_with_worker(start_worker: bool) -> Self {
        Self::new_with_options(start_worker, true, None).await
    }

    async fn new_with_options(
        start_worker: bool,
        valid_witness_signature: bool,
        freebird_client: Option<Arc<FreebirdClient>>,
    ) -> Self {
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
                            let signature = if valid_witness_signature {
                                sign_attestation(&req.attestation, sk.as_ref())
                            } else {
                                vec![0; 64]
                            };
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
            network_config.clone(),
            storage.clone(),
            freebird_client,
            get_metrics_handle(),
            None,
            None,
            false,
        );

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        if start_worker {
            let worker = AttestationWorker::new(
                network_config,
                storage.clone(),
                Arc::new(NodeClient::new()),
            );
            tokio::spawn(Reconciler::new(worker, cancel.clone()).run());
        }

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
            storage,
        }
    }

    async fn post_attestation(&self, hash: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/v1/attestations", self.gateway_url))
            .json(&serde_json::json!({ "hash": hash }))
            .send()
            .await
            .expect("failed to send attestation request")
    }

    async fn get_attestation(&self, hash: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/v1/attestations/{}", self.gateway_url, hash))
            .send()
            .await
            .expect("failed to get attestation job")
    }

    async fn wait_confirmed(&self, hash: &str) -> serde_json::Value {
        for _ in 0..200 {
            let response = self.get_attestation(hash).await;
            if response.status().is_success() {
                let body: serde_json::Value = response.json().await.unwrap();
                if body["status"] == "confirmed" {
                    return body;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("attestation job did not confirm")
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
    let response = app.post_attestation(hash).await;

    let status = response.status();
    let body_text = response.text().await.unwrap();
    assert_eq!(status, 202, "Expected 202 Accepted, got {:?}", body_text);
    let body: serde_json::Value = serde_json::from_str(&body_text).unwrap();
    assert_eq!(body["status"], "pending");
    assert_eq!(body["attestation"]["hash"], hash);
    assert!(body.get("signed_attestation").is_none());

    let body = app.wait_confirmed(hash).await;
    assert_eq!(body["signed_attestation"]["attestation"]["hash"], hash);
    assert!(
        body["signed_attestation"]["signatures"]["signatures"][0]["signature"]
            .as_str()
            .is_some_and(|signature| signature
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())),
        "signature should be canonical lowercase hex"
    );
}

#[tokio::test]
async fn test_get_attestation_status() {
    let app = TestApp::new().await;
    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let response = app.post_attestation(hash).await;
    assert_eq!(response.status(), 202);
    app.wait_confirmed(hash).await;

    let response = app.get_attestation(hash).await;
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["status"], "confirmed");
}

#[tokio::test]
async fn test_submit_duplicate() {
    let app = TestApp::new().await;
    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

    let first = app.post_attestation(hash).await;
    assert_eq!(first.status(), 202);
    let first: serde_json::Value = first.json().await.unwrap();

    let duplicate = app.post_attestation(hash).await;
    assert_eq!(duplicate.status(), 202);
    let duplicate: serde_json::Value = duplicate.json().await.unwrap();
    assert_eq!(duplicate["attestation"], first["attestation"]);

    app.wait_confirmed(hash).await;
    let confirmed_duplicate = app.post_attestation(hash).await;
    assert_eq!(confirmed_duplicate.status(), 200);
    let body: serde_json::Value = confirmed_duplicate.json().await.unwrap();
    assert_eq!(body["status"], "confirmed");
}

#[tokio::test]
async fn legacy_timestamp_routes_are_removed() {
    let app = TestApp::new().await;
    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    assert_eq!(
        app.client
            .post(format!("{}/v1/timestamp", app.gateway_url))
            .json(&serde_json::json!({ "hash": hash }))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        app.client
            .get(format!("{}/v1/timestamp/{hash}", app.gateway_url))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test]
async fn pending_jobs_cannot_return_proofs_or_bundles() {
    let app = TestApp::new_with_worker(false).await;
    let hash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    assert_eq!(app.post_attestation(hash).await.status(), 202);
    assert_eq!(
        app.client
            .get(format!("{}/v1/proof/{hash}", app.gateway_url))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        app.client
            .get(format!("{}/v1/bundle/{hash}", app.gateway_url))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test]
async fn confirmed_batched_job_preserves_proof_and_bundle_behavior() {
    let app = TestApp::new().await;
    let hash = "d591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    assert_eq!(app.post_attestation(hash).await.status(), 202);
    app.wait_confirmed(hash).await;
    let hash_array: [u8; 32] = hex::decode(hash).unwrap().try_into().unwrap();
    let leaves = vec![hash_array];
    let batch = witness_core::AttestationBatch {
        id: 0,
        network_id: "test-network".to_string(),
        merkle_root: witness_core::MerkleTree::new(leaves.clone()).root(),
        period_start: 1,
        period_end: 2,
        attestation_count: 1,
    };
    app.storage.store_batch(&batch, &leaves).await.unwrap();

    let proof = app
        .client
        .get(format!("{}/v1/proof/{hash}", app.gateway_url))
        .send()
        .await
        .unwrap();
    assert_eq!(proof.status(), 200);
    let proof: serde_json::Value = proof.json().await.unwrap();
    assert_eq!(proof["hash"], hash);
    assert_eq!(proof["index"], 0);

    let bundle = app
        .client
        .get(format!("{}/v1/bundle/{hash}", app.gateway_url))
        .send()
        .await
        .unwrap();
    assert_eq!(bundle.status(), 200);
    let bundle: witness_core::ProofBundle = bundle.json().await.unwrap();
    assert_eq!(bundle.signed_attestation.attestation.hash, hash_array);
    assert!(bundle.batch_inclusion.is_some());
}

#[tokio::test]
async fn invalid_quorum_is_visible_as_retryable_api_state() {
    let app = TestApp::new_with_options(true, false, None).await;
    let hash = "b591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    assert_eq!(app.post_attestation(hash).await.status(), 202);
    for _ in 0..200 {
        let response = app.get_attestation(hash).await;
        let body: serde_json::Value = response.json().await.unwrap();
        if body["status"] == "retryable" {
            assert!(body.get("signed_attestation").is_none());
            assert!(body["attempts"].as_u64().unwrap() >= 1);
            assert!(body["next_attempt_at"].as_u64().is_some());
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("invalid quorum never became API-visible retryable state");
}

#[tokio::test]
async fn existing_job_retry_does_not_reconsume_one_use_freebird_token() {
    let verification_count = Arc::new(AtomicUsize::new(0));
    let count = verification_count.clone();
    let verifier = Router::new().route(
        "/v1/verify",
        post(move || {
            let count = count.clone();
            async move {
                let attempt = count.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::json!({ "ok": attempt == 0 }))
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let verifier_url = format!("http://{}", listener.local_addr().unwrap());
    let verifier_handle =
        tokio::spawn(async move { axum::serve(listener, verifier).await.unwrap() });
    let freebird = Arc::new(FreebirdClient::new(FreebirdConfig {
        verifier_url: Some(verifier_url),
        required: true,
        consume_tokens: true,
        allow_insecure_local: true,
    }));
    let app = TestApp::new_with_options(false, true, Some(freebird)).await;
    let hash = "c591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    let token_body = serde_json::json!({
        "hash": hash,
        "freebird_token": { "token_b64": "one-use-token" }
    });

    let invalid = app
        .client
        .post(format!("{}/v1/attestations", app.gateway_url))
        .json(&serde_json::json!({
            "hash": "invalid",
            "freebird_token": { "token_b64": "one-use-token" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 400);
    assert_eq!(verification_count.load(Ordering::SeqCst), 0);

    let first_request = app
        .client
        .post(format!("{}/v1/attestations", app.gateway_url))
        .json(&token_body)
        .send();
    let retry_request = app
        .client
        .post(format!("{}/v1/attestations", app.gateway_url))
        .json(&token_body)
        .send();
    let (first, retry) = tokio::join!(first_request, retry_request);
    let first = first.unwrap();
    let retry = retry.unwrap();
    assert_eq!(first.status(), 202);
    assert_eq!(retry.status(), 202);
    let first_job: serde_json::Value = first.json().await.unwrap();
    let retry_job: serde_json::Value = retry.json().await.unwrap();
    assert_eq!(retry_job["attestation"], first_job["attestation"]);
    assert_eq!(verification_count.load(Ordering::SeqCst), 1);

    let later_retry = app
        .client
        .post(format!("{}/v1/attestations", app.gateway_url))
        .json(&token_body)
        .send()
        .await
        .unwrap();
    assert_eq!(later_retry.status(), 202);
    let later_job: serde_json::Value = later_retry.json().await.unwrap();
    assert_eq!(later_job["attestation"], first_job["attestation"]);
    assert_eq!(verification_count.load(Ordering::SeqCst), 1);
    verifier_handle.abort();
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
        .post(format!("{}/v1/attestations", app.gateway_url))
        .json(&large_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
}
