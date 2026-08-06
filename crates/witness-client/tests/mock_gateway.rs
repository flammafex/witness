//! Integration tests for `witness-client` against an `axum` mock gateway.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use witness_client::{Error, PollConfig, WitnessClient};
use witness_core::types::{AttestationJobResponse, AttestationJobStatus};
use witness_core::{
    Attestation, NetworkConfig, SignedAttestation, VerifyRequest, VerifyResponse, WitnessInfo,
};

const HASH: [u8; 32] = [7u8; 32];

fn pending_job() -> AttestationJobResponse {
    AttestationJobResponse {
        attestation: Attestation {
            hash: HASH,
            timestamp: 100,
            network_id: "network".to_string(),
            sequence: 1,
        },
        status: AttestationJobStatus::Pending,
        signed_attestation: None,
        attempts: 0,
        next_attempt_at: Some(100),
        last_error: None,
    }
}

fn confirmed_job() -> AttestationJobResponse {
    let mut signed = SignedAttestation::new(Attestation {
        hash: HASH,
        timestamp: 100,
        network_id: "network".to_string(),
        sequence: 1,
    });
    signed.add_signature("w1".to_string(), vec![1, 2, 3]);
    AttestationJobResponse {
        attestation: signed.attestation.clone(),
        status: AttestationJobStatus::Confirmed,
        signed_attestation: Some(signed),
        attempts: 1,
        next_attempt_at: None,
        last_error: None,
    }
}

fn failed_job() -> AttestationJobResponse {
    AttestationJobResponse {
        attestation: Attestation {
            hash: HASH,
            timestamp: 100,
            network_id: "network".to_string(),
            sequence: 1,
        },
        status: AttestationJobStatus::Failed,
        signed_attestation: None,
        attempts: 3,
        next_attempt_at: None,
        last_error: Some("witness timeout".to_string()),
    }
}

fn malformed_confirmed_job() -> AttestationJobResponse {
    AttestationJobResponse {
        attestation: Attestation {
            hash: HASH,
            timestamp: 100,
            network_id: "network".to_string(),
            sequence: 1,
        },
        status: AttestationJobStatus::Confirmed,
        signed_attestation: None,
        attempts: 1,
        next_attempt_at: None,
        last_error: None,
    }
}

fn sample_network() -> NetworkConfig {
    NetworkConfig {
        id: "net".to_string(),
        witnesses: vec![WitnessInfo {
            id: "w1".to_string(),
            pubkey: "abc".to_string(),
            endpoint: "http://localhost:1".to_string(),
            auth_token: None,
        }],
        threshold: 1,
        signature_scheme: Default::default(),
        federation: Default::default(),
        external_anchors: Default::default(),
        federation_peers: vec![],
    }
}

async fn spawn_server(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{address}")
}

fn fast_poll() -> PollConfig {
    PollConfig {
        interval: Duration::from_millis(10),
        timeout: Duration::from_secs(5),
        respect_next_attempt_at: false,
    }
}

#[tokio::test]
async fn create_and_get_attestation_roundtrip() {
    let expected_hash = hex::encode(HASH);
    let app = Router::new()
        .route("/v1/attestations", post(|| async { Json(pending_job()) }))
        .route(
            "/v1/attestations/:hash",
            get(move |Path(hash): Path<String>| {
                let expected_hash = expected_hash.clone();
                async move {
                    assert_eq!(hash, expected_hash);
                    Json(pending_job())
                }
            }),
        );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let created = client.create_attestation(HASH, None).await.unwrap();
    assert_eq!(created.status, AttestationJobStatus::Pending);

    let fetched = client.get_attestation(HASH).await.unwrap();
    assert_eq!(fetched.attestation, created.attestation);
}

#[tokio::test]
async fn wait_for_confirmation_accepted() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls2 = calls.clone();
    let app = Router::new().route(
        "/v1/attestations/:hash",
        get(move |Path(_): Path<String>| {
            let calls = calls2.clone();
            async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    Json(pending_job())
                } else {
                    Json(confirmed_job())
                }
            }
        }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let signed = client
        .wait_for_confirmation(HASH, fast_poll())
        .await
        .unwrap();
    assert_eq!(signed.attestation.hash, HASH);
}

#[tokio::test]
async fn wait_for_confirmation_failed_job() {
    let app = Router::new().route(
        "/v1/attestations/:hash",
        get(|| async { Json(failed_job()) }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let err = client
        .wait_for_confirmation(HASH, fast_poll())
        .await
        .unwrap_err();
    match err {
        Error::JobFailed {
            hash,
            attempts,
            last_error,
        } => {
            assert_eq!(hash, hex::encode(HASH));
            assert_eq!(attempts, 3);
            assert_eq!(last_error.as_deref(), Some("witness timeout"));
        }
        other => panic!("expected JobFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_confirmation_timeout() {
    let app = Router::new().route(
        "/v1/attestations/:hash",
        get(|| async { Json(pending_job()) }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let poll = PollConfig {
        interval: Duration::from_millis(5),
        timeout: Duration::from_millis(50),
        respect_next_attempt_at: false,
    };
    let err = client.wait_for_confirmation(HASH, poll).await.unwrap_err();
    match err {
        Error::ConfirmationTimeout {
            hash, last_status, ..
        } => {
            assert_eq!(hash, hex::encode(HASH));
            assert_eq!(last_status, AttestationJobStatus::Pending);
        }
        other => panic!("expected ConfirmationTimeout, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_confirmation_confirmed_without_signatures_is_decode_error() {
    let app = Router::new().route(
        "/v1/attestations/:hash",
        get(|| async { Json(malformed_confirmed_job()) }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let err = client
        .wait_for_confirmation(HASH, fast_poll())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Decode(_)),
        "expected Decode, got {err:?}"
    );
}

#[tokio::test]
async fn get_anchors_404_is_not_found_not_empty() {
    let app = Router::new().route(
        "/v1/anchors/:hash",
        get(|| async { (StatusCode::NOT_FOUND, "not found").into_response() }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let err = client.get_anchors(HASH).await.unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn network_and_network_from_fetch() {
    let config = sample_network();
    let app = Router::new().route(
        "/v1/network",
        get(move || async move { Json(config.clone()) }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let fetched = client.network().await.unwrap();
    assert_eq!(fetched.id, "net");

    let fetched_from = client.network_from(&url).await.unwrap();
    assert_eq!(fetched_from.id, "net");
}

#[tokio::test]
async fn verify_remote_posts_to_verify() {
    let app = Router::new().route(
        "/v1/verify",
        post(|Json(_req): Json<VerifyRequest>| async move {
            Json(VerifyResponse {
                valid: true,
                verified_signatures: 1,
                required_signatures: 1,
                message: "ok".to_string(),
            })
        }),
    );
    let url = spawn_server(app).await;
    let client = WitnessClient::new(&url).unwrap();

    let signed = SignedAttestation::new(Attestation {
        hash: HASH,
        timestamp: 100,
        network_id: "network".to_string(),
        sequence: 1,
    });
    let resp = client.verify_remote(&signed).await.unwrap();
    assert!(resp.valid);
}
