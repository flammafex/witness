use axum::{extract::State, routing::get, Json, Router};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::sync::Mutex;

use witness_core::log::LogConsistencyProof;
use witness_core::{
    merkle::{consistency_path, merkle_tree_hash},
    AttestationSignatures, NetworkConfig, SignatureScheme, SignedAttestation, SignedTreeHead,
    TreeHead, WitnessInfo, WitnessSignature,
};

use witness_auditor::audit::{Auditor, TickResult};
use witness_auditor::storage::Storage;

fn test_network() -> (NetworkConfig, SigningKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey = hex::encode(signing_key.verifying_key().as_bytes());
    let cfg = NetworkConfig {
        id: "test-net".to_string(),
        witnesses: vec![WitnessInfo {
            id: "w1".to_string(),
            pubkey,
            endpoint: "http://localhost:3001".to_string(),
            auth_token: None,
        }],
        threshold: 1,
        signature_scheme: SignatureScheme::Ed25519,
        federation: Default::default(),
        external_anchors: Default::default(),
        federation_peers: vec![],
    };
    (cfg, signing_key)
}

fn make_head(network: &NetworkConfig, leaves: &[[u8; 32]], timestamp: u64) -> TreeHead {
    TreeHead {
        network_id: network.id.clone(),
        tree_size: leaves.len() as u64,
        timestamp,
        root_hash: merkle_tree_hash(leaves),
    }
}

fn sign_sth(network: &NetworkConfig, key: &SigningKey, head: TreeHead) -> SignedTreeHead {
    let attestation = head.to_attestation();
    let signature = key.sign(&attestation.to_bytes()).to_bytes().to_vec();
    let signed_attestation = SignedAttestation {
        attestation,
        signatures: AttestationSignatures::MultiSig {
            signatures: vec![WitnessSignature {
                witness_id: network.witnesses[0].id.clone(),
                signature,
            }],
        },
    };
    SignedTreeHead {
        tree_head: head,
        signed_attestation,
    }
}

#[derive(Clone)]
struct ServerState {
    network: NetworkConfig,
    latest_sth: Arc<Mutex<SignedTreeHead>>,
    consistency_proof: Arc<Mutex<Option<LogConsistencyProof>>>,
}

async fn start_server(state: ServerState) -> String {
    let router = Router::new()
        .route("/v1/network", get(network_handler))
        .route("/v1/log/sth", get(sth_handler))
        .route("/v1/log/consistency", get(consistency_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .unwrap();
    });
    format!("http://{}", addr)
}

async fn network_handler(State(state): State<ServerState>) -> Json<NetworkConfig> {
    Json(state.network.clone())
}

async fn sth_handler(State(state): State<ServerState>) -> Json<SignedTreeHead> {
    let sth = state.latest_sth.lock().await.clone();
    Json(sth)
}

#[derive(serde::Deserialize)]
struct ConsistencyQuery {
    #[serde(rename = "first")]
    _first: u64,
    #[serde(rename = "second")]
    _second: u64,
}

async fn consistency_handler(
    State(state): State<ServerState>,
    axum::extract::Query(_q): axum::extract::Query<ConsistencyQuery>,
) -> Json<LogConsistencyProof> {
    let proof = state.consistency_proof.lock().await.clone().unwrap();
    Json(proof)
}

async fn in_mem_storage() -> Storage {
    let storage = Storage::new(":memory:").await.unwrap();
    storage.migrate().await.unwrap();
    storage
}

#[tokio::test]
async fn test_first_sth_accepted() {
    let (network, key) = test_network();
    let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
    let head = make_head(&network, &leaves, 1000);
    let sth = sign_sth(&network, &key, head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(sth.clone())),
        consistency_proof: Arc::new(Mutex::new(None)),
    };
    let url = start_server(state).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage);

    let result = auditor.tick().await.unwrap();
    assert!(matches!(result, TickResult::NewSth(_)), "expected NewSth");
}

#[tokio::test]
async fn test_no_change() {
    let (network, key) = test_network();
    let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
    let head = make_head(&network, &leaves, 1000);
    let sth = sign_sth(&network, &key, head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(sth.clone())),
        consistency_proof: Arc::new(Mutex::new(None)),
    };
    let url = start_server(state).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage.clone());

    auditor.tick().await.unwrap();

    let result = auditor.tick().await.unwrap();
    assert!(matches!(result, TickResult::NoChange), "expected NoChange");
}

#[tokio::test]
async fn test_new_sth_verified() {
    let (network, key) = test_network();
    let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| [i; 32]).collect();

    let old_head = make_head(&network, &leaves[..3], 1000);
    let new_head = make_head(&network, &leaves, 2000);
    let old_sth = sign_sth(&network, &key, old_head);
    let new_sth = sign_sth(&network, &key, new_head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(old_sth.clone())),
        consistency_proof: Arc::new(Mutex::new(Some(LogConsistencyProof {
            old_sth: old_sth.clone(),
            new_sth: new_sth.clone(),
            hashes: consistency_path(3, &leaves).unwrap(),
        }))),
    };
    let url = start_server(state.clone()).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage);

    auditor.tick().await.unwrap();

    *state.latest_sth.lock().await = new_sth;

    let result = auditor.tick().await.unwrap();
    assert!(
        matches!(result, TickResult::NewSth(ref s) if s.tree_head.tree_size == 7),
        "expected NewSth with tree_size 7"
    );
}

#[tokio::test]
async fn test_tree_size_regression() {
    let (network, key) = test_network();
    let leaves_old: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
    let leaves_new: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();

    let old_head = make_head(&network, &leaves_old, 1000);
    let new_head = make_head(&network, &leaves_new, 2000);
    let old_sth = sign_sth(&network, &key, old_head);
    let new_sth = sign_sth(&network, &key, new_head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(old_sth)),
        consistency_proof: Arc::new(Mutex::new(None)),
    };
    let url = start_server(state.clone()).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage.clone());

    auditor.tick().await.unwrap();

    *state.latest_sth.lock().await = new_sth;

    let result = auditor.tick().await.unwrap();
    assert!(matches!(result, TickResult::Failed), "expected Failed");

    let failures = storage.recent_failures(10).await.unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].failure_type, "tree_size_regression");
}

#[tokio::test]
async fn test_root_mismatch() {
    let (network, key) = test_network();
    let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
    let head = make_head(&network, &leaves, 1000);
    let sth = sign_sth(&network, &key, head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(sth.clone())),
        consistency_proof: Arc::new(Mutex::new(None)),
    };
    let url = start_server(state.clone()).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage.clone());

    auditor.tick().await.unwrap();

    let mut tampered_leaves = leaves.clone();
    tampered_leaves[0] = [99u8; 32];
    let new_head = make_head(&network, &tampered_leaves, 2000);
    let new_sth = sign_sth(&network, &key, new_head);

    *state.latest_sth.lock().await = new_sth;

    let result = auditor.tick().await.unwrap();
    assert!(matches!(result, TickResult::Failed), "expected Failed");

    let failures = storage.recent_failures(10).await.unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].failure_type, "root_mismatch");
}

#[tokio::test]
async fn test_signature_failure() {
    let (network, _key) = test_network();
    let wrong_key = SigningKey::generate(&mut OsRng);

    let leaves: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
    let head = make_head(&network, &leaves, 1000);
    let bad_sth = sign_sth(&network, &wrong_key, head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(bad_sth)),
        consistency_proof: Arc::new(Mutex::new(None)),
    };
    let url = start_server(state).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage.clone());

    let result = auditor.tick().await.unwrap();
    assert!(matches!(result, TickResult::Failed), "expected Failed");

    let failures = storage.recent_failures(10).await.unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].failure_type, "sth_signature");
}

#[tokio::test]
async fn test_consistency_failure() {
    let (network, key) = test_network();
    let leaves: Vec<[u8; 32]> = (0u8..7).map(|i| [i; 32]).collect();
    let mut tampered_leaves = leaves.clone();
    tampered_leaves[1] = [99u8; 32];

    let old_head = make_head(&network, &leaves[..3], 1000);
    let new_head = make_head(&network, &tampered_leaves, 2000);
    let old_sth = sign_sth(&network, &key, old_head);
    let new_sth = sign_sth(&network, &key, new_head);

    let state = ServerState {
        network: network.clone(),
        latest_sth: Arc::new(Mutex::new(old_sth.clone())),
        consistency_proof: Arc::new(Mutex::new(Some(LogConsistencyProof {
            old_sth: old_sth.clone(),
            new_sth: new_sth.clone(),
            hashes: consistency_path(3, &tampered_leaves).unwrap(),
        }))),
    };
    let url = start_server(state.clone()).await;
    let storage = in_mem_storage().await;
    let auditor = Auditor::new(&url, storage.clone());

    auditor.tick().await.unwrap();

    *state.latest_sth.lock().await = new_sth;

    let result = auditor.tick().await.unwrap();
    assert!(matches!(result, TickResult::Failed), "expected Failed");

    let failures = storage.recent_failures(10).await.unwrap();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].failure_type, "consistency");
}
