use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{connect_info::ConnectInfo, State},
    http::{header::AUTHORIZATION, StatusCode},
    response::{IntoResponse, Json},
};
use tokio::sync::Mutex;
use witness_core::merkle::{consistency_path, inclusion_path};
use witness_core::types::{AttestationJobResponse, AttestationJobStatus, CreateAttestationRequest};
use witness_core::{
    AttestationEvent, BatchInclusion, CrossAnchorRequest, CrossAnchorResponse, ExternalAnchorProof,
    LogConsistencyProof, LogInclusionProofResponse, MerkleProof, MerkleProofResponse, MerkleTree,
    NetworkConfigPublic, ProofBundle, VerifyRequest, VerifyResponse,
};

// Types referenced only by the (feature-gated) `#[utoipa::path]` annotations.
#[cfg(feature = "openapi")]
use witness_core::{NetworkConfig, SignedTreeHead};

use super::{AttestationState, CoreState, FederationState, MetricsState};
use crate::epoch::epoch_secs;
use crate::error::AppError;
use crate::metrics::RequestTimer;
use crate::real_ip::real_ip;
use crate::storage::Storage;

/// Response body for `GET /health`.
#[cfg(feature = "openapi")]
#[derive(utoipa::ToSchema)]
#[allow(dead_code)] // schema-only type; fields are never read at runtime
pub(super) struct HealthResponse {
    pub status: String,
}

// ============================================================================
// CoreState handlers
// ============================================================================

pub(super) async fn root_handler() -> impl IntoResponse {
    axum::response::Redirect::temporary("/admin")
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse)
    )
))]
pub(super) async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/config",
    responses(
        (status = 200, description = "Public network configuration (informational only; not a trust anchor)", body = NetworkConfigPublic)
    )
))]
pub(super) async fn config_handler(State(state): State<CoreState>) -> impl IntoResponse {
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/network",
    responses(
        (status = 200, description = "Full network configuration with witness public keys (auth tokens stripped server-side)", body = NetworkConfig)
    )
))]
pub(super) async fn network_config_handler(State(state): State<CoreState>) -> impl IntoResponse {
    Json((*state.config).clone())
}

/// Decode a hex-encoded SHA-256 hash from a path/query parameter into a
/// fixed-size byte array, mapping malformed hex or wrong-length values to
/// `AppError::InvalidHash`.
pub(super) fn decode_hash(hash: &str) -> Result<[u8; 32], AppError> {
    let hash_bytes = hex::decode(hash).map_err(|_| AppError::InvalidHash)?;
    hash_bytes.try_into().map_err(|_| AppError::InvalidHash)
}

/// Rebuild the merkle tree over a batch's stored leaves and produce the
/// inclusion proof for `merkle_index`.
pub(super) async fn build_merkle_inclusion_proof(
    storage: &Storage,
    batch_id: i64,
    merkle_index: usize,
) -> Result<MerkleProof, AppError> {
    let batch_hashes = storage.get_batch_attestation_hashes(batch_id).await?;
    let tree = MerkleTree::new(batch_hashes);
    tree.inclusion_proof(merkle_index)
        .ok_or_else(|| AppError::Other(anyhow::anyhow!("Failed to generate merkle proof")))
}

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/attestations/{hash}",
    params(
        ("hash" = String, Path, description = "Hex-encoded SHA-256 hash (64 lowercase hex chars)")
    ),
    responses(
        (status = 200, description = "Attestation job for the hash", body = AttestationJobResponse),
        (status = 404, description = "No attestation job exists for this hash")
    )
))]
pub(super) async fn get_attestation_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up attestation job for hash: {}", hash);

    let hash_array = decode_hash(&hash)?;

    let job = state
        .storage
        .get_job(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(job))
}

#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/v1/verify",
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Gateway's verification opinion (non-authoritative; prefer local verification)", body = VerifyResponse)
    )
))]
pub(super) async fn verify_handler(
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

#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/anchors/{hash}",
    params(
        ("hash" = String, Path, description = "Hex-encoded SHA-256 hash (64 lowercase hex chars)")
    ),
    responses(
        (status = 200, description = "External anchor proofs (empty array if the attestation is known but not yet batched)", body = [ExternalAnchorProof]),
        (status = 404, description = "Unknown attestation")
    )
))]
pub(super) async fn get_anchors_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up external anchors for hash: {}", hash);

    let hash_array = decode_hash(&hash)?;

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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/proof/{hash}",
    params(
        ("hash" = String, Path, description = "Hex-encoded SHA-256 hash (64 lowercase hex chars)")
    ),
    responses(
        (status = 200, description = "Merkle inclusion proof", body = MerkleProofResponse),
        (status = 404, description = "Attestation not confirmed or not yet batched")
    )
))]
pub(super) async fn get_proof_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Looking up merkle proof for hash: {}", hash);

    let hash_array = decode_hash(&hash)?;
    let job = state
        .storage
        .get_job(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;
    if job.status != AttestationJobStatus::Confirmed || job.signed_attestation.is_none() {
        return Err(AppError::NotFound);
    }

    let batch_info = state
        .storage
        .get_attestation_batch_info(&hash)
        .await?
        .ok_or(AppError::NotBatched)?;

    let (batch_id, merkle_index, merkle_root) = batch_info;

    let proof = build_merkle_inclusion_proof(&state.storage, batch_id, merkle_index).await?;

    Ok(Json(MerkleProofResponse {
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/bundle/{hash}",
    params(
        ("hash" = String, Path, description = "Hex-encoded SHA-256 hash (64 lowercase hex chars)")
    ),
    responses(
        (status = 200, description = "Self-contained proof bundle", body = ProofBundle),
        (status = 404, description = "Attestation not found")
    )
))]
pub(super) async fn get_proof_bundle_handler(
    State(state): State<CoreState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("Building proof bundle for hash: {}", hash);

    let hash_array = decode_hash(&hash)?;

    let job = state
        .storage
        .get_job(&hash_array)
        .await?
        .ok_or(AppError::NotFound)?;
    let signed_attestation = job.signed_attestation.ok_or(AppError::NotFound)?;

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

        let mut merkle_proof =
            build_merkle_inclusion_proof(&state.storage, batch_id, merkle_index).await?;
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/log/sth",
    responses(
        (status = 200, description = "Latest signed tree head", body = SignedTreeHead),
        (status = 404, description = "Log is empty (no batches closed yet)")
    )
))]
pub(super) async fn get_latest_sth_handler(
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
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/log/sth/{tree_size}",
    params(
        ("tree_size" = u64, Path, description = "Tree size to fetch the signed tree head for")
    ),
    responses(
        (status = 200, description = "Signed tree head at the given tree size", body = SignedTreeHead),
        (status = 404, description = "No STH published at this tree size")
    )
))]
pub(super) async fn get_sth_at_size_handler(
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
pub(super) struct ConsistencyQuery {
    first: u64,
    second: u64,
}

/// RFC 9162 §4.10 GetConsistency: prove that the log of size `first` is a
/// prefix of the log of size `second`.  Both endpoints are inclusive — they
/// must each correspond to a previously published STH.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/log/consistency",
    params(
        ("first" = u64, Query, description = "Old tree size (>= 1)"),
        ("second" = u64, Query, description = "New tree size (>= first)")
    ),
    responses(
        (status = 200, description = "Consistency proof linking the two signed tree heads", body = LogConsistencyProof),
        (status = 404, description = "No STH at one of the requested tree sizes")
    )
))]
pub(super) async fn get_consistency_handler(
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
pub(super) struct LogProofQuery {
    hash: String,
    tree_size: u64,
}

/// RFC 9162 §4.11 GetProofByHash: inclusion proof for `hash` against the
/// STH at `tree_size`.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/v1/log/proof",
    params(
        ("hash" = String, Query, description = "Hex-encoded SHA-256 hash (64 lowercase hex chars)"),
        ("tree_size" = u64, Query, description = "Tree size to prove inclusion against")
    ),
    responses(
        (status = 200, description = "Log inclusion proof", body = LogInclusionProofResponse),
        (status = 404, description = "Hash not in the log at this tree size")
    )
))]
pub(super) async fn get_log_proof_handler(
    State(state): State<CoreState>,
    axum::extract::Query(q): axum::extract::Query<LogProofQuery>,
) -> Result<impl IntoResponse, AppError> {
    let hash_array = decode_hash(&q.hash)?;

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

// ============================================================================
// AttestationState handler
// ============================================================================

#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/v1/attestations",
    request_body = CreateAttestationRequest,
    responses(
        (status = 200, description = "Attestation job reached a terminal state (confirmed or failed)", body = AttestationJobResponse),
        (status = 202, description = "Attestation job is pending or retryable", body = AttestationJobResponse),
        (status = 429, description = "Rate limited")
    )
))]
pub(super) async fn create_attestation_handler(
    State(state): State<AttestationState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CreateAttestationRequest>,
) -> Result<(StatusCode, Json<AttestationJobResponse>), AppError> {
    let _timer = RequestTimer::new("attestations");
    let hash = decode_hash(&request.hash)?;

    if let Some(job) = state.storage.get_job(&hash).await? {
        return Ok((job_http_status(job.status), Json(job)));
    }

    // Serialize admission and reservation for the same hash within this
    // gateway process. The database remains the cross-process canonicality
    // authority; the second lookup avoids consuming one-use admission tokens
    // for ordinary retries and local races.
    let creation_lock = state
        .creation_locks
        .entry(hash)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    let creation_guard = creation_lock.lock().await;
    match state.storage.get_job(&hash).await {
        Ok(Some(job)) => {
            drop(creation_guard);
            state.creation_locks.remove(&hash);
            return Ok((job_http_status(job.status), Json(job)));
        }
        Ok(None) => {}
        Err(error) => {
            drop(creation_guard);
            state.creation_locks.remove(&hash);
            return Err(AppError::from(error));
        }
    }

    let reservation_result: Result<_, AppError> = async {
        let client_ip = real_ip(&headers, addr, state.behind_proxy);

        if state.rate_limiter.check_key(&client_ip).is_err() {
            tracing::warn!("Attestation rate limit exceeded for IP: {}", client_ip);
            return Err(AppError::RateLimited);
        }

        tracing::info!("Received attestation request for hash: {}", request.hash);

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

        state
            .storage
            .reserve_job(&hash, &state.config.id, epoch_secs())
            .await
            .map_err(AppError::from)
    }
    .await;
    drop(creation_guard);
    state.creation_locks.remove(&hash);
    let reservation = reservation_result?;

    if reservation.created {
        let event = AttestationEvent {
            event_type: "attestation".to_string(),
            hash: request.hash,
            timestamp: reservation.job.attestation.timestamp,
        };
        let _ = state.event_tx.send(event);
    }

    let status = job_http_status(reservation.job.status);
    Ok((status, Json(reservation.job)))
}

pub(super) fn job_http_status(status: AttestationJobStatus) -> StatusCode {
    match status {
        AttestationJobStatus::Pending | AttestationJobStatus::Retryable => StatusCode::ACCEPTED,
        AttestationJobStatus::Confirmed | AttestationJobStatus::Failed => StatusCode::OK,
    }
}

// ============================================================================
// FederationState handler
// ============================================================================

pub(super) async fn federation_anchor_handler(
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

    state
        .storage
        .reserve_job(&request.batch.merkle_root, &state.config.id, epoch_secs())
        .await?;

    // Cross-anchor callers still require a signed response, but signing now
    // goes through the same durable verified worker as public submissions.
    let witness_attestation = {
        let mut confirmed = None;
        for _ in 0..150 {
            let job = state
                .storage
                .get_job(&request.batch.merkle_root)
                .await?
                .ok_or(AppError::InternalError)?;
            if job.status == AttestationJobStatus::Failed {
                return Err(AppError::InternalError);
            }
            if let Some(signed) = job.signed_attestation {
                confirmed = Some(signed);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        confirmed.ok_or(AppError::InsufficientSignatures {
            got: 0,
            required: state.config.threshold,
        })?
    };

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

pub(super) async fn metrics_handler(
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
