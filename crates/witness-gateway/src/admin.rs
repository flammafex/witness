//! Admin Dashboard UI for Witness Gateway
//!
//! Provides a read-only web dashboard for monitoring network health,
//! attestation statistics, witness status, and external anchors.
//!
//! Static files are embedded in the binary for easy deployment.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::storage::Storage;
use witness_core::NetworkConfig;

// Embed static files at compile time
const INDEX_HTML: &str = include_str!("../static/admin/index.html");
const STYLES_CSS: &str = include_str!("../static/admin/styles.css");
const APP_JS: &str = include_str!("../static/admin/app.js");

/// Shared state for admin endpoints
#[derive(Clone)]
pub struct AdminState {
    pub config: Arc<NetworkConfig>,
    pub storage: Arc<Storage>,
    pub start_time: SystemTime,
}

impl AdminState {
    pub fn new(config: Arc<NetworkConfig>, storage: Arc<Storage>) -> Self {
        Self {
            config,
            storage,
            start_time: SystemTime::now(),
        }
    }
}

/// Create admin router with all dashboard routes
pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        // Static file routes (embedded in binary)
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/styles.css", get(serve_styles))
        .route("/app.js", get(serve_app_js))
        // API routes
        .route("/api/stats", get(stats_handler))
        .route("/api/witnesses", get(witnesses_handler))
        .route("/api/recent", get(recent_handler))
        .route("/api/anchors", get(anchors_handler))
        .route("/api/metrics", get(metrics_handler))
        .route("/api/attestation/:hash", get(attestation_handler))
        .route("/api/attestations", get(attestations_handler))
        .route("/api/batches", get(batches_handler))
        .with_state(state)
}

// ============================================================================
// Static File Handlers (embedded)
// ============================================================================

async fn serve_index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_styles() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/css")
        .body(STYLES_CSS.into())
        .unwrap()
}

async fn serve_app_js() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(APP_JS.into())
        .unwrap()
}

// ============================================================================
// API Handlers - Existing Endpoints
// ============================================================================

#[derive(Serialize)]
struct DashboardStats {
    network_id: String,
    signature_scheme: String,
    threshold: usize,
    witness_count: usize,
    uptime_seconds: u64,
    total_attestations: u64,
    attestations_24h: u64,
    total_batches: u64,
    federation_enabled: bool,
    external_anchors_enabled: bool,
}

async fn stats_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let uptime = state
        .start_time
        .elapsed()
        .unwrap_or(Duration::ZERO)
        .as_secs();

    let total_attestations = state
        .storage
        .count_attestations()
        .await
        .unwrap_or(0);

    let attestations_24h = state
        .storage
        .count_attestations_since(now_secs() - 86400)
        .await
        .unwrap_or(0);

    let total_batches = state
        .storage
        .count_batches()
        .await
        .unwrap_or(0);

    Json(DashboardStats {
        network_id: state.config.id.clone(),
        signature_scheme: format!("{}", state.config.signature_scheme),
        threshold: state.config.threshold,
        witness_count: state.config.witnesses.len(),
        uptime_seconds: uptime,
        total_attestations,
        attestations_24h,
        total_batches,
        federation_enabled: state.config.federation.enabled,
        external_anchors_enabled: state.config.external_anchors.enabled,
    })
}

#[derive(Serialize)]
struct WitnessStatus {
    id: String,
    endpoint: String,
    status: String,
    latency_ms: Option<u64>,
}

async fn witnesses_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let mut witnesses = Vec::new();

    for witness in &state.config.witnesses {
        let (status, latency_ms) = check_witness_health(&witness.endpoint).await;

        witnesses.push(WitnessStatus {
            id: witness.id.clone(),
            endpoint: witness.endpoint.clone(),
            status,
            latency_ms,
        });
    }

    Json(witnesses)
}

async fn check_witness_health(endpoint: &str) -> (String, Option<u64>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let start = std::time::Instant::now();

    match client.get(format!("{}/health", endpoint)).send().await {
        Ok(resp) if resp.status().is_success() => {
            let latency = start.elapsed().as_millis() as u64;
            ("online".to_string(), Some(latency))
        }
        Ok(resp) => (format!("error:{}", resp.status().as_u16()), None),
        Err(_) => ("offline".to_string(), None),
    }
}

#[derive(Serialize)]
struct RecentAttestation {
    hash: String,
    timestamp: u64,
    sequence: u64,
    signature_count: usize,
    time_ago: String,
}

async fn recent_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let attestations = state
        .storage
        .get_recent_attestations(20)
        .await
        .unwrap_or_default();

    let now = now_secs();

    let recent: Vec<RecentAttestation> = attestations
        .into_iter()
        .map(|a| RecentAttestation {
            hash: hex::encode(a.attestation.hash),
            timestamp: a.attestation.timestamp,
            sequence: a.attestation.sequence,
            signature_count: a.signature_count(),
            time_ago: format_time_ago(now.saturating_sub(a.attestation.timestamp)),
        })
        .collect();

    Json(recent)
}

#[derive(Serialize)]
struct AnchorStatus {
    provider: String,
    enabled: bool,
    last_anchor_time: Option<u64>,
    last_anchor_ago: Option<String>,
    total_anchors: u64,
}

async fn anchors_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let mut anchors = Vec::new();
    let now = now_secs();

    // Get configured providers
    for provider in &state.config.external_anchors.providers {
        let provider_name = format!("{:?}", provider.provider_type).to_lowercase();

        let (last_time, total) = state
            .storage
            .get_anchor_stats(&provider_name)
            .await
            .unwrap_or((None, 0));

        anchors.push(AnchorStatus {
            provider: provider_name,
            enabled: provider.enabled,
            last_anchor_time: last_time,
            last_anchor_ago: last_time.map(|t| format_time_ago(now.saturating_sub(t))),
            total_anchors: total,
        });
    }

    Json(anchors)
}

// ============================================================================
// API Handlers - New Endpoints
// ============================================================================

async fn metrics_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let metrics = state
        .storage
        .get_throughput_metrics()
        .await
        .unwrap_or_default();

    Json(metrics)
}

#[derive(Serialize)]
struct AttestationDetail {
    hash: String,
    timestamp: u64,
    timestamp_human: String,
    network_id: String,
    sequence: u64,
    signatures: Vec<SignatureInfo>,
    batch_id: Option<u64>,
    anchor_proofs: Vec<AnchorProofInfo>,
}

#[derive(Serialize)]
struct SignatureInfo {
    witness_id: String,
    signature: String,
}

#[derive(Serialize)]
struct AnchorProofInfo {
    provider: String,
    timestamp: u64,
    proof: serde_json::Value,
}

async fn attestation_handler(
    State(state): State<AdminState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // Parse hash - support full hash or prefix (min 8 chars)
    if hash.len() < 8 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Hash must be at least 8 characters",
        ));
    }

    let result = state
        .storage
        .get_attestation_by_prefix(&hash)
        .await
        .map_err(|_| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Database error"))?;

    let Some((attestation, batch_id)) = result else {
        return Err((axum::http::StatusCode::NOT_FOUND, "Attestation not found"));
    };

    // Get anchor proofs if batched
    let anchor_proofs = if let Some(bid) = batch_id {
        state
            .storage
            .get_anchor_proofs(bid as u64)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|p| AnchorProofInfo {
                provider: format!("{}", p.provider),
                timestamp: p.timestamp,
                proof: p.proof,
            })
            .collect()
    } else {
        Vec::new()
    };

    // Extract signatures
    let signatures: Vec<SignatureInfo> = match &attestation.signatures {
        witness_core::signature_scheme::AttestationSignatures::MultiSig { signatures } => {
            signatures
                .iter()
                .map(|s| SignatureInfo {
                    witness_id: s.witness_id.clone(),
                    signature: hex::encode(&s.signature),
                })
                .collect()
        }
        witness_core::signature_scheme::AttestationSignatures::Aggregated { signature, signers } => {
            signers
                .iter()
                .map(|signer| SignatureInfo {
                    witness_id: signer.clone(),
                    signature: hex::encode(signature),
                })
                .collect()
        }
    };

    let timestamp = attestation.attestation.timestamp;
    let datetime = chrono_from_timestamp(timestamp);

    Ok(Json(AttestationDetail {
        hash: hex::encode(attestation.attestation.hash),
        timestamp,
        timestamp_human: datetime,
        network_id: attestation.attestation.network_id.clone(),
        sequence: attestation.attestation.sequence,
        signatures,
        batch_id: batch_id.map(|b| b as u64),
        anchor_proofs,
    }))
}

#[derive(Deserialize)]
struct PaginationQuery {
    page: Option<u64>,
    limit: Option<u64>,
    search: Option<String>,
}

#[derive(Serialize)]
struct AttestationsResponse {
    attestations: Vec<AttestationListItem>,
    total: u64,
    page: u64,
    pages: u64,
}

#[derive(Serialize)]
struct AttestationListItem {
    hash: String,
    timestamp: u64,
    network_id: String,
    sequence: u64,
    signature_count: usize,
    batch_id: Option<u64>,
    time_ago: String,
}

async fn attestations_handler(
    State(state): State<AdminState>,
    Query(query): Query<PaginationQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(100);
    let search = query.search.filter(|s| s.len() >= 8);

    let (attestations, total) = state
        .storage
        .get_attestations_paginated(page, limit, search.as_deref())
        .await
        .unwrap_or_default();

    let now = now_secs();
    let pages = (total + limit - 1) / limit;

    let items: Vec<AttestationListItem> = attestations
        .into_iter()
        .map(|(signed, batch_id)| AttestationListItem {
            hash: hex::encode(signed.attestation.hash),
            timestamp: signed.attestation.timestamp,
            network_id: signed.attestation.network_id.clone(),
            sequence: signed.attestation.sequence,
            signature_count: signed.signature_count(),
            batch_id: batch_id.map(|b| b as u64),
            time_ago: format_time_ago(now.saturating_sub(signed.attestation.timestamp)),
        })
        .collect();

    Json(AttestationsResponse {
        attestations: items,
        total,
        page,
        pages,
    })
}

#[derive(Serialize)]
struct BatchesResponse {
    batches: Vec<BatchInfo>,
    total: u64,
    page: u64,
    pages: u64,
}

#[derive(Serialize)]
struct BatchInfo {
    id: u64,
    merkle_root: String,
    attestation_count: u64,
    created_at: u64,
    anchored: bool,
}

async fn batches_handler(
    State(state): State<AdminState>,
    Query(query): Query<PaginationQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).min(100);

    let (batches, total) = state
        .storage
        .get_batches_paginated(page, limit)
        .await
        .unwrap_or_default();

    let pages = (total + limit - 1) / limit;

    let items: Vec<BatchInfo> = batches
        .into_iter()
        .map(|(batch, anchored)| BatchInfo {
            id: batch.id,
            merkle_root: hex::encode(batch.merkle_root),
            attestation_count: batch.attestation_count,
            created_at: batch.period_end,
            anchored,
        })
        .collect();

    Json(BatchesResponse {
        batches: items,
        total,
        page,
        pages,
    })
}

// ============================================================================
// Helpers
// ============================================================================

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn format_time_ago(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s ago", seconds)
    } else if seconds < 3600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h ago", seconds / 3600)
    } else {
        format!("{}d ago", seconds / 86400)
    }
}

fn chrono_from_timestamp(timestamp: u64) -> String {
    use std::fmt::Write;

    let secs = timestamp;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year, month, day from days since epoch
    // Using a simplified algorithm
    let mut days = days_since_epoch as i64;
    let mut year = 1970i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;

    let mut result = String::new();
    let _ = write!(
        result,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    );
    result
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}
