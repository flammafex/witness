//! Admin Dashboard UI for Witness Gateway
//!
//! Provides a read-only web dashboard for monitoring network health,
//! attestation statistics, witness status, and external anchors.

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::metrics;
use crate::storage::Storage;
use witness_core::NetworkConfig;

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
        .route("/", get(dashboard_page))
        .route("/api/stats", get(stats_handler))
        .route("/api/witnesses", get(witnesses_handler))
        .route("/api/recent", get(recent_handler))
        .route("/api/anchors", get(anchors_handler))
        .with_state(state)
}

// ============================================================================
// API Handlers
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

    // Update Prometheus gauge
    metrics::set_attestations_24h(attestations_24h);

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
// Dashboard HTML Page
// ============================================================================

async fn dashboard_page(State(state): State<AdminState>) -> impl IntoResponse {
    Html(generate_dashboard_html(&state.config))
}

fn generate_dashboard_html(config: &NetworkConfig) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🙌 Witness Dashboard - {network_id}</title>
    <style>
        :root {{
            --bg: #0a0a0a;
            --card-bg: #141414;
            --border: #2a2a2a;
            --text: #e0e0e0;
            --text-dim: #888;
            --accent: #4a9eff;
            --success: #4ade80;
            --warning: #fbbf24;
            --error: #f87171;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, monospace;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 1rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 1.5rem;
        }}
        h1 {{ font-size: 1.25rem; font-weight: 600; }}
        h1 span {{ color: var(--accent); }}
        .meta {{ color: var(--text-dim); font-size: 0.875rem; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
        }}
        .card-title {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-bottom: 0.5rem;
            letter-spacing: 0.05em;
        }}
        .stat {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
        }}
        .stat-small {{ font-size: 1rem; color: var(--text); }}
        .witnesses {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        .witness {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            background: var(--bg);
            border-radius: 6px;
            font-size: 0.875rem;
        }}
        .dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}
        .dot.online {{ background: var(--success); }}
        .dot.offline {{ background: var(--error); }}
        .dot.loading {{ background: var(--warning); animation: pulse 1s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
        .latency {{ color: var(--text-dim); font-size: 0.75rem; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }}
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            color: var(--text-dim);
            font-weight: 500;
            text-transform: uppercase;
            font-size: 0.7rem;
            letter-spacing: 0.05em;
        }}
        .hash {{
            font-family: inherit;
            color: var(--accent);
            cursor: pointer;
        }}
        .hash:hover {{
            text-decoration: underline;
        }}
        .hash.copied {{
            color: var(--success);
        }}
        .time-ago {{ color: var(--text-dim); }}
        .badge {{
            display: inline-block;
            padding: 0.125rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
        }}
        .badge.success {{ background: rgba(74, 222, 128, 0.1); color: var(--success); }}
        .badge.warning {{ background: rgba(251, 191, 36, 0.1); color: var(--warning); }}
        .badge.error {{ background: rgba(248, 113, 113, 0.1); color: var(--error); }}
        .section-title {{
            font-size: 0.875rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}
        .anchor-grid {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}
        .anchor {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 0.75rem;
            background: var(--bg);
            border-radius: 6px;
            font-size: 0.8rem;
        }}
        .anchor .name {{ font-weight: 500; }}
        .anchor .info {{ color: var(--text-dim); font-size: 0.7rem; }}
        footer {{
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--text-dim);
            font-size: 0.75rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🙌 <span>Witness</span> Dashboard</h1>
            <div class="meta">
                Network: <strong>{network_id}</strong> |
                Scheme: <strong>{signature_scheme}</strong> |
                Threshold: <strong>{threshold}/{witness_count}</strong>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-title">Total Attestations</div>
                <div class="stat" id="total-attestations">-</div>
            </div>
            <div class="card">
                <div class="card-title">Last 24 Hours</div>
                <div class="stat" id="attestations-24h">-</div>
            </div>
            <div class="card">
                <div class="card-title">Batches</div>
                <div class="stat" id="total-batches">-</div>
            </div>
            <div class="card">
                <div class="card-title">Uptime</div>
                <div class="stat stat-small" id="uptime">-</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 1.5rem;">
            <div class="section-title">Witnesses</div>
            <div class="witnesses" id="witnesses">
                <div class="witness"><span class="dot loading"></span> Loading...</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 1.5rem;">
            <div class="section-title">External Anchors</div>
            <div class="anchor-grid" id="anchors">
                <div class="anchor">Loading...</div>
            </div>
        </div>

        <div class="card">
            <div class="section-title">Recent Attestations</div>
            <table>
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>Sequence</th>
                        <th>Signatures</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody id="recent">
                    <tr><td colspan="4" style="text-align: center; color: var(--text-dim);">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <footer>
            🙌 Witness · Anonymous Quorum Timestamping
        </footer>
    </div>

    <script>
        async function fetchJson(url) {{
            const resp = await fetch(url);
            return resp.json();
        }}

        function copyHash(el) {{
            const hash = el.dataset.hash;
            navigator.clipboard.writeText(hash).then(() => {{
                el.classList.add('copied');
                el.textContent = 'Copied!';
                setTimeout(() => {{
                    el.classList.remove('copied');
                    el.textContent = hash.substring(0, 16) + '...';
                }}, 1000);
            }});
        }}

        function formatUptime(seconds) {{
            const d = Math.floor(seconds / 86400);
            const h = Math.floor((seconds % 86400) / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            if (d > 0) return `${{d}}d ${{h}}h ${{m}}m`;
            if (h > 0) return `${{h}}h ${{m}}m`;
            return `${{m}}m`;
        }}

        async function updateStats() {{
            try {{
                const stats = await fetchJson('/admin/api/stats');
                document.getElementById('total-attestations').textContent =
                    stats.total_attestations.toLocaleString();
                document.getElementById('attestations-24h').textContent =
                    stats.attestations_24h.toLocaleString();
                document.getElementById('total-batches').textContent =
                    stats.total_batches.toLocaleString();
                document.getElementById('uptime').textContent = formatUptime(stats.uptime_seconds);
            }} catch (e) {{
                console.error('Failed to fetch stats:', e);
            }}
        }}

        async function updateWitnesses() {{
            try {{
                const witnesses = await fetchJson('/admin/api/witnesses');
                const container = document.getElementById('witnesses');
                container.innerHTML = witnesses.map(w => `
                    <div class="witness">
                        <span class="dot ${{w.status === 'online' ? 'online' : 'offline'}}"></span>
                        <span>${{w.id}}</span>
                        ${{w.latency_ms ? `<span class="latency">${{w.latency_ms}}ms</span>` : ''}}
                    </div>
                `).join('');
            }} catch (e) {{
                console.error('Failed to fetch witnesses:', e);
            }}
        }}

        async function updateRecent() {{
            try {{
                const recent = await fetchJson('/admin/api/recent');
                const tbody = document.getElementById('recent');
                if (recent.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim);">No attestations yet</td></tr>';
                    return;
                }}
                tbody.innerHTML = recent.map(a => `
                    <tr>
                        <td><span class="hash" data-hash="${{a.hash}}" onclick="copyHash(this)">${{a.hash.substring(0, 16)}}...</span></td>
                        <td>#${{a.sequence}}</td>
                        <td><span class="badge success">${{a.signature_count}} sigs</span></td>
                        <td class="time-ago">${{a.time_ago}}</td>
                    </tr>
                `).join('');
            }} catch (e) {{
                console.error('Failed to fetch recent:', e);
            }}
        }}

        async function updateAnchors() {{
            try {{
                const anchors = await fetchJson('/admin/api/anchors');
                const container = document.getElementById('anchors');
                if (anchors.length === 0) {{
                    container.innerHTML = '<div class="anchor" style="color: var(--text-dim);">No external anchors configured</div>';
                    return;
                }}
                container.innerHTML = anchors.map(a => `
                    <div class="anchor">
                        <span class="dot ${{a.enabled ? (a.last_anchor_time ? 'online' : 'loading') : 'offline'}}"></span>
                        <span class="name">${{a.provider}}</span>
                        <span class="info">${{a.last_anchor_ago ? 'Last: ' + a.last_anchor_ago : (a.enabled ? 'Pending' : 'Disabled')}}</span>
                    </div>
                `).join('');
            }} catch (e) {{
                console.error('Failed to fetch anchors:', e);
            }}
        }}

        // Initial load
        updateStats();
        updateWitnesses();
        updateRecent();
        updateAnchors();

        // Refresh periodically
        setInterval(updateStats, 10000);
        setInterval(updateWitnesses, 30000);
        setInterval(updateRecent, 5000);
        setInterval(updateAnchors, 60000);
    </script>
</body>
</html>
"##,
        network_id = config.id,
        signature_scheme = config.signature_scheme,
        threshold = config.threshold,
        witness_count = config.witnesses.len(),
    )
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
