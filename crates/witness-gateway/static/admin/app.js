// State management
const state = {
    currentTab: 'overview',
    stats: null,
    witnesses: [],
    recentAttestations: [],
    anchors: [],
    metrics: null,
    // Pagination state
    attestationsPage: 1,
    attestationsSearch: '',
    batchesPage: 1,
    // Current attestation for modal
    currentAttestation: null
};

// Configuration
const ITEMS_PER_PAGE = 50;
const BATCHES_PER_PAGE = 20;

// ============================================================================
// API Helpers
// ============================================================================

async function fetchJson(url) {
    const resp = await fetch(url);
    if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return resp.json();
}

// ============================================================================
// Time Formatting
// ============================================================================

function formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function formatTimeAgo(timeAgo) {
    return timeAgo;
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

function formatDate(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toISOString().split('T')[0];
}

// ============================================================================
// Toast Notifications
// ============================================================================

function showError(message) {
    const toast = document.getElementById('error-toast');
    const msgEl = document.getElementById('error-message');
    msgEl.textContent = message;
    toast.classList.remove('hidden', 'success');
    setTimeout(() => toast.classList.add('hidden'), 5000);
}

function showSuccess(message) {
    const toast = document.getElementById('error-toast');
    const msgEl = document.getElementById('error-message');
    msgEl.textContent = message;
    toast.classList.remove('hidden');
    toast.classList.add('success');
    setTimeout(() => toast.classList.add('hidden'), 3000);
}

// ============================================================================
// Tab Navigation
// ============================================================================

function switchTab(tabName) {
    state.currentTab = tabName;

    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === tabName);
    });

    // Load tab-specific data
    switch (tabName) {
        case 'overview':
            loadOverview();
            break;
        case 'attestations':
            loadAttestations();
            break;
        case 'batches':
            loadBatches();
            break;
        case 'anchors':
            loadAnchorDetails();
            break;
    }
}

// ============================================================================
// Overview Tab
// ============================================================================

async function loadOverview() {
    await Promise.all([
        updateStats(),
        updateWitnesses(),
        updateRecent(),
        updateAnchorsOverview(),
        updateMetrics()
    ]);
}

async function updateStats() {
    try {
        const stats = await fetchJson('/admin/api/stats');
        state.stats = stats;

        document.getElementById('total-attestations').textContent =
            stats.total_attestations.toLocaleString();
        document.getElementById('attestations-24h').textContent =
            stats.attestations_24h.toLocaleString();
        document.getElementById('uptime').textContent = formatUptime(stats.uptime_seconds);

        // Update network info
        document.getElementById('network-info').innerHTML = `
            Network: <strong>${stats.network_id}</strong> |
            Scheme: <strong>${stats.signature_scheme}</strong> |
            Threshold: <strong>${stats.threshold}/${stats.witness_count}</strong>
        `;
    } catch (e) {
        console.error('Failed to fetch stats:', e);
    }
}

async function updateMetrics() {
    try {
        const metrics = await fetchJson('/admin/api/metrics');
        state.metrics = metrics;

        const throughputEl = document.getElementById('throughput');
        if (metrics.attestations_per_minute > 0) {
            throughputEl.textContent = `${metrics.attestations_per_minute.toFixed(1)}/min`;
        } else {
            throughputEl.textContent = '-';
        }
    } catch (e) {
        console.error('Failed to fetch metrics:', e);
        document.getElementById('throughput').textContent = '-';
    }
}

async function updateWitnesses() {
    try {
        const witnesses = await fetchJson('/admin/api/witnesses');
        state.witnesses = witnesses;

        const container = document.getElementById('witnesses');
        if (witnesses.length === 0) {
            container.innerHTML = '<div class="witness" style="color: var(--text-dim);">No witnesses configured</div>';
            return;
        }

        container.innerHTML = witnesses.map(w => `
            <div class="witness">
                <span class="dot ${w.status === 'online' ? 'online' : 'offline'}"></span>
                <span>${escapeHtml(w.id)}</span>
                ${w.latency_ms ? `<span class="latency">${w.latency_ms}ms</span>` : ''}
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to fetch witnesses:', e);
    }
}

async function updateRecent() {
    try {
        const recent = await fetchJson('/admin/api/recent');
        state.recentAttestations = recent;

        const tbody = document.getElementById('recent');
        if (recent.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading-cell">No attestations yet</td></tr>';
            return;
        }

        tbody.innerHTML = recent.map(a => `
            <tr>
                <td><span class="hash" onclick="lookupAttestation('${a.hash}')">${a.hash.substring(0, 16)}...</span></td>
                <td>#${a.sequence.toLocaleString()}</td>
                <td><span class="badge success">${a.signature_count} sigs</span></td>
                <td class="time-ago">${formatTimeAgo(a.time_ago)}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Failed to fetch recent:', e);
    }
}

async function updateAnchorsOverview() {
    try {
        const anchors = await fetchJson('/admin/api/anchors');
        state.anchors = anchors;

        const container = document.getElementById('anchors-overview');
        if (anchors.length === 0) {
            container.innerHTML = '<div class="anchor" style="color: var(--text-dim);">No external anchors configured</div>';
            return;
        }

        container.innerHTML = anchors.map(a => `
            <div class="anchor">
                <span class="dot ${a.enabled ? (a.last_anchor_time ? 'online' : 'loading') : 'offline'}"></span>
                <span class="name">${escapeHtml(a.provider)}</span>
                <span class="info">${a.last_anchor_ago ? 'Last: ' + a.last_anchor_ago : (a.enabled ? 'Pending' : 'Disabled')}</span>
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to fetch anchors:', e);
    }
}

// ============================================================================
// Attestations Tab
// ============================================================================

async function loadAttestations(page = 1, search = '') {
    state.attestationsPage = page;
    state.attestationsSearch = search;

    const tbody = document.getElementById('attestations-table');
    tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Loading...</td></tr>';

    try {
        let url = `/admin/api/attestations?page=${page}&limit=${ITEMS_PER_PAGE}`;
        if (search && search.length >= 8) {
            url += `&search=${encodeURIComponent(search)}`;
        }

        const data = await fetchJson(url);

        document.getElementById('attestations-total').textContent = `(${data.total.toLocaleString()} total)`;

        if (data.attestations.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No attestations found</td></tr>';
            document.getElementById('attestations-pagination').innerHTML = '';
            return;
        }

        tbody.innerHTML = data.attestations.map(a => `
            <tr>
                <td><span class="hash" onclick="lookupAttestation('${a.hash}')">${a.hash.substring(0, 16)}...</span></td>
                <td>#${a.sequence.toLocaleString()}</td>
                <td>${escapeHtml(a.network_id)}</td>
                <td><span class="badge success">${a.signature_count} sigs</span></td>
                <td>${a.batch_id ? `#${a.batch_id}` : '<span class="badge neutral">unbatched</span>'}</td>
                <td class="time-ago">${formatTimeAgo(a.time_ago)}</td>
            </tr>
        `).join('');

        renderPagination('attestations-pagination', data.page, data.pages, (p) => {
            loadAttestations(p, state.attestationsSearch);
        });
    } catch (e) {
        console.error('Failed to fetch attestations:', e);
        tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">Failed to load attestations</td></tr>';
    }
}

// ============================================================================
// Batches Tab
// ============================================================================

async function loadBatches(page = 1) {
    state.batchesPage = page;

    const tbody = document.getElementById('batches-table');
    tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">Loading...</td></tr>';

    try {
        const data = await fetchJson(`/admin/api/batches?page=${page}&limit=${BATCHES_PER_PAGE}`);

        document.getElementById('batches-total').textContent = `(${data.total.toLocaleString()} total)`;

        if (data.batches.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">No batches yet</td></tr>';
            document.getElementById('batches-pagination').innerHTML = '';
            return;
        }

        tbody.innerHTML = data.batches.map(b => `
            <tr>
                <td>#${b.id}</td>
                <td><span class="hash">${b.merkle_root.substring(0, 16)}...</span></td>
                <td>${b.attestation_count.toLocaleString()}</td>
                <td>${formatDate(b.created_at)}</td>
                <td>${b.anchored
                    ? '<span class="badge success">anchored</span>'
                    : '<span class="badge warning">pending</span>'
                }</td>
            </tr>
        `).join('');

        renderPagination('batches-pagination', data.page, data.pages, loadBatches);
    } catch (e) {
        console.error('Failed to fetch batches:', e);
        tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">Failed to load batches</td></tr>';
    }
}

// ============================================================================
// Anchors Tab
// ============================================================================

async function loadAnchorDetails() {
    const container = document.getElementById('anchor-details');
    container.innerHTML = '<div class="loading-cell">Loading...</div>';

    try {
        const anchors = await fetchJson('/admin/api/anchors');

        if (anchors.length === 0) {
            container.innerHTML = '<div class="empty-state"><div class="icon">-</div><p>No external anchors configured</p></div>';
            return;
        }

        container.innerHTML = anchors.map(a => `
            <div class="anchor-card">
                <div class="anchor-header">
                    <span class="dot ${a.enabled ? (a.last_anchor_time ? 'online' : 'loading') : 'offline'}"></span>
                    <span class="name">${escapeHtml(a.provider)}</span>
                    <span class="badge ${a.enabled ? 'success' : 'neutral'}">${a.enabled ? 'enabled' : 'disabled'}</span>
                </div>
                <div class="anchor-stats">
                    <div>Total anchors: <strong>${a.total_anchors.toLocaleString()}</strong></div>
                    <div>Last anchor: <strong>${a.last_anchor_ago || 'Never'}</strong></div>
                </div>
            </div>
        `).join('');
    } catch (e) {
        console.error('Failed to fetch anchor details:', e);
        container.innerHTML = '<div class="loading-cell">Failed to load anchor details</div>';
    }
}

// ============================================================================
// Attestation Lookup & Modal
// ============================================================================

async function lookupAttestation(hash) {
    if (!hash || hash.length < 8) {
        showError('Hash must be at least 8 characters');
        return;
    }

    try {
        const data = await fetchJson(`/admin/api/attestation/${encodeURIComponent(hash)}`);
        state.currentAttestation = data;
        showAttestationModal(data);
    } catch (e) {
        console.error('Failed to lookup attestation:', e);
        showError('Attestation not found');
    }
}

function showAttestationModal(attestation) {
    const modal = document.getElementById('attestation-modal');
    const detail = document.getElementById('attestation-detail');

    // Render attestation details
    detail.innerHTML = `
        <div class="detail-section">
            <div class="detail-label">Hash</div>
            <div class="detail-value hash-full">${attestation.hash}</div>
        </div>

        <div class="detail-grid">
            <div class="detail-item">
                <div class="label">Sequence</div>
                <div class="value">#${attestation.sequence.toLocaleString()}</div>
            </div>
            <div class="detail-item">
                <div class="label">Timestamp</div>
                <div class="value">${formatTimestamp(attestation.timestamp)}</div>
            </div>
            <div class="detail-item">
                <div class="label">Network</div>
                <div class="value">${escapeHtml(attestation.network_id)}</div>
            </div>
            <div class="detail-item">
                <div class="label">Batch</div>
                <div class="value">${attestation.batch_id ? '#' + attestation.batch_id : '-'}</div>
            </div>
        </div>

        <div class="detail-section">
            <div class="detail-label">Signatures (${attestation.signatures.length})</div>
            <div class="signature-list">
                ${attestation.signatures.map(s => `
                    <div class="signature-item">
                        <span class="dot online"></span>
                        <span class="witness-id">${escapeHtml(s.witness_id)}</span>
                        <span class="sig">${s.signature.substring(0, 32)}...</span>
                    </div>
                `).join('')}
            </div>
        </div>

        ${attestation.anchor_proofs && attestation.anchor_proofs.length > 0 ? `
            <div class="detail-section">
                <div class="detail-label">External Anchors</div>
                ${attestation.anchor_proofs.map(p => `
                    <div class="anchor-proof-item">
                        <span class="dot online"></span>
                        <div>
                            <div class="provider">${escapeHtml(p.provider)}</div>
                            <div class="timestamp">${formatTimestamp(p.timestamp)}</div>
                            ${p.proof && p.proof.url ? `<a href="${p.proof.url}" target="_blank" class="proof-link">${p.proof.url}</a>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        ` : ''}
    `;

    modal.classList.remove('hidden');
}

function hideModal() {
    document.getElementById('attestation-modal').classList.add('hidden');
    state.currentAttestation = null;
}

function copyAttestationJson() {
    if (!state.currentAttestation) return;

    const json = JSON.stringify(state.currentAttestation, null, 2);
    navigator.clipboard.writeText(json).then(() => {
        showSuccess('JSON copied to clipboard');
    }).catch(() => {
        showError('Failed to copy to clipboard');
    });
}

// ============================================================================
// Pagination
// ============================================================================

function renderPagination(containerId, current, total, onPageChange) {
    const container = document.getElementById(containerId);

    if (total <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    // Previous button
    html += `<button ${current === 1 ? 'disabled' : ''} onclick="(${onPageChange.toString()})(${current - 1})">Prev</button>`;

    // Page numbers
    const maxVisible = 5;
    let startPage = Math.max(1, current - Math.floor(maxVisible / 2));
    let endPage = Math.min(total, startPage + maxVisible - 1);

    if (endPage - startPage < maxVisible - 1) {
        startPage = Math.max(1, endPage - maxVisible + 1);
    }

    if (startPage > 1) {
        html += `<button onclick="(${onPageChange.toString()})(1)">1</button>`;
        if (startPage > 2) {
            html += '<span class="page-info">...</span>';
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="${i === current ? 'active' : ''}" onclick="(${onPageChange.toString()})(${i})">${i}</button>`;
    }

    if (endPage < total) {
        if (endPage < total - 1) {
            html += '<span class="page-info">...</span>';
        }
        html += `<button onclick="(${onPageChange.toString()})(${total})">${total}</button>`;
    }

    // Next button
    html += `<button ${current === total ? 'disabled' : ''} onclick="(${onPageChange.toString()})(${current + 1})">Next</button>`;

    container.innerHTML = html;
}

// ============================================================================
// Utilities
// ============================================================================

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Initial load
    loadOverview();

    // Tab click handlers
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Search handler
    document.getElementById('search-btn').addEventListener('click', () => {
        const hash = document.getElementById('hash-search').value.trim();
        if (hash) lookupAttestation(hash);
    });

    // Enter key for search
    document.getElementById('hash-search').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const hash = e.target.value.trim();
            if (hash) lookupAttestation(hash);
        }
    });

    // Attestation filter (in attestations tab)
    const attestationFilter = document.getElementById('attestation-filter');
    if (attestationFilter) {
        attestationFilter.addEventListener('input', debounce((e) => {
            const search = e.target.value.trim();
            if (search.length === 0 || search.length >= 8) {
                loadAttestations(1, search);
            }
        }, 300));
    }

    // Modal close handlers
    document.querySelector('.modal-close').addEventListener('click', hideModal);
    document.querySelector('.modal-close-btn').addEventListener('click', hideModal);
    document.querySelector('.modal-overlay').addEventListener('click', hideModal);

    // Copy JSON button
    document.getElementById('copy-json-btn').addEventListener('click', copyAttestationJson);

    // Toast close
    document.querySelector('.toast-close').addEventListener('click', () => {
        document.getElementById('error-toast').classList.add('hidden');
    });

    // Escape key to close modal
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideModal();
        }
    });

    // Polling for overview (only when on overview tab)
    setInterval(() => {
        if (state.currentTab === 'overview') {
            updateStats();
            updateRecent();
            updateMetrics();
        }
    }, 5000);

    setInterval(() => {
        if (state.currentTab === 'overview') {
            updateWitnesses();
            updateAnchorsOverview();
        }
    }, 30000);
});
