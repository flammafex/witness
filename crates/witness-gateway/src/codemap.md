# crates/witness-gateway/src/

## Responsibility

All source of the `witness-gateway` binary and library: the public HTTP API,
durable attestation-job storage, threshold aggregation of witness signatures,
batch/STH management, federation + external anchoring, Freebird admission,
metrics, and the security hardening (SSRF, rate limiting, constant-time auth).

## Design

The crate is organized as one library crate (`lib.rs` re-exports 16 modules)
plus a thin `main.rs` binary that wires everything. HTTP is Axum with focused
per-route state. Background work is a set of independent `tokio::spawn` loops
over the same `Arc<Storage>` and `Arc<NetworkConfig>`. All auth comparisons use
`witness_core::constant_time_eq`; all outbound HTTP uses the SSRF-safe client.

## Module map

### main.rs — CLI entrypoint & composition root
- **Responsibility**: Parse CLI/env config, load+validate `network.json`, build
  storage and every manager, start background tasks, run `GatewayServer`, and
  coordinate graceful shutdown via a `CancellationToken` (SIGINT/SIGTERM).
- **Key items**: `Args` (config/port/host/database, `--admin-ui`,
  `--admin-api-key`, `--ws-auth-token`, `--metrics-token`, `--behind-proxy`,
  all with env fallbacks); startup validation that every witness has a
  non-empty `auth_token`; `is_non_loopback_host` warning logic.
- **Consumers**: everything is created here — `Storage`, `AnchorManager`,
  `FederationClient`, `BatchManager`, `Reconciler`/`AttestationWorker`,
  `FreebirdClient` (env-driven), `AdminState`, `GatewayServer`.
- **Security**: startup abort on missing witness tokens; SECURITY warnings when
  Freebird is disabled, federation lacks `inbound_auth_token`, or the gateway
  binds non-loopback without a proxy.

### lib.rs — module facade
- **Responsibility**: Declare the 16 public modules. No logic.
- **Consumers**: `main.rs` imports everything from here.

### server/ — HTTP layer (module directory, split from the former ~1390-line server.rs)
- **Responsibility**: The Axum router and every handler: public config/verify/
  proof/bundle/RFC 9162 endpoints, attestation submission, federation anchor
  inbound, metrics, WebSocket events, admin middleware. Cosmetically split
  (Phase 4) into:
  - `server/mod.rs` (554 lines): imports, `NetworkConfigPublic`, `AttestationEvent`,
    the focused states (`CoreState`, `AttestationState`, `FederationState`,
    `MetricsState`, `AdminAuthState`), `GatewayServer` + router (line 214),
    admin middleware, `collect_signatures_until_threshold`, body_limit/cors tests.
  - `server/routes.rs` (601 lines): all 20 handlers — root/health/config/network,
    `decode_hash`, `build_merkle_inclusion_proof`, get_attestation/verify/
    get_anchors/get_proof/get_proof_bundle, RFC 9162 (`get_latest_sth`,
    `get_sth_at_size`, `get_consistency`, `get_log_proof`), `create_attestation`,
    `federation_anchor`, `metrics`, plus `ProofResponse`/`ConsistencyQuery`/
    `LogProofQuery`/`LogInclusionProofResponse`.
  - `server/ws.rs` (113 lines): `ws_events_handler`, `handle_ws_connection`.
  - `server/federation_auth.rs` (192 lines): `FederationAuthStore`, `TokenEntry`,
    `generate_random_token`, and their tests.
- **Key types**: `GatewayServer` (orchestrator), focused states (`CoreState`,
  `AttestationState`, `FederationState`, `MetricsState`, `AdminAuthState`),
  `FederationAuthStore` (in-memory per-partner token rotation + expiry),
  `NetworkConfigPublic` (token-stripped `/v1/config` response), `AttestationEvent`.
- **Key handlers**: `create_attestation_handler` (admission pipeline),
  `federation_anchor_handler` (inbound cross-anchor, bearer auth + 10/min
  rate limit, polls the durable worker until the signed response is ready),
  `verify_handler` (re-verifies via `witness_core::verify_signed_attestation`),
  `get_proof_bundle_handler` (self-contained `ProofBundle`),
  `get_consistency_handler`/`get_log_proof_handler` (RFC 9162 §4.10/§4.11),
  `ws_events_handler` (broadcast channel, first-message token challenge),
  `metrics_handler` (bearer-gated Prometheus), `collect_signatures_until_threshold`
  (used by batch/STH signing).
- **Consumers**: main.rs (GatewayServer), batch_manager.rs
  (`collect_signatures_until_threshold`), admin.rs (`admin_router` nest).
- **Security**: federation inbound auth via `FederationAuthStore` +
  `constant_time_eq`; `CorsLayer::permissive()` at router level; `DefaultBodyLimit`
  64 KB; admin middleware authenticates before rate-limiting (no state leak to
  unauthenticated callers).

### admin.rs — admin dashboard UI
- **Responsibility**: Read-only operator dashboard at `/admin`: stats, witness
  health/latency, recent attestations, anchor status.
- **Key items**: `AdminState` (config + storage + start_time); `admin_router`
  (`/`, `/api/stats`, `/api/witnesses`, `/api/recent`, `/api/anchors`);
  `generate_dashboard_html` (self-contained HTML/JS, polling fetch).
- **Consumers**: server/mod.rs nests `admin_router` behind `admin_auth_middleware`
  when `--admin-ui` is set.
- **Security**: never configured without an API key (main.rs aborts); middleware
  checks `x-admin-key` / Bearer / Basic against the key via `constant_time_eq`,
  5/min per-IP rate limit after auth.

### storage.rs — SQLite persistence
- **Responsibility**: All database access for the job lifecycle, batching,
  cross-anchors, STHs, external anchors, log queries, and admin stats. WAL mode
  + `synchronous=Normal` set at connection time (not in a migration).
- **Key types**: `Storage` (sqlx `SqlitePool`, 5 conns, 5s busy timeout),
  `JobReservation` (canonical tuple + `created` flag), `JobClaim` (attestation +
  opaque lease token + expiry + attempts), `LogState` (cached O(1) STH state).
- **Key functions**: `reserve_job` (atomic sequence + insert, canonical across
  all networks), `claim_job` (one due unexpired pending/retryable job), `complete_verified_job`
  (lease-guarded immutable finalization, replaces fragments), `reschedule_job`
  (exponential backoff `now + MIN(300, 1 << MIN(attempts-1,8))`), `fail_job`,
  `get_job` (consistent snapshot; signatures only for confirmed),
  `get_unbatched_attestations`/`store_batch` (transactional batch + merkle-index
  linking), `store_cross_anchor`, `store_sth`/`get_sth`/`get_latest_sth`,
  `get_log_leaves`/`get_log_index`, `store_anchor_proof`, admin counters.
- **Consumers**: every other module — server/, batch_manager.rs,
  anchor_manager.rs, federation_client.rs, reconciler.rs, admin.rs.
- **Notes**: `migrate_bls_legacy_rows` is a runtime data migration; `u64↔i64`
  range checks reject out-of-range values; `sanitize_job_error` strips control
  chars and caps at 512 chars; heavy test coverage of lease races, rollback
  atomicity, and migration behavior.

### batch_manager.rs — periodic batch closure + STH signing
- **Responsibility**: On `federation.batch_period`, close the current batch over
  all confirmed unbatched attestations, store it, and issue a threshold-signed
  RFC 9162 STH.
- **Key items**: `BatchManager` (`start` spawns the interval loop; disabled when
  federation is off; holds `Arc<dyn WitnessClientTrait>` for witness fan-out),
  `close_batch` (re-verifies every candidate via
  `verify_signed_attestation` and skips invalid ones), `sign_and_store_sth`
  (global Merkle Tree Hash over all log leaves → `TreeHead` → threshold
  signatures via `collect_signatures_until_threshold` → Ed25519 multisig or BLS
  aggregate → re-verify before persisting).
- **Consumers**: main.rs; drives `AnchorManager::anchor_batch_async` and
  `FederationClient::cross_anchor_batch` (both fire-and-forget).
- **Design note**: STH failure is loud but non-fatal — the batch stands and the
  next closure catches up; no timestamp watermark on candidates.

### anchor_manager.rs — external anchoring orchestration
- **Responsibility**: Initialize enabled anchor providers from
  `external_anchors` config and anchor each closed batch to them.
- **Key items**: `AnchorManager::new` (builds `InternetArchiveProvider`,
  `TrillianProvider`, `DnsTxtProvider`, `EthereumProvider` from config;
  skips misconfigured providers with error logs), `anchor_batch_async`
  (spawns the work), `anchor_batch_internal` (parallel fan-out, requires
  `minimum_required` successes, persists proofs + metrics).
- **Consumers**: main.rs, batch_manager.rs.

### anchor_providers.rs — external anchor provider implementations
- **Responsibility**: Concrete `AnchorProvider` implementations.
- **Key items**: `AnchorProvider` trait (`anchor`, `provider_type`);
  `InternetArchiveProvider` (Save API over a data-URL payload),
  `EthereumProvider` (0-value tx carrying the merkle root as calldata, waits for
  a successful receipt; RPC URL SSRF-validated in `new`), `TrillianProvider`
  (POST base64 JSON entry to `<log_url>/add`, records tree_size/log_index/
  inclusion_proof), `DnsTxtProvider` (HTTP DNS API, `_witness-<id>.<domain>`
  TXT record, optional Bearer API key).
- **Consumers**: anchor_manager.rs.
- **Security**: Ethereum RPC URL goes through `validate_outbound_url`; all
  providers use hardened clients built by `http_client::build_client`.

### federation_client.rs — outbound cross-anchor client
- **Responsibility**: Submit a closed batch to every peer network for
  cross-anchoring and store the returned `CrossAnchor`s.
- **Key items**: `cross_anchor_batch` (parallel fan-out, collects successes),
  `request_cross_anchor` (POST `<peer.gateway>/v1/federation/anchor` with
  `bearer_auth(peer.auth_token)`), `validate_outbound_url` SSRF check per peer.
- **Consumers**: main.rs, batch_manager.rs.

### witness_client.rs — witness signing client
- **Responsibility**: Talk to `witness-node` instances: request signatures and
  poll health.
- **Key items**: `request_signature` (POST `<endpoint>/v1/sign`, bearer auth
  with the witness's `auth_token`, returns `SignResponse`), `health_check`
  (GET /health, 5s timeout).
- **Consumers**: reconciler.rs (via `WitnessClientTrait`), batch_manager.rs
  (STH signing via `WitnessClientTrait`), server/mod.rs
  (`collect_signatures_until_threshold`), main.rs (health poller).

### reconciler.rs — leased attestation worker + reconciler loop
- **Responsibility**: The durable threshold-aggregation engine for attestation
  jobs: claim → collect → verify → confirm/retry/fail.
- **Key types**: `AttestationWorker` (claim + collect + finalize),
  `JobClock`/`SystemJobClock` (injectable time for tests), `RunOutcome`
  (`Idle|Confirmed|RetryScheduled|Failed|LeaseLost`), `Reconciler` (cancel-aware
  run loop with 1s idle interval).
- **Key functions**: `run_once` (claim_job → `validate_claim` → `collect_verified_result` →
  threshold re-verification → `complete_verified_job`), `collect_verified_result`
  (parallel fan-out with per-witness signature verification, witness-id match
  check, dedup, attempt deadline `min(request_timeout, lease-1ms)`, BLS
  aggregation), `validate_claim` (config valid + unique witness ids/keys +
  tokens present; failures are terminal).
- **Consumers**: main.rs spawns `Reconciler::run`; storage.rs provides the job
  primitives; `WitnessClientTrait` (traits.rs) makes the worker testable with
  mocks (extensive Ed25519/BLS/cancellation/lease test suite).
- **Security**: this is the only place ordinary attestation signatures are
  collected and verified before persistence; every individual signature is
  checked, and the final result is re-verified with the client-facing verifier.

### freebird.rs — Freebird anonymous rate limiting
- **Responsibility**: Verify Freebird proof-of-work/humanity tokens against an
  external verifier as an admission gate for attestation requests.
- **Key items**: `FreebirdClient` (env-configured: `FREEBIRD_VERIFIER_URL`,
  `FREEBIRD_REQUIRED`, `FREEBIRD_CONSUME_TOKENS`, `FREEBIRD_ALLOW_INSECURE_LOCAL`),
  `FreebirdError`; `verify` posts `{ "token_b64": "..." }` to `/v1/verify`
  (consuming, default) or `/v1/check` (non-consuming).
- **Consumers**: server/routes.rs `create_attestation_handler`.
- **Security**: URL validated via `validate_local_dev_url` (plaintext loopback
  only, dev) or `validate_outbound_url` (SSRF filter); required vs permissive
  mode determines 401 behavior; non-consuming mode warns about token reuse.

### dns_resolver.rs — SSRF-safe DNS resolver
- **Responsibility**: `reqwest::dns::Resolve` impl that blocks loopback,
  RFC-1918/private, link-local, and IPv6 local/ULA ranges — except for
  explicitly whitelisted internal host suffixes (`.internal`, `.local`,
  `.docker`, `.svc`, `.cluster.local`).
- **Key items**: `SafeResolver`, `resolve_safe`, `is_private_ip`, `is_whitelisted`.
- **Consumers**: http_client.rs (`build_client` installs it on every outbound
  client).

### http_client.rs — hardened HTTP client + SSRF validation
- **Responsibility**: Single factory for hardened `reqwest::Client`s
  (HTTPS-only unless allowed, 10s timeout, SafeResolver DNS) and URL
  validation helpers.
- **Key items**: `build_client(allow_http)`, `validate_outbound_url` (rejects
  loopback/private/link-local via DNS or literal), `validate_local_dev_url`
  (plaintext loopback only, for dev Freebird), `check_ip_allowed`.
- **Consumers**: witness_client.rs, federation_client.rs, freebird.rs,
  anchor_providers.rs.
- **Security**: the SSRF filter for all outbound network calls; keep enabled.

### metrics.rs — Prometheus metrics
- **Responsibility**: Global recorder + counters/gauges/histograms.
- **Key items**: `init_metrics` (PrometheusBuilder), `record_attestation`,
  `record_signatures`, `record_batch`, `record_anchor`, `set_attestations_24h`,
  `set_witness_health`, `set_uptime`, `RequestTimer` (per-endpoint duration
  histogram).
- **Consumers**: main.rs (init + uptime/health pollers), server/mod.rs (timer),
  reconciler.rs, batch_manager.rs, anchor_manager.rs, admin.rs.

### real_ip.rs — trusted client IP extraction
- **Responsibility**: Resolve the effective client IP for rate limiting.
- **Key items**: `real_ip(headers, socket_addr, behind_proxy)` — when
  `behind_proxy`, uses the leftmost `X-Forwarded-For` entry (set by a trusted
  reverse proxy); otherwise the TCP socket address.
- **Consumers**: server/ (attestation, federation, admin middleware),
  main.rs (via `--behind-proxy`).
- **Security**: never trust the header in direct-connect mode, or any client can
  spoof its IP to bypass rate limits.

### traits.rs — witness client abstraction
- **Responsibility**: `WitnessClientTrait` async trait over signature collection
  so `AttestationWorker` and `BatchManager` (STH signing) can be unit-tested with
  mock witnesses.
- **Key items**: `WitnessClientTrait::request_signature`; blanket impl for
  `witness_client::WitnessClient`.
- **Consumers**: reconciler.rs (worker holds `Arc<dyn WitnessClientTrait>`),
  batch_manager.rs (`BatchManager` holds `Arc<dyn WitnessClientTrait>` for STH
  signing).

### error.rs — HTTP error mapping
- **Responsibility**: `AppError` enum + `IntoResponse` mapping every failure to
  an HTTP status with a JSON `{ "error": ... }` body.
- **Key items**: variants (InvalidHash, NotFound, NotBatched, InvalidSignature,
  InsufficientSignatures, Unauthorized, RateLimited, DatabaseError, Freebird*),
  `From` impls for `sqlx::Error`, `anyhow::Error`, `FreebirdError`.
- **Consumers**: every handler in server/routes.rs returns `Result<_, AppError>`.

### epoch.rs — wall-clock helper
- **Responsibility**: `epoch_secs()` — current UNIX time in seconds (used for
  attestation timestamps, leases, expiry, retry scheduling).
- **Consumers**: storage.rs, batch_manager.rs, server/, anchor_providers.rs,
  reconciler.rs, admin.rs, anchor_manager.rs (indirectly).

## Flow (request lifecycle + background workers)

**Public timestamp request** → `server/routes.rs::create_attestation_handler`
(admission: dedupe, per-hash lock, rate limit, Freebird) →
`storage.reserve_job` (canonical pending tuple) → broadcast `AttestationEvent`
→ **Reconciler loop** (`reconciler.rs`) `claim_job` → `collect_verified_result`
(witness fan-out via `WitnessClient`, per-signature verify) → threshold check →
`complete_verified_job` → confirmed, immutable.

**Batch loop** → `BatchManager` tick → verified candidates →
`storage.store_batch` → `sign_and_store_sth` (threshold-signed tree head) →
fire-and-forget `AnchorManager::anchor_batch_async` (parallel providers,
minimum-required gate, persist proofs) and `FederationClient::cross_anchor_batch`
(peer fan-out, store cross-anchors).

**Inbound federation** → `federation_anchor_handler` (bearer auth, rate limit) →
`reserve_job(merkle_root)` → wait for the durable worker to confirm it → return
a `CrossAnchor` wrapping the threshold-signed attestation.

**Retrieval/verification** → handlers read storage, recompute Merkle proofs from
`get_batch_attestation_hashes`/`get_log_leaves`, and expose STHs/consistency/
inclusion for offline verification by clients and the auditor.

## Integration

- **witness-core**: all types, crypto, Merkle/log proof computation, verification
  and constant-time helpers; the gateway never implements signing itself.
- **witness-node**: outbound `WitnessClient` for signatures; inbound clients of
  our endpoints include `witness-cli` and `witness-auditor`.
- **Peers**: outbound `FederationClient` ↔ inbound `federation_anchor_handler`
  (both Bearer-authenticated).
- **External**: Internet Archive / Trillian / DNS API / Ethereum RPC (SSRF-safe);
  Freebird verifier (SSRF-safe, loopback-only in dev).
- **Security-sensitive modules**: server/ (all auth + CORS),
  http_client.rs + dns_resolver.rs (SSRF), freebird.rs (verification logic),
  main.rs (startup token validation), real_ip.rs (spoofing resistance),
  storage.rs (lease correctness underpins every confirmed result).
