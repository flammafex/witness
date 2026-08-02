# crates/witness-gateway/

## Responsibility

Gateway server that aggregates witness signatures for timestamping. This is the
MAIN binary of the Witness system: it exposes the public HTTP API, admits and
deduplicates timestamp requests, runs the durable leased workers that collect
and threshold-verify witness signatures, closes batches into a Merkle log,
issues RFC 9162 Signed Tree Heads, cross-anchors batches with peer federations,
and anchors batch roots to external services (Internet Archive, Trillian, DNS
TXT, Ethereum). It also hosts the admin dashboard, Prometheus metrics, WebSocket
event stream, and optional Freebird anonymous rate limiting.

It is the only crate besides `witness-node` that orchestrates signing activity;
all signing primitives live in `witness-core` (the shared trust root), and all
verification is performed against `witness-core` verifiers before anything is
persisted as a confirmed result.

## Design

- **Library facade + thin binary**: `src/lib.rs` exposes 16 modules; `main.rs`
  is a thin CLI wrapper (`clap`) that reads `network.json`, validates it (witness
  `auth_token`s mandatory at startup), initializes storage + migrations, and
  wires the background tasks before handing control to `server::GatewayServer`.
- **Route-grouped Axum state**: `server/mod.rs` deliberately uses *focused* state
  structs (`AttestationState`, `FederationState`, `MetricsState`, `CoreState`,
  `AdminAuthState`) instead of one blob, so rate limits and admission controls
  are scoped per route family. `CorsLayer::permissive()` is applied router-wide
  (security-sensitive — see note below).
- **Durable lease-based job model**: attestation lifecycle is `reserve_job →
  claim_job (opaque 32-byte lease token + expiry) → complete_verified_job /
  reschedule_job / fail_job`. Sequence allocation and canonical-tuple insertion
  share one RAII transaction in `storage.rs`; leases make retries crash-safe and
  allow multiple gateway replicas to claim distinct work.
- **Two signature schemes**: Ed25519 multi-sig (per-witness rows in `signatures`)
  and BLS12-381 aggregated signatures (`aggregated_signatures`/`aggregated_signers`),
  selected by `NetworkConfig.signature_scheme`.
- **Threshold everywhere**: attestations, batch STHs, and cross-anchor responses
  all require a verified threshold of witness signatures before persisting.
  Defence in depth — the worker re-verifies the final aggregate with the same
  verifier clients will use.
- **Background task set** (all `tokio::spawn` from `main.rs`):
  - `reconciler::Reconciler` — single leased attestation worker loop (drains pending jobs).
  - `batch_manager::BatchManager` — periodic batch closure + STH signing.
  - `anchor_manager::AnchorManager` — fire-and-forget external anchoring per batch.
  - `federation_client::FederationClient` — fire-and-forget cross-anchor fan-out.
  - `metrics` uptime gauge + witness health pollers.
- **SSRF-hardened outbound HTTP**: every client goes through
  `http_client::build_client`, which installs `dns_resolver::SafeResolver`
  (blocks loopback/private/link-local resolutions) and HTTPS-only unless an
  explicit dev flag allows plaintext loopback. `validate_outbound_url` is
  additionally called by federation, Freebird, and the Ethereum RPC provider.
- **Forward-only SQL migrations** compiled via `sqlx::migrate!("./migrations")`
  run at startup (`storage::Storage::migrate`), plus a runtime idempotent
  one-time data migration (`migrate_bls_legacy_rows`) that moves legacy
  `BLS_AGGREGATED:...` rows into the dedicated BLS tables.

## Flow

1. **Admission** — `POST /v1/attestations` (`create_attestation_handler`):
   hex-decode 32-byte hash → fast duplicate lookup → in-process per-hash mutex
   (second lookup under lock to avoid consuming one-use admission tokens) →
   `real_ip` (trusted only behind proxy) → governor per-IP rate limit (30/min)
   → optional Freebird token verification (required mode → 401 without token) →
   `storage.reserve_job` atomically creates the canonical pending tuple.
2. **Threshold aggregation** — the `Reconciler` loop calls `storage.claim_job`
   (leases one due job), validates config invariants, fans out `WitnessClient`
   signing requests in parallel, verifies every individual response
   (Ed25519/BLS, witness-id match, no duplicates), and on reaching threshold
   aggregates and re-verifies before `complete_verified_job`.
3. **Storage** — confirmed `SignedAttestation` rows are written under lease; any
   previously-persisted fragments are replaced atomically. Confirmed results are
   immutable (a stale lease or mismatched tuple is a no-op).
4. **Batching** — `BatchManager` periodically selects confirmed, unbatched
   candidates (ordered by `(sequence, hash)`, no timestamp watermark so
   long-retried jobs stay eligible), stores the batch + Merkle root
   transactionally, then issues a threshold-signed STH over the full log.
5. **Anchoring pipeline** — on batch close, `AnchorManager` fans out to enabled
   external providers (≥ `minimum_required` successes required) and
   `FederationClient` submits `POST /v1/federation/anchor` to peers; proofs and
   cross-anchors are persisted per batch.
6. **Verification/retrieval** — clients read the job (`GET /v1/attestations/:hash`),
   Merkle proofs (`/v1/proof/:hash`), self-contained proof bundles
   (`/v1/bundle/:hash`), anchors (`/v1/anchors/:hash`), and RFC 9162 log
   endpoints (STH at latest/specific size, consistency, inclusion). `POST
   /v1/verify` re-checks a signed attestation against the network config.

## Integration

- **witness-core** — shared trust root consumed everywhere: `Attestation`,
  `SignedAttestation`, `NetworkConfig`, `AttestationBatch`, `SignedTreeHead`,
  `CrossAnchor`, `ExternalAnchorProof`, Merkle/log/proof types,
  `verify_signed_attestation`, `aggregate_signatures_bls`, `constant_time_eq`.
  Crate boundary is strict: gateway orchestrates and verifies, it never defines
  crypto or serialization.
- **witness-node** — via `WitnessClient` (HTTP `POST /v1/sign`, bearer auth with
  per-witness tokens; `GET /health` for the health poller).
- **Peer federations** — via `FederationClient` (outbound) and the inbound
  `/v1/federation/anchor` route (bearer `inbound_auth_token`, in-memory
  `FederationAuthStore` with rotation + hourly expiry cleanup).
- **External anchor providers** — Internet Archive (Save API data-URL), Trillian
  (JSON log), DNS TXT (HTTP DNS API), Ethereum (0-value data tx) — all behind
  the SSRF-safe HTTP client.
- **Freebird** — optional out-of-process anonymous rate limiter: `{ "token_b64":
  "..." }` to `/v1/verify` (consuming, default) or `/v1/check` (non-consuming).
  URL-gated to loopback-only in dev mode; SSRF-validated otherwise.
- **Observability** — Prometheus metrics via `metrics-exporter-prometheus`
  (`/metrics`, bearer-token gated), structured tracing via `tracing`/EnvFilter,
  optional `/admin` dashboard (x-admin-key / Bearer / Basic auth,
  `constant_time_eq`, 5/min rate limit).
- **CLI/auditor** — `witness-cli` and `witness-auditor` are HTTP clients of this
  crate's public endpoints and consume `witness-core` for offline verification.

### Security-sensitive areas (flag before modifying)

- **Auth token validation**: witness `auth_token`s (startup abort if missing),
  federation `inbound_auth_token` + rotated tokens, admin API key, metrics
  bearer token, and WebSocket first-message token — all compared with
  `witness_core::constant_time_eq`.
- **SSRF filter**: `http_client::validate_outbound_url` +
  `dns_resolver::SafeResolver` must stay enabled on all outbound calls
  (witness/federation/Freebird/anchor providers).
- **Freebird verification logic**: endpoint selection (`/v1/verify` vs
  `/v1/check`) and required/permissive modes in `freebird.rs`.
- **CORS**: `CorsLayer::permissive()` on the gateway router — confirm intent
  before tightening.
- **`network.json` shape** — carries witness `auth_token` in plaintext;
  operational secret. `network_config_handler` must keep stripping tokens
  (`#[serde(skip_serializing)]` on token fields).
