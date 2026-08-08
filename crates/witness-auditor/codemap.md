# crates/witness-auditor/

## Responsibility

`witness-auditor` is an independent auditor binary that continuously walks a witness gateway's RFC 9162 (Certificate Transparency v2) log chain: it polls the gateway's latest Signed Tree Head, verifies the threshold signature on each new STH and the RFC 9162 consistency proof linking it to the previously accepted STH, and persists an append-only record of every accepted STH and every detected anomaly in SQLite. Its purpose is *anti-rollback memory* — if a gateway deletes or rewinds entries, changes a root at the same tree size, or emits a bogus signature/consistency proof, the auditor records a failure that survives restarts. It is a **client only**: it holds no keys and performs no signing.

## Design

- Hybrid `[[bin]]` + library crate. `lib.rs` exposes `audit`, `client`, `storage` modules; `main.rs` is a thin clap CLI over them.
- **Core abstraction**: `Auditor` (audit.rs) — holds `gateway_url`, a `GatewayClient`, and `Storage`. Its `tick()` performs one audit cycle and returns `TickResult::{NoChange, NewSth(SignedTreeHead), Failed}`.
- **Verification is delegated to `witness-core`** (`verify_signed_tree_head`, `verify_log_consistency`) against the network's secret-free `NetworkVerificationConfig` fetched from the gateway — the gateway is never trusted for the verdict, only for its own transcript.
- **Persistent state** (`storage.rs`, sqlx/SQLite in WAL mode): `audited_sths` keyed by `(gateway_url, tree_size)` holds every successfully verified STH; `audit_failures` is an append-only anomaly log. `FailureType` is an enum serialized as a string so new variants don't require a schema migration.
- `tick()` checks, in order: fetch latest STH → tree-size regression vs. last accepted → root-hash mismatch at the same tree size → threshold-signature verification → RFC 9162 consistency proof `prev.size → latest.size` → persist. First-ever STH for a gateway is signature-verified then accepted (no consistency check possible).
- CLI: `check` (one cycle, exit code reflects failure), `watch` (continuous poll loop with configurable interval), `status` (latest STH + recent failures), `history` (recent STHs across gateways).

## Flow

1. `main.rs` parses `--gateway`/`WITNESS_GATEWAY`, `--database`/`WITNESS_AUDITOR_DB` (default `witness-auditor.db`) and a subcommand; opens `Storage` and runs `sqlx::migrate!("./migrations")` (forward-only).
2. `check`/`watch` construct `Auditor::new` and call `tick()`.
3. `tick()`: `GatewayClient.get_latest_sth()` → if fetch fails, record `Fetch` failure → `Storage.latest_sth(gateway_url)` → either `accept_first_sth` (verify signature, record) or `audit_with_previous` (regression/root-mismatch checks, signature verify, consistency-proof verify, record).
4. Every anomaly writes to `audit_failures`; every verified STH writes to `audited_sths`. `status`/`history` read that state back out for operators.

## Integration

- HTTP client to the gateway's log endpoints: `GET /v1/log/sth`, `GET /v1/log/consistency?first=&second=`, `GET /v1/network` (see `src/codemap.md`).
- Uses `witness-core` for types (`SignedTreeHead`, `TreeHead`, `LogConsistencyProof`, `NetworkVerificationConfig`, `SignedAttestation`) and all verification functions.
- Depends on `sqlx` with the `migrate` feature; the single forward-only migration `migrations/0001_initial_schema.sql` is compiled in and run at startup.
- Runs standalone (cron-driven `check` or daemonized `watch`); nothing else in the workspace consumes the auditor crate.
- **Trust note / security-sensitive**: the auditor fetches its own `NetworkVerificationConfig` from the gateway it audits, so its trust anchor is the network's public-key set; an attacker controlling both the gateway transcript and the config endpoint could fool the auditor. Independent key distribution (config snapshot at bootstrap) is a hardening direction — flag before changing verification behavior.
