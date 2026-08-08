# crates/witness-auditor/src/

## Responsibility

Five modules implementing the auditor: the CLI entry point (`main.rs`), module re-exports (`lib.rs`), the audit loop (`audit.rs`), the gateway HTTP client (`client.rs`), and SQLite persistence (`storage.rs`).

### `main.rs`

- **Responsibility**: binary entry point; clap CLI (`--gateway`, `--database`); storage bootstrap; command dispatch.
- **Key items**: `Cli { gateway, database }`, `Commands::{Check, Watch{interval}, Status, History{limit}}`; `tracing_subscriber::fmt::init()`.
- **Flow**: open `Storage::new(db)` + `storage.migrate()` → dispatch. `Check` runs one `Auditor::tick()` and prints/exits per `TickResult` (exit 1 on `Failed`); `Watch` loops `tick()` with `tokio::time::sleep(interval)`; `Status`/`History` query `Storage` for the latest STH/failures/STH history.
- **Consumers**: the `witness-auditor` binary.

### `lib.rs`

- **Responsibility**: library facade; declares `pub mod audit; pub mod client; pub mod storage;`.
- **Consumers**: `main.rs` (`witness_auditor::{audit, storage}`).

### `audit.rs`

- **Responsibility**: core auditor logic — one poll-and-verify cycle against a gateway.
- **Key types**: `TickResult::{NoChange, NewSth(SignedTreeHead), Failed}`; `Auditor { gateway_url, client: GatewayClient, storage: Storage }`.
- **Key functions**: `Auditor::new`, `Auditor::tick` (fetch latest STH, compare to stored previous, dispatch), `audit_with_previous` (tree-size regression → same-size root mismatch → `verify_signed_tree_head` → `verify_log_consistency` → `Storage::record_sth`), `accept_first_sth` (signature-verify then record).
- **Behavior**: every failure path records a `FailureType` (Fetch / SthSignature / Consistency / TreeSizeRegression / RootMismatch) with a detail string before returning `Failed`.
- **Consumers**: `main.rs` (`check`, `watch`).

### `client.rs`

- **Responsibility**: minimal `reqwest` HTTP client for the gateway's log endpoints (30 s timeout).
- **Key types**: `GatewayClient { client, gateway_url }` (normalizes trailing `/`).
- **Key functions / routes**: `get_network_config()` → `GET /v1/network` (`NetworkVerificationConfig`); `get_latest_sth()` → `GET /v1/log/sth`; `get_consistency_proof(first, second)` → `GET /v1/log/consistency?first=&second=`. Non-2xx → contextualized `anyhow` error.
- **Consumers**: `audit.rs`.

### `storage.rs`

- **Responsibility**: persistent auditor state — the anti-rollback memory. WAL SQLite via `sqlx`.
- **Key types**: `Storage { pool: SqlitePool }`; `FailureType` enum (`as_str` variants: `fetch`, `sth_signature`, `consistency`, `tree_size_regression`, `root_mismatch`); `RecordedFailure` struct.
- **Key functions**: `new` (WAL + `create_if_missing`), `migrate` (`sqlx::migrate!("./migrations")`), `record_sth` (INSERT OR IGNORE, stores full `signed_attestation_json`), `latest_sth` (max `tree_size` per gateway), `sth_at` (exact-size lookup for root-mismatch detection), `record_failure` (append-only), `recent_sths`/`recent_failures`, `row_to_sth` (rehydrates `SignedTreeHead`).
- **Consumers**: `audit.rs`; `main.rs` (`status`, `history`).
