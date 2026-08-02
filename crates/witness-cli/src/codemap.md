# crates/witness-cli/src/

## Responsibility

Three modules making up the `witness` binary: the clap command tree (`main.rs`), the gateway HTTP client (`client.rs`), and the per-command implementations (`commands/`).

### `main.rs`

- **Responsibility**: CLI definition and dispatch. `Cli` carries `--gateway` (default `http://localhost:8080`, env `WITNESS_GATEWAY`); `Commands` enum holds `Attest`, `Status`, `Verify`, `Config`, `Anchors`, `Log` (→ `LogCommands::{Sth, Consistency}`), `VerifyProof`; `Config {}` is handled inline.
- **Key items**: `#[command(version)]`, per-subcommand args (`--file`/`--hash` mutually exclusive on `attest`; `--bundle`/`--hash` and `--network-config`/`--online` constraints on `verify-proof`; repeatable `--peer-config`).
- **Flow**: parse → `match cli.command` → delegate to `commands::*::run` / `client::WitnessClient::new().get_config()`.
- **Consumers**: the `witness` binary only; tests assert the exposed command surface.

### `client.rs`

- **Responsibility**: thin `reqwest` HTTP client for the gateway with typed `witness-core` responses.
- **Key types**: `WitnessClient { client: reqwest::Client, gateway_url: String }` (30 s timeout).
- **Key functions / routes**:
  - `create_attestation(hash, freebird_token)` → `POST /v1/attestations`
  - `get_attestation(hash)` → `GET /v1/attestations/{hash}`
  - `get_config()` → `GET /v1/config` (returns `serde_json::Value`)
  - `get_network_config()` / `get_network_config_from(gateway_url)` → `GET /v1/network` (second variant fetches peer-network configs for cross-anchor verification)
  - `get_proof_bundle(hash)` → `GET /v1/bundle/{hash}`
  - `get_latest_sth()` → `GET /v1/log/sth`
  - `get_log_consistency(first, second)` → `GET /v1/log/consistency?first=&second=`
  - `get_batch_anchors(hash)` → `GET /v1/anchors/{hash}`; 404 → empty `Vec<ExternalAnchorProof>`
- **Behavior**: non-2xx responses become `anyhow` errors carrying status + body text; JSON parse failures are contextualized.
- **Consumers**: every `commands/*` module; `Config` in `main.rs`. Tests use an `axum` mock gateway to pin the `/v1/attestations*` contracts.

### `commands/mod.rs`

- **Responsibility**: module re-export shim. Declares `pub mod anchors, get, log, timestamp, verify, verify_proof;` (file is named `timestamp.rs`/`get.rs` per the original command names, though the CLI surface now uses `attest`/`status`).
- **Consumers**: `main.rs` dispatch.
