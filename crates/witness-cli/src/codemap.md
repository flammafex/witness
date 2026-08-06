# crates/witness-cli/src/

## Responsibility

Three modules making up the `witness` binary: the clap command tree (`main.rs`) and the per-command implementations (`commands/`). The CLI is an HTTP client consumer of the `witness-client` crate (no local `client.rs`).

### `main.rs`

- **Responsibility**: CLI definition and dispatch. `Cli` carries `--gateway` (default `http://localhost:8080`, env `WITNESS_GATEWAY`); `Commands` enum holds `Attest`, `Status`, `Verify`, `Config`, `Anchors`, `Log` (→ `LogCommands::{Sth, Consistency}`), `VerifyProof`; `Config {}` is handled inline.
- **Key items**: `#[command(version)]`, per-subcommand args (`--file`/`--hash` mutually exclusive on `attest`; `--bundle`/`--hash` and `--network-config`/`--online` constraints on `verify-proof`; repeatable `--peer-config`).
- **Flow**: parse → `match cli.command` → delegate to `commands::*::run` / `witness_client::WitnessClient::new().public_config()`.
- **Consumers**: the `witness` binary only; tests assert the exposed command surface.

### `witness-client` (external dependency)

- **Responsibility**: the CLI delegates all gateway HTTP to the `witness-client` crate (`WitnessClient`), which returns typed `witness-core` responses and a typed `Error` enum. The CLI maps `witness_client::Error` to `anyhow` via `?`.
- **Key methods used**: `create_attestation([u8;32], freebird_token)`, `get_attestation([u8;32])`, `public_config()`, `network()` / `network_from(url)`, `get_bundle([u8;32])`, `sth()`, `consistency(first, second)`, `get_anchors([u8;32])`.
- **Anchors semantics**: the SDK maps an unknown attestation (404) to `Error::NotFound`; the CLI catches it in `anchors.rs` and renders an empty list, preserving the historical display.
- **Consumers**: every `commands/*` module; `Config` in `main.rs`. The SDK's own `witness-client` test suite pins the `/v1/attestations*` contracts against an `axum` mock gateway.

### `commands/mod.rs`

- **Responsibility**: module re-export shim. Declares `pub mod anchors, get, log, timestamp, verify, verify_proof;` (file is named `timestamp.rs`/`get.rs` per the original command names, though the CLI surface now uses `attest`/`status`).
- **Consumers**: `main.rs` dispatch.
