# crates/witness-cli/

## Responsibility

`witness-cli` builds the `witness` binary: an HTTP client for the Witness network. It submits SHA-256 hashes (of files or raw hex) to the gateway to reserve/canonicalize attestation jobs, polls job status, verifies threshold-signed attestations and full proof bundles (threshold signature + Merkle batch inclusion + cross-anchors + external anchors), inspects RFC 9162 log state (STHs, consistency proofs), and displays external anchor proofs. It is a **client only** — it holds no signing keys and performs no signing, per the strict crate boundaries.

## Design

- Single `[[bin]]` named `witness`; no library target. `clap` command tree under `Cli { gateway, command }` with the gateway URL configurable via `--gateway`/`-g` or the `WITNESS_GATEWAY` env var (default `http://localhost:8080`).
- Subcommands: `attest`, `status`, `verify`, `config`, `anchors`, `log` (with `sth` and `consistency` sub-subcommands), and `verify-proof`. Each command is a thin module in `src/commands/` that formats user input, calls `WitnessClient`, and prints `text` or `json` output.
- **`WitnessClient`** (`client.rs`) is a `reqwest` wrapper with a 30 s timeout — one method per gateway route, parsing responses into `witness-core` types. 404 on anchors is normalized to an empty list.
- **Verification is local and trust-minimizing**: `verify`, `log --verify`, and `verify-proof` fetch the network's `NetworkConfig` (from gateway files or `--network-config`/`--peer-config` paths) and run `witness-core` cryptographic verification (`verify_signed_attestation`, `verify_signed_tree_head`, `verify_log_consistency`, `verify_proof_bundle`) — the gateway's answer is never trusted for the verdict.
- `verify-proof` supports fully offline operation (bundle + network config + peer configs from files) and hybrid online mode (fetch home config and any missing peer configs referenced by cross-anchors from peer gateways).
- Dev-dependency on `axum` to spin up mock gateways for route-contract tests.
- A `tests` module asserts the CLI exposes the current command set (and rejects the legacy `timestamp`/`get` names).

## Flow

1. `main.rs` parses `Cli` and dispatches to the matching `commands::*::run(...)`.
2. Each command validates input (e.g. 64-char hex SHA-256 for hash-based commands), optionally computes SHA-256 from a file, loads a Freebird token file if given, and calls the appropriate `WitnessClient` method.
3. Results are rendered as pretty JSON or human-readable text; verification commands print a pass/fail verdict (failing verification exits non-zero).
4. `attest`/`status` print `AttestationJobResponse` state including the signed attestation's verified signature count once the job completes.

## Integration

- Talks **only** to the gateway's HTTP API: `POST /v1/attestations`, `GET /v1/attestations/{hash}`, `GET /v1/config`, `GET /v1/network`, `GET /v1/bundle/{hash}`, `GET /v1/log/sth`, `GET /v1/log/consistency?first=&second=`, `GET /v1/anchors/{hash}` (see `src/commands/codemap.md` for the per-command mapping).
- Uses `witness-core` for all domain types (`AttestationJobResponse`, `CreateAttestationRequest`, `ProofBundle`, `NetworkConfig`, `SignedTreeHead`, `LogConsistencyProof`, `ExternalAnchorProof`, `FreebirdToken`) and all verification functions.
- Optional Freebird integration: a Freebird token JSON file passed to `attest` is embedded in `CreateAttestationRequest` for anonymous rate limiting.
- The CLI never contacts witness nodes directly — it is a pure gateway client, like `witness-auditor`.
