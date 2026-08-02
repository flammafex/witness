# crates/witness-cli/src/commands/

## Responsibility

Per-subcommand implementations for the `witness` CLI. Each module formats user input, calls `WitnessClient`, and prints `json` or `text` output. **Clients only — no signing.** `attest` additionally computes SHA-256 over a file; verification commands run `witness-core` crypto locally against fetched or file-supplied `NetworkConfig`s.

### `attest` — `timestamp.rs`

- **Args**: `--file` (SHA-256 computed client-side) xor `--hash` (64-hex SHA-256), `--output`, `--save`, `--freebird-token <json>`.
- **Route**: `POST /v1/attestations` via `WitnessClient::create_attestation(hash, freebird_token)`.
- **Behavior**: reads file/hash, optionally loads a `FreebirdToken` from JSON, submits the attestation job, prints `AttestationJobResponse` (status, hash, timestamp, network, sequence, attempts, signature count once signed) and optionally persists the job snapshot to `--save`.

### `status` — `get.rs`

- **Args**: positional `hash`, `--output`.
- **Route**: `GET /v1/attestations/{hash}` via `WitnessClient::get_attestation(hash)`.
- **Behavior**: polls/looks up the durable attestation job for a hash and prints its current status (including verified signature count when complete).

### `verify` — `verify.rs`

- **Args**: positional attestation JSON file, `--output`.
- **Route**: `GET /v1/network` (fetch `NetworkConfig`) via `WitnessClient::get_network_config()`; the signed attestation itself is read from the local file.
- **Behavior**: parses a `SignedAttestation` from file, then **locally** verifies via `witness_core::verify_signed_attestation(&attestation, &config)`; prints valid/invalid verdict with `verified vs threshold` signature counts. Exit code 1 on invalid.

### `config` — inline in `main.rs`

- **Route**: `GET /v1/config` via `WitnessClient::get_config()`.
- **Behavior**: pretty-prints the gateway's configuration as JSON.

### `anchors` — `anchors.rs`

- **Args**: positional `hash`, `--output`.
- **Route**: `GET /v1/anchors/{hash}` via `WitnessClient::get_batch_anchors(hash)`.
- **Behavior**: lists `ExternalAnchorProof`s for the attestation, with provider-specific rendering (`InternetArchive` → archive URL/merkle root; `Trillian`/`DnsTxt`/`Blockchain` → raw proof JSON). Empty list prints a "not yet anchored" explanation.

### `log sth` — `log.rs`

- **Args**: `--output`, `--verify`.
- **Routes**: `GET /v1/log/sth` via `WitnessClient::get_latest_sth()`; with `--verify`, also `GET /v1/network` and `witness_core::verify_signed_tree_head(&sth, &config)` (prints threshold signature validity count).
- **Behavior**: displays the gateway's latest `SignedTreeHead` (tree size, timestamp, network, root hash).

### `log consistency` — `log.rs`

- **Args**: `--first <tree_size>`, `--second <tree_size>` (must match published STHs), `--output`, `--verify`.
- **Routes**: `GET /v1/log/consistency?first={}&second={}` via `WitnessClient::get_log_consistency(first, second)`; with `--verify`, also `GET /v1/network` and `witness_core::verify_log_consistency(&proof, &config)` (RFC 9162 consistency verification).
- **Behavior**: fetches and displays the RFC 9162 consistency proof linking the two tree sizes (old/new roots + proof hashes).

### `verify-proof` — `verify_proof.rs`

- **Args**: `--bundle <file>` xor `--hash`; `--network-config <file>` or `--online` (mutually exclusive intent); repeatable `--peer-config <file>`; `--output`.
- **Routes**: bundle from `GET /v1/bundle/{hash}` (or a local file); home config from `GET /v1/network` (or `--network-config` file); in `--online` mode, missing peer configs referenced by `bundle.cross_anchors` are fetched from each peer's gateway via `GET /v1/network` (`WitnessClient::get_network_config_from`).
- **Behavior**: assembles `ProofVerificationConfig { network, peers }` and **locally** runs `witness_core::verify_proof_bundle(&bundle, &config)` — verifying threshold signatures, Merkle batch inclusion, cross-anchors, and reporting external-anchor presence and an assurance `level`. Failing verification exits 1. Supports fully offline verification from files.
