# Changelog

All notable changes to Witness should be recorded here.

This project is pre-1.0. Minor versions may include breaking changes until a
stable API policy is published.

## Unreleased

## 0.7.0 - 2026-08-02

### Added

- Test hardening for witness-node signing admission (missing/wrong bearer token,
  token-rotation grace, timestamp skew, wrong network, corrupt key) and for
  gateway STH signing (Ed25519/BLS persistence and verification, threshold not
  met, garbage signatures rejected, empty-log short-circuit).
- `WitnessClientTrait` abstraction so STH signing in `BatchManager` and
  signature collection share one mockable seam for the test suite.

### Changed

- **Security:** Federation bearer-token validation now compares tokens in
  constant time (`witness_core::constant_time_eq`), matching the
  attestation-facing auth path and closing the last non-constant-time auth
  check in the gateway. **Security-sensitive change.**
- Internal: split `crates/witness-gateway/src/server.rs` (~1390 lines, the
  largest file) into a `server/` module directory — `mod.rs`, `routes.rs`,
  `ws.rs`, `federation_auth.rs`. Purely cosmetic; route registration, handler
  behavior, and public paths are unchanged.
- Internal: deduplicated hash decoding and Merkle inclusion-proof construction
  across the gateway handlers.
- Removed dead `/v1/timestamp` location blocks from the nginx template (the API
  moved to `/v1/attestations` in 0.6.5).
- Fixed `examples/start-triple.sh` launching gateway 3 on port 5002 (collision
  with gateway 2) instead of 5003.

### Fixed

- `examples/demo.sh` still called the pre-0.6.5 `timestamp`/`get` subcommands and
  verified the job-response wrapper instead of the signed attestation; it now
  uses `attest`/`status`, polls until the job is `Confirmed`, and verifies the
  extracted `signed_attestation`.
- Example config generators (`setup.sh`, `setup-gateway.sh`, `setup-triple.sh`,
  `federation/setup.sh`, `bls/setup.sh`) emitted `localhost` witness endpoints,
  which the gateway's SSRF `SafeResolver` rejects; they now emit `127.0.0.1`
  literals (the nodes' actual bind host), so the example network works while
  keeping SSRF protection intact.

## 0.6.5 - 2026-07-18

### Added

- Durable, idempotent attestation jobs with leased recovery and bounded retry
  backoff across quorum outages and gateway restarts.

### Changed

- **Breaking:** Replaced `POST`/`GET /v1/timestamp` with
  `POST`/`GET /v1/attestations`. Clients must submit and poll attestation jobs.
- Confirmation is now gated on local threshold-signature verification; only
  confirmed canonical attestations enter batches, logs, proofs, and bundles.

### Fixed

- Duplicate submissions now reuse one atomically reserved canonical tuple and
  sequence, including while work is pending or retried.

## 0.6.0 - 2026-06-26

### Changed

- **Breaking:** Attestation and signature JSON serialization now encodes byte
  fields (`[u8; 32]` hashes, `Vec<u8>` signatures) as lowercase hex strings
  instead of integer arrays. A new `serde_hex` module in `witness-core` backs
  this. Clients and auditors must decode hex where they previously read arrays.
  **Security-sensitive change (attestation serialization format).**
- Switched HTTP client TLS backend from native-tls (OpenSSL) to rustls. This
  eliminates the OpenSSL native dependency, simplifying cross-compilation and
  static linking. Certificate validation behavior is unchanged (system root
  store via rustls-native-certs). **Security-sensitive change.**
- Disabled default features on `metrics-exporter-prometheus` (drops the
  `push-gateway` feature and its `hyper-tls`/`native-tls` dependency). The
  gateway only uses the Prometheus scrape endpoint (`http-listener`), so this
  removes the last OpenSSL transitive dependency without behavior change.
- Updated Freebird token handling to accept only the current token file shape
  with `token_b64`.
- Updated Witness-to-Freebird verifier requests to send the current
  `{ "token_b64": "..." }` contract.

### Added

- Forgejo Actions release workflow (`.forgejo/workflows/release.yml`) that
  builds a native x86_64 Linux binary archive and publishes it to the Forgejo
  releases page with SHA-256 checksums.
- Added security policy, threat model, release packaging notes, contribution
  guide, and Freebird integration guidance.

### Fixed

- Applied Rust formatting across the workspace.
- Fixed clippy warnings in Merkle proof tests and gateway reconciler scaffolding.
