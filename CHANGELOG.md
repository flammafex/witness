# Changelog

All notable changes to Witness should be recorded here.

This project is pre-1.0. Minor versions may include breaking changes until a
stable API policy is published.

## Unreleased

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
