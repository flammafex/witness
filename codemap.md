# Repository Atlas: witness

## Project Responsibility

Witness is a content-private, accountless quorum timestamper. Clients submit
SHA-256 hashes; a federation of witness nodes threshold-signs an attestation
(Ed25519 or BLS12-381 aggregate signatures). Optional federation cross-anchoring
and external anchors (Internet Archive, Trillian, DNS, Ethereum) add durability;
optional Freebird integration provides anonymous rate limiting.

Pre-1.0, unaudited, not Byzantine-fault-tolerant. Crate boundaries are strict:
signing and verification logic lives only in `witness-node` and
`witness-gateway`; `witness-core` is the shared trust root (types, crypto,
Merkle/log/proof verification). Migrations are forward-only SQL compiled in via
`sqlx::migrate!`.

## System Entry Points

- `crates/witness-gateway/src/main.rs` — main gateway binary (HTTP API, aggregation, storage, batching, federation, anchoring)
- `crates/witness-node/src/main.rs` — per-witness signing service binary (holds private key)
- `crates/witness-cli/src/main.rs` — `witness` CLI (client-only, local verification)
- `crates/witness-auditor/src/main.rs` — independent RFC 9162 STH-chain auditor
- `Cargo.toml` — workspace dependency manifest + release profile (opt-level 3, LTO, 1 codegen unit)
- `README.md` — user-facing documentation

## Repository Directory Map

| Directory | Responsibility Summary | Detailed Map |
|-----------|------------------------|--------------|
| `crates/` | Five-crate Rust workspace: core (trust root), node (signing), gateway (API/aggregation), cli (client), auditor (STH-chain audit). | [View Map](crates/codemap.md) |
| `crates/witness-core/` | Shared trust root: all domain types, Ed25519 + BLS12-381 crypto, RFC 9162 Merkle/STH/log proof verification, federation cross-anchor + ProofBundle verification, canonical `Attestation::to_bytes()` signing message. Pure library, no keys or I/O. | [View Map](crates/witness-core/codemap.md) |
| `crates/witness-node/` | Per-witness signing service: holds private key (zeroized on drop), threshold-signs attestation shares via `POST /v1/sign` behind constant-time bearer auth + per-IP rate limiting. | [View Map](crates/witness-node/codemap.md) |
| `crates/witness-gateway/` | Main binary: public HTTP API, admission/dedupe, durable lease-based workers collecting + threshold-verifying witness signatures, batch Merkle closure, RFC 9162 STH issuance, federation cross-anchoring, external anchors, admin/metrics/WebSocket, optional Freebird rate limiting, SSRF-safe outbound HTTP. | [View Map](crates/witness-gateway/codemap.md) |
| `crates/witness-cli/` | `witness` binary: pure gateway HTTP client — submits hashes, polls attestation jobs, locally verifies threshold-signed attestations and full proof bundles with witness-core crypto against fetched or offline `NetworkVerificationConfig`s. | [View Map](crates/witness-cli/codemap.md) |
| `crates/witness-auditor/` | Independent auditor continuously walking a gateway's RFC 9162 log: verifies STH threshold signatures + consistency proofs, persists every accepted STH and anomaly in SQLite so rollbacks survive restarts. No keys, no signing. | [View Map](crates/witness-auditor/codemap.md) |
| `configs/` | Deployment + access-control config: `server/nginx.conf` reverse proxy with per-route IP allowlists (compensating control for gateway `CorsLayer::permissive()`), plus root Docker/compose/entrypoint assets. | [View Map](configs/codemap.md) |
| `examples/` | Runnable example networks covering every feature variant (standard 3-witness, dual/triple gateway, `federation/` cross-anchoring, `bls/` aggregation) via a uniform setup → start → demo → stop lifecycle. | [View Map](examples/codemap.md) |
| `landing/` | Self-contained marketing/landing page (`index.html`) with a live WebSocket attestation ticker streaming from the production gateway. | [View Map](landing/codemap.md) |
| `scripts/` | Freebird+Witness end-to-end smoke test booting a real Freebird issuer/verifier and asserting token-gated attestation through the gateway. | [View Map](scripts/codemap.md) |
| `docs/` | Threat model, release notes, freebird integration, comparison — operator/security documentation (not code-mapped). | — |

## Data & Control Flow

1. Client posts a SHA-256 hash → gateway `POST /v1/attestations`.
2. Gateway admits/dedupes (optional Freebird token check), persists an attestation job (lease-based, recoverable across restarts).
3. Gateway fans out to witness nodes → each threshold-signs an attestation share → gateway collects and threshold-verifies.
4. Gateway closes batches, builds RFC 9162 Merkle trees, issues signed tree heads.
5. Optional: cross-anchor with peer federations; anchor to external providers (Internet Archive, Trillian, DNS, Ethereum).
6. Clients retrieve and locally verify attestations / proof bundles via the CLI; the auditor independently verifies the STH chain.

## Security-Sensitive Areas (flag before modifying)

- Signing/verification logic (Ed25519 / BLS12-381) — `witness-core/src/{crypto,bls,signature_scheme}.rs`, `witness-node/src/server.rs`
- Attestation serialization format — `Attestation::to_bytes()` in `witness-core/src/types.rs`
- Merkle roots, inclusion/consistency proofs, signed tree heads — `witness-core/src/{merkle,log}.rs`
- Auth tokens (witness, federation, admin/metrics/WebSocket), `network.json` shape
- Freebird verification logic — `witness-gateway/src/freebird.rs`
- External anchor providers + SSRF filter — `witness-gateway/src/{anchor_providers,http_client,dns_resolver}.rs`
- Database migrations (forward-only) — `crates/*/migrations/`
- `CorsLayer::permissive()` on the gateway router
