# AGENTS.md

Guidance for AI coding agents (Codex and similar) working in this repository.
Read this before making changes.

## What this is

Witness is a Rust workspace implementing a content-private, accountless quorum
timestamper. Clients submit SHA-256 hashes; a federation of witness nodes
threshold-signs an attestation. Optional federation cross-anchoring and
external anchors (Internet Archive, Trillian, DNS, Ethereum) add durability.
Optional Freebird integration provides anonymous rate limiting.

Pre-1.0, unaudited, not Byzantine-fault-tolerant. Treat all signing,
verification, and serialization code as high-stakes.

## Repo layout

```
crates/
  witness-core/      Shared lib: types, crypto (Ed25519 + BLS12-381), Merkle/log/proofs
  witness-node/      Signing service binary (holds private keys)
  witness-gateway/   Main binary: API, aggregation, storage, batching, federation, anchoring
  witness-cli/       CLI binary `witness`
  witness-auditor/   Independent auditor walking RFC 9162 STH chains
configs/server/      nginx template with per-route IP allowlists
docs/                threat-model, release, freebird-integration
examples/            setup/start/demo scripts + federation/ and bls/ variants
migrations/          (per-crate, under crates/*/migrations/) forward-only SQL
```

Key files:
- `crates/witness-core/src/types.rs` — domain model (Attestation, SignedAttestation, NetworkConfig, request/response types)
- `crates/witness-gateway/src/server.rs` — all HTTP routes + `timestamp_handler` (~1500 lines, largest file)
- `crates/witness-gateway/src/storage.rs` — SQLite persistence
- `crates/witness-gateway/migrations/` — 7 SQL migrations compiled in via `sqlx::migrate!`
- `Cargo.toml` — workspace deps centralized here; crates reference via `.workspace = true`

## Setup, run, test, lint, build

Prerequisites: Rust 1.70+ (Dockerfile pins 1.91), SQLite, and `pkg-config libssl-dev clang` on Debian/Ubuntu.

```bash
# Lint (must pass clean — CONTRIBUTING.md)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Test
cargo test --workspace

# Build (release profile: opt-level 3, LTO, 1 codegen unit)
cargo build --release --workspace

# Run example 3-witness network (generates keys + config)
./examples/setup.sh && ./examples/start.sh && ./examples/demo.sh && ./examples/stop.sh

# Docker
docker compose up --build
```

Binaries land in `target/release/`: `witness-node`, `witness-gateway`, `witness` (CLI), `witness-auditor`.

## Coding conventions

- **Crate boundaries are strict** (see CONTRIBUTING.md). Only `witness-node` and `witness-gateway` contain signing logic. `witness-core` is the shared trust root.
  - core = types, crypto, Merkle/log/proof verification
  - node = witness signing service
  - gateway = public API, storage, batching, federation, anchoring
  - cli / auditor = HTTP clients only
- **Workspace deps** are centralized in root `Cargo.toml [workspace.dependencies]`. Add new deps there and reference via `.workspace = true`.
- **Errors:** `thiserror` in libraries, `anyhow` in binaries, gateway maps to HTTP via `AppError`.
- **Security hygiene:** `zeroize` on key material, `subtle` for constant-time ops, bearer tokens validated at startup (gateway aborts if any witness lacks `auth_token`), SSRF filter on outbound HTTP.
- **Migrations** are forward-only SQL files under `crates/*/migrations/`, compiled in via `sqlx::migrate!`, run on startup. No down migrations.
- **Docs discipline:** user-facing → README; operator → PRODUCTION; security → SECURITY + docs/threat-model; release → docs/release + CHANGELOG.

## Testing expectations

- `cargo test --workspace` must pass.
- Security-sensitive changes (see list below) must include tests or test vectors showing both accepted and rejected cases.
- When changing Freebird admission logic, verify against the current Freebird verifier API (`{ "token_b64": "..." }` to `/v1/verify` or `/v1/check`). Freebird evolves independently.
- If deployment assets change, smoke-test Docker or the example network.
- Integration scenarios worth checking: threshold enforcement (start 1 witness below threshold → fail), witness failure (stop witnesses until below threshold), duplicate hash handling (returns existing attestation).

## PR / review expectations

- All four dev checks green before submitting:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `cargo build --release --workspace`
- Scope changes to existing crate boundaries; don't bleed gateway logic into core, etc.
- Public behavior changes must update the relevant doc (README / PRODUCTION / SECURITY / docs/release / CHANGELOG).
- Call out security-sensitive changes explicitly in the PR description.

## Constraints — do not touch without asking

These areas are security-sensitive or operationally fragile. Flag and ask before modifying:

- signing or verification logic (Ed25519 / BLS)
- attestation serialization format
- Merkle roots, inclusion proofs, consistency proofs, signed tree heads
- witness auth tokens, federation auth tokens, admin/metrics/WebSocket auth
- Freebird verification logic
- external anchor providers (outbound network calls; SSRF filter must stay enabled)
- database migrations (forward-only; a missing `0003` migration exists in the sequence — confirm before renumbering or adding)
- `network.json` shape (carries witness `auth_token` in plaintext; operational secret)
- `CorsLayer::permissive()` on the gateway router — confirm intent before tightening

Also: the project has had no external security audit and no CI gates yet (per docs/threat-model.md). Treat crypto paths as unverified-by-third-parties.

## Definition of done

A change is complete when:

1. `cargo fmt --all -- --check` is clean.
2. `cargo clippy --workspace --all-targets -- -D warnings` is clean.
3. `cargo test --workspace` passes.
4. `cargo build --release --workspace` succeeds.
5. Security-sensitive changes include accepted/rejected test cases.
6. Relevant docs updated (README / PRODUCTION / SECURITY / docs/release / CHANGELOG).
7. If deployment assets changed: Docker or example network smoke-tested.
8. No secrets, private keys, bearer tokens, or `.env` values committed.
9. Crate boundaries respected; no logic leaked across them.

## Repository Map

A full codemap is available at `codemap.md` in the project root.

Before working on any task, read `codemap.md` to understand:
- Project architecture and entry points
- Directory responsibilities and design patterns
- Data flow and integration points between modules

For deep work on a specific folder, also read that folder's `codemap.md`.
