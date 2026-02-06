# Contributor Guide for AI Agents

This guide helps AI agents ramp up quickly on the Witness codebase.

## Mission & Context
- **Product:** Witness — a federated, threshold-signed timestamping service with optional blockchain anchoring.
- **Primary goal:** Stabilization (production-focused). Favor safety, clarity, and minimal risk changes.

## Repository Map (High Level)
```
/workspace/witness
├── crates/
│   ├── witness-core/      # Core types, crypto, merkle, federation, anchors
│   ├── witness-node/      # Witness signing service (HTTP server)
│   ├── witness-gateway/   # Client API + aggregation + batching + storage
│   └── witness-cli/       # CLI client (timestamp, verify, get, etc.)
├── configs/server/        # Nginx template for production
├── examples/              # Setup/start/demo scripts
├── Dockerfile             # Multi-stage builds (node + gateway)
├── docker-compose.yaml    # Local/dev orchestration
├── README.md              # Product overview + architecture
└── TESTING.md             # Build/test/run guidance
```

## Architectural Style
- **Distributed system** with multiple services (gateway + witness nodes) in a single Rust workspace.
- **Shared core library** (`witness-core`) for types/crypto/merkle/federation/anchors.

## Tech Stack
- **Language:** Rust 2021
- **HTTP framework:** Axum (tokio runtime)
- **DB:** SQLite via sqlx (gateway)
- **Crypto:** Ed25519 + BLS12-381
- **CLI:** clap
- **Infra:** Docker/Docker Compose; Nginx template in `configs/server`

## Entry Points (Executables)
- `witness-gateway` — boots gateway server, storage, batching, federation, anchors, Freebird, metrics.
- `witness-node` — boots witness signing server and validates timestamp/network ID.
- `witness` (CLI) — timestamp, get, verify, config, anchors, token wallet.

## Key Request Flow (Timestamp)
1. **CLI** sends a timestamp request to the **gateway** (`POST /v1/timestamp`).
2. **Gateway** creates an attestation, requests signatures from all witnesses concurrently.
3. **Witness nodes** validate timestamp/network ID and sign.
4. **Gateway** aggregates/validates signatures, stores in SQLite, returns attestation.

## Important Domains
- **Core types:** `Attestation`, `SignedAttestation`, `NetworkConfig`, `TimestampRequest` in `witness-core`.
- **Signature schemes:** Ed25519 multi-sig and BLS aggregated signatures.
- **Batching/anchors:** Gateway manages batches and optional external anchoring.
- **Federation:** Cross-anchor support between networks.
- **Sybil resistance:** Optional Freebird token checks at gateway.

## Persistence
- Gateway stores attestations, signatures, batches, anchors in SQLite.
- Schema migrations are handled in code in `Storage::migrate`.

## Operational Notes
- Nginx template restricts access to sensitive endpoints (timestamp create, federation anchors, witness signing, etc.).
- Docker Compose builds a local network with 3 witness nodes + gateway.

## Developer Workflow
### Build
```bash
cargo build --release
```

### Test
```bash
cargo test
```

### Run Example Network
```bash
./examples/setup.sh
./examples/start.sh
```

### Docker Compose
```bash
docker compose up --build
```

## Change Hygiene for AI Agents
- Prefer **small, incremental changes** with clear reasoning.
- Avoid refactors unless explicitly requested.
- Add/update tests only when necessary and remove any temporary scaffolding.
- When touching production behavior, consider config compatibility and backward safety.

## High-Risk Areas / Caution
- **Gateway coordination logic** (batching, federation, Freebird, signature aggregation).
- **Signature verification and crypto paths**.
- **SQLite schema migration logic** (no explicit migration tooling).
- **Network configs** (format changes could break deployments).

## When in Doubt
- Ask for clarification about production topology, federation usage, and anchor providers.
- Confirm whether changes must preserve existing network.json formats and CLI output.

---

If you add or adjust behavior, update this guide as needed so future agents stay aligned.
