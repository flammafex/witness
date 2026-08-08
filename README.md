# 🙌 Witness

**A content-private, accountless quorum timestamper. Anonymous rate-limiting available with [Freebird](https://git.carpocratian.org/sibyl/freebird).**

Witness lets a federation of independent operators co-sign that a hash existed at a particular time. Clients submit only SHA-256 hashes—never content—and receive a threshold signature from a quorum of witnesses; no account, login, or wallet is required. Batches can be cross-anchored by peer federations and committed to external systems (Internet Archive, Trillian, DNS, Ethereum) for additional, independent durability.

## Features

- **Durable & Free:** Submission returns immediately; leased workers retry quorum signing without gas fees
- **Threshold Signatures:** Requires multiple independent witnesses to collude to forge
- **Signature Schemes:** Ed25519 (fast) or `blst::min_sig` BLS12-381 (48-byte G1 aggregate signature, 96-byte G2 public key, 75% signature-byte saving vs three 64-byte Ed25519 signatures)
- **Federation:** Independent networks cross-anchor for additional security
- **External Anchoring:** Batch merkle roots to Internet Archive, Trillian, DNS, or Ethereum
- **Light Clients:** Merkle proofs for verification without full history
- **Privacy:** Only hashes are submitted, not content
- **Sybil Resistance:** Optional [Freebird](https://git.carpocratian.org/sibyl/freebird) integration for anonymous rate limiting

## Project Documents

- [Security Policy](SECURITY.md): vulnerability reporting, production baseline, and known limitations.
- [Threat Model](docs/threat-model.md): security goals, assumptions, non-goals, actors, and current gaps.
- [Production Deployment](PRODUCTION.md): gateway deployment, TLS/proxy setup, monitoring, backups, and upgrades.
- [Release Packaging](docs/release.md): release artifacts, checksums, container tags, and pre-tag checklist.
- [Freebird Integration](docs/freebird-integration.md): current verifier contract and public-gateway abuse-control guidance.
- [Testing Guide](TESTING.md): local, unit, integration, and manual test workflows.
- [Contributing](CONTRIBUTING.md): development checks and security-sensitive change guidance.
- [Changelog](CHANGELOG.md): release notes and compatibility changes.

## Quick Start

### Docker (Recommended)

```bash
# Start the network (gateway + 3 witnesses)
docker compose up --build

# Attest something (then poll the returned job)
docker compose exec gateway witness-cli \
  --gateway http://localhost:8080 \
  attest --hash $(echo -n "hello" | sha256sum | awk '{print $1}')
```

### From Source

```bash
# Prerequisites: Rust 1.70+, SQLite

# Build
cargo build --release

# Set up example network (generates keys + config)
./examples/setup.sh

# Start network
./examples/start.sh

# Create an attestation job for a file
cargo run -p witness-cli -- attest --file README.md
```

## Architecture

```
Client → Gateway → durable job in SQLite
                    ↓ leased retry worker
                 Witnesses (threshold sign) → verified result
                    ↓
              Batch Manager → External Anchors
```

| Component | Description |
|-----------|-------------|
| **witness-core** | Types, crypto (Ed25519 + BLS12-381), merkle trees |
| **witness-node** | Witness server that signs attestations |
| **witness-gateway** | Client API, signature aggregation, batching, storage |
| **witness-cli** | Command-line tool for timestamping and verification |

## CLI Usage

```bash
# Attest a file
witness attest --file document.pdf

# Attest a hash
witness attest --hash abc123...

# Poll job status
witness status <hash>

# Verify an attestation
witness verify attestation.json

# View network config
witness config
```

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/attestations` | Atomically reserve or retrieve an attestation job |
| `GET` | `/v1/attestations/:hash` | Read a stable job snapshot |
| `POST` | `/v1/verify` | Verify a signed attestation |
| `GET` | `/v1/proof/:hash` | Get merkle inclusion proof (light client) |
| `GET` | `/v1/anchors/:hash` | Get external anchor proofs |
| `GET` | `/v1/config` | Get network configuration |
| `GET` | `/ws/events` | WebSocket for real-time attestation events |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/admin` | Admin dashboard (if enabled and authenticated) |

### Attestation Job Request

```bash
curl -X POST http://localhost:8080/v1/attestations \
  -H "Content-Type: application/json" \
  -d '{"hash":"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"}'
```

New and nonconfirmed jobs return `202 Accepted`. A duplicate already-confirmed
job returns `200 OK`. Poll `GET /v1/attestations/:hash` until `status` is
`confirmed`. `pending` and `retryable` responses contain the immutable tuple but
never an unsigned `SignedAttestation`; `failed` is terminal. A confirmed response
includes `signed_attestation`.

### Pending response

```json
{
  "attestation": {
    "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
    "timestamp": 1699454445,
    "network_id": "example-network",
    "sequence": 42
  },
  "status": "pending",
  "attempts": 0,
  "next_attempt_at": 1699454445
}
```

For `retryable`, `next_attempt_at` and a bounded `last_error` describe the next
worker attempt. Witness outages, invalid responses, timeouts, and temporary BLS
aggregation failures retry with bounded exponential backoff. The same persisted
tuple is signed on every attempt.

Batch and transparency-log order follows confirmation availability and batch
closure, not reservation time: each batch orders its eligible jobs by
`(sequence, hash)`, while a lower-sequence job that confirms after an earlier
batch is appended in a later batch. This prevents reservation gaps or old
timestamps from stranding recovered jobs.

### Breaking deployment migration

The attestation job API replaces the old timestamp API. There are no
`/v1/timestamp` routes and the bundled CLI no longer has `timestamp` or `get`
commands. Deploy the migrated gateway database and the new gateway/CLI together;
older clients receive `404 Not Found`. Jobs left pending before a restart are
unlocked by migration or reclaimed after lease expiry and resumed by the worker.

## Configuration

### Network Configuration (`network.json`)

```json
{
  "id": "my-network",
  "threshold": 2,
  "signature_scheme": "Ed25519",
  "witnesses": [
    {"id": "witness-1", "pubkey": "...", "endpoint": "http://localhost:3001", "auth_token": "<random-secret>"},
    {"id": "witness-2", "pubkey": "...", "endpoint": "http://localhost:3002", "auth_token": "<random-secret>"},
    {"id": "witness-3", "pubkey": "...", "endpoint": "http://localhost:3003", "auth_token": "<random-secret>"}
  ],
  "federation": {
    "enabled": false,
    "peers": []
  },
  "external_anchors": {
    "enabled": false,
    "providers": []
  }
}
```

### Signature Schemes

**Ed25519** (default)
- Fast signing (~50μs)
- Multiple signatures stored (N × 64 bytes)
- Best for: low latency, few witnesses

**BLS12-381**
- `blst::min_sig`: 48-byte compressed G1 aggregate signature and 96-byte compressed G2 public key
- 75% signature-byte saving versus three 64-byte Ed25519 signatures
- Best for: high throughput, many witnesses

```bash
# Generate BLS keys
witness-node --generate-key --bls
```

### External Anchoring

Anchor batch merkle roots to external services for additional security:

```json
{
  "external_anchors": {
    "enabled": true,
    "anchor_period": 3600,
    "providers": [
      {"type": "internet_archive", "enabled": true},
      {"type": "trillian", "enabled": true, "log_url": "https://..."},
      {"type": "dns_txt", "enabled": true, "domain": "anchors.example.com"},
      {"type": "blockchain", "enabled": true, "rpc_url": "https://...", "chain_id": 1}
    ]
  }
}
```

### Freebird (Sybil Resistance)

Anonymous rate limiting without user tracking:

```bash
# Gateway configuration
export FREEBIRD_VERIFIER_URL=https://freebird-verifier.example.org
export FREEBIRD_REQUIRED=true  # Reject requests without valid tokens
export FREEBIRD_CONSUME_TOKENS=true  # Default: consume tokens via /v1/verify (recommended)

# CLI usage
witness attest --file doc.pdf --freebird-token token.json
```

`token.json` uses the current Freebird verifier token shape:

```json
{"token_b64":"<base64url-freebird-token>"}
```

`FREEBIRD_CONSUME_TOKENS=false` switches to non-consuming `/v1/check` mode. This allows token reuse until expiry and should only be used for explicit proof-of-possession flows with strict rate limiting.

For local integration tests only, `FREEBIRD_ALLOW_INSECURE_LOCAL=true` permits a plaintext loopback verifier URL such as `http://127.0.0.1:8082`. Do not set it for public deployments.

### Admin Dashboard Auth

Admin UI requires an API key when enabled:

```bash
# Option 1: CLI flag
cargo run --release -p witness-gateway -- \
  --config examples/network.json \
  --port 8080 \
  --admin-ui \
  --admin-api-key "replace-with-random-secret"

# Option 2: environment variable
export WITNESS_ADMIN_API_KEY="replace-with-random-secret"
cargo run --release -p witness-gateway -- \
  --config examples/network.json \
  --port 8080 \
  --admin-ui
```

For browser access, use HTTP Basic Auth (`username: admin`, `password: <admin-api-key>`).  
For API access, send either:
- `Authorization: Bearer <admin-api-key>`
- `X-Admin-Key: <admin-api-key>`

## Production Deployment

### Recommended Architecture

Deploy 3 independent networks across different datacenters. Clients query all gateways and require 2-of-3 agreement.

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Gateway A  │  │  Gateway B  │  │  Gateway C  │
│  Frankfurt  │  │  Nuremberg  │  │  Helsinki   │
│ 3 witnesses │  │ 3 witnesses │  │ 3 witnesses │
└─────────────┘  └─────────────┘  └─────────────┘
       │                │                │
       └────────────────┼────────────────┘
                        ▼
              Client queries all 3
              Requires 2-of-3 agreement
```

### Hetzner Cloud Setup (~€18/month)

| Server | Location | Role |
|--------|----------|------|
| VPS 1 | Frankfurt | Gateway A + Witness B3 + Witness C2 |
| VPS 2 | Nuremberg | Gateway B + Witness C3 + Witness A2 |
| VPS 3 | Helsinki | Gateway C + Witness A3 + Witness B2 |

Each datacenter hosts witnesses from all networks—no single failure takes down any network.

### Production Checklist

- [ ] 5-7 witnesses minimum per network
- [ ] Threshold > 50% (e.g., 4-of-7)
- [ ] TLS on all endpoints
- [ ] Federation with 2+ peer networks
- [ ] External anchoring enabled
- [ ] Database backups configured
- [ ] Admin dashboard enabled (`--admin-ui --admin-api-key ...`)

## Examples

### Basic Network (Ed25519)

```bash
./examples/setup.sh
./examples/start.sh
./examples/demo.sh
```

### Federation (3 Networks)

```bash
./examples/federation/setup.sh
./examples/federation/start.sh
./examples/federation/demo.sh
```

### BLS Signatures

```bash
./examples/bls/setup.sh
./examples/bls/start.sh
./examples/bls/demo.sh
```

## Security Model

### Threats Mitigated

| Threat | Mitigation |
|--------|------------|
| Single witness compromise | Threshold signatures (N-of-M) |
| Signature forgery | Ed25519/BLS cryptographic security |
| Timestamp manipulation | Multiple independent witnesses |
| Content exposure | Only hashes submitted |
| Network compromise | Federation + external anchoring |
| Denial of service | Freebird token-based rate limiting |

### Residual Risks

- **Gateway compromise:** Mitigated by federation, not eliminated
- **Clock manipulation:** Requires threshold witnesses to collude
- **Network partitions:** No Byzantine fault tolerance

## Performance

| Metric | Ed25519 | BLS |
|--------|---------|-----|
| Typical worker signing pass | 50-150ms | 60-180ms |
| Signature size (3 witnesses) | 192 bytes | 48 bytes |
| Throughput | 100-500 req/s | 80-400 req/s |

API submission latency is separate from signing latency: `POST /v1/attestations`
only durably reserves the tuple, and clients poll while workers obtain quorum.

## FAQ

**Q: What does "Anonymous Quorum" mean?**

A: "Anonymous" because you submit only a hash—no accounts, no identity, no tracking. "Quorum" because multiple independent witnesses must sign before an attestation is valid. You get privacy and trust without a single point of failure.

**Q: Is this really free?**

A: For users, yes. Gateway operators pay gas costs only if they enable Ethereum anchoring (optional).

**Q: Can witnesses see my data?**

A: No. You only submit SHA-256 hashes, not the content itself.

**Q: How is this different from a traditional timestamp authority?**

A: Traditional TSAs require trusting a single party. Witness requires multiple independent parties to collude, and optionally anchors to public systems for additional verification.

## License

Apache 2.0 - see LICENSE file for details.
