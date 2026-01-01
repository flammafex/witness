# 🙌 Witness

**Prove when something existed—without trusting any single party, and without the bottlenecks of a blockchain.**

Witness is a federated threshold-signed timestamping service. It provides cryptographic proof of existence with instant, free transactions—using blockchains only as an optional settlement layer, not as an execution engine.

## Features

- **Instant & Free:** Timestamps in 50-150ms with no gas fees
- **Threshold Signatures:** Requires multiple independent witnesses to collude to forge
- **Signature Schemes:** Ed25519 (fast) or BLS12-381 (50% smaller signatures)
- **Federation:** Independent networks cross-anchor for additional security
- **External Anchoring:** Batch merkle roots to Internet Archive, Trillian, DNS, or Ethereum
- **Light Clients:** Merkle proofs for verification without full history
- **Privacy:** Only hashes are submitted, not content
- **Sybil Resistance:** Optional [Freebird](https://git.carpocratian.org/sibyl/freebird) integration for anonymous rate limiting

## Quick Start

### Docker (Recommended)

```bash
# Start the network (gateway + 3 witnesses)
docker compose up --build

# Timestamp something
docker compose exec gateway witness-cli \
  --gateway http://localhost:8080 \
  timestamp --hash $(echo -n "hello" | sha256sum | awk '{print $1}')
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

# Timestamp a file
cargo run -p witness-cli -- timestamp --file README.md
```

## Architecture

```
Client → Gateway → Witnesses (threshold sign) → Signed Attestation
           ↓
      SQLite DB ← Batch Manager → External Anchors
```

| Component | Description |
|-----------|-------------|
| **witness-core** | Types, crypto (Ed25519 + BLS12-381), merkle trees |
| **witness-node** | Witness server that signs attestations |
| **witness-gateway** | Client API, signature aggregation, batching, storage |
| **witness-cli** | Command-line tool for timestamping and verification |

## CLI Usage

```bash
# Timestamp a file
witness timestamp --file document.pdf

# Timestamp a hash
witness timestamp --hash abc123...

# Retrieve existing timestamp
witness get <hash>

# Verify an attestation
witness verify attestation.json

# View network config
witness config
```

## API Reference

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/timestamp` | Submit hash for timestamping |
| `GET` | `/v1/timestamp/:hash` | Retrieve existing attestation |
| `POST` | `/v1/verify` | Verify a signed attestation |
| `GET` | `/v1/proof/:hash` | Get merkle inclusion proof (light client) |
| `GET` | `/v1/anchors/:hash` | Get external anchor proofs |
| `GET` | `/v1/config` | Get network configuration |
| `GET` | `/ws/events` | WebSocket for real-time attestation events |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/admin` | Admin dashboard (if enabled) |

### Timestamp Request

```bash
curl -X POST http://localhost:8080/v1/timestamp \
  -H "Content-Type: application/json" \
  -d '{"hash":"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"}'
```

### Response

```json
{
  "attestation": {
    "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
    "timestamp": 1699454445,
    "network_id": "example-network",
    "sequence": 42
  },
  "signatures": {
    "MultiSig": {
      "signatures": [
        {"witness_id": "witness-1", "signature": "..."},
        {"witness_id": "witness-2", "signature": "..."}
      ]
    }
  }
}
```

## Configuration

### Network Configuration (`network.json`)

```json
{
  "id": "my-network",
  "threshold": 2,
  "signature_scheme": "Ed25519",
  "witnesses": [
    {"id": "witness-1", "endpoint": "http://localhost:3001", "public_key": "..."},
    {"id": "witness-2", "endpoint": "http://localhost:3002", "public_key": "..."},
    {"id": "witness-3", "endpoint": "http://localhost:3003", "public_key": "..."}
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
- Signature aggregation (N signatures → 96 bytes)
- 50% bandwidth savings for 3+ witnesses
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
export FREEBIRD_VERIFIER_URL=http://localhost:8082
export FREEBIRD_ISSUER_IDS=issuer:prod:v1
export FREEBIRD_REQUIRED=true  # Reject requests without valid tokens

# CLI usage
witness timestamp --file doc.pdf --freebird-acquire http://localhost:8081
```

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
- [ ] Admin dashboard enabled (`--admin-ui`)

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
| Latency | 50-150ms | 60-180ms |
| Signature size (3 witnesses) | 192 bytes | 96 bytes |
| Throughput | 100-500 req/s | 80-400 req/s |

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
