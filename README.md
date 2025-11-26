<div align=center><img src="church.png" width=72 height=72>

_A mission of [The Carpocratian Church of Commonality and Equality](https://carpocratian.org/en/church/)_</div>

<div align=center><img src="mission.png" width=256 height=200></div>

# 🙌 Witness: Threshold Witness Timestamping System

**Prove when something existed—without trusting any single party, and without needing a blockchain.**

Witness is a federated witness network that provides threshold-signed timestamps. It's designed to be a privacy-preserving, decentralized timestamping service that doesn't rely on blockchains or single points of trust.

## Key Features

- **No Blockchain Required:** Witnesses ARE the trust anchor
- **Threshold Signatures:** Requires multiple independent witnesses to collude to forge timestamps
- **BLS Signature Aggregation:** Optional BLS12-381 signatures provide 50% bandwidth savings
- **Federated Architecture:** Multiple independent networks can cross-anchor for additional security
- **Privacy-Preserving:** Only hashes are submitted, not content
- **Simple Integration:** Easy-to-use CLI and REST API

## Design Philosophy

Witness has two operating modes:

1. **Minimal (single network):** One set of witnesses with threshold signatures. Good for development and low-stakes use.

2. **Federated (cross-network anchoring):** Multiple independent Witness networks periodically witness each other's merkle roots. This is the default "secure" mode.

Mode 3 is planned for a future release.

3. **Hardened (external anchors):** Additional anchoring to Certificate Transparency logs, Internet Archive, DNS TXT records, physical escrow.

## Architecture

```
Client → Gateway → Witnesses (threshold sign) → Signed Attestation
```

### Components

- **witness-core:** Shared types, crypto primitives (Ed25519 + BLS12-381), verification logic
- **witness-node:** Individual witness node that signs attestations
- **witness-gateway:** Aggregates requests, fans out to witnesses, collects/aggregates signatures
- **witness-cli:** Command-line tool for timestamping files

### How It Works

1. Client submits a SHA-256 hash to the gateway
2. Gateway creates an attestation with timestamp and sequence number
3. Gateway requests signatures from all witness nodes
4. Witness nodes independently sign the attestation
5. Gateway collects signatures and returns signed attestation to client
6. Client can verify the attestation has threshold signatures

## Quick Start

### Prerequisites

- Rust 1.70+ (`cargo --version`)
- SQLite

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/witness
cd witness
```

2. Run the setup script to generate keys and configs:
```bash
./examples/setup.sh
```

This creates a 3-witness network with threshold=2 (any 2 out of 3 witnesses must sign).

3. Start the network:
```bash
./examples/start.sh
```

This starts:
- 3 witness nodes on ports 3001, 3002, 3003
- 1 gateway on port 8080

### Try It Out

Timestamp a file:
```bash
cargo run -p witness-cli -- timestamp --file README.md --save attestation.json
```

Look up a timestamp:
```bash
cargo run -p witness-cli -- get <hash>
```

Verify an attestation:
```bash
cargo run -p witness-cli -- verify attestation.json
```

Run the demo:
```bash
./examples/demo.sh
```

Stop the network:
```bash
./examples/stop.sh
```

### Phase 2: Federation (Advanced)

For production deployments, use **federated networks** for enhanced security:

```bash
# Setup 3 independent networks with cross-anchoring
./examples/federation/setup.sh

# Start all networks (9 witnesses, 3 gateways)
./examples/federation/start.sh

# Run federation demo
./examples/federation/demo.sh

# Stop all networks
./examples/federation/stop.sh
```

**Federation provides:**
- **3 independent networks** that witness each other
- **Periodic batch closing** (every 60 seconds by default)
- **Cross-network attestations** of merkle roots
- **Enhanced security:** Requires compromising multiple independent networks

See `examples/federation/README.md` for details.

### Phase 4: BLS Signature Aggregation (Advanced)

For high-throughput or bandwidth-constrained deployments, use **BLS signatures**:

```bash
# Setup 3-witness network with BLS aggregation
./examples/bls/setup.sh

# Start the BLS network
./examples/bls/start.sh

# See aggregation in action (3 signatures → 1)
./examples/bls/demo.sh

# Stop the network
./examples/bls/stop.sh
```

**BLS provides:**
- **50% bandwidth savings:** 3×96-byte signatures aggregate to 1×96-byte signature
- **Smaller storage:** Single signature instead of N signatures
- **Faster verification:** One pairing check instead of N signature verifications
- **Same security:** BLS12-381 provides 128-bit security (comparable to Ed25519)

**Comparison:**

| Aspect | Ed25519 (3 witnesses) | BLS (3 witnesses) |
|--------|----------------------|-------------------|
| Signature size | 192 bytes (3×64) | 96 bytes |
| Verification | 3 checks | 1 pairing |
| **Bandwidth** | 192 bytes | **96 bytes (50% savings)** |

See `examples/bls/README.md` for detailed documentation.

## Usage Guide

### Witness CLI

The `witness` CLI tool provides commands for interacting with the network:

#### Timestamp a file
```bash
witness timestamp --file <path>
```

Options:
- `--file <path>`: File to timestamp (computes SHA-256)
- `--hash <hex>`: Hash to timestamp (if you already have it)
- `--output <format>`: Output format (text or json)
- `--save <path>`: Save attestation to file
- `--gateway <url>`: Gateway URL (default: http://localhost:8080)

#### Get existing timestamp
```bash
witness get <hash>
```

#### Verify attestation
```bash
witness verify <attestation-file>
```

#### View network config
```bash
witness config
```

### Gateway API

The gateway exposes a REST API:

#### `POST /v1/timestamp`
Submit a hash for timestamping.

Request:
```json
{
  "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
}
```

Response:
```json
{
  "attestation": {
    "attestation": {
      "hash": [/* 32 bytes */],
      "timestamp": 1234567890,
      "network_id": "example-network",
      "sequence": 1
    },
    "signatures": [
      {
        "witness_id": "witness-1",
        "signature": [/* 64 bytes */]
      }
    ]
  }
}
```

#### `GET /v1/timestamp/:hash`
Retrieve an existing timestamp.

#### `POST /v1/verify`
Verify a signed attestation.

Request:
```json
{
  "attestation": { /* SignedAttestation object */ }
}
```

Response:
```json
{
  "valid": true,
  "verified_signatures": 3,
  "required_signatures": 2,
  "message": "Valid: 3 of 3 signatures verified, 2 required"
}
```

#### `GET /v1/config`
Get network configuration (witnesses, threshold, etc).

## Configuration

### Witness Node Config

Each witness node requires a configuration file (`witness.json`):

**Ed25519 (default):**
```json
{
  "id": "witness-1",
  "signature_scheme": "ed25519",
  "private_key": "hex-encoded-ed25519-private-key",
  "port": 3001,
  "network_id": "example-network",
  "max_clock_skew": 300
}
```

**BLS (for aggregation):**
```json
{
  "id": "witness-1",
  "signature_scheme": "bls",
  "private_key": "hex-encoded-bls-private-key",
  "port": 3001,
  "network_id": "example-network",
  "max_clock_skew": 300
}
```

Generate keypairs:
```bash
# Ed25519 (default)
cargo run -p witness-node -- --generate-key

# BLS
cargo run -p witness-node -- --generate-key --bls
```

### Network Config

The gateway requires a network configuration file (`network.json`):

**Ed25519:**
```json
{
  "id": "example-network",
  "signature_scheme": "ed25519",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "hex-encoded-32-byte-ed25519-public-key",
      "endpoint": "http://localhost:3001"
    }
  ],
  "federation": {
    "enabled": true,
    "batch_period": 60,
    "peer_networks": [...]
  }
}
```

**BLS:**
```json
{
  "id": "example-network",
  "signature_scheme": "bls",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "hex-encoded-48-byte-bls-public-key",
      "endpoint": "http://localhost:3001"
    }
  ],
  "federation": {
    "enabled": true,
    "batch_period": 60,
    "peer_networks": [...]
  }
}
```

**Fields:**
- `id`: Unique identifier for this network
- `signature_scheme`: "ed25519" (default) or "bls" (for aggregation)
- `threshold`: Minimum number of signatures required
- `witnesses`: List of witness nodes in the network
- `federation`: Federation configuration (optional)

## Security Considerations

### Trust Model

In Mode 1 (current implementation):
- **Trust assumption:** Fewer than `threshold` witnesses collude
- **Attack vector:** If threshold witnesses are compromised, they can forge timestamps
- **Mitigation:** Use threshold ≥ 2, run witnesses on independent infrastructure

Recommended configurations:
- **Low stakes:** 3 witnesses, threshold 2 (2-of-3)
- **Medium stakes:** 5 witnesses, threshold 3 (3-of-5)
- **High stakes:** 7+ witnesses, threshold >50% + use Mode 2 federation

### Best Practices

1. **Witness Independence:** Run witnesses on separate infrastructure, different providers
2. **Key Security:** Keep witness private keys in secure storage (HSM for production)
3. **Clock Sync:** Use NTP to keep witness clocks synchronized
4. **Monitoring:** Monitor witness availability and response times
5. **Backups:** Back up gateway database regularly

### What Witness Does NOT Provide

- **Content confidentiality:** You submit hashes, but the hash itself is public
- **Real-time guarantees:** Timestamps are based on witness clocks, not physical time
- **Byzantine fault tolerance:** Witnesses are assumed honest or offline, not malicious
- **Legal proof:** Timestamps are cryptographic proof, not legal proof

## Development

### Project Structure

```
witness/
├── crates/
│   ├── witness-core/      # Core types and crypto
│   ├── witness-node/      # Witness node server
│   ├── witness-gateway/   # Gateway server
│   └── witness-cli/       # CLI tool
├── examples/              # Example configs and scripts
└── Cargo.toml            # Workspace definition
```

### Building

Build all crates:
```bash
cargo build --release
```

Build specific crate:
```bash
cargo build --release -p witness-node
```

Run tests:
```bash
cargo test
```

### Running Components Individually

Witness node:
```bash
cargo run -p witness-node -- --config witness.json
```

Gateway:
```bash
cargo run -p witness-gateway -- --config network.json --port 8080
```

CLI:
```bash
cargo run -p witness-cli -- --gateway http://localhost:8080 timestamp --file README.md
```

## FAQ

**Q: Why not use a blockchain?**
A: Bye, bye blockchain.

**Q: How is this different from RFC 3161 timestamping?**
A: RFC 3161 requires trusting a single timestamping authority. Witness uses threshold signatures across multiple independent witnesses.

**Q: Can witnesses see my data?**
A: No, you only submit SHA-256 hashes, not the content itself.

**Q: What happens if a witness goes down?**
A: As long as the threshold number of witnesses are available, the network continues operating.

**Q: Can I self-host my own witness network?**
A: Yes! Use the example configs as a template and deploy witnesses to your infrastructure.

**Q: What's the difference between Witness and Certificate Transparency?**
A: CT logs are for TLS certificates and operated by large organizations. Witness is general-purpose and designed for easier self-hosting.

## License

MIT License - see LICENSE file for details.
