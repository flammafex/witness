# BLS Witness Network Example

This example demonstrates **BLS signature aggregation** for the Witness timestamping system.

## What is BLS?

BLS (Boneh-Lynn-Shacham) signatures have a unique property: **multiple signatures can be aggregated into a single signature**. This provides:

- **50% bandwidth savings**: 3 signatures = 96 bytes instead of 192 bytes
- **Smaller storage**: One signature stored instead of N
- **Faster verification**: Single pairing check instead of N signature verifications
- **Same security**: BLS12-381 provides 128-bit security (comparable to Ed25519)

## Network Setup

This example creates a 3-witness network using BLS signatures:

- **witness-1**: `localhost:8001` (BLS signer)
- **witness-2**: `localhost:8002` (BLS signer)
- **witness-3**: `localhost:8003` (BLS signer)
- **gateway**: `localhost:9000` (aggregates signatures)
- **threshold**: 2 of 3 signatures required

## Quick Start

```bash
# 1. Setup the network (generate BLS keys)
./examples/bls/setup.sh

# 2. Start all nodes
./examples/bls/start.sh

# 3. Run the demo (see aggregation in action)
./examples/bls/demo.sh

# 4. Stop the network
./examples/bls/stop.sh
```

## How It Works

### 1. **Key Generation**

```bash
witness-node --generate-key --bls
```

Generates a BLS12-381 keypair:
- **Private key**: 32 bytes (hex encoded)
- **Public key**: 48 bytes (hex encoded, compressed G1 point)

### 2. **Witness Signing**

Each witness signs the attestation independently using BLS:

```rust
// witness-node signs with BLS secret key
let signature = sign_attestation_bls(&attestation, &secret_key);
// Returns: 96-byte BLS signature (G2 point)
```

### 3. **Gateway Aggregation**

The gateway collects N individual signatures and aggregates them:

```rust
// Collect signatures from witnesses
let sig1 = witness1.sign(attestation);  // 96 bytes
let sig2 = witness2.sign(attestation);  // 96 bytes
let sig3 = witness3.sign(attestation);  // 96 bytes

// Aggregate into single signature
let aggregated = aggregate_signatures_bls(&[sig1, sig2, sig3]);
// Returns: 96 bytes (same size, but represents all 3!)
```

### 4. **Verification**

Verify the aggregated signature against aggregated public keys:

```rust
// Aggregate public keys
let agg_pubkey = aggregate_pubkeys(&[pk1, pk2, pk3]);

// Single pairing check verifies all signatures
verify_aggregated_signature_bls(&attestation, &aggregated, &agg_pubkey);
```

## Ed25519 vs BLS Comparison

| Aspect | Ed25519 (Multi-sig) | BLS (Aggregated) |
|--------|---------------------|------------------|
| Signature size (3 witnesses) | 192 bytes (3×64) | 96 bytes |
| Public key size | 32 bytes | 48 bytes |
| Signing speed | ~50 μs | ~500 μs |
| Verification (3 sigs) | 3 checks (~150 μs) | 1 pairing (~2 ms) |
| **Bandwidth** | 192 bytes | **96 bytes (50% savings)** |
| **Storage** | 3 rows | **1 row** |
| Security level | 128-bit | 128-bit |

**Best for:**
- **Ed25519**: Low latency, small witness count
- **BLS**: High throughput, many witnesses, bandwidth-constrained

## Configuration

### Witness Config (`witness-N.json`)

```json
{
  "id": "witness-1",
  "signature_scheme": "bls",
  "private_key": "<hex-encoded-32-bytes>",
  "network_id": "bls-network",
  "port": 8001,
  "max_clock_skew": 300
}
```

### Network Config (`network.json`)

```json
{
  "id": "bls-network",
  "signature_scheme": "bls",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "<hex-encoded-48-bytes>",
      "endpoint": "http://localhost:8001"
    }
  ]
}
```

**Important**: Both witness and network configs must specify `"signature_scheme": "bls"`.

## Testing

### Timestamp a file

```bash
witness timestamp \
  --gateway http://localhost:9000 \
  --file myfile.txt
```

Expected output:
```
✓ Timestamp successful!

Hash:      a3f5...
Timestamp: 1234567890
Network:   bls-network
Sequence:  1

Signatures: BLS aggregated signature from 3 witnesses
  - witness-1
  - witness-2
  - witness-3
```

### Verify signature aggregation

```bash
# Get attestation and inspect
witness get --gateway http://localhost:9000 --hash <hash> --output json | jq '.signatures'
```

Should show:
```json
{
  "Aggregated": {
    "signature": "96-byte-hex-string",
    "signers": ["witness-1", "witness-2", "witness-3"]
  }
}
```

### Check logs

```bash
# Watch gateway aggregate signatures
tail -f examples/bls/gateway.log | grep -i "aggregat"

# Expected output:
# Collected 3 BLS signatures to aggregate (threshold: 2)
# Aggregated 3 BLS signatures into single signature
```

## Bandwidth Analysis

For a single attestation with 3 witnesses:

**Ed25519 Multi-sig:**
```
Header: 32 bytes (hash) + 8 (timestamp) + ... = ~50 bytes
Signatures: 3 × (8-byte ID + 64-byte sig) = 216 bytes
Total: ~266 bytes
```

**BLS Aggregated:**
```
Header: 32 bytes (hash) + 8 (timestamp) + ... = ~50 bytes
Signature: 96 bytes (1 aggregated)
Signers: 3 × 8-byte IDs = 24 bytes
Total: ~170 bytes
```

**Savings: 96 bytes per attestation (36%)**

At scale (1M attestations/day): **96 MB/day savings**

## Advanced: BLS + Federation

For cross-network anchoring, BLS provides even greater benefits:

```bash
# 3 networks, each with 3 witnesses = 9 total witnesses
# Ed25519: 9 × 64 = 576 bytes of signatures
# BLS: 96 bytes (single aggregated signature from all 9)
# Savings: 83%!
```

See `examples/federation/` for federation setup, then adapt for BLS.

## Troubleshooting

**"Signature verification failed"**
- Ensure all witnesses and network config use `"signature_scheme": "bls"`
- Check witness logs for signing errors
- Verify public keys match between witness and network configs

**"Invalid BLS public key"**
- BLS public keys are 48 bytes (96 hex chars), not 32 bytes
- Re-run setup.sh to generate fresh keys

**Gateway not aggregating**
- Check gateway logs: `tail -f examples/bls/gateway.log`
- Should see "Aggregated N BLS signatures"
- If seeing "Collected N Ed25519 signatures", check network config

## Next Steps

1. **Performance testing**: Benchmark BLS vs Ed25519 at scale
2. **Federation with BLS**: Combine BLS + cross-network anchoring
3. **Threshold signatures**: Implement true threshold BLS (not just aggregation)
4. **Production**: Deploy with Docker, monitoring, and HA

## References

- [BLS Signatures (IRTF Draft)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)
- [BLS12-381 Curve](https://github.com/zkcrypto/bls12_381)
- [blst Library](https://github.com/supranational/blst)
