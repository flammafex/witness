# Federation Example (Phase 2)

This example demonstrates **Phase 2: Federated cross-network anchoring** with 3 independent Witness networks.

## What This Demonstrates

- **3 independent networks** (A, B, C) each with their own witnesses
- **Periodic batch closing** every 60 seconds
- **Cross-network anchoring** where networks witness each other's batches
- **Enhanced security** requiring compromise of multiple independent networks

## Setup

### 1. Generate Keys and Configuration

```bash
./examples/federation/setup.sh
```

This creates:
- 9 witness nodes (3 per network)
- 3 gateway configurations with federation enabled
- All keys and configs in `examples/federation/`

### 2. Start All Networks

```bash
./examples/federation/start.sh
```

This starts:
- **Network A**: Gateway on 9001, Witnesses on 8001-8003
- **Network B**: Gateway on 9002, Witnesses on 8011-8013
- **Network C**: Gateway on 9003, Witnesses on 8021-8023

### 3. Run the Demo

```bash
./examples/federation/demo.sh
```

This demonstrates:
1. Timestamping on Network A
2. Timestamping on Network B
3. Waiting for batch close (60 seconds)
4. Automatic cross-anchoring between networks
5. Verification of federation

### 4. Stop Networks

```bash
./examples/federation/stop.sh
```

## Architecture

```
Network A (9001)          Network B (9002)          Network C (9003)
├─ witness-a-1 (8001)     ├─ witness-b-1 (8011)     ├─ witness-c-1 (8021)
├─ witness-a-2 (8002)     ├─ witness-b-2 (8012)     ├─ witness-c-2 (8022)
└─ witness-a-3 (8003)     └─ witness-b-3 (8013)     └─ witness-c-3 (8023)

        ↓                         ↓                         ↓
Every 60 seconds: Close batch, compute merkle root
        ↓                         ↓                         ↓
Submit to peer networks:
A → B, C                  B → A, C                  C → A, B
        ↓                         ↓                         ↓
Peers sign merkle root (cross-anchor)
        ↓                         ↓                         ↓
Store cross-anchors locally
```

## How Federation Works

### 1. Normal Timestamping (Phase 1)

```bash
# Client submits hash to Network A
curl -X POST http://localhost:9001/v1/timestamp \
  -H "Content-Type: application/json" \
  -d '{"hash":"..."}'

# Gateway fans out to witnesses
# Collects threshold signatures (2 of 3)
# Returns signed attestation
```

### 2. Batch Closing (every 60 seconds)

```
# Gateway automatically:
1. Collects all attestations since last batch
2. Builds merkle tree from attestation hashes
3. Computes merkle root
4. Stores batch in database
```

### 3. Cross-Anchoring

```
# Gateway submits batch to peer networks:
POST http://localhost:9002/v1/federation/anchor
POST http://localhost:9003/v1/federation/anchor

# Peers timestamp the merkle root:
1. Create attestation for merkle root
2. Get signatures from peer's witnesses
3. Return cross-anchor with signatures

# Gateway stores cross-anchors locally
```

### 4. Enhanced Verification

```
# Client can now verify:
1. Attestation has threshold signatures ✓ (Phase 1)
2. Attestation is in merkle tree batch ✓ (Phase 2)
3. Batch was cross-anchored by N peer networks ✓ (Phase 2)
4. Cross-anchors have valid signatures ✓ (Phase 2)
```

## Security Model

### Phase 1 (Single Network)
- **Attack**: Compromise 2 of 3 witnesses in Network A
- **Result**: Can forge timestamps

### Phase 2 (Federation)
- **Attack**: Compromise 2 of 3 witnesses in ALL networks (A, B, C)
- **Requires**: 6 witnesses across 3 independent operators
- **Much harder**: Different organizations, infrastructure, security

## Configuration

Each network's `network-*.json` includes:

```json
{
  "federation": {
    "enabled": true,
    "batch_period": 60,
    "peer_networks": [
      {
        "id": "network-b",
        "gateway": "http://localhost:9002",
        "min_witnesses": 2
      }
    ],
    "cross_anchor_threshold": 2
  }
}
```

- `batch_period`: How often to close batches (seconds)
- `peer_networks`: Which networks to cross-anchor with
- `cross_anchor_threshold`: Minimum peer networks required

## Monitoring

Watch federation in action:

```bash
# Network A gateway logs
tail -f examples/federation/gateway-a.log

# Look for:
# - "Closing batch with N attestations"
# - "Batch X created: ... attestations, root: ..."
# - "Submitting batch X for cross-anchoring to 2 peer networks"
# - "Received cross-anchor from network: network-b"
# - "Received 2 cross-anchors for batch X"
```

## Testing

### Manual Testing

```bash
# 1. Start networks
./examples/federation/start.sh

# 2. Timestamp on Network A
cargo run -p witness-cli -- --gateway http://localhost:9001 \
  timestamp --file README.md --save /tmp/a.json

# 3. Wait 60 seconds for batch

# 4. Check Network A logs
grep "cross-anchor" examples/federation/gateway-a.log

# 5. Verify cross-anchoring happened
# Should see:
# - "Batch 1 created"
# - "Submitting batch 1 for cross-anchoring"
# - "Received cross-anchor from network: network-b"
# - "Received cross-anchor from network: network-c"
```

### Failure Testing

Test network resilience:

```bash
# Kill one peer network
kill $(cat examples/federation/gateway-b.pid)

# Timestamp on Network A
cargo run -p witness-cli -- --gateway http://localhost:9001 \
  timestamp --file test.txt

# After 60 seconds:
# - Batch still closes
# - Only Network C provides cross-anchor
# - System continues working (degrades gracefully)
```

## Production Deployment

For production, run each network in different environments:

- **Network A**: Your organization
- **Network B**: Trusted partner organization
- **Network C**: Another independent operator

Each should:
- Run on separate infrastructure
- Use hardware security modules (HSM) for witness keys
- Have independent security practices
- Be geographically distributed

## Troubleshooting

**Batches not closing:**
- Check `batch_period` in config
- Ensure federation is enabled
- Look for errors in gateway logs

**Cross-anchors not working:**
- Verify peer gateways are reachable
- Check peer gateway ports are correct
- Ensure peer networks have correct public keys

**Database errors:**
- Delete `examples/federation/*.db` and restart
- Check disk space

## Next Steps

- Adjust `batch_period` for your use case (default: 60s)
- Add more peer networks for stronger security
- Implement monitoring and alerting
- Deploy to production infrastructure
- Consider Phase 3 external anchors (CT logs, etc.)
