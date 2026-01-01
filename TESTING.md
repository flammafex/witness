# Testing Guide

## Prerequisites

- Rust 1.70+ with cargo
- SQLite
- curl (for API testing)

## Quick Test

```bash
# Build
cargo build --release

# Run unit tests
cargo test

# Set up and run example network
./examples/setup.sh
./examples/start.sh
./examples/demo.sh
./examples/stop.sh
```

## Manual Testing

### 1. Build

```bash
cargo build --release
```

Binaries will be in `target/release/`:
- `witness-node`
- `witness-gateway`
- `witness` (CLI)

### 2. Generate Keys and Configuration

```bash
./examples/setup.sh
```

Creates:
- `examples/witness1.json`, `witness2.json`, `witness3.json`
- `examples/network.json`

### 3. Start Network

```bash
# Start all witnesses and gateway
./examples/start.sh

# Or manually in separate terminals:
cargo run --release -p witness-node -- --config examples/witness1.json
cargo run --release -p witness-node -- --config examples/witness2.json
cargo run --release -p witness-node -- --config examples/witness3.json
cargo run --release -p witness-gateway -- --config examples/network.json --port 8080
```

### 4. Test Health Endpoints

```bash
curl http://localhost:3001/health  # Witness 1
curl http://localhost:8080/health  # Gateway
```

### 5. Timestamp a File

```bash
echo "Hello, Witness!" > /tmp/test.txt
cargo run -p witness-cli -- timestamp --file /tmp/test.txt --save /tmp/attestation.json
```

### 6. Verify

```bash
# Look up by hash
HASH=$(sha256sum /tmp/test.txt | awk '{print $1}')
cargo run -p witness-cli -- get $HASH

# Verify attestation file
cargo run -p witness-cli -- verify /tmp/attestation.json
```

## API Testing

```bash
# Get network config
curl http://localhost:8080/v1/config | jq

# Timestamp a hash
curl -X POST http://localhost:8080/v1/timestamp \
  -H "Content-Type: application/json" \
  -d '{"hash":"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"}' | jq

# Get merkle proof (after batch closes)
curl http://localhost:8080/v1/proof/$HASH | jq

# Verify via API
curl -X POST http://localhost:8080/v1/verify \
  -H "Content-Type: application/json" \
  -d @/tmp/attestation.json | jq
```

## Unit Tests

```bash
cargo test --workspace
```

## Integration Tests

### Threshold Behavior

1. Start only 1 witness (below threshold of 2)
2. Try to timestamp → should fail with "Insufficient signatures"

### Witness Failure

1. Start all 3 witnesses, timestamp succeeds
2. Stop 1 witness, timestamp still succeeds (2 remaining)
3. Stop another witness, timestamp fails (only 1 left)

### Duplicate Handling

1. Timestamp same hash twice
2. Second request should return existing attestation

## Test Checklist

- [ ] All crates build
- [ ] Unit tests pass
- [ ] Witness nodes start
- [ ] Gateway starts
- [ ] Timestamping works
- [ ] Retrieval by hash works
- [ ] Verification passes for valid attestations
- [ ] Invalid attestations are rejected
- [ ] Threshold enforcement works
- [ ] Duplicates return existing attestation
- [ ] Admin dashboard loads (`--admin-ui` flag)

## Troubleshooting

**Witness won't start:** Check private key format (64 hex chars), port availability, config JSON validity.

**Gateway can't reach witnesses:** Verify endpoints in network.json, check firewall rules.

**Insufficient signatures:** Ensure threshold witnesses are running and clocks are synchronized.

**Verification fails:** Check public keys match, attestation JSON is not corrupted.
