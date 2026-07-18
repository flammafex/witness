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

### 5. Create and Poll an Attestation Job

```bash
echo "Hello, Witness!" > /tmp/test.txt
cargo run -p witness-cli -- attest --file /tmp/test.txt --save /tmp/attestation-job.json
```

### 6. Verify

```bash
# Look up by hash
HASH=$(sha256sum /tmp/test.txt | awk '{print $1}')
cargo run -p witness-cli -- status $HASH

# Once confirmed, save the latest snapshot and extract the signed result
curl http://localhost:8080/v1/attestations/$HASH > /tmp/attestation-job.json
jq '.signed_attestation' /tmp/attestation-job.json > /tmp/attestation.json
cargo run -p witness-cli -- verify /tmp/attestation.json
```

## API Testing

```bash
# Get network config
curl http://localhost:8080/v1/config | jq

# Reserve an attestation job
curl -X POST http://localhost:8080/v1/attestations \
  -H "Content-Type: application/json" \
  -d '{"hash":"a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"}' | jq

# Poll until status is confirmed
curl http://localhost:8080/v1/attestations/$HASH | jq

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
2. Submit a job; it should remain `retryable` and expose `next_attempt_at`

### Witness Failure

1. Start all 3 witnesses; a submitted job reaches `confirmed`
2. Stop 1 witness; jobs still confirm with 2 remaining
3. Stop another witness; jobs remain `retryable` until quorum returns

### Duplicate Handling

1. Submit the same hash twice while pending
2. Both responses must contain the exact same timestamp/network/sequence tuple
3. After confirmation, another submission returns the same signed result

### Restart Recovery

1. Submit a job while witnesses are unavailable and observe `retryable`
2. Restart the gateway using the same SQLite database
3. Restore quorum and verify the same tuple reaches `confirmed`

### Breaking API Regression

`POST /v1/timestamp` and `GET /v1/timestamp/:hash` must return `404`. Pending
jobs must not return successful `/v1/proof/:hash` or `/v1/bundle/:hash` results.

## Test Checklist

- [ ] All crates build
- [ ] Unit tests pass
- [ ] Witness nodes start
- [ ] Gateway starts
- [ ] Attestation submission returns a durable pending/confirmed job
- [ ] Status polling by hash works
- [ ] Verification passes for valid attestations
- [ ] Invalid attestations are rejected
- [ ] Threshold enforcement works
- [ ] Duplicates return the existing immutable tuple/result
- [ ] Admin dashboard loads (`--admin-ui --admin-api-key <key>`)

## Troubleshooting

**Witness won't start:** Check private key format (64 hex chars), port availability, config JSON validity.

**Gateway can't reach witnesses:** Verify endpoints in network.json, check firewall rules.

**Insufficient signatures:** Ensure threshold witnesses are running and clocks are synchronized.

**Verification fails:** Check public keys match, attestation JSON is not corrupted.
