# Testing Guide for Witness

This document describes how to test the Witness timestamping system.

## Prerequisites

- Rust 1.70+ with cargo
- Network access to crates.io (for downloading dependencies)
- SQLite
- curl (for API testing)

## Quick Test

Once you have network access to crates.io:

```bash
# 1. Build all components
cargo build --release

# 2. Run unit tests
cargo test

# 3. Set up example network
./examples/setup.sh

# 4. Start the network
./examples/start.sh

# 5. Run the demo
./examples/demo.sh

# 6. Stop the network
./examples/stop.sh
```

## Manual Testing

### Step 1: Build Components

```bash
cargo build --release
```

Expected output:
- All crates should compile without errors
- Binaries in `target/release/`:
  - `witness-node`
  - `witness-gateway`
  - `witness`

### Step 2: Generate Keys and Configuration

```bash
./examples/setup.sh
```

Expected output:
- `examples/witness1.json`
- `examples/witness2.json`
- `examples/witness3.json`
- `examples/network.json`

Each witness config should contain a unique private key.

### Step 3: Start Witness Nodes

In separate terminals:

```bash
# Terminal 1
cargo run --release -p witness-node -- --config examples/witness1.json

# Terminal 2
cargo run --release -p witness-node -- --config examples/witness2.json

# Terminal 3
cargo run --release -p witness-node -- --config examples/witness3.json
```

Expected output for each:
```
Starting witness node: witness-X
Public key: [hex string]
Listening on port: 300X
Witness node listening on 0.0.0.0:300X
```

Test witness health:
```bash
curl http://localhost:3001/health
# Should return: {"status":"ok"}
```

### Step 4: Start Gateway

```bash
cargo run --release -p witness-gateway -- \
    --config examples/network.json \
    --port 8080 \
    --database examples/gateway.db
```

Expected output:
```
Loaded network configuration: example-network
Witnesses: 3
Threshold: 2
Database initialized: "examples/gateway.db"
Gateway listening on 0.0.0.0:8080
```

Test gateway health:
```bash
curl http://localhost:8080/health
# Should return: {"status":"ok"}
```

### Step 5: Test Timestamping

Create a test file:
```bash
echo "Hello, Witness!" > /tmp/test.txt
```

Timestamp the file:
```bash
cargo run -p witness-cli -- timestamp --file /tmp/test.txt --save /tmp/attestation.json
```

Expected output:
```
File: /tmp/test.txt
SHA-256: [hash]

Requesting timestamp from gateway...
✓ Timestamp successful!

Hash:      [hash]
Timestamp: [unix timestamp] ([relative time])
Network:   example-network
Sequence:  1

Signatures: 3 witnesses signed
  - witness-1
  - witness-2
  - witness-3

Attestation saved to: /tmp/attestation.json
```

### Step 6: Verify Timestamp

Look up by hash:
```bash
HASH=$(sha256sum /tmp/test.txt | awk '{print $1}')
cargo run -p witness-cli -- get $HASH
```

Verify the attestation:
```bash
cargo run -p witness-cli -- verify /tmp/attestation.json
```

Expected output:
```
Verifying attestation...
Hash: [hash]

✓ VALID

Valid: 3 of 3 signatures verified, 2 required
```

### Step 7: Test Verification Failure

Modify the attestation file to corrupt a signature:
```bash
# Edit /tmp/attestation.json and change a byte in one of the signatures
```

Verify again:
```bash
cargo run -p witness-cli -- verify /tmp/attestation.json
```

Should show validation error.

## API Testing

### Get Network Config

```bash
curl http://localhost:8080/v1/config | jq
```

Expected: Network configuration JSON with all witnesses.

### Timestamp a Hash

```bash
HASH="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"

curl -X POST http://localhost:8080/v1/timestamp \
  -H "Content-Type: application/json" \
  -d "{\"hash\":\"$HASH\"}" | jq
```

Expected: SignedAttestation JSON.

### Look Up Timestamp

```bash
curl http://localhost:8080/v1/timestamp/$HASH | jq
```

### Verify Attestation

```bash
curl -X POST http://localhost:8080/v1/verify \
  -H "Content-Type: application/json" \
  -d @/tmp/attestation.json | jq
```

## Unit Tests

Run unit tests for all crates:

```bash
cargo test --workspace
```

Expected tests to pass:
- `witness-core::crypto` tests (signing, verification, hashing)
- Type serialization tests
- Error handling tests

## Integration Tests

Test threshold behavior:

1. Start only 1 witness (below threshold of 2)
2. Try to timestamp a file
3. Should fail with "Insufficient signatures" error

Test witness failure:

1. Start all 3 witnesses
2. Timestamp a file (should succeed)
3. Stop 1 witness
4. Timestamp another file (should still succeed with 2 signatures)
5. Stop another witness (only 1 left)
6. Timestamp another file (should fail)

## Performance Testing

Basic performance test:

```bash
# Timestamp 100 different files
for i in {1..100}; do
    echo "Test $i" > /tmp/test-$i.txt
    cargo run -p witness-cli -- timestamp --file /tmp/test-$i.txt --output json > /dev/null
done
```

Check gateway performance:
- Response times should be < 100ms for local network
- Database should handle concurrent requests
- All witnesses should respond

## Troubleshooting

### Witness won't start

Check:
- Private key is valid hex (64 characters)
- Port is not already in use
- Config file is valid JSON

### Gateway can't connect to witnesses

Check:
- Witnesses are running and accessible
- Endpoints in network.json match witness ports
- No firewall blocking connections

### Insufficient signatures error

Check:
- At least `threshold` witnesses are running
- Witness clocks are synchronized (within max_clock_skew)
- Network connectivity between gateway and witnesses

### Signature verification fails

Check:
- Public keys in network.json match witness private keys
- Attestation JSON is not corrupted
- Network ID matches in all configs

## Test Checklist

- [ ] All crates build successfully
- [ ] Unit tests pass
- [ ] Can generate keypairs
- [ ] Can start witness nodes
- [ ] Can start gateway
- [ ] Can timestamp a file
- [ ] Can retrieve timestamp by hash
- [ ] Can verify valid attestation
- [ ] Invalid attestations are rejected
- [ ] System works with threshold number of witnesses
- [ ] System fails appropriately with below-threshold witnesses
- [ ] API endpoints return correct responses
- [ ] Database stores attestations correctly
- [ ] Multiple clients can timestamp concurrently
- [ ] Duplicate timestamps return existing attestation

## Known Limitations

- Network access required for initial cargo build (downloads dependencies)
- SQLite database is not replicated (gateway single point of failure in Mode 1)
- No authentication/rate limiting on API endpoints
- Clock skew between witnesses not automatically detected
- No automatic witness health monitoring

## Next Steps for Production

- [ ] Add comprehensive error handling tests
- [ ] Add load testing suite
- [ ] Add network partition tests
- [ ] Add Byzantine behavior tests (malicious witness simulation)
- [ ] Add monitoring and metrics
- [ ] Add backup/restore procedures
- [ ] Add deployment automation
