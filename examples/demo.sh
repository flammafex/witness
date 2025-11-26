#!/bin/bash

# Demo script showing Witness capabilities

set -e

echo "╔════════════════════════════════════════════╗"
echo "║   Witness Timestamping Demo               ║"
echo "╚════════════════════════════════════════════╝"
echo

# Check if network is running
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "❌ Gateway is not running. Start with ./examples/start.sh"
    exit 1
fi

echo "✓ Network is running"
echo

# Create a test file
echo "1. Creating test file..."
echo "Hello, Witness!" > /tmp/test-file.txt
echo "   Content: Hello, Witness!"
echo

# Timestamp the file
echo "2. Timestamping file..."
cargo run -p witness-cli -- timestamp --file /tmp/test-file.txt --save /tmp/attestation.json
echo

# Retrieve the timestamp
echo "3. Looking up timestamp by hash..."
HASH=$(sha256sum /tmp/test-file.txt | awk '{print $1}')
cargo run -p witness-cli -- get "$HASH"
echo

# Verify the attestation
echo "4. Verifying attestation..."
cargo run -p witness-cli -- verify /tmp/attestation.json
echo

# Show network config
echo "5. Network configuration:"
cargo run -p witness-cli -- config | head -20
echo

echo "╔════════════════════════════════════════════╗"
echo "║   Demo Complete!                           ║"
echo "╚════════════════════════════════════════════╝"
echo
echo "The attestation has been saved to: /tmp/attestation.json"
echo "This JSON file is your cryptographic proof that the file"
echo "existed at the recorded timestamp."
echo
echo "Try modifying the file and timestamping again:"
echo "  echo 'Modified!' > /tmp/test-file.txt"
echo "  cargo run -p witness-cli -- timestamp --file /tmp/test-file.txt"
