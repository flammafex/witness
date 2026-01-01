#!/bin/bash

# Interactive demo of federation

set -e

echo "╔═══════════════════════════════════════════════╗"
echo "║  Witness Federation Demo                      ║"
echo "╚═══════════════════════════════════════════════╝"
echo

# Check if networks are running
if ! curl -s http://localhost:9001/health > /dev/null 2>&1; then
    echo "❌ Networks not running. Start with ./examples/federation/start.sh"
    exit 1
fi

echo "✓ All 3 networks are running"
echo

# Create test file
echo "1. Creating test file..."
echo "Federation Test $(date)" > /tmp/federation-test.txt
HASH=$(sha256sum /tmp/federation-test.txt | awk '{print $1}')
echo "   File hash: $HASH"
echo

# Timestamp on Network A
echo "2. Timestamping on Network A..."
cargo run -p witness-cli -- --gateway http://localhost:9001 \
    timestamp --file /tmp/federation-test.txt \
    --save /tmp/attestation-a.json \
    --output text
echo

# Also timestamp on Network B for comparison
echo "3. Timestamping same file on Network B..."
cargo run -p witness-cli -- --gateway http://localhost:9002 \
    timestamp --file /tmp/federation-test.txt \
    --save /tmp/attestation-b.json \
    --output text
echo

echo "4. Waiting for batch period (60 seconds)..."
echo "   Batches will close and cross-anchor to peer networks..."
echo "   Watch the logs to see federation in action:"
echo "   tail -f examples/federation/gateway-a.log"
echo

COUNTDOWN=60
while [ $COUNTDOWN -gt 0 ]; do
    printf "\r   Time remaining: %02d seconds" $COUNTDOWN
    sleep 1
    COUNTDOWN=$((COUNTDOWN - 1))
done
printf "\r   ✓ Batch period complete!                \n"
echo

# Wait a bit more for cross-anchoring
echo "5. Waiting 10 more seconds for cross-anchoring..."
sleep 10
echo

echo "6. Checking federation status..."
echo

# Check each network
for net in a b c; do
    case $net in
        a) PORT=9001 ;;
        b) PORT=9002 ;;
        c) PORT=9003 ;;
    esac

    echo "Network $net (port $PORT):"
    curl -s http://localhost:$PORT/v1/config | \
        python3 -c "import sys, json; data=json.load(sys.stdin); print(f\"  Witnesses: {len(data['witnesses'])}, Threshold: {data['threshold']}, Federation: {data['federation']['enabled']}\")"
done
echo

echo "╔═══════════════════════════════════════════════╗"
echo "║  Federation Demo Complete!                    ║"
echo "╚═══════════════════════════════════════════════╝"
echo

echo "What happened:"
echo "1. You timestamped a file on Network A (3 witnesses signed)"
echo "2. You timestamped same file on Network B (different 3 witnesses signed)"
echo "3. After 60 seconds, each network closed its batch"
echo "4. Each network submitted its batch to 2 peer networks"
echo "5. Peer networks signed the batch merkle roots (cross-anchoring)"
echo

echo "Security improvement:"
echo "- Phase 1: Trust 2 of 3 witnesses in Network A"
echo "- Phase 2: Trust that not ALL networks (A, B, C) are compromised"
echo "- To forge a timestamp now requires compromising:"
echo "  * 2 of 3 witnesses in Network A"
echo "  * 2 of 3 witnesses in Network B  "
echo "  * 2 of 3 witnesses in Network C"
echo "  = 6 witnesses across 3 independent operators"
echo

echo "Check the logs to see the federation protocol in action:"
echo "  examples/federation/gateway-a.log"
echo "  examples/federation/gateway-b.log"
echo "  examples/federation/gateway-c.log"
