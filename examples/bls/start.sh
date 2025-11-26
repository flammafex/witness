#!/bin/bash
# Start BLS witness network

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BLS_DIR="$PROJECT_ROOT/examples/bls"

echo "Starting BLS witness network..."
echo

# Check if configs exist
if [ ! -f "$BLS_DIR/network.json" ]; then
    echo "Error: Network not set up. Run ./examples/bls/setup.sh first"
    exit 1
fi

# Create database file
touch "$BLS_DIR/gateway.db"

# Start witnesses in background
for i in 1 2 3; do
    echo "Starting witness-$i on port $((8000 + i))..."
    "$PROJECT_ROOT/target/release/witness-node" \
        --config "$BLS_DIR/witness-$i.json" \
        > "$BLS_DIR/witness-$i.log" 2>&1 &
    echo $! > "$BLS_DIR/witness-$i.pid"
    sleep 0.5
done

echo
echo "Starting gateway on port 9000..."

# Start gateway
NETWORK_CONFIG="$BLS_DIR/network.json" \
DATABASE_URL="sqlite:$BLS_DIR/gateway.db" \
"$PROJECT_ROOT/target/release/witness-gateway" \
    > "$BLS_DIR/gateway.log" 2>&1 &
echo $! > "$BLS_DIR/gateway.pid"

sleep 2

echo
echo "=========================================="
echo "BLS Network Started!"
echo "=========================================="
echo
echo "Witnesses:"
for i in 1 2 3; do
    if ps -p $(cat "$BLS_DIR/witness-$i.pid" 2>/dev/null) > /dev/null 2>&1; then
        echo "  ✓ witness-$i: http://localhost:$((8000 + i))"
    else
        echo "  ✗ witness-$i: FAILED TO START (check witness-$i.log)"
    fi
done

echo
echo "Gateway:"
if ps -p $(cat "$BLS_DIR/gateway.pid" 2>/dev/null) > /dev/null 2>&1; then
    echo "  ✓ http://localhost:9000"
else
    echo "  ✗ FAILED TO START (check gateway.log)"
fi

echo
echo "Logs:"
echo "  tail -f $BLS_DIR/witness-*.log"
echo "  tail -f $BLS_DIR/gateway.log"
echo
echo "Next: ./examples/bls/demo.sh to see BLS aggregation in action"
echo
