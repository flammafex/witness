#!/bin/bash

# Start all 3 federated networks

set -e

echo "Starting 3 federated Witness networks..."
echo

# Check if configs exist
if [ ! -f "examples/federation/network-a.json" ]; then
    echo "Configuration files not found. Run './examples/federation/setup.sh' first."
    exit 1
fi

PROJECT_ROOT="$(pwd)"

# Start all witnesses
echo "Starting 9 witness nodes..."

for net in a b c; do
    for i in 1 2 3; do
        echo "  Starting witness-$net-$i..."
        cargo run --release -p witness-node -- \
            --config "$PROJECT_ROOT/examples/federation/witness-$net-$i.json" \
            > "examples/federation/witness-$net-$i.log" 2>&1 &

        PID=$!
        echo $PID > "examples/federation/witness-$net-$i.pid"
    done
done

echo
echo "Waiting for witnesses to start..."
sleep 3

# Start gateways
echo
echo "Starting 3 gateway nodes..."

for net in a b c; do
    case $net in
        a) PORT=9001 ;;
        b) PORT=9002 ;;
        c) PORT=9003 ;;
    esac

    echo "  Starting gateway-$net on port $PORT..."

    # Create database file
    touch "$PROJECT_ROOT/examples/federation/gateway-$net.db"

    cargo run --release -p witness-gateway -- \
        --config "$PROJECT_ROOT/examples/federation/network-$net.json" \
        --port $PORT \
        --database "$PROJECT_ROOT/examples/federation/gateway-$net.db" \
        > "examples/federation/gateway-$net.log" 2>&1 &

    PID=$!
    echo $PID > "examples/federation/gateway-$net.pid"
done

echo
echo "Waiting for gateways to start..."
sleep 3

echo
echo "╔═══════════════════════════════════════════════╗"
echo "║  Federation Network Running!                  ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "3 Networks × 3 Witnesses each = 9 witness nodes"
echo "3 Gateway nodes with federation enabled"
echo
echo "Gateways:"
echo "  Network A: http://localhost:9001"
echo "  Network B: http://localhost:9002"
echo "  Network C: http://localhost:9003"
echo
echo "Batch period: 60 seconds"
echo "  (Batches close every minute and cross-anchor to peers)"
echo
echo "Try it:"
echo "  # Timestamp on Network A"
echo "  cargo run -p witness-cli -- --gateway http://localhost:9001 timestamp --file README.md"
echo
echo "  # After 60 seconds, batches will cross-anchor automatically"
echo "  # Check logs to see federation in action:"
echo "  tail -f examples/federation/gateway-a.log"
echo
echo "Stop with: ./examples/federation/stop.sh"
