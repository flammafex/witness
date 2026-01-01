#!/bin/bash

# Start the Witness network
# Runs 3 witness nodes and 1 gateway

set -e

echo "Starting Witness network..."
echo

# Check if configs exist
if [ ! -f "examples/network.json" ]; then
    echo "Configuration files not found. Run './examples/setup.sh' first."
    exit 1
fi

# Build if needed
echo "Building binaries..."
cargo build --release

echo
echo "Starting witness nodes..."

# Get absolute path to project root
PROJECT_ROOT="$(pwd)"

# Start witness nodes in background
for i in 1 2 3; do
    echo "Starting witness-$i on port $((3000 + i))..."
    cargo run --release -p witness-node -- \
        --config "$PROJECT_ROOT/examples/witness$i.json" \
        > "examples/witness$i.log" 2>&1 &

    WITNESS_PID=$!
    echo $WITNESS_PID > "examples/witness$i.pid"
    echo "  PID: $WITNESS_PID"
done

# Wait for witnesses to start
echo
echo "Waiting for witnesses to start..."
sleep 2

# Start gateway
echo
echo "Starting gateway on port 8080..."

# Create database file if it doesn't exist
touch "$PROJECT_ROOT/examples/gateway.db"

cargo run --release -p witness-gateway -- \
    --config "$PROJECT_ROOT/examples/network.json" \
    --port 8080 \
    --database "$PROJECT_ROOT/examples/gateway.db" \
    > "examples/gateway.log" 2>&1 &

GATEWAY_PID=$!
echo $GATEWAY_PID > "examples/gateway.pid"
echo "  PID: $GATEWAY_PID"

# Wait for gateway to start
sleep 2

echo
echo "✓ Witness network is running!"
echo
echo "Gateway:  http://localhost:8080"
echo "Witness 1: http://localhost:3001"
echo "Witness 2: http://localhost:3002"
echo "Witness 3: http://localhost:3003"
echo
echo "Logs:"
echo "  examples/witness1.log"
echo "  examples/witness2.log"
echo "  examples/witness3.log"
echo "  examples/gateway.log"
echo
echo "Try it out:"
echo "  cargo run -p witness-cli -- timestamp --file README.md"
echo
echo "Stop with: ./examples/stop.sh"
