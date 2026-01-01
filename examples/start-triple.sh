#!/bin/bash

# Start three gateway networks
# Gateway 1: port 5001 with 3 witness nodes
# Gateway 2: port 5002 with 3 witness nodes
# Gateway 3: port 5003 with 3 witness nodes

set -e

echo "Starting triple-gateway Witness network..."
echo

# Check if configs exist
if [ ! -f "examples/gateway1/network.json" ]; then
    echo "Configuration files not found. Run './examples/setup-gateway.sh' first."
    exit 1
fi

# Build if needed
echo "Building binaries..."
cargo build --release

echo

# Get absolute path to project root
PROJECT_ROOT="$(pwd)"

# Start witness nodes for both gateways
echo "Starting 9 witness nodes (3 per gateway)..."

# Gateway 1 witnesses (ports 4001-4003)
for i in 1 2 3; do
    echo "  Starting gateway1-witness-$i on port $((4000 + i))..."
    cargo run --release -p witness-node -- \
        --config "$PROJECT_ROOT/examples/gateway1/witness$i.json" \
        > "examples/gateway1/witness$i.log" 2>&1 &

    PID=$!
    echo $PID > "examples/gateway1/witness$i.pid"
done

# Gateway 2 witnesses (ports 4004-4006)
for i in 1 2 3; do
    echo "  Starting gateway2-witness-$i on port $((4003 + i))..."
    cargo run --release -p witness-node -- \
        --config "$PROJECT_ROOT/examples/gateway2/witness$i.json" \
        > "examples/gateway2/witness$i.log" 2>&1 &

    PID=$!
    echo $PID > "examples/gateway2/witness$i.pid"
done

# Gateway 3 witnesses (ports 4007-4009)
for i in 1 2 3; do
    echo "  Starting gateway3-witness-$i on port $((4003 + i))..."
    cargo run --release -p witness-node -- \
        --config "$PROJECT_ROOT/examples/gateway3/witness$i.json" \
        > "examples/gateway3/witness$i.log" 2>&1 &

    PID=$!
    echo $PID > "examples/gateway3/witness$i.pid"
done

echo
echo "Waiting for witnesses to start..."
sleep 4

# Start gateways
echo
echo "Starting 3 gateway nodes..."

# Gateway 1
echo "  Starting gateway-1 on port 5001..."
touch "$PROJECT_ROOT/examples/gateway1/gateway.db"

cargo run --release -p witness-gateway -- \
    --config "$PROJECT_ROOT/examples/gateway1/network.json" \
    --port 5001 \
    --database "$PROJECT_ROOT/examples/gateway1/gateway.db" \
    > "examples/gateway1/gateway.log" 2>&1 &

PID=$!
echo $PID > "examples/gateway1/gateway.pid"

# Gateway 2
echo "  Starting gateway-2 on port 5002..."
touch "$PROJECT_ROOT/examples/gateway2/gateway.db"

cargo run --release -p witness-gateway -- \
    --config "$PROJECT_ROOT/examples/gateway2/network.json" \
    --port 5002 \
    --database "$PROJECT_ROOT/examples/gateway2/gateway.db" \
    > "examples/gateway2/gateway.log" 2>&1 &

PID=$!
echo $PID > "examples/gateway2/gateway.pid"

# Gateway 3
echo "  Starting gateway-3 on port 5003..."
touch "$PROJECT_ROOT/examples/gateway3/gateway.db"

cargo run --release -p witness-gateway -- \
    --config "$PROJECT_ROOT/examples/gateway3/network.json" \
    --port 5002 \
    --database "$PROJECT_ROOT/examples/gateway3/gateway.db" \
    > "examples/gateway3/gateway.log" 2>&1 &

PID=$!
echo $PID > "examples/gateway3/gateway.pid"

echo
echo "Waiting for gateways to start..."
sleep 3

echo
echo "╔═══════════════════════════════════════════════╗"
echo "║  Triple-Gateway Network Running!                ║"
echo "╚═══════════════════════════════════════════════╝"
echo
echo "3 Gateway networks × 3 Witnesses each = 9 witness nodes"
echo
echo "Gateways:"
echo "  Gateway 1: http://localhost:5001"
echo "  Gateway 2: http://localhost:5002"
echo "  Gateway 3: http://localhost:5003"
echo
echo "Gateway 1 Witnesses:"
echo "  witness-1: http://localhost:4001"
echo "  witness-2: http://localhost:4002"
echo "  witness-3: http://localhost:4003"
echo
echo "Gateway 2 Witnesses:"
echo "  witness-1: http://localhost:4004"
echo "  witness-2: http://localhost:4005"
echo "  witness-3: http://localhost:4006"
echo
echo "Gateway 3 Witnesses:"
echo "  witness-1: http://localhost:4007"
echo "  witness-2: http://localhost:4008"
echo "  witness-3: http://localhost:4009"
echo
echo "Logs:"
echo "  Gateway 1: examples/gateway1/*.log"
echo "  Gateway 2: examples/gateway2/*.log"
echo "  Gateway 3: examples/gateway3/*.log"
echo
echo "Try it:"
echo "  # Timestamp via Gateway 1"
echo "  cargo run -p witness-cli -- --gateway http://localhost:5001 timestamp --file README.md"
echo
echo "  # Timestamp via Gateway 2"
echo "  cargo run -p witness-cli -- --gateway http://localhost:5002 timestamp --file README.md"
echo
echo "  # Timestamp via Gateway 3"
echo "  cargo run -p witness-cli -- --gateway http://localhost:5003 timestamp --file README.md"
echo
echo "Stop with: kill \$(cat examples/gateway*/witness*.pid examples/gateway*/gateway.pid)"
echo
