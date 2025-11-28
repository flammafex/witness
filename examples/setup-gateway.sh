#!/bin/bash

# Setup script for dual-gateway example
# Creates 2 independent networks with 3 witnesses each

set -e

echo "╔═══════════════════════════════════════════════╗"
echo "║  Dual-Gateway Setup (2 Networks)              ║"
echo "╚═══════════════════════════════════════════════╝"
echo

# Create directories
mkdir -p examples/gateway1
mkdir -p examples/gateway2

# Build binaries first
echo "Building binaries..."
cargo build --release -p witness-node -p witness-gateway

echo
echo "Generating keys for 2 networks × 3 witnesses each..."
echo

# Generate keys for Gateway 1
echo "=== Gateway 1 ==="
for i in 1 2 3; do
    echo "  Witness $i"

    OUTPUT=$(cargo run --release -p witness-node -- --generate-key 2>&1)
    PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | awk '{print $3}')
    PRIVKEY=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')

    # Store keys
    eval "G1_W${i}_PUBKEY=$PUBKEY"
    eval "G1_W${i}_PRIVKEY=$PRIVKEY"
    PORT=$((4000 + i))
    eval "G1_W${i}_PORT=$PORT"

    # Create witness config
    cat > "examples/gateway1/witness$i.json" <<EOF
{
  "id": "gateway1-witness-$i",
  "private_key": "$PRIVKEY",
  "port": $PORT,
  "network_id": "gateway1-network",
  "max_clock_skew": 300
}
EOF
done
echo

# Generate keys for Gateway 2
echo "=== Gateway 2 ==="
for i in 1 2 3; do
    echo "  Witness $i"

    OUTPUT=$(cargo run --release -p witness-node -- --generate-key 2>&1)
    PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | awk '{print $3}')
    PRIVKEY=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')

    # Store keys
    eval "G2_W${i}_PUBKEY=$PUBKEY"
    eval "G2_W${i}_PRIVKEY=$PRIVKEY"
    PORT=$((4003 + i))
    eval "G2_W${i}_PORT=$PORT"

    # Create witness config
    cat > "examples/gateway2/witness$i.json" <<EOF
{
  "id": "gateway2-witness-$i",
  "private_key": "$PRIVKEY",
  "port": $PORT,
  "network_id": "gateway2-network",
  "max_clock_skew": 300
}
EOF
done
echo

echo "Creating network configurations..."

# Gateway 1 network config
cat > "examples/gateway1/network.json" <<EOF
{
  "id": "gateway1-network",
  "threshold": 2,
  "witnesses": [
    {
      "id": "gateway1-witness-1",
      "pubkey": "$G1_W1_PUBKEY",
      "endpoint": "http://localhost:$G1_W1_PORT"
    },
    {
      "id": "gateway1-witness-2",
      "pubkey": "$G1_W2_PUBKEY",
      "endpoint": "http://localhost:$G1_W2_PORT"
    },
    {
      "id": "gateway1-witness-3",
      "pubkey": "$G1_W3_PUBKEY",
      "endpoint": "http://localhost:$G1_W3_PORT"
    }
  ],
  "federation_peers": []
}
EOF

# Gateway 2 network config
cat > "examples/gateway2/network.json" <<EOF
{
  "id": "gateway2-network",
  "threshold": 2,
  "witnesses": [
    {
      "id": "gateway2-witness-1",
      "pubkey": "$G2_W1_PUBKEY",
      "endpoint": "http://localhost:$G2_W1_PORT"
    },
    {
      "id": "gateway2-witness-2",
      "pubkey": "$G2_W2_PUBKEY",
      "endpoint": "http://localhost:$G2_W2_PORT"
    },
    {
      "id": "gateway2-witness-3",
      "pubkey": "$G2_W3_PUBKEY",
      "endpoint": "http://localhost:$G2_W3_PORT"
    }
  ],
  "federation_peers": []
}
EOF

echo "✓ Dual-gateway setup complete!"
echo
echo "Configuration created:"
echo "  - 2 independent networks"
echo "  - 3 witnesses per network (6 total)"
echo "  - Threshold: 2 of 3 witnesses per network"
echo
echo "Ports:"
echo "  Gateway 1: Port 5001, Witnesses 4001-4003"
echo "  Gateway 2: Port 5002, Witnesses 4004-4006"
echo
echo "Files created:"
echo "  examples/gateway1/network.json"
echo "  examples/gateway1/witness1.json"
echo "  examples/gateway1/witness2.json"
echo "  examples/gateway1/witness3.json"
echo "  examples/gateway2/network.json"
echo "  examples/gateway2/witness1.json"
echo "  examples/gateway2/witness2.json"
echo "  examples/gateway2/witness3.json"
echo
echo "Next: Run './examples/start-gateway.sh' to start both networks"
