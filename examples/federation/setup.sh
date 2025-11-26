#!/bin/bash

# Setup script for 3-network federation example
# Creates 3 independent Witness networks that cross-anchor each other

set -e

echo "╔═══════════════════════════════════════════════╗"
echo "║  Witness Federation Setup (3 Networks)       ║"
echo "╚═══════════════════════════════════════════════╝"
echo

# Build binaries first
echo "Building binaries..."
cargo build --release -p witness-node -p witness-gateway

echo
echo "Generating keys for 3 networks × 3 witnesses each..."
echo

# Generate keys for each network
for net in a b c; do
    echo "=== Network $net ==="

    for i in 1 2 3; do
        echo "  Witness $net-$i"

        OUTPUT=$(cargo run --release -p witness-node -- --generate-key 2>&1)
        PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | awk '{print $3}')
        PRIVKEY=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')

        # Store keys
        eval "NET_${net^^}_W${i}_PUBKEY=$PUBKEY"
        eval "NET_${net^^}_W${i}_PRIVKEY=$PRIVKEY"
        eval "NET_${net^^}_W${i}_PORT=$((8000 + ($(printf '%d' "'$net") - 97) * 10 + i))"

        # Create witness config
        PORT=$((8000 + ($(printf '%d' "'$net") - 97) * 10 + i))
        cat > "examples/federation/witness-$net-$i.json" <<EOF
{
  "id": "witness-$net-$i",
  "private_key": "$PRIVKEY",
  "port": $PORT,
  "network_id": "network-$net",
  "max_clock_skew": 300
}
EOF
    done
    echo
done

# Create network configurations with federation
echo "Creating network configurations with federation..."
echo

# Network A (port 9001)
cat > "examples/federation/network-a.json" <<EOF
{
  "id": "network-a",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-a-1",
      "pubkey": "$NET_A_W1_PUBKEY",
      "endpoint": "http://localhost:$NET_A_W1_PORT"
    },
    {
      "id": "witness-a-2",
      "pubkey": "$NET_A_W2_PUBKEY",
      "endpoint": "http://localhost:$NET_A_W2_PORT"
    },
    {
      "id": "witness-a-3",
      "pubkey": "$NET_A_W3_PUBKEY",
      "endpoint": "http://localhost:$NET_A_W3_PORT"
    }
  ],
  "federation": {
    "enabled": true,
    "batch_period": 60,
    "peer_networks": [
      {
        "id": "network-b",
        "gateway": "http://localhost:9002",
        "min_witnesses": 2
      },
      {
        "id": "network-c",
        "gateway": "http://localhost:9003",
        "min_witnesses": 2
      }
    ],
    "cross_anchor_threshold": 2
  }
}
EOF

# Network B (port 9002)
cat > "examples/federation/network-b.json" <<EOF
{
  "id": "network-b",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-b-1",
      "pubkey": "$NET_B_W1_PUBKEY",
      "endpoint": "http://localhost:$NET_B_W1_PORT"
    },
    {
      "id": "witness-b-2",
      "pubkey": "$NET_B_W2_PUBKEY",
      "endpoint": "http://localhost:$NET_B_W2_PORT"
    },
    {
      "id": "witness-b-3",
      "pubkey": "$NET_B_W3_PUBKEY",
      "endpoint": "http://localhost:$NET_B_W3_PORT"
    }
  ],
  "federation": {
    "enabled": true,
    "batch_period": 60,
    "peer_networks": [
      {
        "id": "network-a",
        "gateway": "http://localhost:9001",
        "min_witnesses": 2
      },
      {
        "id": "network-c",
        "gateway": "http://localhost:9003",
        "min_witnesses": 2
      }
    ],
    "cross_anchor_threshold": 2
  }
}
EOF

# Network C (port 9003)
cat > "examples/federation/network-c.json" <<EOF
{
  "id": "network-c",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-c-1",
      "pubkey": "$NET_C_W1_PUBKEY",
      "endpoint": "http://localhost:$NET_C_W1_PORT"
    },
    {
      "id": "witness-c-2",
      "pubkey": "$NET_C_W2_PUBKEY",
      "endpoint": "http://localhost:$NET_C_W2_PORT"
    },
    {
      "id": "witness-c-3",
      "pubkey": "$NET_C_W3_PUBKEY",
      "endpoint": "http://localhost:$NET_C_W3_PORT"
    }
  ],
  "federation": {
    "enabled": true,
    "batch_period": 60,
    "peer_networks": [
      {
        "id": "network-a",
        "gateway": "http://localhost:9001",
        "min_witnesses": 2
      },
      {
        "id": "network-b",
        "gateway": "http://localhost:9002",
        "min_witnesses": 2
      }
    ],
    "cross_anchor_threshold": 2
  }
}
EOF

echo "✓ Federation setup complete!"
echo
echo "Configuration created:"
echo "  - 3 networks (A, B, C)"
echo "  - 3 witnesses per network (9 total)"
echo "  - Threshold: 2 of 3 witnesses per network"
echo "  - Batch period: 60 seconds"
echo "  - Cross-anchor threshold: 2 peer networks"
echo
echo "Ports:"
echo "  Network A: Gateway 9001, Witnesses 8001-8003"
echo "  Network B: Gateway 9002, Witnesses 8011-8013"
echo "  Network C: Gateway 9003, Witnesses 8021-8023"
echo
echo "Next: Run './examples/federation/start.sh' to start all networks"
