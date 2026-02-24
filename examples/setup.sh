#!/bin/bash

# Setup script for Witness example network
# This creates a 3-witness network with threshold=2

set -e

echo "Setting up Witness example network..."
echo

# Build the binaries first
echo "Building witness-node..."
cargo build --release -p witness-node

echo "Generating keypairs for 3 witnesses..."
echo

# Generate 3 keypairs
for i in 1 2 3; do
    echo "=== Witness $i ==="

    # Generate keypair
    OUTPUT=$(cargo run --release -p witness-node -- --generate-key 2>&1)

    PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | awk '{print $3}')
    PRIVKEY=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')
    AUTH_TOKEN=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')

    echo "Public key:  $PUBKEY"
    echo "Private key: $PRIVKEY"
    echo

    # Create witness config
    cat > "examples/witness$i.json" <<EOF
{
  "id": "witness-$i",
  "private_key": "$PRIVKEY",
  "port": $((3000 + i)),
  "host": "127.0.0.1",
  "network_id": "example-network",
  "max_clock_skew": 300,
  "signing_auth_token": "$AUTH_TOKEN"
}
EOF

    # Store for network config
    eval "WITNESS${i}_PUBKEY=$PUBKEY"
    eval "WITNESS${i}_PORT=$((3000 + i))"
    eval "WITNESS${i}_AUTH_TOKEN=$AUTH_TOKEN"
done

echo "Creating network configuration..."

# Create network config
cat > "examples/network.json" <<EOF
{
  "id": "example-network",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "$WITNESS1_PUBKEY",
      "endpoint": "http://localhost:$WITNESS1_PORT",
      "auth_token": "$WITNESS1_AUTH_TOKEN"
    },
    {
      "id": "witness-2",
      "pubkey": "$WITNESS2_PUBKEY",
      "endpoint": "http://localhost:$WITNESS2_PORT",
      "auth_token": "$WITNESS2_AUTH_TOKEN"
    },
    {
      "id": "witness-3",
      "pubkey": "$WITNESS3_PUBKEY",
      "endpoint": "http://localhost:$WITNESS3_PORT",
      "auth_token": "$WITNESS3_AUTH_TOKEN"
    }
  ],
  "federation_peers": []
}
EOF

echo "✓ Configuration files created:"
echo "  - examples/witness1.json"
echo "  - examples/witness2.json"
echo "  - examples/witness3.json"
echo "  - examples/network.json"
echo
echo "Run './examples/start.sh' to start the network"
