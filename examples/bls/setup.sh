#!/bin/bash
# Setup script for BLS witness network example
# This demonstrates BLS signature aggregation (3 signatures -> 1)

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BLS_DIR="$PROJECT_ROOT/examples/bls"

echo "Setting up BLS witness network with 3 witnesses..."
echo "This will demonstrate BLS signature aggregation"
echo

# Build the binaries
echo "Building witness-node and witness-gateway..."
cd "$PROJECT_ROOT"
cargo build --release --bin witness-node --bin witness-gateway 2>/dev/null
echo "✓ Binaries built"
echo

# Clean up any existing configs
rm -rf "$BLS_DIR/witness-"* "$BLS_DIR/gateway"* "$BLS_DIR/network.json"

# Generate BLS keys for 3 witnesses
echo "Generating BLS keypairs for 3 witnesses..."
for i in 1 2 3; do
    echo "  Generating witness-$i..."
    OUTPUT=$("$PROJECT_ROOT/target/release/witness-node" --generate-key --bls)

    PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | awk '{print $3}')
    PRIVKEY=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')

    # Create witness config
    cat > "$BLS_DIR/witness-$i.json" <<EOF
{
  "id": "witness-$i",
  "signature_scheme": "bls",
  "private_key": "$PRIVKEY",
  "network_id": "bls-network",
  "port": $((8000 + i)),
  "max_clock_skew": 300
}
EOF

    echo "    ✓ witness-$i: ${PUBKEY:0:16}..."
done

echo

# Create network config with BLS scheme
echo "Creating network configuration..."

# Read public keys from witness configs
PUBKEY1=$(jq -r '.id as $id | "witness-node --config examples/bls/witness-1.json" | @sh' "$BLS_DIR/witness-1.json" 2>/dev/null | xargs -I {} sh -c "{} 2>&1 | grep 'Public key:' || echo ''") || true
PUBKEY2=$(jq -r '.id as $id | "witness-node --config examples/bls/witness-2.json" | @sh' "$BLS_DIR/witness-2.json" 2>/dev/null | xargs -I {} sh -c "{} 2>&1 | grep 'Public key:' || echo ''") || true
PUBKEY3=$(jq -r '.id as $id | "witness-node --config examples/bls/witness-3.json" | @sh' "$BLS_DIR/witness-3.json" 2>/dev/null | xargs -I {} sh -c "{} 2>&1 | grep 'Public key:' || echo ''") || true

# Extract public keys from the generated configs directly
PUBKEY1=$("$PROJECT_ROOT/target/release/witness-node" --config "$BLS_DIR/witness-1.json" 2>&1 | grep "Public key:" | awk '{print $3}' || echo "")
PUBKEY2=$("$PROJECT_ROOT/target/release/witness-node" --config "$BLS_DIR/witness-2.json" 2>&1 | grep "Public key:" | awk '{print $3}' || echo "")
PUBKEY3=$("$PROJECT_ROOT/target/release/witness-node" --config "$BLS_DIR/witness-3.json" 2>&1 | grep "Public key:" | awk '{print $3}' || echo "")

# Fallback: extract from private keys if the above doesn't work
if [ -z "$PUBKEY1" ]; then
    echo "Warning: Could not auto-detect public keys. Generating fresh..."
    for i in 1 2 3; do
        OUTPUT=$("$PROJECT_ROOT/target/release/witness-node" --generate-key --bls)
        PUBKEY=$(echo "$OUTPUT" | grep "Public key:" | awk '{print $3}')
        PRIVKEY=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')

        # Update witness config
        jq --arg pk "$PRIVKEY" '.private_key = $pk' "$BLS_DIR/witness-$i.json" > "$BLS_DIR/witness-$i.json.tmp"
        mv "$BLS_DIR/witness-$i.json.tmp" "$BLS_DIR/witness-$i.json"

        eval "PUBKEY$i=$PUBKEY"
    done
fi

cat > "$BLS_DIR/network.json" <<EOF
{
  "id": "bls-network",
  "signature_scheme": "bls",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "$PUBKEY1",
      "endpoint": "http://localhost:8001"
    },
    {
      "id": "witness-2",
      "pubkey": "$PUBKEY2",
      "endpoint": "http://localhost:8002"
    },
    {
      "id": "witness-3",
      "pubkey": "$PUBKEY3",
      "endpoint": "http://localhost:8003"
    }
  ]
}
EOF

echo "✓ Network configuration created"
echo

# Create gateway config
cat > "$BLS_DIR/gateway.json" <<EOF
{
  "network_config": "examples/bls/network.json",
  "database_url": "sqlite:$BLS_DIR/gateway.db",
  "port": 9000
}
EOF

echo "✓ Gateway configuration created"
echo

echo "=========================================="
echo "BLS Network Setup Complete!"
echo "=========================================="
echo
echo "Network: bls-network (BLS signatures)"
echo "Threshold: 2 of 3 witnesses"
echo
echo "Witnesses:"
echo "  witness-1: http://localhost:8001"
echo "  witness-2: http://localhost:8002"
echo "  witness-3: http://localhost:8003"
echo
echo "Gateway: http://localhost:9000"
echo
echo "Next steps:"
echo "  ./examples/bls/start.sh    - Start the network"
echo "  ./examples/bls/demo.sh     - Run BLS aggregation demo"
echo "  ./examples/bls/stop.sh     - Stop the network"
echo
