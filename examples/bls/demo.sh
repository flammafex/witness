#!/bin/bash
# Demo script for BLS signature aggregation

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BLS_DIR="$PROJECT_ROOT/examples/bls"
GATEWAY="http://localhost:9000"

echo "=========================================="
echo "BLS Signature Aggregation Demo"
echo "=========================================="
echo
echo "This demo shows how BLS signatures aggregate:"
echo "  • Ed25519: 3 signatures = 192 bytes (3×64)"
echo "  • BLS:     1 signature =  96 bytes (50% savings!)"
echo
read -p "Press Enter to continue..."
echo

# Create test file
echo "Step 1: Creating test file..."
echo "Hello from BLS witness network!" > "$BLS_DIR/test-file.txt"
echo "✓ Created test-file.txt"
echo

# Timestamp the file
echo "Step 2: Requesting timestamp from gateway..."
echo "  Gateway will:"
echo "    1. Request 3 individual BLS signatures from witnesses"
echo "    2. Aggregate them into 1 signature"
echo "    3. Store the aggregated signature"
echo

OUTPUT=$("$PROJECT_ROOT/target/release/witness" \
    --gateway "$GATEWAY" \
    timestamp \
    --file "$BLS_DIR/test-file.txt" \
    --save "$BLS_DIR/test-file.txt.attestation" \
    --output text)

echo "$OUTPUT"
echo

# Extract hash for verification
HASH=$(echo "$OUTPUT" | grep "Hash:" | awk '{print $2}')

echo "Step 3: Examining the stored attestation..."
echo

# Get the attestation and show details
ATTESTATION=$("$PROJECT_ROOT/target/release/witness" \
    --gateway "$GATEWAY" \
    get "$HASH" \
    --output json)

echo "Attestation JSON:"
echo "$ATTESTATION" | jq '.'
echo

# Parse signature info
IS_AGGREGATED=$(echo "$ATTESTATION" | jq -r '.signatures | has("Aggregated")')

if [ "$IS_AGGREGATED" = "true" ]; then
    SIGNATURE=$(echo "$ATTESTATION" | jq -r '.signatures.Aggregated.signature')
    SIGNERS=$(echo "$ATTESTATION" | jq -r '.signatures.Aggregated.signers | join(", ")')
    SIG_BYTES=$((${#SIGNATURE} / 2))

    echo "=========================================="
    echo "✓ BLS Aggregation Successful!"
    echo "=========================================="
    echo
    echo "Signature Details:"
    echo "  Type:     BLS Aggregated"
    echo "  Signers:  $SIGNERS"
    echo "  Size:     $SIG_BYTES bytes (single aggregated signature)"
    echo
    echo "Comparison:"
    echo "  Ed25519:  192 bytes (3 × 64-byte signatures)"
    echo "  BLS:      $SIG_BYTES bytes  (1 aggregated signature)"
    echo "  Savings:  $((192 - SIG_BYTES)) bytes ($(( (192 - SIG_BYTES) * 100 / 192 ))%)"
    echo
else
    echo "Warning: Expected BLS aggregated signature but got multi-sig"
    echo "Check that network is configured with signature_scheme: \"bls\""
fi

echo
echo "Step 4: Verifying the aggregated signature..."
echo

# Verify
VERIFY_OUTPUT=$("$PROJECT_ROOT/target/release/witness" \
    --gateway "$GATEWAY" \
    verify "$BLS_DIR/test-file.txt.attestation")

echo "$VERIFY_OUTPUT"
echo

echo "=========================================="
echo "Demo Complete!"
echo "=========================================="
echo
echo "Key Takeaways:"
echo "  • BLS aggregates N signatures into 1"
echo "  • 50% bandwidth savings vs Ed25519"
echo "  • Single pairing verification (faster)"
echo "  • Same security guarantees"
echo
echo "Logs available at:"
echo "  Gateway: tail -f $BLS_DIR/gateway.log"
echo "  Witness: tail -f $BLS_DIR/witness-*.log"
echo
