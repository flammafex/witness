#!/bin/bash
# Stop BLS witness network

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BLS_DIR="$PROJECT_ROOT/examples/bls"

echo "Stopping BLS witness network..."
echo

# Stop witnesses
for i in 1 2 3; do
    if [ -f "$BLS_DIR/witness-$i.pid" ]; then
        PID=$(cat "$BLS_DIR/witness-$i.pid")
        if ps -p $PID > /dev/null 2>&1; then
            echo "Stopping witness-$i (PID $PID)..."
            kill $PID 2>/dev/null || kill -9 $PID 2>/dev/null
        fi
        rm -f "$BLS_DIR/witness-$i.pid"
    fi
done

# Stop gateway
if [ -f "$BLS_DIR/gateway.pid" ]; then
    PID=$(cat "$BLS_DIR/gateway.pid")
    if ps -p $PID > /dev/null 2>&1; then
        echo "Stopping gateway (PID $PID)..."
        kill $PID 2>/dev/null || kill -9 $PID 2>/dev/null
    fi
    rm -f "$BLS_DIR/gateway.pid"
fi

# Fallback: kill by name
pkill -f "witness-node.*bls/witness" 2>/dev/null || true
pkill -f "witness-gateway.*bls/network" 2>/dev/null || true

sleep 1

echo
echo "✓ BLS network stopped"
echo
