#!/bin/bash

# Stop the Witness network

echo "Stopping Witness network..."

# Stop gateway
if [ -f "examples/gateway.pid" ]; then
    PID=$(cat examples/gateway.pid)
    if kill -0 $PID 2>/dev/null; then
        echo "Stopping gateway (PID $PID)..."
        kill $PID
        # Wait for it to exit
        sleep 1
        # Force kill if still running
        if kill -0 $PID 2>/dev/null; then
            echo "  Force killing gateway..."
            kill -9 $PID 2>/dev/null
        fi
    fi
    rm -f examples/gateway.pid
fi

# Stop witnesses
for i in 1 2 3; do
    if [ -f "examples/witness$i.pid" ]; then
        PID=$(cat "examples/witness$i.pid")
        if kill -0 $PID 2>/dev/null; then
            echo "Stopping witness-$i (PID $PID)..."
            kill $PID
            sleep 0.5
            # Force kill if still running
            if kill -0 $PID 2>/dev/null; then
                kill -9 $PID 2>/dev/null
            fi
        fi
        rm -f "examples/witness$i.pid"
    fi
done

# Fallback: kill any remaining witness processes by name
echo "Cleaning up any remaining processes..."
pkill -f "witness-gateway" 2>/dev/null
pkill -f "witness-node" 2>/dev/null

echo "✓ Network stopped"
