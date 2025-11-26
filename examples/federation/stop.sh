#!/bin/bash

# Stop all federated networks

echo "Stopping federation networks..."

# Stop gateways
for net in a b c; do
    if [ -f "examples/federation/gateway-$net.pid" ]; then
        PID=$(cat "examples/federation/gateway-$net.pid")
        if kill -0 $PID 2>/dev/null; then
            echo "Stopping gateway-$net (PID $PID)..."
            kill $PID
            sleep 0.5
            if kill -0 $PID 2>/dev/null; then
                kill -9 $PID 2>/dev/null
            fi
        fi
        rm -f "examples/federation/gateway-$net.pid"
    fi
done

# Stop witnesses
for net in a b c; do
    for i in 1 2 3; do
        if [ -f "examples/federation/witness-$net-$i.pid" ]; then
            PID=$(cat "examples/federation/witness-$net-$i.pid")
            if kill -0 $PID 2>/dev/null; then
                echo "Stopping witness-$net-$i (PID $PID)..."
                kill $PID
                sleep 0.2
                if kill -0 $PID 2>/dev/null; then
                    kill -9 $PID 2>/dev/null
                fi
            fi
            rm -f "examples/federation/witness-$net-$i.pid"
        fi
    done
done

# Fallback cleanup
echo "Cleaning up any remaining processes..."
pkill -f "witness-gateway.*federation" 2>/dev/null
pkill -f "witness-node.*federation" 2>/dev/null

echo "✓ Federation networks stopped"
