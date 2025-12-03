#!/bin/bash
set -e

echo "=== Docker Entrypoint Debug ==="
echo "Current user: $(id -u):$(id -g) ($(whoami))"
echo "Command to execute: $@"

# Fix permissions on volumes if running as root
# This is needed because Docker volumes are owned by root by default
if [ "$(id -u)" = "0" ]; then
    echo "Running as root, fixing permissions..."

    # Ensure the data directory exists and has correct permissions for writing
    mkdir -p /data
    echo "Before chown - /data permissions: $(ls -ld /data)"
    chown -R witness:witness /data
    echo "After chown - /data permissions: $(ls -ld /data)"

    # Ensure config directory is readable by witness user
    if [ -d /config ]; then
        chmod -R a+rX /config
        echo "/config permissions: $(ls -ld /config)"
    fi

    echo "Switching to witness user and executing: $@"
    # Switch to witness user and execute the command
    exec gosu witness "$@"
else
    echo "Already running as witness user"
    # Already running as witness user
    exec "$@"
fi
