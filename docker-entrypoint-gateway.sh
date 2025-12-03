#!/bin/bash
set -e

# Fix permissions on volumes if running as root
# This is needed because Docker volumes are owned by root by default
if [ "$(id -u)" = "0" ]; then
    # Ensure the data directory exists and has correct permissions for writing
    mkdir -p /data
    chown -R witness:witness /data

    # Ensure config directory is readable by witness user
    if [ -d /config ]; then
        chmod -R a+rX /config
    fi

    # Switch to witness user and execute the command
    exec gosu witness "$@"
else
    # Already running as witness user
    exec "$@"
fi
