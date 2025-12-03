# ==============================================================================
# Stage 1: Builder
# ==============================================================================
FROM rust:1.91 as builder

WORKDIR /app

# Install build dependencies
# libssl-dev is required for crypto compilation
# clang/llvm might be required for 'blst' (BLS signatures) depending on the crate version
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire workspace
COPY . .

# Build all binaries in release mode
RUN cargo build --release

# ==============================================================================
# Stage 2: Witness Node Runtime
# ==============================================================================
FROM debian:bookworm-slim as witness-node

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r witness && useradd -r -g witness witness

# Create directory for config/keys
RUN mkdir -p /data && chown -R witness:witness /data

# Copy binary from builder
COPY --from=builder /app/target/release/witness-node /usr/local/bin/witness-node

# Set environment defaults
ENV RUST_LOG=info

# Switch to non-root user
USER witness
VOLUME ["/data"]
EXPOSE 3000

# Expects a config file to be mounted or generated at /data/node-config.json
CMD ["witness-node", "--config", "/data/node-config.json"]

# ==============================================================================
# Stage 3: Witness Gateway Runtime
# ==============================================================================
FROM debian:bookworm-slim as witness-gateway

WORKDIR /app

# Install runtime dependencies (sqlite3 lib might be needed if dynamically linked)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    sqlite3 \
    gosu \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r witness && useradd -r -g witness witness

# Create directory for database and config
RUN mkdir -p /data && chown -R witness:witness /data

# Copy binaries from builder
COPY --from=builder /app/target/release/witness-gateway /usr/local/bin/witness-gateway
COPY --from=builder /app/target/release/witness /usr/local/bin/witness

# Copy entrypoint script
COPY docker-entrypoint-gateway.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-gateway.sh

# Set environment defaults
ENV RUST_LOG=info

VOLUME ["/data"]
EXPOSE 8080

# Use entrypoint to fix permissions before running as witness user
ENTRYPOINT ["/usr/local/bin/docker-entrypoint-gateway.sh"]

# Default command points to data volume
CMD ["witness-gateway", "--config", "/data/network.json", "--database", "/data/gateway.db"]