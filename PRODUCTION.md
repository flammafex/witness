# Production Deployment Guide

This guide covers running the Witness Gateway in production. It assumes you have already generated witness keys and written a `network.json` configuration file.

---

## 1. Prerequisites

### Rust Toolchain

The gateway is built with Rust. Install Rust 1.70 or later via rustup:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version
```

Build dependencies on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y pkg-config libssl-dev clang
```

### SQLite

The gateway uses SQLite 3 for persistence. Most Linux distributions ship it by default. Verify with:

```bash
sqlite3 --version
```

### Reverse Proxy (Recommended)

Run the gateway behind nginx, Traefik, or a cloud load balancer for TLS termination, rate limiting, and static asset serving. The gateway binds to localhost by default and does not terminate TLS itself.

### systemd (Linux Bare Metal)

If you are running on a Linux server without containers, use systemd to manage the service.

---

## 2. Build

Build the release binary from the workspace root:

```bash
cargo build --release -p witness-gateway
```

The binary appears at:

```
target/release/witness-gateway
```

Copy it to your deployment host:

```bash
scp target/release/witness-gateway witness@prod-server:/usr/local/bin/
```

The release profile enables `opt-level = 3`, full LTO, and a single codegen unit for the smallest, fastest binary.

---

## 3. Configuration

Configuration comes from two sources: a `network.json` file and environment variables.

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `network.json` | Path to network configuration file |
| `--host` | `127.0.0.1` | Interface to bind to |
| `--port` | `8080` | HTTP port to listen on |
| `--database` | `gateway.db` | Path to SQLite database file |
| `--admin-ui` | `false` | Enable the admin dashboard at `/admin` |
| `--admin-api-key` | (env) | API key for admin access |
| `--ws-auth-token` | (env) | Token required for WebSocket connections |
| `--metrics-token` | (env) | Bearer token required for `/metrics` |
| `--behind-proxy` | `false` | Trust `X-Forwarded-For` for real client IP |

### Environment Variables

#### Core

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | No | SQLite connection string. The gateway builds this automatically from `--database`, but you can override it if you need custom SQLite pragmas. |
| `RUST_LOG` | No | Tracing filter. Default: `witness_gateway=info,tower_http=info`. Use `debug` for troubleshooting. |

#### Admin & Monitoring

| Variable | Required | Description |
|----------|----------|-------------|
| `WITNESS_ADMIN_API_KEY` | Only if `--admin-ui` is set | Secret key for the admin dashboard. Passed via `--admin-api-key` or this env var. |
| `WITNESS_WS_AUTH_TOKEN` | No | If set, WebSocket clients must authenticate with this token before receiving events. |
| `WITNESS_METRICS_TOKEN` | No | If set, the `/metrics` endpoint requires `Authorization: Bearer <token>`. |
| `WITNESS_BEHIND_PROXY` | No | Set to `true` when running behind a reverse proxy so the gateway reads `X-Forwarded-For` instead of the connection IP. |

#### Freebird (Anonymous Rate Limiting)

| Variable | Required | Description |
|----------|----------|-------------|
| `FREEBIRD_VERIFIER_URL` | No | URL of the Freebird verifier service. If unset, Freebird is disabled. |
| `FREEBIRD_REQUIRED` | No | Set to `true` or `1` to reject timestamp requests that lack a valid Freebird token. Default: `false`. |
| `FREEBIRD_CONSUME_TOKENS` | No | Set to `false` to use non-consuming `/v1/check` mode. Default: `true` (consuming `/v1/verify`). Only use `false` for explicit proof-of-possession flows with strict rate limiting. |
| `FREEBIRD_ALLOW_INSECURE_LOCAL` | No | Local development only. Set to `true` only for plaintext loopback verifier smoke tests. Never enable for public deployments. |

### network.json

The `network.json` file defines your witness set, threshold, federation peers, and external anchor providers. A minimal example:

```json
{
  "id": "my-network",
  "threshold": 2,
  "signature_scheme": "Ed25519",
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "...",
      "endpoint": "https://witness-1.example.com:3000",
      "auth_token": "<random-secret>"
    },
    {
      "id": "witness-2",
      "pubkey": "...",
      "endpoint": "https://witness-2.example.com:3000",
      "auth_token": "<random-secret>"
    }
  ],
  "federation": {
    "enabled": false,
    "peers": []
  },
  "external_anchors": {
    "enabled": false,
    "providers": []
  }
}
```

**Security note:** Every witness must have a non-empty `auth_token`. The gateway validates this at startup and aborts if any witness is missing one.

---

## 4. Database Setup

The gateway uses sqlx with embedded migrations. On first startup it creates the SQLite database and runs all pending migrations automatically.

### Migration Behavior

Migrations live in `crates/witness-gateway/migrations/` and are compiled into the binary. The gateway runs them in order on startup via `storage.migrate()`. You do not need to run any external migration tool.

### SQLite Settings

The connection is configured with:

- **Journal mode:** WAL (Write-Ahead Logging)
- **Synchronous:** NORMAL
- **Max connections:** 5

These settings are hardcoded for durability and concurrency. Do not place the database on a network filesystem. SQLite requires local disk access.

### Database Location

Use a persistent directory, not `/tmp`:

```bash
mkdir -p /var/lib/witness
chown witness:witness /var/lib/witness
```

Then start the gateway with:

```bash
witness-gateway --database /var/lib/witness/gateway.db
```

---

## 5. TLS Termination

The gateway speaks plain HTTP. Terminate TLS at the edge with nginx, Traefik, or a cloud load balancer (AWS ALB, GCP LB, Cloudflare).

### nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name gateway.example.com;

    ssl_certificate /etc/letsencrypt/live/gateway.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/gateway.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts tuned for threshold-signature latency (50-200ms)
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }
}
```

### Important: Set `--behind-proxy`

When running behind a reverse proxy, start the gateway with `--behind-proxy` (or `WITNESS_BEHIND_PROXY=true`). This tells the gateway to read `X-Forwarded-For` instead of the direct connection IP for rate limiting and logging. Without this, all clients appear as the proxy's IP.

---

## 6. Running as a Service

### systemd Unit File

Create `/etc/systemd/system/witness-gateway.service`:

```ini
[Unit]
Description=Witness Gateway
After=network.target

[Service]
Type=simple
User=witness
Group=witness
WorkingDirectory=/var/lib/witness

Environment="RUST_LOG=witness_gateway=info,tower_http=info"
Environment="WITNESS_BEHIND_PROXY=true"
Environment="WITNESS_ADMIN_API_KEY=<replace-with-random-secret>"
Environment="WITNESS_METRICS_TOKEN=<replace-with-random-secret>"

# Freebird (optional but recommended for public gateways)
# Environment="FREEBIRD_VERIFIER_URL=https://freebird.example.com"
# Environment="FREEBIRD_REQUIRED=true"
# Environment="FREEBIRD_CONSUME_TOKENS=true"

ExecStart=/usr/local/bin/witness-gateway \
    --config /etc/witness/network.json \
    --host 127.0.0.1 \
    --port 8080 \
    --database /var/lib/witness/gateway.db \
    --admin-ui

# Graceful shutdown on restart/upgrade
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/witness
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable witness-gateway
sudo systemctl start witness-gateway
sudo systemctl status witness-gateway
```

View logs:

```bash
sudo journalctl -u witness-gateway -f
```

---

## 7. Docker

### Dockerfile

A multi-stage Dockerfile is included in the repository root. It builds the workspace and produces two targets: `witness-node` and `witness-gateway`.

Build the gateway image:

```bash
docker build --target witness-gateway -t witness-gateway:latest .
```

Run:

```bash
docker run -d \
  --name witness-gateway \
  -p 8080:8080 \
  -v /opt/witness/network.json:/data/network.json:ro \
  -v /opt/witness/data:/data \
  -e RUST_LOG=witness_gateway=info \
  -e WITNESS_BEHIND_PROXY=true \
  witness-gateway:latest \
  witness-gateway \
    --config /data/network.json \
    --host 0.0.0.0 \
    --port 8080 \
    --database /data/gateway.db
```

### docker compose

For a full network (gateway + witnesses), use the provided `docker-compose.yaml`:

```bash
# Create environment file
cat > .env <<EOF
RUST_LOG=info,witness_gateway=debug
WITNESS_BEHIND_PROXY=true
EOF

docker compose up -d
```

The compose file mounts two volumes:

- `witness-config`: shared `network.json` and witness configs
- `gateway-data`: persistent SQLite database

---

## 8. Monitoring

### Prometheus Metrics

The gateway exposes metrics at `/metrics`. If `WITNESS_METRICS_TOKEN` is set, access requires:

```bash
curl -H "Authorization: Bearer <token>" https://gateway.example.com/metrics
```

Without a token, metrics are publicly readable. Protect this endpoint at the reverse proxy if you do not configure a token.

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `witness_attestations_total` | Counter | Total attestations created |
| `witness_signatures_collected` | Counter | Signatures collected per witness |
| `witness_batches_total` | Counter | Total batches closed |
| `witness_external_anchors_total` | Counter | External anchors per provider |
| `witness_attestations_24h` | Gauge | Attestations in the last 24 hours |
| `witness_witness_health` | Gauge | Health status per witness (1 = healthy, 0 = unhealthy) |
| `witness_uptime_seconds` | Gauge | Process uptime in seconds |
| `witness_request_duration_seconds` | Histogram | Request latency per endpoint |

### Health Check

Use `/health` for load balancer health checks:

```bash
curl -f http://gateway.example.com/health
# {"status":"ok"}
```

### Log Levels

Adjust verbosity with `RUST_LOG`:

```bash
# Debug during an incident
RUST_LOG=witness_gateway=debug,tower_http=debug

# Quiet production logging
RUST_LOG=witness_gateway=warn
```

---

## 9. Backup

### SQLite Backup Strategy

The gateway stores all attestations, batches, and anchor proofs in a single SQLite file. Back it up regularly.

#### Online Backup (Recommended)

SQLite supports online backups via the backup API. The gateway uses WAL mode, so you can copy the file safely while the process is running:

```bash
sqlite3 /var/lib/witness/gateway.db ".backup '/backups/gateway-$(date +%Y%m%d-%H%M%S).db'"
```

Or use the `.backup` command inside the sqlite3 CLI for a consistent snapshot.

#### Automated Cron Job

```bash
# /etc/cron.d/witness-backup
0 */6 * * * witness sqlite3 /var/lib/witness/gateway.db ".backup '/backups/gateway-latest.db'" && cp /backups/gateway-latest.db /backups/gateway-$(date +\%Y\%m\%d-\%H\%M\%S).db
```

#### Restore

Stop the gateway, replace the database, and restart:

```bash
sudo systemctl stop witness-gateway
cp /backups/gateway-latest.db /var/lib/witness/gateway.db
sudo systemctl start witness-gateway
```

The gateway runs migrations on startup, so restored databases from older versions will be upgraded automatically.

---

## 10. Upgrades

### Rolling Upgrade Procedure

The gateway supports graceful shutdown on `SIGTERM` and `SIGINT`. In-flight requests are allowed to complete before the process exits.

1. **Prepare the new binary**

   ```bash
   cargo build --release -p witness-gateway
   scp target/release/witness-gateway prod-server:/tmp/witness-gateway-new
   ```

2. **Run database migrations (dry run)**

   Migrations run automatically on startup, but you can verify them first by starting the new binary on a copy of the database in a staging environment.

3. **Deploy with minimal downtime**

   ```bash
   # On the production host
   sudo cp /tmp/witness-gateway-new /usr/local/bin/witness-gateway
   sudo systemctl restart witness-gateway
   ```

   systemd sends `SIGTERM`, the gateway drains in-flight requests (up to the systemd `TimeoutStopSec`), then the new binary starts and applies any pending migrations.

4. **Verify**

   ```bash
   sudo systemctl status witness-gateway
   curl -f https://gateway.example.com/health
   ```

### Migration Safety

Migrations are forward-only. The gateway uses `sqlx::migrate!` with compiled-in migration files. Downgrades require restoring from backup.

If you need to rollback:

1. Stop the gateway.
2. Restore the database from a pre-upgrade backup.
3. Deploy the previous binary version.
4. Start the gateway.

### Witness Key Rotation

If you rotate witness keys, update `network.json` and restart the gateway. It reads the config file at startup. Witness health metrics will show unhealthy endpoints until the new witnesses come online.

---

## Security Checklist

- [ ] Gateway binds to `127.0.0.1` (or container-internal interface), not `0.0.0.0`, unless required by your network layout
- [ ] TLS is terminated at the reverse proxy or load balancer
- [ ] `WITNESS_BEHIND_PROXY=true` is set when running behind a proxy
- [ ] Admin API key is a long random string (use `openssl rand -hex 32`)
- [ ] Metrics token is configured or `/metrics` is blocked at the proxy
- [ ] Freebird is enabled for public-facing gateways (`FREEBIRD_REQUIRED=true`)
- [ ] Witness auth tokens are non-empty and rotated regularly
- [ ] Database directory is backed up every 6 hours
- [ ] systemd hardening options (`ProtectSystem`, `NoNewPrivileges`) are enabled
- [ ] Outbound requests are restricted by the built-in SSRF filter (blocks loopback, RFC-1918, and link-local addresses)

## Troubleshooting

**Startup fails with "witness is missing auth_token"**

Every entry in `network.json`'s `witnesses` array needs a non-empty `auth_token` field.

**Database is locked**

Do not run multiple gateway processes against the same SQLite file. Use a single instance or switch to a single writer with read replicas if you need horizontal scaling.

**High latency on timestamp requests**

Check witness health metrics. A slow or unreachable witness will block the threshold signature collection. The gateway stops collecting once the threshold is reached, but slow witnesses can add tail latency.

**Freebird verification fails**

Verify `FREEBIRD_VERIFIER_URL` is reachable from the gateway host. Witness sends the current Freebird verifier request shape, `{ "token_b64": "..." }`, to `/v1/verify` in consuming mode and `/v1/check` in non-consuming mode. The gateway's HTTP client rejects private IP ranges to prevent SSRF, so the verifier must be on a public routable address or you must adjust the network topology accordingly.
