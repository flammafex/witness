# configs/

## Responsibility

Deployment and operational configuration for a production Witness deployment. This folder holds the only checked-in runtime config artifact — `server/nginx.conf`, a templated reverse-proxy config that fronts the gateway and witness nodes with per-route IP allowlists — and thematically is the home for the root-level container/Compose deployment assets (`Dockerfile`, `docker-compose.yaml`, `docker-compose.build.yaml`, `docker-entrypoint-gateway.sh`). Network-level access control is enforced *here* (nginx `allow`/`deny`), because the application layer itself is not the security boundary: see the `CorsLayer::permissive()` note below.

## Design

### `server/nginx.conf` — TLS-terminating reverse proxy with per-route IP allowlists

A single templated nginx server block (see `configs/server/codemap.md` for the full route/allowlist inventory). Placeholders `{{SERVER_NAME}}`, `{{ADMIN_IP}}`, `{{INTERNAL_CIDR}}`, `{{CLIENT_IP}}`, `{{PEER_GATEWAY_1}}`, `{{PEER_GATEWAY_2}}` are substituted at deploy time. Upstreams are all localhost: `gateway_backend` (`127.0.0.1:8080`) plus three named witnesses `witness_a1`/`witness_b3`/`witness_c2` (`127.0.0.1:3001/3002/3003`).

The allowlist model is *route-by-route* (not one blanket rule), split into tiers:
- **Public read-only**: `/health`, `/v1/config`, `GET /v1/timestamp/{hash}`, `/v1/verify`, `/v1/anchors/{hash}`, `/v1/proof/{hash}`, witness `/health` and `/v1/info` (needed for public key discovery).
- **Admin-only**: `/metrics` (`{{ADMIN_IP}}`); `/admin` (`{{ADMIN_IP}}` + `{{INTERNAL_CIDR}}`); catch-all `/` (`{{ADMIN_IP}}`).
- **Trusted clients**: `POST /v1/timestamp`, `/ws/events`, and the `/v1/` prefix catch-all (`{{ADMIN_IP}}` + `{{CLIENT_IP}}`).
- **Gateway peers only**: `/v1/federation/anchor` and each witness `/v1/sign` (`127.0.0.1` + the two `{{PEER_GATEWAY_*}}` IPs).

**CorsLayer::permissive() context:** the gateway's axum router applies `tower_http::cors::CorsLayer::permissive()` (`crates/witness-gateway/src/server.rs` lines 383, 1287, 1316), so any origin can issue browser requests at the HTTP layer. This is called out in AGENTS.md as a flagged item ("confirm intent before tightening"). The nginx allowlists are the compensating network-level control that keeps permissive CORS from being a hole — tightening CORS *and* the nginx allowlists together is the defense-in-depth posture.

**Operational caveat:** the `network.json` config that nginx frontends carries witness `auth_token`s in plaintext; nginx's IP restrictions for `/v1/sign` and `/v1/federation/anchor` are what protect those routes at the edge (plus the bearer-token checks in the binaries).

### Root deployment files (covered here thematically)

- **`Dockerfile`** — three-stage build:
  - *Builder*: `rust:1.91` (pins the toolchain), `apt` installs `pkg-config` + `clang` (for `blst`/BLS), copies the whole workspace, then `cargo build --release`. Critically it sets `CARGO_PROFILE_RELEASE_LTO=off` and `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16` to reduce build memory/time in containers — this **overrides** the root `[profile.release]` (`opt-level = 3`, `lto = true`, `codegen-units = 1`, see root `Cargo.toml`), so Docker artifacts are not the same as locally-built release binaries.
  - *`witness-node` runtime*: `debian:bookworm-slim`, non-root `witness` user, `/data` volume, `EXPOSE 3000`, default `CMD` `witness-node --config /data/node-config.json`.
  - *`witness-gateway` runtime*: additionally copies the `witness` CLI and `witness-auditor` binaries, installs `sqlite3` + `gosu`, uses `docker-entrypoint-gateway.sh` as `ENTRYPOINT`, `EXPOSE 8080`, default `CMD` `witness-gateway --config /data/network.json --database /data/gateway.db`.
- **`docker-compose.yaml`** — pulls prebuilt images from the Forgejo registry (`git.carpocratian.org/sibyl/witness-node:latest`, `witness-gateway:latest`). An ephemeral `setup` service runs once (guarded by `if [ -f /data/network.json ]`) to generate 3 witness keypairs, auth tokens, and `network.json` (threshold 2, network `docker-net`) into the shared `witness-config` volume; then `witness-1..3` (port 3000, healthcheck on `/health`) and `gateway` (publishes `8080:8080`, config from `witness-config`, sqlite db on the persistent `gateway-data` volume, optional `.env`). Single `witness-net` bridge network.
- **`docker-compose.build.yaml`** — Compose override to build locally instead of pulling: maps each service to the matching Dockerfile stage (`target: witness-node` / `target: witness-gateway`). Used as `docker compose -f docker-compose.yaml -f docker-compose.build.yaml up --build`.
- **`docker-entrypoint-gateway.sh`** — permission-fixing entrypoint. If started as root (Docker volume mount default), it `mkdir -p /data`, `chown witness:witness /data`, makes `/config` world-readable, then `exec gosu witness "$@"` to drop privileges; if already the `witness` user it execs directly.

## Flow

1. Operator deploys `configs/server/nginx.conf` with placeholders substituted (TLS certs from Let's Encrypt paths), or brings up the container stack via `docker compose` (ephemeral `setup` → witnesses → gateway).
2. Client TLS terminates at nginx. Requests are matched to a route's `allow`/`deny` list; if the source IP passes, the request is reverse-proxied to `gateway_backend` (public API) or the named witness upstream.
3. `/v1/timestamp` (create) and `/ws/events` pass only for allowlisted clients; `/v1/sign` (gateway→witness threshold signing) and `/v1/federation/anchor` (gateway↔gateway cross-anchoring) pass only from peer IPs. Bearer-token checks in the binaries remain the second layer.
4. In the Docker path, the entrypoint fixes volume permissions, drops to the non-root `witness` user, and the gateway persists attestations to the SQLite volume.

## Integration

- `configs/server/nginx.conf` → reverse-proxies `crates/witness-gateway` (ports 8080 + API routes) and `crates/witness-node` (ports 3001–3003, sign/info routes). Route paths must stay in sync with `crates/witness-gateway/src/server.rs` handlers.
- `configs/server/nginx.conf` routes mirror the gateway API surface documented for clients (config/timestamp/verify/anchors/proof) and must match the allowlist model enforced at the edge.
- `Dockerfile` + `docker-compose*.yaml` → build/run the same `witness-node` and `witness-gateway` binaries; compose `setup` mirrors what `examples/setup.sh` does on bare metal.
- Workspace release profile (`Cargo.toml [profile.release]`) is referenced by `Dockerfile` builds (which deliberately override LTO/codegen-units).
- Nginx `/ws/events` route pairs with the live landing page ticker (`landing/index.html`), which connects to `wss://gateway.metacan.org/ws/events`.
