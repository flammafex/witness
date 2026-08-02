# configs/server/

## Responsibility

Holds `nginx.conf`, the templated nginx reverse-proxy configuration for a production Witness deployment. Its job is twofold: terminate TLS for the gateway and witness nodes, and enforce **per-route IP allowlists** so that write/signing/federation routes are reachable only from trusted sources. This is the network-level access control layer for the whole stack; the app-layer default is `CorsLayer::permissive()` (see `crates/witness-gateway/src/server/mod.rs` lines 264/502/531), so nginx is what actually gates who can talk to what.

## Design

### Placeholders (substituted before deploy)

| Placeholder | Meaning |
|---|---|
| `{{SERVER_NAME}}` | Public domain, e.g. `witness1.example.org` (used for `server_name` and Let's Encrypt paths) |
| `{{ADMIN_IP}}` | Operator/admin source IP |
| `{{INTERNAL_CIDR}}` | Internal network CIDR (e.g. `10.0.0.0/8`) |
| `{{CLIENT_IP}}` | Trusted client IP |
| `{{PEER_GATEWAY_1}}` / `{{PEER_GATEWAY_2}}` | Peer gateway IPs for federation/signing |

### Upstreams

- `gateway_backend` → `127.0.0.1:8080`
- `witness_a1` → `127.0.0.1:3001`, `witness_b3` → `127.0.0.1:3002`, `witness_c2` → `127.0.0.1:3003`

TLS: port 80 redirects to HTTPS; port 443 uses TLS 1.2/1.3 with a restrained ECDHE cipher set.

## Flow — route inventory and allowlists

### Gateway endpoints

| Route | Match | Access | Notes |
|---|---|---|---|
| `/health` | exact | **public** | |
| `/metrics` | exact | `{{ADMIN_IP}}` only | |
| `/admin` | prefix | `{{ADMIN_IP}}`, `{{INTERNAL_CIDR}}` | admin panel |
| `/v1/config` | exact | **public** | client discovery of witnesses/threshold |
| `/v1/verify` | exact | **public** | read-only verification |
| `/v1/federation/anchor` | exact | `127.0.0.1`, `{{PEER_GATEWAY_1}}`, `{{PEER_GATEWAY_2}}` | gateway↔gateway cross-anchoring |
| `/v1/anchors/{hex-hash}` | regex | **public** | external anchor lookup |
| `/v1/proof/{hex-hash}` | regex | **public** | light-client proof |
| `/ws/events` | exact | `{{ADMIN_IP}}`, `{{CLIENT_IP}}` | WebSocket; sets `Upgrade`/`Connection` headers, `proxy_read_timeout 86400` |
| `/v1/` (catch-all) | prefix | `{{ADMIN_IP}}`, `{{CLIENT_IP}}` | unknown v1 routes default to trusted clients |
| `/` (catch-all) | prefix | `{{ADMIN_IP}}` only | everything else |

### Witness endpoints (three witness upstreams, same pattern each)

| Route | Access | Notes |
|---|---|---|
| `/witness-{a1,b3,c2}/health` | **public** | |
| `/witness-{a1,b3,c2}/v1/info` | **public** | public key discovery |
| `/witness-{a1,b3,c2}/v1/sign` | `127.0.0.1`, `{{PEER_GATEWAY_1}}`, `{{PEER_GATEWAY_2}}` only | threshold-signing call — **gateway peers only** |

All proxied routes forward `Host` and `X-Real-IP`; restricted gateway routes additionally forward `X-Forwarded-For`/`X-Forwarded-Proto`.

### Security posture

- Every `location` that is not explicitly public ends in `deny all;` — default-deny per route.
- `/v1/sign` and `/v1/federation/anchor` are the crown jewels (they trigger signing / cross-anchoring) and are restricted to localhost + declared peers, on top of the bearer-token checks inside `witness-node` / `witness-gateway`.
- Note the asymmetry: gateway **read** paths are public (good — anyone should verify), while gateway **write** paths (the `/v1/` catch-all that covers `POST /v1/attestations`, plus `/ws/events`) and all witness **sign** paths are gated.

## Integration

- Reverse-proxies `crates/witness-gateway` (the `gateway_backend` upstream) and `crates/witness-node` (three witness upstreams).
- Route paths must match handlers in `crates/witness-gateway/src/server/routes.rs`; the nginx allowlist model is the compensating control for the `CorsLayer::permissive()` default in that server.
- `/ws/events` supports the live event ticker consumed by `landing/index.html` (`wss://gateway.metacan.org/ws/events`).
- Consumed as a deployment template by operators (substitute placeholders, point Let's Encrypt paths at the real domain); it is the bare-metal/VM counterpart to the Docker networking in `docker-compose.yaml`.
