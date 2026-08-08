# examples/

## Responsibility

Runnable, self-contained example Witness networks for development and demos. Every variant follows the same lifecycle — **setup** (build + generate keypairs/configs) → **start** (launch witness nodes + gateways in the background) → **demo** (drive the running network via the CLI to show behavior) → **stop** (kill by PID files with force-kill fallbacks). These scripts are the canonical way to exercise the three integration scenarios called out in AGENTS.md (threshold enforcement, witness failure, duplicate-hash handling) and to showcase feature variants: plain Ed25519 quorum signing, dual/triple independent networks, cross-network federation, and BLS signature aggregation.

## Design

All scripts assume they run from the workspace root (`PROJECT_ROOT="$(pwd)"`), use `cargo build --release` / `cargo run --release` against the `witness-node`, `witness-gateway`, and `witness-cli` binaries, and persist runtime state (`.log`, `.pid`, `.db`, generated `network.json`/`witness*.json`) inside `examples/`. `set -e` throughout. Setup scripts generate keypairs via `witness-node --generate-key`, parse `Public key:`/`Private key:` from stdout, mint per-witness random auth tokens (`od -An -N32 -tx1 /dev/urandom`), and write JSON configs. `network.json` (the same shape the gateway consumes, including plaintext `auth_token`s) is the central artifact every start script checks for.

### Standard network — 3 witnesses, threshold 2 (`setup.sh`, `start.sh`, `demo.sh`, `stop.sh`)

- **setup.sh**: builds `witness-node`, generates 3 keypairs + tokens, writes `examples/witness1.json`…`witness3.json` (id `witness-N`, port `3000+N`, host `127.0.0.1`, `network_id` `example-network`, `max_clock_skew` 300) and `examples/network.json` (threshold 2, endpoints `http://localhost:3001..3003`, empty `federation_peers`).
- **start.sh**: requires `network.json`, builds the workspace, launches 3 witness nodes (ports **3001–3003**) and 1 gateway (port **8080**, sqlite db `examples/gateway.db`), each backgrounded with PID files; prints endpoints and a CLI hint.
- **demo.sh**: requires the gateway on 8080; creates `/tmp/test-file.txt`, submits it via `witness-cli attest --file`, polls with `status`, verifies the saved signed attestation, and prints the public config.
- **stop.sh**: stops gateway + witnesses by PID (graceful kill, then `kill -9`), removes PID files, and `pkill -f` fallbacks.

### Dual-gateway mode — 2 independent networks (`setup-gateway.sh`, `start-gateway.sh`)

- **setup-gateway.sh**: creates `examples/gateway1/` and `examples/gateway2/`, each with 3 witness configs + its own `network.json`. Gateway 1 witnesses on ports **4001–4003** (`network_id` `gateway1-network`), Gateway 2 on **4004–4006** (`gateway2-network`); both threshold 2.
- **start-gateway.sh**: launches 6 witness nodes and 2 gateways (**5001**, **5002**), each with own sqlite db and logs under `examples/gatewayN/`. Hint: target a specific gateway with `witness-cli --gateway http://localhost:500N`. No dedicated demo/stop script (stop hint in its banner: `kill $(cat examples/gateway*/witness*.pid examples/gateway*/gateway.pid)`).

### Triple-gateway mode — 3 independent networks (`setup-triple.sh`, `start-triple.sh`)

- **setup-triple.sh**: same pattern for a third network — `examples/gateway3/`, witnesses on **4007–4009** (`network_id` `gateway3-network`), threshold 2.
- **start-triple.sh**: launches 9 witness nodes and 3 gateways (**5001/5002/5003**). A prior discrepancy (gateway-3 passing `--port 5002`) has been fixed.

### `federation/` — 3 networks that cross-anchor (`setup.sh`, `start.sh`, `demo.sh`, `stop.sh`)

- **setup.sh**: builds binaries; for networks **a, b, c** generates 3 keypairs each (9 total) and writes `examples/federation/witness-$net-$i.json` (ports **8001–8003** for a, **8011–8013** for b, **8021–8023** for c). Then writes `network-a.json`/`network-b.json`/`network-c.json` with threshold 2 and a full **federation block**: `enabled: true`, `batch_period: 60` seconds, `peer_networks` listing the other two gateways (`http://localhost:9001/9002/9003`, `min_witnesses: 2`), and `cross_anchor_threshold: 2`.
- **start.sh**: launches all 9 witnesses + 3 gateways (**9001/9002/9003**), each with own db/log/pid files.
- **demo.sh**: requires the 9001 gateway; timestamps a file on Network A (and the same file on Network B for comparison), waits the 60s batch period plus 10s for cross-anchoring, then queries each gateway's `/v1/config` and prints the federation status. Documents the security thesis: forging now requires 2-of-3 witnesses in *all three* networks (6 witnesses across 3 operators).
- **stop.sh**: PID-based stop for the 9 witnesses + 3 gateways, with `pkill -f "witness-.*federation"` fallbacks.

### `bls/` — BLS signature aggregation (`setup.sh`, `start.sh`, `demo.sh`, `stop.sh`)

- **setup.sh**: self-locating (`PROJECT_ROOT` from `BASH_SOURCE`); generates **BLS** keypairs via `witness-node --generate-key --bls`, writes witness configs with `"signature_scheme": "bls"` (ports **8001–8003**, `network_id` `bls-network`), `network.json` with `signature_scheme: bls` + threshold 2, and a `gateway.json`. Note it cleans old `witness-*`/`gateway*`/`network.json` artifacts first.
- **start.sh**: starts the 3 witnesses and the gateway on port **9000** — the gateway is launched from env (`NETWORK_CONFIG=.../network.json`, `DATABASE_URL=sqlite:.../gateway.db`) rather than CLI args. Verifies each process is alive and reports failures.
- **demo.sh**: explains the pitch (Ed25519: 3 sigs = 192 bytes; BLS `min_sig`: 1 aggregated G1 sig = 48 bytes, 75% signature-byte savings); attests a test file via the `witness` CLI, checks `status` JSON for the `{ signature, signers }` BLS aggregate, then verifies the extracted signed attestation.
- **stop.sh**: PID-based stop + `pkill -f "witness-.*bls/..."` fallbacks.

## Flow

Common lifecycle per network variant:

1. **setup** — build release binaries, generate N keypairs + auth tokens, emit `witness*.json` + `network.json` (and gateway config where applicable).
2. **start** — check for `network.json`, build if needed, launch witness nodes (background, PID files, logs), sleep for readiness, then launch gateway(s) with `--config network.json --port P --database gateway.db` (or env vars in the bls variant).
3. **demo** — curl a `/health` to confirm liveness, create a test file, timestamp it through `witness-cli`, look it up by hash, verify the attestation (standard); the federation demo adds a 70s batch/cross-anchor wait plus `/v1/config` federation introspection; the bls demo inspects the aggregated-signature JSON.
4. **stop** — kill by PID files (graceful then `-9`), remove PID files, `pkill -f` fallback sweep.

## Integration

- Exercises the same binaries that production runs: `crates/witness-node`, `crates/witness-gateway`, `crates/witness-cli`. No special build paths — straight `cargo run --release -p <crate>`.
- The standard network is what `cargo test`/example flows and `AGENTS.md`'s integration scenarios assume; `federation/` exercises the gateway's federation cross-anchoring and `bls/` exercises `witness-core`'s BLS aggregation paths end-to-end.
- `docker-compose.yaml`'s ephemeral `setup` service replicates `examples/setup.sh` inside a container (same keygen + `network.json` pattern).
- The root deployment files (`Dockerfile`, `docker-compose*.yaml`, `docker-entrypoint-gateway.sh`) are documented in `configs/codemap.md`.
