# examples/bls/

## Responsibility

Runnable example Witness network demonstrating **BLS12-381 signature aggregation** — the variant where 3 individual witness signatures collapse into 1 aggregated signature instead of 3 separate Ed25519 signatures. It uses `blst::min_sig`: each signature is a compressed 48-byte G1 point and each public key is a compressed 96-byte G2 point. Follows the standard lifecycle (`setup.sh` → `start.sh` → `demo.sh` → `stop.sh`) with a threshold-2, 3-witness network whose explicit purpose is to show the 75% signature-byte savings (48 bytes vs 3 × 64 = 192 bytes). A local `README.md` documents the BLS variant in depth.

## Design

Self-locating scripts: each derives `PROJECT_ROOT` from `${BASH_SOURCE[0]}` (`$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)`) and `BLS_DIR="$PROJECT_ROOT/examples/bls"`, so they run from any working directory (unlike the root `examples/*.sh` scripts which assume the workspace root as CWD). `set -e`; the demo uses `read -p` for interactivity.

- **BLS keygen**: keys are generated with `witness-node --generate-key --bls` (distinct from the default Ed25519 path). Witness configs carry `"signature_scheme": "bls"` (id `witness-N`, port `8000+N`, host `127.0.0.1`, `network_id` `bls-network`, `max_clock_skew` 300). `network.json` is written with `"signature_scheme": "bls"` and threshold 2; a `gateway.json` config is also emitted (though `start.sh` ends up using env vars instead of it).
- **setup.sh**: builds `witness-node` + `witness-gateway`, **cleans stale artifacts first** (`rm -rf "$BLS_DIR/witness-"* "$BLS_DIR/gateway"* "$BLS_DIR/network.json"`), then generates 3 BLS keypairs + random auth tokens. It attempts multiple strategies to capture public keys for `network.json` (jq-based re-invocation, `witness-node --config` stdout parsing, and a fresh-keygen fallback if detection yields empty) — an evident source of script fragility if the binary's stdout format changes.
- **start.sh**: launches witnesses on **8001–8003** (direct `target/release/witness-node` invocation, not `cargo run`), then the gateway on **9000** configured via environment (`NETWORK_CONFIG="$BLS_DIR/network.json"`, `DATABASE_URL="sqlite:$BLS_DIR/gateway.db"`) rather than CLI args. Verifies each spawned PID is alive and prints ✓/✗ per process.
- **demo.sh**: pitches the comparison (Ed25519: 3 sigs = 192 bytes; BLS `min_sig`: 1 sig = 48 bytes, 75% signature-byte savings, single pairing verification), attests a test file through the `witness` CLI, checks `status` JSON for the `{ signature, signers }` aggregate shape, and verifies the extracted signed attestation.
- **stop.sh**: PID-based stop (graceful kill with `kill -9` fallback) plus `pkill -f "witness-node.*bls/witness"` / `pkill -f "witness-gateway.*bls/network"` sweeps.

## Flow

1. `setup.sh` — build binaries, wipe old configs, generate 3 BLS keypairs + tokens, write `witness-1.json`…`witness-3.json` and `network.json` (`signature_scheme: bls`, threshold 2) plus `gateway.json`.
2. `start.sh` — start 3 witnesses on 8001–8003 (PID files + logs), then the gateway on 9000 from env config; wait and verify processes.
3. `demo.sh` — create `test-file.txt`, `attest` via CLI with `--save`, `status` by hash and inspect the `{ signature, signers }` aggregate, compute byte savings, and `verify` the extracted signed attestation.
4. `stop.sh` — kill by PID files, fallback `pkill` sweep.

## Integration

- Exercises the BLS12-381 code paths in `crates/witness-core` (via `blst`) end-to-end: witness threshold signing produces 3 BLS signatures, and the gateway aggregates them into one — the demo asserts the aggregated shape, so any regression in aggregation surfaces as a demo failure.
- Uses the same `witness-node` / `witness-gateway` / `witness` binaries as production, only with the `bls` signature scheme wired through witness + network configs.
- The dual-scheme capability it demonstrates (Ed25519 or BLS12-381) is a headline feature on the landing page (`landing/index.html`).
- Sister example: `examples/federation/` shows the federation variant; root `examples/setup.sh` shows the standard Ed25519 network.
