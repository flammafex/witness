# examples/federation/

## Responsibility

Runnable example of the **federation feature**: three independent Witness networks (a, b, c), each with 3 witnesses and threshold 2, configured to **cross-anchor batches** to one another. Demonstrates the security upgrade from trusting one network's quorum to requiring compromise across *all three* operators. Follows the standard lifecycle (`setup.sh` → `start.sh` → `demo.sh` → `stop.sh`). A local `README.md` documents the federation setup in depth.

## Design

Scripts assume the workspace root as CWD (`PROJECT_ROOT="$(pwd)"`), `set -e`, and store state under `examples/federation/` (`witness-$net-$i.json`, `network-$net.json`, plus runtime `.log`/`.pid`/`.db` files).

- **Keygen**: for each network in `a b c`, `setup.sh` generates 3 keypairs (`witness-node --generate-key`) + random auth tokens, and derives witness ports arithmetically: `8000 + (ascii(net) - 97) * 10 + i` — network **a** on **8001–8003**, **b** on **8011–8013**, **c** on **8021–8023**. Witness ids are `witness-$net-$i`, `network_id` is `network-$net`.
- **Network configs**: `network-a.json` / `network-b.json` / `network-c.json`, each threshold 2 with a full **federation block**:
  - `enabled: true`
  - `batch_period: 60` (seconds — batches close every minute)
  - `peer_networks`: the *other two* gateways (`http://localhost:9001/9002/9003`) with `min_witnesses: 2`
  - `cross_anchor_threshold: 2` (batch must be countersigned by 2 of 2 peer networks)
- **start.sh**: launches all 9 witnesses, then 3 gateways on **9001** (a), **9002** (b), **9003** (c) via a `case` on the network letter, each with its own sqlite db and PID/log files.
- **demo.sh**: interactive-ish (no `read`), requires gateway 9001; attests the same file on Network A and Network B, waits the **60s batch period + 10s** for cross-anchoring, then queries each gateway's `/v1/config` and prints witness count / threshold / `federation.enabled` per network. Closes by explaining the threat model: forging now requires 2-of-3 witnesses in each of A, B, *and* C — 6 witnesses across 3 independent operators.
- **stop.sh**: PID-based stop for 9 witnesses + 3 gateways (graceful then `-9`), with `pkill -f "witness-gateway.*federation"` / `pkill -f "witness-node.*federation"` fallbacks.

## Flow

1. `setup.sh` — build binaries, generate 9 keypairs, write 9 witness configs + 3 network configs with mutual `peer_networks`.
2. `start.sh` — start 9 witnesses (8001–8003 / 8011–8013 / 8021–8023), then gateways 9001/9002/9003; wait for readiness.
3. `demo.sh` — attest on Networks A and B; wait ~70s for the batch period and cross-anchoring; introspect `/v1/config` federation status on all three gateways.
4. `stop.sh` — kill all 12 processes by PID, fallback sweeps.

## Flow (batch cross-anchoring, per the demo narrative)

Clients timestamp via a gateway → the gateway batches pending hashes → every 60s (`batch_period`) the batch closes and its Merkle root is submitted to the peer networks' `/v1/federation/anchor` endpoints → peers require `min_witnesses: 2` to countersign → the originating batch is considered cross-anchored once `cross_anchor_threshold: 2` peer networks have signed.

## Integration

- Exercises the gateway's federation machinery in `crates/witness-gateway` (batch closing, outbound `/v1/federation/anchor` submission to peer gateways, countersignature collection) and the resulting federation-augmented attestation format in `crates/witness-core`.
- The three gateways and their peer references mirror the production topology the nginx template supports: `configs/server/nginx.conf` restricts `/v1/federation/anchor` to `127.0.0.1` + `{{PEER_GATEWAY_1}}`/`{{PEER_GATEWAY_2}}` — the two-peer cross-anchor model this example runs is exactly the deployment shape that allowlist was built for.
- Federation is a headline feature on the landing page (`landing/index.html`, "Independent networks can cross-anchor batches").
- Sister example: `examples/bls/` shows the BLS aggregation variant; root `examples/setup.sh` shows the single-network Ed25519 baseline.
