# scripts/

## Responsibility

Ad-hoc operational scripts for the Witness workspace. `freebird-witness-smoke.sh` is an end-to-end smoke test that stands up a full **Freebird + Witness** stack — Freebird issuer + verifier, a 3-witness threshold-2 Witness network configured to *require* Freebird tokens, an actual token issuance, and a timestamp request through the gateway with that token — then asserts that admission control worked. `check-generated-drift.sh` is the fail-closed repository-root gate that regenerates and compares the TS schema/types, golden vectors, and OpenAPI output. It exists because AGENTS.md calls out that Freebird evolves independently and generated contracts must remain synchronized.

## Design

Bash, `set -euo pipefail`. Configurable entirely via environment variables:

The generation-drift gate is intentionally environment-independent: it derives
the repository root from its own path, runs all generators using repository-
relative paths, and compares every expected output to `HEAD`.

| Env var | Default | Purpose |
|---|---|---|
| `FREEBIRD_DIR` | `../freebird` (sibling checkout) | Freebird repo root; script exits if `Cargo.toml` missing there |
| `FREEBIRD_ISSUER_PORT` | `18081` | issuer bind port |
| `FREEBIRD_VERIFIER_PORT` | `18082` | verifier bind port |
| `WITNESS_GATEWAY_PORT` | `18080` | gateway port |
| `WITNESS_BASE_PORT` | `18100` | witness-1 base (witnesses on 18101–18103) |

Runs entirely in a `mktemp -d` scratch dir; a `trap cleanup EXIT` kills all spawned PIDs and either removes the temp dir (success) or preserves it and dumps the last 80 lines of every log (failure). Readiness is polled via `wait_for_url` (up to 120 one-second attempts).

Pipeline of helper functions mirroring the example-network pattern (`generate_witness_configs` reuses `witness-node --generate-key` + random auth tokens, writing `witness{1..3}.json` and `network.json` with threshold 2 and network id `smoke-network`):

1. `require_freebird` — locate the Freebird checkout.
2. `main` builds the whole workspace release (`cargo build --release --workspace`).
3. `start_freebird` — boots the Freebird issuer (`freebird-issuer` on `18081`, admin API key, `ISSUER_ID=issuer:witness-smoke:v4`, no TLS) and verifier (`freebird-verifier` on `18082`, audience `witness-smoke`, pointing at the issuer's `.well-known/issuer`), each with an isolated `CARGO_TARGET_DIR` under the temp dir.
4. `issue_freebird_token` — runs Freebird's `freebird-interface` binary to mint a token saved to `$TMP_DIR/token.json`.
5. `start_witness` — launches the 3 witness nodes, then the gateway with Freebird **required**: `FREEBIRD_REQUIRED=true`, `FREEBIRD_CONSUME_TOKENS=true`, `FREEBIRD_ALLOW_INSECURE_LOCAL=true`, `FREEBIRD_VERIFIER_URL=http://127.0.0.1:18082`.

## Flow

1. Build Witness release binaries.
2. Start Freebird issuer + verifier; wait for `/health` / `.well-known/issuer`.
3. Issue a Freebird token via `freebird-interface`.
4. Start 3 witnesses + a gateway configured to reject tokenless timestamps.
5. Timestamp a fixed SHA-256 hash via the `witness` CLI passing `--freebird-token $TMP_DIR/token.json`; save the attestation JSON.
6. **Assertions** (both must pass for exit 0):
   - the attestation contains `"network_id": "smoke-network"`, proving a timestamp went through; and
   - the gateway log contains the line `Freebird token verified`, proving the token was actually validated (not bypassed) end-to-end.

## Integration

- Bridges two independent projects: the external Freebird rate-limiting/admission system (`FREEBIRD_DIR`, issuer+verifier binaries, `freebird-interface` token client) and the Witness workspace (`witness-node`, `witness-gateway`, `witness` CLI).
- The gateway side depends on the Freebird verifier client wiring in `crates/witness-gateway` (env knobs `FREEBIRD_VERIFIER_URL` / `FREEBIRD_REQUIRED` / `FREEBIRD_CONSUME_TOKENS` / `FREEBIRD_ALLOW_INSECURE_LOCAL`; "permissive mode" when `FREEBIRD_REQUIRED` is unset). Keep this script in lockstep with Freebird's verifier API (per AGENTS.md, verify against `/v1/verify` or `/v1/check` semantics as Freebird evolves).
- Its config-generation pattern (keygen, auth tokens, `network.json` threshold 2) is the same one used by `examples/setup.sh` and the compose `setup` service.
- Related docs: `docs/freebird-integration.md` and the `FREEBIRD_*` env knobs in `crates/witness-gateway`.
