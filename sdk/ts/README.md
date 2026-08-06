# @witness/sdk — TypeScript SDK

The TypeScript SDK for the Witness timestamping network. It provides the full
client surface, the local verifier, WebSocket support, and a typed error
hierarchy (spec §6 of `docs/sdk-enhancement-spec.md`).

ESM-first, `fetch` injectable (Node 18+ and browsers), no Node-only APIs in the
core path.

> **Pre-1.0, unaudited, not Byzantine-fault-tolerant.** This project has had no
> external security audit. Publishing this SDK does **not** constitute a
> security audit. Treat all signing, verification, and serialization code as
> unverified-by-third-parties.

## Local verification is the default — pin your config first

The gateway's answer is **never** trusted for the verdict. The local verifier
(`WitnessVerifier`) is the **default, trust-minimizing verification path**. It
pins a caller-supplied `NetworkConfig` and delegates every cryptographic check
to a WASM-compiled `witness-core` module (`crates/witness-core-wasm`) — the
single trust root (spec §4.3, Path A). No crypto is hand-ported to JS.

Verification is pinned to a config you supply — the verifier never silently
fetches one. The recommended pattern is to pin a `NetworkConfig` (prefer a
`network.json`-derived config checked into your repo) and verify against it:

```ts
import { WitnessClient } from '@witness/sdk';
import { WitnessVerifier } from '@witness/sdk/verify';

const client = new WitnessClient({ gatewayUrl: 'https://gateway.example.com' });

// 1. Pin a config. Prefer a pinned network.json-derived config:
//    const verifier = await WitnessVerifier.create(pinnedNetwork);
//    Or fetch it once (TOFU convenience — fetches home + peer configs):
const verifier = await WitnessVerifier.fetch(client);

// 2. Submit a hash and wait for confirmation.
const hash = new Uint8Array(32); // your SHA-256 content hash
await client.createAttestation(hash);
const signed = await client.waitForConfirmation(hash);

// 3. Verify LOCALLY against the pinned config — never trust the gateway's
//    verdict. Returns the number of valid signatures; throws
//    VerificationError on failure.
const count = verifier.verifyAttestation(signed);
if (count < verifier.networkConfig().threshold) throw new Error('sub-threshold');

// 4. Fetch a self-contained proof bundle and verify it offline.
const bundle = await client.getBundle(hash);
const result = verifier.verifyBundle(bundle); // level: none/basic/batched/federated
```

`WitnessVerifier.create(network, peers?)` constructs a verifier from a pinned
config (peers required for cross-anchor / Federated verification).
`WitnessVerifier.fetch(client)` is the explicit TOFU convenience: it fetches
the home network config (and each cross-anchor peer's config) from the gateway,
then loads the WASM module. Both are async — they guarantee the WASM module is
ready before you call the synchronous `verify*` methods.

`publicConfig()` (`/v1/config`) is **informational only** (witness count,
scheme, threshold) and is **not** a trust anchor — it is insufficient for
verification.

## Client surface

`WitnessClient` is a thin, keyless HTTP client. It performs **no** URL
filtering — the gateway-side SSRF hardening protects server-initiated traffic,
not client endpoint choice.

| Area | Method |
|---|---|
| Write | `createAttestation(hash, opts?)` — idempotent on duplicate hash |
| Read | `getAttestation(hash)`, `waitForConfirmation(hash, poll?)`, `getBundle(hash)`, `getProof(hash)`, `getAnchors(hash)`, `health()` |
| Config | `publicConfig()` (informational), `network()`, `networkFrom(url)` (trust-anchor fetch) |
| Log | `sth()`, `sthAtSize(size)`, `consistency(first, second)`, `logProof(hash, size)` |
| Push | `subscribeEvents(opts?)` |
| Remote (non-authoritative) | `verifyRemote(signed)` — the gateway's opinion |

`waitForConfirmation` polls until the job reaches a terminal state, honoring
the server's `next_attempt_at` hint and clamped to the configured timeout.
`confirmed` without a `signed_attestation` is a protocol violation and throws
`DecodeError`; `failed` throws `JobFailedError`; timeout throws
`ConfirmationTimeoutError`; an `AbortSignal` stops polling.

`getAnchors` distinguishes an *unknown attestation* (404 → `NotFoundError`) from
a *known but unbatched* one (200 with `[]`); it does **not** normalize 404 to
empty.

`FreebirdTokenInput = string | { tokenB64: string }` — a bare string is sugar
for `{ tokenB64 }`; the SDK always serializes the wire shape `{ "token_b64": ... }`.

## WitnessVerifier — local verification (WASM, single trust root)

`WitnessVerifier` pins a caller-supplied `NetworkConfig` (and optional peer
configs) and delegates every cryptographic check to the WASM-compiled
`witness-core` module — the single trust root. No crypto is hand-ported to JS.

| Method | Verifies | Returns |
|---|---|---|
| `verifyAttestation(signed)` | threshold-signed attestation | number of valid signatures |
| `verifyBundle(bundle)` | self-contained proof bundle (home network + batch + cross-anchors) | `ProofBundleVerification` (level: none/basic/batched/federated) |
| `verifySth(sth)` | signed tree head | number of valid signatures |
| `verifyConsistency(proof)` | RFC 9162 consistency between two STHs | `void` |
| `verifyLogInclusion(proof, leafHex)` | RFC 9162 inclusion proof against the STH in the response | `void` |

`verifyLogInclusion` takes the queried hash (`leafHex`) because
`LogInclusionProofResponse` deliberately omits the leaf — the caller supplies
the hash they asked the log to prove.

Failures throw `VerificationError` with a machine-readable `reason`
(`sub-threshold`, `duplicate-signer`, `unknown-witness`, `bad-signature`,
`index-size-mismatch`, `ambiguous-signature-encoding`).

The barrel also exports the explicit `decodeAttestationSignatures`
discriminating decoder (spec §3.5) and `decodeHex`.

## The `./verify` subpath

Import the verifier from `@witness/sdk/verify` (as in the examples above). This
subpath keeps the crypto/WASM code out of bundles that only talk HTTP — the
main `@witness/sdk` entry point re-exports it too, but bundlers can tree-shake
the crypto path when you import from the subpath.

## Error hierarchy

Every gateway failure mode a consumer must branch on is a typed error class
with a machine-readable `code` — consumers never string-match on messages:

| Class | `code` | Meaning |
|---|---|---|
| `TransportError` | `transport` | connect/TLS/timeout/abort |
| `HttpStatusError` | `http` | non-2xx that is not a 404 on a read endpoint |
| `NotFoundError` | `not_found` | 404 on a read endpoint |
| `JobFailedError` | `job_failed` | job reached the terminal `failed` state |
| `ConfirmationTimeoutError` | `confirmation_timeout` | polling timed out |
| `DecodeError` | `decode` | undecodable response or protocol violation |
| `VerificationError` | `verification` | local verification failed (`reason` field) |
| `AuthRequiredError` | `auth_required` | WebSocket auth failed (close code 4001) |

All extend `WitnessError`, which carries the `code` and a human-readable
message.

## WebSocket events

`subscribeEvents(opts)` connects to `/ws/events` and performs the first-message
auth handshake (`{"type":"auth_required"}` → reply `{"token": ...}` within the
server's 5s window). A close code of 4001 raises `AuthRequiredError` (no
auto-retry). Reconnects re-run the handshake with exponential backoff + jitter.

## Conformance gate (§4.2)

Every golden vector in `sdk/vectors/` is run against the TS implementation
(WASM verifier + decoder) and must pass **100%** — this is the release gate:

```sh
npm run test:conformance
```

## Type generation (schema from serde, never hand-maintained)

The TypeScript wire types are **generated**, never hand-written. The pipeline is:

1. **Rust** — `witness-core` wire types carry `#[derive(schemars::JsonSchema)]`.
   The generator binary `crates/witness-core/src/bin/gen_ts_types.rs` derives
   JSON Schema directly from those serde types and emits a single combined
   document to `sdk/ts/schema/schema.json`:

   ```sh
   cargo run -p witness-core --bin gen_ts_types
   ```

2. **Node** — `scripts/gen-types.mjs` runs `json-schema-to-typescript` over
   `schema.json` and emits `src/types.generated.ts`:

   ```sh
   npm run gen:types
   ```

The generated `src/types.generated.ts` is **checked in**. Field names keep
serde's `snake_case` wire names. Hex-encoded byte fields (`[u8; 32]`, `Vec<u8>`)
appear as `string` (they are lowercase hex strings on the wire). Auth/federation
tokens are excluded from the schema entirely.

## Drift CI gate

Regeneration must produce **zero diff**, otherwise CI fails. This — not a
hand-written YAML file — is what keeps the TS types synchronized with the serde
types:

```sh
npm run check:types   # npm run gen:types && git diff --exit-code src/types.generated.ts
```

The full gate also regenerates the schema from Rust and checks it for drift:

```sh
cargo run -p witness-core --bin gen_ts_types && git diff --exit-code sdk/ts/schema/schema.json
```

## Typecheck

```sh
npm run typecheck   # tsc --noEmit
```

## Security notes

- Never log Freebird tokens or WS auth tokens.
- Verification against a config fetched from the same gateway is
  trust-on-first-use; pin `network.json`-derived configs for a stronger anchor.
- The SDK accepts a caller-supplied gateway URL and performs no URL filtering.

## Status

Pre-1.0, unaudited, not Byzantine-fault-tolerant. Publishing this SDK does not
constitute a security audit.
