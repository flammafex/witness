# witness-client

A typed, keyless client SDK for the [Witness](https://git.carpocratian.org/sibyl/witness)
timestamping network. It covers the full attestation lifecycle (submit, poll,
fetch proofs/bundles/anchors), the transparency-log read surface, optional
WebSocket push events, and — most importantly — **local** verification.

`witness-cli` is built on this crate.

> **Pre-1.0, unaudited, not Byzantine-fault-tolerant.** This project has had no
> external security audit. Publishing this SDK does **not** constitute a
> security audit. Treat all signing, verification, and serialization code as
> unverified-by-third-parties.

## Local verification is the default — pin your config first

The gateway's answer is **never** trusted for the verdict. The plainly-named
`verify*` functions run client-side against `witness-core` semantics and are
the default, trust-minimizing path. Talking to `POST /v1/verify` is available
only under the explicitly-labelled `WitnessClient::verify_remote` ("the
gateway's opinion"), which is **non-authoritative**.

Verification functions take a caller-supplied `NetworkConfig` as a parameter —
they never silently fetch one. Fetching a config from a gateway is a
trust-on-first-use (TOFU) convenience, so the recommended pattern is to fetch a
`NetworkConfig` **once**, pin it, and verify against that pinned config:

```rust,no_run
use witness_client::{WitnessClient, verify, verify_proof_bundle};
use witness_core::{NetworkConfig, ProofVerificationConfig};

#[tokio::main]
async fn main() -> Result<(), witness_client::Error> {
    let client = WitnessClient::new("https://gateway.example.com")?;

    // 1. Fetch the full network config ONCE (witness pubkeys, threshold,
    //    scheme, federation peers). Auth tokens are stripped server-side.
    //    Prefer pinning a `network.json`-derived config checked into your repo.
    let network: NetworkConfig = client.network().await?;

    // 2. Submit a hash and wait for confirmation.
    let hash = [0u8; 32]; // your SHA-256 content hash
    client.create_attestation(hash, None).await?;
    let signed = client.wait_for_confirmation(hash, Default::default()).await?;

    // 3. Verify LOCALLY against the pinned config — never trust the gateway's
    //    verdict. Returns the number of valid signatures.
    let count = verify(&signed, &network)?;
    assert!(count >= network.threshold);

    // 4. Fetch a self-contained proof bundle and verify it offline.
    let bundle = client.get_bundle(hash).await?;
    let config = ProofVerificationConfig { network, peers: vec![] };
    let result = verify_proof_bundle(&bundle, &config)?;
    println!("bundle verification level: {:?}", result.level);

    Ok(())
}
```

Fetching a config from the same gateway you are verifying against is
trust-on-first-use; for a stronger guarantee, pin a `network.json`-derived
config. `public_config()` (`/v1/config`) is **informational only** (witness
count, scheme, threshold) and is **not** a trust anchor — it is insufficient
for verification.

## Client surface

`WitnessClient` is a thin, keyless HTTP client. It performs **no** URL
filtering — the gateway-side SSRF hardening protects server-initiated traffic,
not client endpoint choice.

| Area | Method |
|---|---|
| Write | `create_attestation(hash, freebird_token)` — idempotent on duplicate hash |
| Read | `get_attestation(hash)`, `wait_for_confirmation(hash, poll)`, `get_bundle(hash)`, `get_proof(hash)`, `get_anchors(hash)`, `health()` |
| Config | `public_config()` (informational), `network()`, `network_from(url)` (trust-anchor fetch) |
| Log | `sth()`, `sth_at_size(size)`, `consistency(first, second)`, `log_proof(hash, size)` |
| Push (`ws` feature) | `subscribe_events(token)` |
| Remote (non-authoritative) | `verify_remote(&signed)` — the gateway's opinion |

`wait_for_confirmation` polls until the job reaches a terminal state, honoring
the server's `next_attempt_at` hint (effective sleep is never below it) and
clamped to the configured timeout. `confirmed` without a `signed_attestation`
is a protocol violation and returns a `Decode` error (never a silent success);
`failed` returns `Error::JobFailed`; timeout returns `Error::ConfirmationTimeout`
carrying the last observed status. Dropping the future stops polling.

`get_anchors` distinguishes an *unknown attestation* (404 → `Error::NotFound`)
from a *known but unbatched* one (200 with `[]`); it does **not** normalize 404
to empty.

`WitnessClientBuilder` configures the per-request timeout (default 30s) and
`User-Agent`.

## Local verification functions

These are thin wrappers over `witness-core` — the single trust root. This crate
never re-implements any cryptography.

| Function | Verifies | Returns |
|---|---|---|
| `verify(&signed, &config)` | threshold-signed attestation | number of valid signatures |
| `verify_proof_bundle(&bundle, &config)` | self-contained proof bundle (home network + batch + cross-anchors) | `ProofBundleVerification` (level: none/basic/batched/federated) |
| `verify_sth(&sth, &config)` | signed tree head | number of valid signatures |
| `verify_consistency(&proof, &config)` | RFC 9162 consistency between two STHs | `()` |
| `verify_log_inclusion(&proof, leaf)` | RFC 9162 inclusion proof against the STH in the response | `()` |

`verify_proof_bundle` reaches `VerificationLevel::Federated` only when the
`ProofVerificationConfig` carries peer `NetworkConfig`s — fetch them with
`network_from(url)` for each cross-anchor peer.

## Error handling

Every gateway failure mode a consumer must branch on is a typed variant of the
`thiserror` `Error` enum — consumers never string-match on messages:

- `InvalidHash` — a hash was not a valid 32-byte value.
- `Transport` — connect/TLS/timeout failure.
- `Http { status, body }` — a non-2xx status that is not a 404 on a read endpoint.
- `NotFound` — 404 on a read endpoint (e.g. unknown attestation).
- `JobFailed { hash, attempts, last_error }` — the job reached the terminal `failed` state.
- `ConfirmationTimeout { hash, elapsed, last_status }` — polling timed out.
- `Decode` — undecodable response, or a protocol violation (e.g. `confirmed` without signatures).
- `WebSocket` — a WebSocket-level failure.
- `Verification` — local verification failed (wrapped from `witness_core`).

`Result<T>` is an alias for `std::result::Result<T, Error>`.

## WebSocket push (`ws` feature)

```toml
witness-client = { version = "0.8", features = ["ws"] }
```

`subscribe_events(token)` connects to `/ws/events` and performs the
first-message auth handshake (`{"type":"auth_required"}` → reply `{"token": ...}`
within the server's 5s window). A close code of 4001 indicates an auth failure.

## Security notes

- Never log Freebird tokens or WS auth tokens.
- Verification against a config fetched from the same gateway is
  trust-on-first-use; pin `network.json`-derived configs for a stronger anchor.
- The SDK accepts a caller-supplied gateway URL and performs no URL filtering.

## License

Apache-2.0.
