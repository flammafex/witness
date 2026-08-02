# crates/witness-node/

## Responsibility

`witness-node` is the per-witness signing service binary in the Witness federation. It holds a witness's private key (an Ed25519 signing key or a BLS12-381 secret key share) and produces threshold-signature shares for attestations on demand. Each federation member runs one instance; the gateway aggregates the individual signatures into a `SignedAttestation`. It is one of only two crates (with `witness-gateway`) allowed to contain signing logic per the strict crate boundaries.

## Design

- Single `[[bin]]` (`witness-node`) — no library. Entry point parses CLI args (`--config`, `--port`, `--host`, `--generate-key`, `--bls`) and either emits a fresh keypair or boots the server.
- **Private key material lives in the config file**: `WitnessNodeConfig.private_key` is a hex-encoded 32-byte Ed25519 seed or BLS secret key, deserialized from `witness.json`. Both `private_key` and the signing bearer tokens are marked `#[serde(skip_serializing)]` so they are never written back out, and the whole config `Drop` impl calls `zeroize()` on the key and tokens.
- **Two signature schemes** selected by `SignatureScheme`: Ed25519 via `witness_core::sign_attestation` (`ed25519-dalek`) or BLS via `witness_core::sign_attestation_bls` (`blst`), using the BLS secret key share for threshold aggregation.
- **Bearer-token auth on `/v1/sign`**: `Authorization: Bearer <token>` compared with `witness_core::constant_time_eq` (constant-time, via `subtle`). A `previous_signing_auth_token` is accepted during rotation; using it logs a "rotate soon" warning. Authentication runs before rate limiting so unauthenticated callers cannot exhaust the limiter.
- **Per-IP rate limiting** (defense-in-depth) via `governor` keyed `RateLimiter` (60 req/min/IP) on the sign endpoint.
- Input validation on the sign path: timestamp within `max_clock_skew` (default 300 s) of node time, and `attestation.network_id` must match the node's `network_id`.
- Axum router with three routes: `GET /health`, `POST /v1/sign`, `GET /v1/info`. State is `WitnessServer` (`Arc<WitnessNodeConfig>` + rate limiter). Errors map to HTTP status via a local `AppError` `IntoResponse` impl.

## Flow

1. `main.rs` parses args; `--generate-key` prints a keypair (Ed25519 or BLS) with instructions for wiring it into the config, then exits.
2. Otherwise `WitnessNodeConfig::load` reads `witness.json`, validates that the configured key parses for the declared scheme and that `signing_auth_token` is non-empty, then `WitnessServer::run` binds `host:port` and serves.
3. On `POST /v1/sign` (`sign_handler`): extract Bearer token → constant-time compare against current/previous token (401 on failure) → per-IP rate-limit check (429) → clock-skew check (400) → network-ID check (400) → derive key from config and produce `SignResponse { witness_id, signature }`.
4. `GET /v1/info` reports `id`, `public_key`, `network_id` — this is how the gateway learns which witness signed and with which key. `GET /health` is a liveness probe.

## Integration

- Depends on `witness-core` for the shared domain types (`SignRequest`, `SignResponse`, `SignatureScheme`) and all signing/encoding primitives (`sign_attestation`, `sign_attestation_bls`, `generate_keypair`, `generate_bls_keypair`, hex encoders, `constant_time_eq`).
- Consumed by `witness-gateway`: the gateway POSTs `SignRequest`s (attestation payload) to each witness's `/v1/sign` and aggregates the returned signatures into a threshold `SignedAttestation`.
- The witness's public key is distributed to other federation members via `network.json` / `/v1/network` so the gateway and verifiers can check the threshold.
- Not called by `witness-cli` or `witness-auditor` — those are HTTP clients of the gateway only.

**Security-sensitive** (flag before modifying, per AGENTS.md): the private key and `signing_auth_token` are stored in plaintext in `witness.json` (an operational secret); `zeroize` on config drop; constant-time token comparison; token rotation semantics; the rate-limiter defense layer; and any change to the signing call path. The node is pre-1.0 and unaudited — all signing behavior is high-stakes.
