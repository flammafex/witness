# crates/witness-node/src/

## Responsibility

Three modules implementing the witness signing service: CLI entry point (`main.rs`), configuration handling and key derivation (`config.rs`), and the HTTP signing server (`server.rs`).

### `main.rs`

- **Responsibility**: binary entry point; clap arg parsing; optional keypair generation; server wiring.
- **Key items**: `Args` struct (`--config`, `--port`, `--host`, `--generate-key`, `--bls`); `#[tokio::main] async fn main`.
- **Flow**: tracing init → if `--generate-key`, print an Ed25519 or BLS keypair and exit → else `WitnessNodeConfig::load`, apply host/port CLI overrides, log identity, `WitnessServer::new(config).run(&host, port)`.
- **Consumers**: the `witness-node` binary itself (crate boundary: no library target, so nothing external imports this).

### `config.rs`

- **Responsibility**: load and validate `witness.json`; derive signing/verifying keys; zeroize secrets.
- **Key types**: `WitnessNodeConfig { id, signature_scheme, private_key, port, host, network_id, signing_auth_token, previous_signing_auth_token, max_clock_skew }`.
- **Key functions**: `WitnessNodeConfig::load` (parses JSON, validates the key parses for the declared scheme and the auth token is non-empty); `ed25519_signing_key` / `ed25519_verifying_key`; `bls_secret_key` / `bls_public_key`; `public_key` (scheme-dispatched, hex-encoded); `Drop` impl zeroizing `private_key` and both tokens.
- **Security-sensitive**: the private key is a hex string in plaintext config; `#[serde(skip_serializing)]` on `private_key` and tokens prevents accidental re-export; `zeroize::Zeroize` on drop.
- **Consumers**: `main.rs` (load/boot), `server.rs` (sign and info handlers read keys and tokens through this type).

### `server.rs`

- **Responsibility**: Axum HTTP surface: `/health`, `/v1/sign`, `/v1/info`; auth, rate limiting, and attestation signing.
- **Key types**: `WitnessServer` (`Arc<WitnessNodeConfig>` + `governor` per-IP `RateLimiter`); private `AppError` enum (Unauthorized / InvalidTimestamp / InvalidNetwork / InternalError / RateLimited) with `IntoResponse` mapping to 401 / 400 / 500 / 429.
- **Key functions**: `WitnessServer::new`, `WitnessServer::run` (binds TCP listener, `axum::serve` with `ConnectInfo`); `health_handler`; `info_handler` (id, public_key, network_id); `sign_handler` (auth → rate limit → timestamp skew → network ID → scheme-dispatched `witness_core::sign_attestation[_bls]`); `bearer_token` (strips `Bearer ` prefix from the `Authorization` header).
- **Consumers**: the `witness-node` binary (`main.rs`); HTTP clients are `witness-gateway` (the sign caller) and operators probing `/health` and `/v1/info`.
