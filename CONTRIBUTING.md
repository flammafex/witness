# Contributing

Witness is a Rust workspace for threshold timestamping. Keep changes scoped and
prefer existing crate boundaries:

- `witness-core`: public types, cryptography, Merkle/log/proof verification
- `witness-node`: witness signing service
- `witness-gateway`: public API, storage, batching, federation, anchoring
- `witness-cli`: user-facing CLI
- `witness-auditor`: independent log/auditor tooling

## Development Checks

Run these before submitting changes:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
```

If deployment assets changed, also smoke-test Docker or the example network.

## Security-Sensitive Changes

Call out changes that affect:

- signing or verification logic
- attestation serialization
- Merkle roots, inclusion proofs, consistency proofs, or signed tree heads
- witness auth tokens
- Freebird verification
- federation auth
- external anchor providers
- admin, metrics, or WebSocket authentication
- database migrations

Security-sensitive changes should include tests or test vectors that show both
the accepted and rejected cases.

## Freebird Compatibility

Freebird evolves independently. When changing Witness admission-control logic,
verify against the current Freebird verifier API. Current verifier requests use:

```json
{ "token_b64": "<base64url-freebird-token>" }
```

See [Freebird Integration](docs/freebird-integration.md).

## Documentation

Public behavior changes should update the relevant docs:

- `README.md` for common user-facing behavior
- `PRODUCTION.md` for operator-facing deployment guidance
- `SECURITY.md` and `docs/threat-model.md` for security boundaries
- `docs/release.md` and `CHANGELOG.md` for release-impacting changes
