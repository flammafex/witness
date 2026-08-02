# crates/

## Responsibility

The Rust workspace — five crates implementing Witness with strict boundary
rules: `witness-core` is the shared trust root (types, crypto, proof
verification), `witness-node` and `witness-gateway` are the only crates allowed
to contain signing logic, and `witness-cli` / `witness-auditor` are HTTP
clients only. Workspace dependencies are centralized in the root `Cargo.toml`
`[workspace.dependencies]`.

## Design

- Layered trust: core defines the domain model and all cryptographic primitives; node and gateway consume it and never re-implement crypto.
- Forward-only SQL migrations per crate, compiled via `sqlx::migrate!`, run on startup.
- Security hygiene: `zeroize` on key material, `subtle` constant-time ops, bearer tokens validated at startup, SSRF filter on outbound HTTP.

## Flow

1. Client → gateway API (`witness-gateway`).
2. Gateway → witness nodes (`witness-node`) collect signature shares, threshold-verify, close batches, issue STHs.
3. Verification of returned attestations / proof bundles happens locally via `witness-cli`; `witness-auditor` independently audits the STH chain.

## Integration

| Crate | Role | Consumes | Detailed Map |
|-------|------|----------|--------------|
| `witness-core` | Trust root: types, Ed25519 + BLS12-381, Merkle/log/proofs | — (no deps on other crates) | [View Map](witness-core/codemap.md) |
| `witness-node` | Signing service (holds private key) | `witness-core` | [View Map](witness-node/codemap.md) |
| `witness-gateway` | Main binary: API, aggregation, storage, anchoring | `witness-core` | [View Map](witness-gateway/codemap.md) |
| `witness-cli` | Client binary with local verification | `witness-core` | [View Map](witness-cli/codemap.md) |
| `witness-auditor` | Independent STH-chain auditor | `witness-core` | [View Map](witness-auditor/codemap.md) |

## Security-Sensitive Areas

Signing/verification in `witness-node` and `witness-gateway`; all crypto in
`witness-core`; migration sequences (forward-only) in each crate's
`migrations/`.
