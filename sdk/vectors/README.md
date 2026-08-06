# Witness SDK Golden Vectors

This directory holds the **conformance contract** for the Witness SDKs
(`@witness/sdk`, Phase 2 of `docs/sdk-enhancement-spec.md`). The TypeScript SDK
is tested against these vectors in CI; **100% parity is a release gate**
(spec §4.2).

The vectors are generated deterministically by
`crates/witness-core/src/bin/gen_vectors.rs` and verified by the integration
test `crates/witness-core/tests/golden_vectors.rs`. They pin the wire and
crypto parameters in spec §3 (the source of truth is the Rust code).

## Files

| File | Category (spec §4.1) |
|------|----------------------|
| `to_bytes.json` | `Attestation::to_bytes()` — empty, multibyte (CJK/emoji), length-prefix-boundary `network_id`s |
| `ed25519.json` | Ed25519 sign/verify — accepted + rejected (wrong key, tampered message, duplicate signer, unknown witness, below-threshold) |
| `bls.json` | BLS keygen (fixed IKM), sign, aggregate, aggregated verify — rejected (DST mismatch, tampered aggregate, wrong signer set, invalid subgroup) |
| `merkle.json` | RFC 9162 roots/inclusion/consistency for tree sizes 0..=17 — rejected (tampered root, wrong index, wrong tree size, truncated path) |
| `sth.json` | STH digest construction + threshold-signed STHs per scheme |
| `wire.json` | `AttestationSignatures` variants, hex adapters, enums, ambiguous/malformed union payloads |

Every file carries a `version` field. Bump it (and regenerate) whenever the
vector format or the pinned §3 parameters change.

## Regenerating

From the workspace root:

```bash
cargo run -p witness-core --bin gen_vectors
```

The generator uses **fixed seeds / fixed IKM only** — no `OsRng` — so output is
byte-for-byte reproducible. After regenerating, verify with:

```bash
cargo test -p witness-core --test golden_vectors
```

## Verifying

```bash
cargo test -p witness-core --test golden_vectors
```

## Stability policy

Per spec §3.9, any change to the pinned wire/crypto parameters is a breaking
change: bump the minor version, **regenerate these vectors**, and note it in
`docs/release` + `CHANGELOG.md`.

## Strict discrimination (spec §3.5)

`wire.json` includes an "ambiguous" payload carrying **both** the multi-sig
shape (`signatures`) and the aggregated shape (`signature` + `signers`). Per
the normative §3.5 rule this is a `DecodeError`, and the Rust
`AttestationSignatures` decoder in `signature_scheme.rs` now rejects it (it is
recorded in the `malformed[]` array). The TS SDK implements the same explicit
discriminating decoder, so Rust and TS agree on strict discrimination.
