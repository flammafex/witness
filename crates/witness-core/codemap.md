# crates/witness-core/

## Responsibility

The shared trust root of the Witness workspace. Owns all domain types (`Attestation`, `SignedAttestation`, `NetworkConfig`, request/response wire types), the two signature schemes (Ed25519 multi-sig and BLS12-381 aggregated), the RFC 9162 batch Merkle tree with inclusion/consistency proof verification, Signed Tree Head (STH) log verification for auditors, federation cross-anchor verification, external-anchor data types, the hex serde adapters, and the canonical attestation byte serialization used as the signing message. It is a pure library: no private key custody, no HTTP, no process logic, no outbound network calls. Every security-relevant primitive the other four crates depend on lives here, making this the highest-stakes crate in the repo.

## Design

- **Strict crate boundary**: signing *logic* is only exercised by `witness-node` and `witness-gateway`; core provides the sign/verify/aggregate primitives and complete verification of a `SignedAttestation` against a `NetworkConfig`.
- **Dual signature scheme**, selected per-network via `SignatureScheme` (serde lowercase; `Ed25519` default, `BLS`). Ed25519 produces a `MultiSig` (one `WitnessSignature` per witness); BLS12-381 aggregates into a single compact signature in `Aggregated { signature, signers }`.
- **Canonical signing message**: `Attestation::to_bytes()` = `hash (32) || timestamp (8 LE) || network_id_len (4 LE) || network_id || sequence (8 LE)`. The length prefix prevents byte-collisions between networks with confusable names. All Ed25519 and BLS signing/verification operates on this exact byte string. **Security-sensitive (attestation serialization format).**
- **RFC 9162 (§2.1) Merkle tree**: domain-separated leaves `H(0x00 ‖ leaf)`, positional internal nodes `H(0x01 ‖ left ‖ right)` (no sorting), and largest-power-of-2 splits for unbalanced trees — the shape that makes consistency proofs possible. Verifiers are position-aware and reject index/size mismatches.
- **STH log layer reuses the attestation machinery**: a `TreeHead`'s domain-separated digest (`STH_DOMAIN` + length-prefixed fields) is wrapped in a synthetic `Attestation`, threshold-signed by witnesses through the normal `/v1/sign` flow, and verified via `verify_signed_attestation`.
- **BLS via `blst` min_sig** (G2 signatures, 96-byte keys/sigs) with a fixed domain-separation tag (`WITNESS_BLS_SIG_…`); secret-key seed material zeroized after `key_gen`; keys generated from `OsRng`.
- **Wire format**: JSON with custom serde hex adapters — raw bytes in memory, lowercase hex strings on the wire (`array32`/`vec`); Merkle/consistency proofs use their own in-crate hex adapters.
- **Constant-time hygiene**: `constant_time_eq` uses `subtle::ConstantTimeEq` for auth-token/password comparisons.
- **Errors**: `thiserror` `WitnessError` + crate `Result<T>`; every verification path returns structured errors for rejected cases.
- **Test discipline**: every security-sensitive module carries inline accepted/rejected test vectors (wrong key, tampered root, duplicate signer, wrong index, tampered consistency path).

## Flow

- **Inbound (timestamping)**: client submits a SHA-256 hash (hex) → `TimestampRequest` → gateway builds an `Attestation` (hash, wall-clock timestamp, `network_id`, monotonic `sequence`) → witnesses return individual signatures (`SignResponse`) → `SignedAttestation` carries `AttestationSignatures` → `verify_signed_attestation` enforces threshold, unique signers, key decoding, and signature-type/scheme agreement.
- **Batching/anchor chain**: attestation hashes become leaves in an RFC 9162 tree → `merkle_root` → `AttestationBatch` → peer networks threshold-sign the root as `CrossAnchor` → external providers anchor the root (`ExternalAnchorProof`). `ProofBundle` layers all four (threshold signature, batch inclusion, cross-anchors, external anchors) for offline verification via `verify_proof_bundle` → `ProofBundleVerification` with a `VerificationLevel` (`None`/`Basic`/`Batched`/`Federated`).
- **Audit flow**: `TreeHead` → `SignedTreeHead` → chains of `LogConsistencyProof`s verified by `verify_signed_tree_head` + `verify_log_consistency` prove the operator never rewrote history; `verify_inclusion_against_sth` proves a leaf sat at a given position in a committed tree.

## Integration

- **witness-node** (signing service): `sign_attestation` (Ed25519) / `sign_attestation_bls` (BLS), `generate_*_keypair`, `encode/decode_*_public_key`, `decode_bls_secret_key`, `constant_time_eq` (signing-token check), `SignRequest`/`SignResponse`, `SignatureScheme`.
- **witness-gateway** (main binary): `verify_signed_attestation`, `aggregate_signatures_bls`, per-witness key decode + `verify_signature`/`verify_signature_bls`, `CrossAnchor` construction, `AnchorProviderType` dispatch, `verify_proof_bundle`, `AttestationJobResponse`/`AttestationJobStatus`, `constant_time_eq` for admin/metrics/WebSocket auth, Freebird types.
- **witness-cli** (HTTP client): offline `verify_proof_bundle` with `ProofVerificationConfig`, `NetworkConfig` parsing, `ProofBundle` display, anchor-provider display, `FreebirdToken`, attestation-job request/response types.
- **witness-auditor** (RFC 9162 walker): `verify_signed_tree_head`, `verify_log_consistency`, `SignedTreeHead`, `TreeHead`, `LogConsistencyProof`, `NetworkConfig`.
- The dependency graph is one-way (core ← node/gateway/cli/auditor); consumers import only the public re-exports in `lib.rs`.

**Security-sensitive within this crate** (flag before modifying): `crypto.rs` (Ed25519 sign/verify), `bls.rs` (BLS sign/verify/aggregate), `signature_scheme.rs` (untagged signature serialization), `types.rs::Attestation::to_bytes` (signing-message format), `merkle.rs` + `log.rs` (proof/STH verification), `serde_hex.rs` (wire format).
