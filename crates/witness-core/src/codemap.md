# crates/witness-core/src/

## Responsibility

The source directory implementing `witness-core`: every domain type, cryptographic primitive, and verification path the other four crates compile against. Modules are ordered to mirror the layered trust chain — from the signed payload (`types`) and signature containers (`signature_scheme`) down to the primitives that create and check them (`crypto`, `bls`), then the batch/anchor layers (`merkle`, `log`, `federation`, `external_anchors`), the wire adapters (`serde_hex`), and the error surface (`error`).

## Design

- **Module layering**: `types` (domain + wire) → `signature_scheme` (multi-sig vs aggregated container) → `crypto`/`bls` (sign/verify primitives) → `merkle` (RFC 9162 batch tree) → `log` (STH/audit chains) → `federation` (cross-anchoring + `ProofBundle`) → `external_anchors` (provider shapes) → `serde_hex` (wire hex) → `error` (`WitnessError`).
- **Public surface is funneled through `lib.rs` re-exports**; no module depends on another beyond the public API, keeping the module graph acyclic.
- **One signing-message format everywhere**: all crypto and verification paths sign/verify `Attestation::to_bytes()`, and the STH layer funnels its digest into that same path via `TreeHead::to_attestation()`.
- **Proof structures carry their own context** (`tree_size`, `leaf_index`, `root`) so verifiers are position-aware and cannot be tricked by truncated paths.
- **Security hygiene**: `zeroize` on BLS key material, `subtle` ct_eq for token comparison, serde `skip_serializing` on bearer tokens (`WitnessInfo::auth_token`, federation tokens), inline accepted/rejected test vectors in every security-sensitive module.

## Flow

- **Entry**: hashes arrive as `TimestampRequest`/`CreateAttestationRequest`; the gateway constructs an `Attestation` (`types.rs`) and dispatches signing to witnesses. `SignRequest`/`SignResponse` are the core-side wire contract.
- **Signing**: node calls `crypto::sign_attestation` (Ed25519) or `bls::sign_attestation_bls`, collected into `AttestationSignatures` (`signature_scheme.rs`).
- **Verification**: `crypto::verify_signed_attestation` dispatches on the signature type — per-witness Ed25519 checks with duplicate-signer rejection, or BLS aggregated verification over the signing subset's public keys (`bls::verify_aggregated_signature_bls`) — and enforces the configured verification threshold.
- **Batching/auditing**: attestation hashes seed `merkle.rs` trees; roots become `AttestationBatch`es, STH `TreeHead`s (`log.rs`), and cross-anchor payloads (`federation.rs`); `verify_proof_bundle` re-assembles and checks the whole chain offline.
- **Exit**: proofs/attestations serialize to JSON via `serde_hex` adapters and leave the crate as `VerifyResponse`/`ProofBundleVerification`/`SignedTreeHead` payloads.

## Integration

- `types.rs` feeds every consumer's wire contract (node, gateway, cli); `crypto.rs` + `bls.rs` power node signing and gateway/cli verification; `log.rs` powers the auditor's STH-chain walk and the gateway's STH endpoint; `federation.rs` powers gateway cross-anchoring and cli's offline `verify_proof_bundle`; `external_anchors.rs` feeds the gateway's anchoring driver and cli's display; `error.rs` types are mapped to HTTP by the gateway's `AppError`.
- Nothing below this directory is consumed externally; the crate root (`lib.rs`) is the only boundary consumers see.

## Modules

### lib.rs
- **Responsibility:** module declarations + the entire public API re-exported at the crate root.
- **Key items:** re-exports for `types`, `crypto`, `error`, `merkle`, `log`, `federation`, `bls`, `signature_scheme`, `external_anchors`.
- **Consumed by:** all four consumers import from `witness_core::` root only.

### types.rs
- **Responsibility:** the domain model — the signed payload, its signature envelope, network config, request/response wire types, and Freebird types. **Security-sensitive: `Attestation::to_bytes()` is the canonical signing message** (`hash ‖ ts ‖ len(network_id) ‖ network_id ‖ sequence`).
- **Key types/functions:** `Attestation` (`new`, `to_bytes`, `Display`), `WitnessSignature`, `SignedAttestation` (`new`, `new_with_aggregated`, `add_signature`, `signature_count`, `is_aggregated`), `WitnessInfo` (`auth_token` `skip_serializing`), `NetworkConfig::validate` (operational config) and `NetworkVerificationConfig::validate` (secret-free trust anchor) + `find_witness`, `TimestampRequest`/`TimestampResponse`, `CreateAttestationRequest`, `AttestationJobStatus` (`Pending`/`Retryable`/`Confirmed`/`Failed`), `AttestationJobResponse`, `VerifyRequest`/`VerifyResponse`, `SignRequest`/`SignResponse`, `FreebirdToken`/`FreebirdConfig`.
- **Consumed by:** node (SignRequest/SignResponse), gateway (job + SignRequest + Freebird), cli (job + Freebird + SignResponse), and every module in this crate.

### crypto.rs
- **Responsibility:** Ed25519 sign/verify primitives and complete signed-attestation verification against a secret-free `NetworkVerificationConfig`. **Security-sensitive (signing + verification).**
- **Key functions:** `generate_keypair`, `sign_attestation`, `verify_signature`, `verify_signed_attestation` (dispatches `MultiSig`/Ed25519 and `Aggregated`/BLS branches; rejects duplicate signers via `HashSet`; enforces threshold; returns verified count), `constant_time_eq` (`subtle` ct_eq), `hash_content` (SHA-256), `encode_public_key`/`decode_public_key` (hex ↔ Ed25519).
- **Consumed by:** node (signing), gateway (verification), cli (offline verification), `log.rs` (STH verification delegates here).

### bls.rs
- **Responsibility:** BLS12-381 signing, verification, and aggregation via `blst::min_sig` (48-byte compressed G1 signatures, 96-byte compressed G2 public keys, fixed DST `WITNESS_BLS_SIG_…`). **Security-sensitive (signing + verification + aggregation).**
- **Key functions:** `generate_bls_keypair` (OsRng IKM → `key_gen`, IKM zeroized), `sign_attestation_bls`, `verify_signature_bls`, `aggregate_signatures_bls`, `verify_aggregated_signature_bls` (`AggregatePublicKey` over the signing subset), `encode/decode_bls_public_key`, `encode/decode_bls_secret_key` (zeroize-enabled secret material).
- **Consumed by:** node (BLS signing + secret-key decode), gateway (aggregation + per-witness verify), `crypto.rs` (BLS branch).

### merkle.rs
- **Responsibility:** RFC 9162 (§2.1) Merkle Tree Hash, inclusion proofs (PATH), and consistency proofs (PROOF) with position-aware verification. **Security-sensitive (proof verification).**
- **Key types/functions:** `MerkleProof` (leaf, siblings bottom-up, `leaf_index`, `tree_size`, `root`), `ConsistencyProof`, `empty_root`, `hash_leaf`, `merkle_tree_hash`, `inclusion_path`, `consistency_path`, `verify_inclusion` (walks with index/size alignment, rejects off-the-top paths), `verify_consistency` (prepends `first_hash` for power-of-2 first sizes; accepts empty proof for empty old tree), `MerkleTree` builder; `pub(crate) hex_bytes_vec` adapter.
- **Consumed by:** `log.rs` (verify_consistency/verify_inclusion), `federation.rs` (batch-inclusion check in `verify_proof_bundle`), gateway (batch tree roots/proofs).

### log.rs
- **Responsibility:** RFC 9162-style Signed Tree Head and consistency-chain verification — the audit path proving no history rewrite. **Security-sensitive (STH verification).**
- **Key types/functions:** `STH_DOMAIN` (bumping it is a hard fork of the scheme), `TreeHead` (`signing_digest` with length-prefixed `network_id`, `to_attestation`), `SignedTreeHead`, `verify_signed_tree_head` (network-id match + digest equality + threshold sig), `LogConsistencyProof`, `verify_log_consistency` (both STHs then RFC 9162 §2.1.4.2), `verify_inclusion_against_sth`.
- **Consumed by:** witness-auditor (STH/consistency walking), gateway (STH publish/verify), cli.

### signature_scheme.rs
- **Responsibility:** the two network signature schemes and the untagged signature container on the wire. **Security-sensitive (serialization).**
- **Key items:** `SignatureScheme` (serde lowercase; `Ed25519` default, `BLS`), `AttestationSignatures` (`#[serde(untagged)]`: `MultiSig { signatures: Vec<WitnessSignature> }` | `Aggregated { signature, signers }`), constructors, `signer_count`, `is_aggregated`.
- **Consumed by:** `types.rs`, `crypto.rs`, gateway, node.

### federation.rs
- **Responsibility:** Phase-2 federation — batch types, cross-anchor verification, and the four-layer offline `ProofBundle` verifier. Verification logic is **security-sensitive**; data types are not.
- **Key types/functions:** `AttestationBatch`, `CrossAnchor`, `verify_cross_anchor` (hash↔merkle_root, network-id, peer-config, threshold sig), `FederationConfig`, `PeerNetworkInfo` (auth tokens `skip_serializing`), `CrossAnchorRequest`/`Response`, `FederatedAttestation`, `FederatedVerifyRequest`/`Response`, `VerificationLevel` (`None`/`Basic`/`Batched`/`Federated{peer_count}`), `BatchInclusion`, `ProofBundle`, `ProofVerificationConfig`, `verify_proof_bundle` (per-layer results; hard error only if the home threshold sig fails), `ProofBundleVerification`.
- **Consumed by:** gateway (batching/cross-anchoring), cli (`verify_proof_bundle`), `external_anchors.rs` (depends on `AttestationBatch`).

### external_anchors.rs
- **Responsibility:** Phase-3 external anchoring — provider types, configuration, and proof payload shapes. Types only; no outbound calls (the SSRF-filtered networking lives in the gateway).
- **Key types:** `AnchorProviderType` (`InternetArchive`/`Trillian`/`DnsTxt`/`Blockchain`), `AnchorProviderConfig` (flattened provider-specific `serde_json::Value`), `ExternalAnchorsConfig` (`anchor_period` default 3600, `minimum_required` default 1), `ExternalAnchorProof`, `AnchoredBatch`, `AnchorRequest`, `AnchorResponse`.
- **Consumed by:** gateway (anchoring driver + provider dispatch), cli (proof display), `federation.rs` (`ExternalAnchorProof` in `ProofBundle`).

### serde_hex.rs
- **Responsibility:** custom serde adapters encoding raw bytes as lowercase hex on the wire. **Security-sensitive (wire serialization).**
- **Key items:** `array32` (hash/root `[u8; 32]` fields), `vec` (signature `Vec<u8>` fields), both enforcing exact-length decode where applicable.
- **Consumed by:** `types.rs`, `signature_scheme.rs`, `federation.rs`, `log.rs` (`TreeHead`).

### error.rs
- **Responsibility:** the crate-wide error enum and `Result` alias.
- **Key items:** `WitnessError` (`InvalidSignature`, `InsufficientSignatures{got,required}`, `InvalidPublicKey`, `InvalidHash`, `WitnessNotFound`, `DuplicateSigner`, `SerializationError`, `NetworkError`, `InvalidTimestamp`), `Result<T>`.
- **Consumed by:** every module in this crate; the gateway maps `WitnessError` → HTTP via `AppError`.
