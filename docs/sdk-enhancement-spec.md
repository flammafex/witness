# SDK Enhancement Spec — Witness

**Scope:** Concrete enhancement specification for the Witness SDK, so that consumers
(Scarcity, Clout, Rendezvous, Prestige, and future clients) never compose bespoke gateway
clients or reimplement Witness cryptography.

**Status:** Current implementation specification for the Witness SDKs. It supersedes
the earlier "Spec 2 — Witness" draft, which omitted endpoints its headline features
depend on and underspecified the TypeScript crypto port. This revision is implementable
as-is.

**Explicitly out of scope:**

- A shared cross-primitive client package. The Witness SDK is enhanced independently.
- The gateway↔witness-node signing protocol (`POST /v1/sign`) — internal operator
  surface, not client API.
- Peer-facing routes (`POST /v1/federation/anchor`), `/metrics`, and `/admin/*` — these
  are documented for completeness but are **not** part of the client SDK surface.
- Database migrations — this spec adds none.

**Repo constraints that apply to all work below** (per `AGENTS.md` / `CONTRIBUTING.md`):

- Crate boundaries are strict: `witness-core` is the shared trust root; client crates are
  HTTP clients only and contain no signing or new crypto logic.
- Workspace dependencies are centralized in root `Cargo.toml [workspace.dependencies]`;
  the new crate references them via `.workspace = true`.
- Errors: `thiserror` in libraries, `anyhow` in binaries.
- Security-sensitive areas touched here (wire serialization, `/v1/network` token
  stripping, WebSocket auth) require accepted **and** rejected test vectors.
- All four dev gates must pass: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`,
  `cargo build --release --workspace`.
- Public behavior changes update README / docs/release / CHANGELOG.
- The project is pre-1.0 and unaudited. Publishing SDKs does **not** constitute a
  security audit; both package READMEs must say so.

---

## 1. Goal

Give consumers a published, typed client SDK (Rust + TypeScript) that covers the **full
attestation lifecycle, the transparency-log read surface, push events, and local
verification** — so the four apps stop reimplementing it. "Local verification" means what
`witness-cli` already practices: the gateway's answer is never trusted for the verdict.

Two concrete deletion targets define success:

1. The four apps' duplicated Witness HTTP adapters → replaced by `@witness/sdk`.
2. The four apps' duplicated verification logic
   (`normalizeSignatureSet` / `verifyBLSAggregatedSignature` / `verifyProof` copies) →
   replaced by the SDK's local verification module, whose correctness is mechanically
   pinned to `witness-core` (§4).

---

## 2. Design principles

1. **Local verification is the default.** The plainly-named `verify*` APIs in both SDKs
   run client-side against `witness-core` semantics. Talking to `POST /v1/verify` is
   available only under the explicitly-labelled name `verifyRemote` / `verify_remote`
   ("the gateway's opinion"), documented as non-authoritative.
2. **Trust anchors are caller-controlled.** Verification APIs accept a caller-supplied
   secret-free `NetworkVerificationConfig` (and peer configs). Fetching configs from gateways is a TOFU
   convenience (`WitnessVerifier.fetch(client)`), never a silent default inside a
   `verify` call.
3. **One trust root.** All crypto semantics live in `witness-core`. The Rust SDK
   re-exports them; the TypeScript SDK is mechanically pinned to them via golden
   vectors (§4) or ships them compiled to WASM (§4.3).
4. **Thin client, honest errors.** The SDK maps every gateway failure mode a consumer
   must branch on into a typed error; no string-matching on messages.
5. **Repo conventions are load-bearing** (see header). Where this spec adds public
   wire types, they live in `witness-core` and are shared by gateway, Rust client, and
   the generated TS types.

---

## 3. Pinned wire & crypto parameters (the conformance contract)

Everything in this section is normative for both SDKs and for the golden vectors in §4.
**Where repo comments disagree with code, the code wins.** It currently disagrees in two
places, called out below.

### 3.1 Canonical signing message — `Attestation::to_bytes()`

Source of truth: `crates/witness-core/src/types.rs::Attestation::to_bytes`.

```
hash          32 bytes, raw
timestamp      8 bytes, u64 little-endian (Unix seconds)
network_id_len 4 bytes, u32 little-endian (byte length, not char count)
network_id     variable, UTF-8 bytes
sequence       8 bytes, u64 little-endian
```

All Ed25519 and BLS signing/verification operates on exactly this byte string. The
length prefix prevents byte-collisions between networks with confusable names; the TS
port must reproduce it, including for empty, multibyte, and boundary-length
`network_id`s.

### 3.2 Ed25519 multi-sig

`ed25519-dalek 2.1`; 64-byte signatures over `to_bytes()`; public keys are 32 bytes,
hex-encoded (lowercase) on the wire; one `WitnessSignature { witness_id, signature }`
per signer. Verification enforces: threshold count, **unique** signers, witness-id ∈
config, per-signature validity. Rejected-case vectors must cover duplicate signer,
unknown witness, wrong key, and sub-threshold sets.

### 3.3 BLS12-381 aggregated signatures

Source of truth: `crates/witness-core/src/bls.rs`.

- Library/orientation: `blst::min_sig` — **48-byte compressed G1 signatures and
  96-byte compressed G2 public keys.**
- **DST (verbatim, byte-exact):** `WITNESS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`
- Hash-to-curve suite implied by the DST: SHA-256 XMD, SSWU, random oracle.
- Verification enables subgroup checks on the signature and public key
  (`signature.verify(true, msg, DST, &[], pk, true)`).
- Aggregation is blst `AggregateSignature` aggregation of individual min_sig signatures;
  the aggregate is verified once against the aggregate of the signers' public keys, and
  the signer list is carried in `AttestationSignatures::Aggregated.signers`.
- **Documentation rule:** all public documentation and codemaps must match the
  implementation: `blst::min_sig` uses 48-byte G1 signatures and 96-byte G2
  public keys. The TS port and examples must not describe the opposite
  orientation.

### 3.4 Hashing and hex wire encoding

- SHA-256 via `sha2` for all hashing (content hashes, Merkle nodes, STH digest).
- `witness-core/src/serde_hex.rs`: raw bytes in memory, **lowercase hex strings** on the
  wire (`array32` for `[u8; 32]`, `vec` for `Vec<u8>`). No `0x` prefix. Decoders in both
  SDKs accept mixed-case hex and reject odd-length strings and non-hex characters
  (matching `hex::decode`); all emitters produce lowercase. The verification-path hex
  (e.g. `WitnessVerifier` inputs) inherits this from `witness-core` via WASM.

### 3.5 `AttestationSignatures` — untagged union

Source of truth: `crates/witness-core/src/signature_scheme.rs`
(explicit discriminating decoder).

- Ed25519 multi-sig serializes as `{ "signatures": [ { "witness_id": string, "signature": hex } ] }`.
- BLS aggregated serializes as `{ "signature": hex, "signers": [string] }`.
- **Discrimination rule (normative):** presence of a `signatures` array ⇒ multi-sig;
  presence of both `signature` and `signers` ⇒ aggregated; anything else (including
  payloads with *both* shapes' keys) is a `DecodeError`. The TS SDK must implement this
  as an explicit decoder — never rely on implicit JSON-schema union coercion — and the
  golden vectors must include malformed/ambiguous payloads.

### 3.6 RFC 9162 Merkle tree

Source of truth: `crates/witness-core/src/merkle.rs`.

- Leaves: `SHA-256(0x00 ‖ leaf)` where leaf is the 32-byte attestation hash.
- Internal nodes: `SHA-256(0x01 ‖ left ‖ right)` — **positional, no sorting**.
- Unbalanced trees split at the largest power of two `< n` (the shape that makes
  consistency proofs possible).
- Inclusion and consistency verification are **position-aware**: proofs carry
  `leaf_index`/`tree_size` and verifiers reject index/size mismatches.
- Vectors must cover tree sizes 0..=17 (crossing several split boundaries), wrong index,
  wrong size, and tampered sibling paths.

### 3.7 Signed Tree Head

Source of truth: `crates/witness-core/src/log.rs`.

- The `TreeHead` digest is domain-separated (`STH_DOMAIN` + length-prefixed fields) and
  wrapped in a synthetic `Attestation`, threshold-signed via the normal witness flow.
- `verify_signed_tree_head` therefore shares the attestation verifier; the TS port must
  reproduce the digest construction byte-exactly.

### 3.8 Other normative wire details

| Item | Rule | Source |
|---|---|---|
| `SignatureScheme` | serde lowercase: `"ed25519"` (default), `"bls"` | `signature_scheme.rs` |
| `AttestationJobStatus` | serde snake_case: `pending`, `retryable`, `confirmed`, `failed` | `types.rs` |
| `FreebirdToken` | `{ "token_b64": string }` | `types.rs` |
| `AttestationJobResponse` | `signed_attestation` present **only** when `confirmed`; `next_attempt_at` / `last_error` omitted when null | `types.rs` |
| `AttestationEvent` | `{ "type": string, "hash": hex, "timestamp": u64 }` | `server/mod.rs` (moved to core per §5.1) |
| WS auth envelope | server may first send `{ "type": "auth_required" }`; client replies `{ "token": string }` within 5 s; failure closes with code 4001 | `server/ws.rs` |
| `VerifyResponse` | `{ valid, verified_signatures, required_signatures, message }` | `types.rs` |

All request-path hashes and echoed hash fields are canonical lowercase hex. The
SDKs may accept a caller's byte representation or mixed-case inbound hex, but
emitters and normalized response values use lowercase.

### 3.8.1 Exact integer handling in the TypeScript SDK

Every Rust `u64` wire field is generated as `U64 = number | bigint`; ordinary
bounded integer fields remain ordinary safe-number types. The TypeScript SDK's
central `lossless-json` codec parses safe integer tokens as `number` and exact
values above `Number.MAX_SAFE_INTEGER` through `u64::MAX` as `bigint`. It never
uses a native `JSON.parse` reviver for u64 preservation. Bigints serialize as
unquoted decimal JSON tokens; unsafe JavaScript numbers, fractional/negative
u64 values, and overflow are rejected. Query APIs carrying u64 accept and
format either exact representation.

### 3.9 Stability policy

This section **is** the versioned surface. Any change to §3 is a breaking change:
bump the minor (pre-1.0 semver), regenerate golden vectors, and note it in
`docs/release` + `CHANGELOG.md`. The `/v1/*` HTTP routes are versioned collectively;
additive routes do not require a bump.

---

## 4. Conformance & golden vectors (mandatory, gates TS SDK release)

### 4.1 Vector generation

Add `crates/witness-core/tests/golden_vectors.rs` (plus a small generator bin or
`xtask`) that **emits and then verifies** checked-in JSON vector files under
`sdk/vectors/`:

1. `to_bytes` — fixed attestations incl. empty, multibyte (CJK/emoji), and
   length-prefix-boundary `network_id`s.
2. Ed25519 — sign/verify per §3.2 with accepted + rejected (wrong key, tampered
   message, duplicate signer, unknown witness, below-threshold) cases.
3. BLS — keygen (fixed IKM), sign, aggregate, aggregated verify; rejected: DST mismatch,
   tampered aggregate, wrong signer set, invalid subgroup encodings.
4. Merkle — roots/inclusion/consistency for tree sizes 0..=17; tampered root, wrong
   index, wrong tree size, truncated path.
5. STH — digest construction vectors + threshold-signed STHs per scheme.
6. Wire encodings — both `AttestationSignatures` variants (§3.5), hex adapters (§3.4),
   all enums (§3.8), ambiguous/malformed union payloads.

### 4.2 TS conformance gate

`@witness/sdk` CI runs every vector against the TS implementation. **100% parity is a
release gate.** A property-based differential suite (random attestations → Rust
sign/digest → TS verify, and vice versa) runs in CI on top.

### 4.3 WASM vs. hand-port — decision gate (Phase 0 deliverable)

Before writing the TS crypto module, prototype **both** paths and record the decision in
`docs/release` + the TS package README:

- **Path A (preferred): WASM.** Compile `witness-core`'s verification functions
  (`verify_signed_attestation`, BLS verify/aggregate-verify, Merkle inclusion/consistency,
  STH verification, `verify_proof_bundle` cores) to `wasm32-unknown-unknown` and wrap in
  `@witness/sdk`. Keeps a single trust root — strongly preferred for a pre-1.0, unaudited
  codebase. Risks to validate: `blst` wasm build (requires the portable/no-asm
  configuration), bundle size, browser + Node compatibility.
- **Path B: hand port** on `@noble/curves` (which all four consumers already depend on).
  Permitted only if Path A is infeasible (build failure, or package > 350 KB compressed
  after pruning, or unacceptable consumer toolchain impact). Path B doubles the crypto
  audit surface and **must** pass §4.2 before any release.

Decision criteria, in priority order: (1) vector parity achievable, (2) single trust
root preserved, (3) bundle/toolchain cost. Either path ships behind the same public API
(§6.3), so consumers never observe the choice.

---

## 5. Rust: crate reorganization

### 5.1 Lift shared wire types into `witness-core`

The gateway currently owns several response types that clients must deserialize. Move
them into `witness-core` (`types.rs` or a new `wire` module), adding `Deserialize` where
missing, and re-import in the gateway:

| Type | Today | Change |
|---|---|---|
| `NetworkConfigPublic { id, threshold, signature_scheme, witness_count }` | `witness-gateway/src/server/mod.rs`, `Serialize`-only | Move to core, derive `Serialize + Deserialize` |
| `AttestationEvent { event_type, hash, timestamp }` | `server/mod.rs`, `&'static str` | Move to core as **owned** struct (`String` fields, `#[serde(rename = "type")]`), shared by gateway broadcaster and both SDKs |
| `ProofResponse { hash, proof, index, merkle_root, batch_id }` (`GET /v1/proof/:hash`) | `server/routes.rs`, `Serialize`-only | Move to core as `MerkleProofResponse`, derive `Deserialize` |
| `LogInclusionProofResponse { leaf_index, tree_size, audit_path, sth }` (`GET /v1/log/proof`) | `server/routes.rs`, `Serialize`-only | Move to core, derive `Deserialize` |

**Security-sensitive:** `/v1/network` and `/v1/config` must keep stripping secrets
(`#[serde(skip_serializing)]` on `WitnessInfo::auth_token`, `inbound_auth_token`,
`previous_inbound_auth_token`). Add a regression test asserting no token value appears
in any serialized public response (accepted: full config round-trips locally; rejected:
serialized output contains `auth_token`).

### 5.2 New crate `crates/witness-client`

- Library crate; deps (centralized in root `[workspace.dependencies]`): `witness-core`,
  `reqwest` (rustls), `thiserror`, `tokio`, `serde/serde_json`, `hex`, `tracing`
  (optional, low-noise). WS support behind feature `ws`: `tokio-tungstenite`,
  `futures-util` (new workspace deps — add to root `Cargo.toml`).
- Member list in root `Cargo.toml` gains `crates/witness-client`;
  `witness-cli` depends on it (`path` + `version`, like `witness-core`).

### 5.3 Naming collision resolution

`witness-gateway/src/witness_client.rs` already defines a public `WitnessClient` (the
gateway→node signing client, holding per-witness bearer tokens). Two public
`WitnessClient` types in one workspace is unacceptable ambiguity for a trust-sensitive
API. **Rename the gateway-internal type to `NodeClient`** (touches
`witness_client.rs`, `reconciler.rs`, `batch_manager.rs` and their mock impls — a
mechanical rename, no behavior change). The published `witness-client` crate owns the
`WitnessClient` name for the public, keyless read/write client.

### 5.4 Error model (`thiserror`)

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid hash: {0}")] InvalidHash(String),
    #[error("transport error")] Transport(#[from] reqwest::Error),
    #[error("gateway returned {status}: {body}")] Http { status: u16, body: String },
    #[error("not found: {0}")] NotFound(String),
    #[error("attestation job failed after {attempts} attempt(s): {last_error:?}")]
    JobFailed { hash: String, attempts: u32, last_error: Option<String> },
    #[error("timed out waiting for confirmation of {hash} after {elapsed:?}")]
    ConfirmationTimeout { hash: String, elapsed: std::time::Duration, last_status: AttestationJobStatus },
    #[error("failed to decode gateway response")] Decode(#[from] serde_json::Error),
    #[error("websocket error: {0}")] WebSocket(String),
    #[error("verification failed")] Verification(#[from] witness_core::WitnessError),
}
pub type Result<T> = std::result::Result<T, Error>;
```

HTTP classification rule: 404 on read endpoints → `NotFound`; other non-2xx → `Http`.
(`GET /v1/anchors/:hash` distinguishes *unknown attestation* — 404 → `NotFound` — from
*known but unbatched* — 200 with `[]`. The current CLI normalizes all 404s to empty; the
SDK must not.)

### 5.5 Client surface

```rust
pub struct WitnessClient { /* reqwest::Client + base url */ }

pub struct PollConfig {
    pub interval: Duration,          // default 2s; effective wait never below server hint
    pub timeout: Duration,           // default 180s
    pub respect_next_attempt_at: bool, // default true
}

impl WitnessClient {
    pub fn new(gateway_url: &str) -> Result<Self>;           // 30s default timeout
    pub fn builder(gateway_url: &str) -> WitnessClientBuilder; // timeout, user-agent, etc.

    // Write path. Idempotent: duplicate hashes return the canonical existing job.
    pub async fn create_attestation(&self, hash: [u8; 32],
        freebird_token: Option<FreebirdToken>) -> Result<AttestationJobResponse>;

    // Read path
    pub async fn get_attestation(&self, hash: [u8; 32]) -> Result<AttestationJobResponse>;
    pub async fn wait_for_confirmation(&self, hash: [u8; 32],
        poll: PollConfig) -> Result<SignedAttestation>;
    pub async fn get_bundle(&self, hash: [u8; 32]) -> Result<ProofBundle>;
    pub async fn get_proof(&self, hash: [u8; 32]) -> Result<MerkleProofResponse>;
    pub async fn get_anchors(&self, hash: [u8; 32]) -> Result<Vec<ExternalAnchorProof>>;
    pub async fn health(&self) -> Result<()>;                // {"status":"ok"}

    // Config surfaces (see §5.7 for trust semantics)
    pub async fn public_config(&self) -> Result<NetworkConfigPublic>;   // info only
    pub async fn network(&self) -> Result<NetworkVerificationConfig>;  // secret-free /v1/network
    pub async fn network_from(&self, gateway_url: &str) -> Result<NetworkVerificationConfig>;

    // Transparency log
    pub async fn sth(&self) -> Result<SignedTreeHead>;
    pub async fn sth_at_size(&self, tree_size: u64) -> Result<SignedTreeHead>;
    pub async fn consistency(&self, first: u64, second: u64) -> Result<LogConsistencyProof>;
    pub async fn log_proof(&self, hash: [u8; 32], tree_size: u64) -> Result<LogInclusionProofResponse>;

    // Push (feature = "ws")
    pub async fn subscribe_events(&self, token: Option<String>)
        -> Result<impl futures_core::Stream<Item = Result<AttestationEvent>>>;

    // NON-authoritative; docstring must say "the gateway's opinion; prefer
    // witness_client::verify for a trust-minimizing verdict."
    pub async fn verify_remote(&self, signed: &SignedAttestation) -> Result<VerifyResponse>;
}

// Local verification — the default, trust-minimizing path. Thin re-exports/wrappers
// over witness-core; witness-client never re-implements them.
pub fn verify(signed: &SignedAttestation, config: &NetworkVerificationConfig) -> Result<usize>;
pub fn verify_proof_bundle(bundle: &ProofBundle, config: &ProofVerificationConfig)
    -> Result<ProofBundleVerification>;
pub fn verify_sth(sth: &SignedTreeHead, config: &NetworkVerificationConfig) -> Result<usize>;
pub fn verify_consistency(proof: &LogConsistencyProof, config: &NetworkVerificationConfig) -> Result<()>;
pub fn verify_log_inclusion(proof: &LogInclusionProofResponse, leaf: [u8; 32]) -> Result<()>;
```

### 5.6 `wait_for_confirmation` semantics (normative)

- Poll `get_attestation` until terminal. Effective sleep per iteration:
  `max(poll.interval, attestation.next_attempt_at - now)` when
  `respect_next_attempt_at`, clamped to `poll.timeout` remaining.
- `confirmed` with `signed_attestation` present → `Ok(signed)`. `confirmed` **without**
  a signed attestation is a protocol violation → `Error::Decode`-class error
  (`Decode` with context), never a silent success.
- `failed` → `Error::JobFailed { hash, attempts, last_error }`.
- Timeout → `Error::ConfirmationTimeout` carrying the last observed status.
- Future-cancellation-safe: dropping the future stops polling (no detached tasks).
- Tests: accepted (pending→confirmed), rejected/failure (failed job, timeout, malformed
  confirmed-without-signatures) against an `axum` mock gateway.

### 5.7 Config fetching and trust semantics

- `public_config()` → `/v1/config`; informational (witness count, scheme, threshold).
  **It is not a trust anchor and must be documented as insufficient for verification.**
- `network()` → `/v1/network` (`NetworkVerificationConfig`: full witness public-key
  set plus public federation discovery, with witness endpoints and all bearer
  tokens stripped server-side).
- `network_from(url)` → same route on an arbitrary gateway; required for cross-anchor
  verification, since `verify_proof_bundle` needs a `ProofVerificationConfig { network,
  peers }` to ever reach `VerificationLevel::Federated`.
- Federation guarantees are scoped: the `cross_anchor_threshold` distinct peer
  networks must provide valid cross-anchor signatures, and each peer config must
  be pinned by the caller. Missing/unreachable peers are reported as unverified;
  federation adds independent durability but is not Byzantine consensus or a
  guarantee against colluding operators.
- Verification functions **only** take configs as parameters. Fetch-and-use is the
  caller's explicit choice (TOFU); SDK docs must show the pinned-config pattern first.

### 5.8 CLI refactor

`witness-cli` depends on `witness-client` and deletes `crates/witness-cli/src/client.rs`.
The mock-gateway route-contract tests in that file move into `witness-client`'s test
suite. CLI UX and local-verification behavior are unchanged (the CLI keeps catching
`NotFound` on anchors to render an empty list, preserving current display semantics).

### 5.9 Publishing

- Publish `witness-core` and `witness-client` (crates.io names to be confirmed by
  maintainers). Path+version workspace deps make this mechanical.
- Pre-1.0 semver policy: breaking changes bump minor; `/v1/*` routes versioned
  collectively (§3.9). Publish does not imply security auditing — READMEs must say so.
- Doc obligations: README (client-facing quickstart incl. pinned-config verification
  example), docs/release, CHANGELOG.

---

## 6. TypeScript: `@witness/sdk`

### 6.1 Packaging

```jsonc
{
  "name": "@witness/sdk",
  "main": "./dist/index.js",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" },
    "./verify": { "types": "./dist/verify/index.d.ts", "import": "./dist/verify/index.js" }
  },
  "files": ["dist", "README.md", "LICENSE"],
  "sideEffects": false,
  "license": "Apache-2.0",
  "engines": { "node": ">=22" },
  "publishConfig": { "access": "public" }
}
```

ESM-first, `fetch` injectable (Node 22+ and browsers), no Node-only APIs in the core
path, direct use of the platform WebSocket API, and `prepublishOnly` must run build, tests, typecheck, the authoritative generation-drift script, and `npm pack --dry-run`
(tests include the §4.2 vector gate). The `verify` subpath keeps crypto code out of
bundles that only talk HTTP. The package is public but pre-1.0: publishing does not
constitute an audit or imply Byzantine-fault tolerance.

### 6.2 Client surface (mirrors §5.5)

```ts
export class WitnessClient {
  constructor(config: { gatewayUrl: string; fetch?: typeof fetch; timeoutMs?: number })

  createAttestation(hash: Uint8Array /* exactly 32 bytes */,
    opts?: { freebirdToken?: FreebirdTokenInput }): Promise<AttestationJob>
  getAttestation(hash: Uint8Array): Promise<AttestationJob>
  waitForConfirmation(hash: Uint8Array, poll?: PollConfig): Promise<SignedAttestation>
  getBundle(hash: Uint8Array): Promise<ProofBundle>
  getProof(hash: Uint8Array): Promise<MerkleProofResponse>
  getAnchors(hash: Uint8Array): Promise<ExternalAnchorProof[]> // 404 → NotFoundError
  health(): Promise<void>

  publicConfig(): Promise<NetworkConfigPublic>  // informational; NOT a trust anchor
  network(): Promise<NetworkVerificationConfig> // secret-free trust anchor shape
  networkFrom(gatewayUrl: string): Promise<NetworkVerificationConfig>

  sth(): Promise<SignedTreeHead>
  sthAtSize(treeSize: U64): Promise<SignedTreeHead>
  consistency(first: U64, second: U64): Promise<LogConsistencyProof>
  logProof(hash: Uint8Array, treeSize: U64): Promise<LogInclusionProofResponse>

  verifyRemote(signed: SignedAttestation): Promise<VerifyResponse> // gateway's opinion

  subscribeEvents(opts?: SubscribeOptions): EventsSubscription // §6.4
}

export type PollConfig = { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal }
// defaults: intervalMs 2000, timeoutMs 180_000; honors next_attempt_at as in §5.6;
// job 'failed' → JobFailedError; timeout → ConfirmationTimeoutError; signal aborts.
```

`type U64 = number | bigint` is generated for Rust `u64` wire fields. The central
`lossless-json` codec must be used for every protocol response/body, WebSocket
event, and WASM JSON input; native `JSON.parse` must not be used to preserve u64.
Wire types are generated (§6.6) and keep serde's snake_case field names; only
SDK-constructed inputs use camelCase normalization. **Freebird token harmonization:**
`FreebirdTokenInput = string | { tokenB64: string }` — a bare string is sugar for
`{ tokenB64 }`; the SDK always serializes the wire shape `{ "token_b64": ... }`
(matching Rust's `FreebirdToken`).

### 6.3 Local verification — the default path

```ts
export class WitnessVerifier {
  /** Pinned trust anchor. Peers required for cross-anchor (Federated) verification. */
  constructor(network: NetworkVerificationConfig, peers?: NetworkVerificationConfig[])
  /** Explicit TOFU convenience: client.network() (+ networkFrom for each cross-anchor peer). */
  static async fetch(client: WitnessClient): Promise<WitnessVerifier>

  verifyAttestation(signed: SignedAttestation): number   // verified sig count
  verifyBundle(bundle: ProofBundle): ProofBundleVerification // level: none/basic/batched/federated
  verifySth(sth: SignedTreeHead): number
  verifyConsistency(proof: LogConsistencyProof): void
  verifyLogInclusion(proof: LogInclusionProofResponse, leafHex: string): void
}
```

`verifyLogInclusion` takes the queried hash (`leafHex`) because
`LogInclusionProofResponse` deliberately omits the leaf — the caller supplies the
hash they asked the log to prove.

Failures throw `VerificationError` with a machine-readable `reason` (sub-threshold,
duplicate signer, unknown witness, bad signature, index/size mismatch, ambiguous
signature encoding). Implementation per the §4.3 decision (WASM or noble + vector
gate). Barrel also exports the explicit `decodeAttestationSignatures` discriminating
decoder (§3.5): `signatures` alone is multi-sig; `signature` plus `signers` is
aggregated; partial or ambiguous union payloads are rejected as `DecodeError`.

### 6.4 WebSocket events

```ts
export type SubscribeOptions = {
  token?: string
  signal?: AbortSignal
  reconnect?: { maxRetries?: number; baseDelayMs?: number } // default: infinite, exp backoff + jitter
  onEvent: (ev: AttestationEvent) => void
  onError?: (err: WitnessError) => void
}
export interface EventsSubscription { close(): void }
```

Implements the auth handshake (§3.8): whenever `{"type":"auth_required"}` is
received, a supplied token is replied with `{"token": ...}` within the server's
5 s window. Without a token, the client reports `AuthRequiredError` and never
reconnects. A token-supplied connection may receive an event before a challenge;
that event is delivered normally. Close code 4001 also reports
`AuthRequiredError` with no auto-retry. Reconnects re-run the handshake, while
explicit close and abort cancel pending reconnect timers. `EventSource`/polling
fallback is intentionally **not** provided — `waitForConfirmation` covers that need.

### 6.5 Error hierarchy

```ts
export class WitnessError extends Error { readonly code: WitnessErrorCode }
export class TransportError extends WitnessError
export class TimeoutError extends TransportError
export class AbortError extends TransportError
export class HttpStatusError extends WitnessError { status: number; body: string }
export class NotFoundError extends WitnessError
export class JobFailedError extends WitnessError { attempts: number; lastError?: string }
export class ConfirmationTimeoutError extends WitnessError { lastStatus: AttestationJobStatus }
export class DecodeError extends WitnessError        // incl. §3.5 ambiguity, bad hex
export class VerificationError extends WitnessError { reason: VerificationFailureReason }
export class AuthRequiredError extends WitnessError
export type WitnessErrorCode = "transport" | "http" | "not_found" | "job_failed"
  | "confirmation_timeout" | "decode" | "verification" | "auth_required"
```

### 6.6 Type generation (schema from serde, never hand-maintained)

- Add `schemars` derives to `witness-core` wire types (behind no feature; cheap).
- A generator bin/xtask emits JSON Schema; `json-schema-to-typescript` (or
  equivalent) produces the TS interfaces; output is checked into `@witness/sdk`.
- **Authoritative drift gate:** from the workspace root,
  `./scripts/check-generated-drift.sh` runs `gen_ts_types`, TS type generation,
  `gen_vectors`, and `gen_openapi --features openapi`, then requires zero diff
  for `sdk/ts/schema/schema.json`, `sdk/ts/src/types.generated.ts`, all checked-in
  vectors, and `docs/openapi.yaml`. CI and the TS `prepublishOnly` gate invoke
  this script; a dirty tree with intended generated changes must fail rather
  than weaken the comparison.

### 6.7 Security notes

- The SDK accepts a caller-supplied gateway URL and performs **no** URL filtering —
  the gateway-side SSRF hardening protects server-initiated traffic, not client
  endpoint choice. Documented, not "fixed".
- Never log Freebird tokens or WS auth tokens.
- Document that verification against a config fetched from the same gateway is
  trust-on-first-use; recommend pinning `network.json`-derived configs.

---

## 7. Gateway docs: OpenAPI + AsyncAPI

1. OpenAPI via `utoipa` annotations in `witness-gateway` (feature `openapi`), emitted
   as a checked-in `docs/openapi.yaml` with a CI drift test (regenerate == zero diff).
   Include type notes for §3.4–3.5 encoding rules; mark untagged unions explicitly.
2. Client-facing document covers: `/health`, `/v1/config`, `/v1/network`,
   `POST /v1/attestations`, `GET /v1/attestations/:hash`, `POST /v1/verify`,
   `/v1/proof/:hash`, `/v1/bundle/:hash`, `/v1/anchors/:hash`, `/v1/log/sth`,
   `/v1/log/sth/:tree_size`, `/v1/log/consistency`, `/v1/log/proof`.
3. Operator-facing routes (`/v1/federation/anchor`, `/metrics`, `/admin/*`) are
   excluded from the client OpenAPI document (or tagged `internal`) — they are
   auth-gated peer/ops surfaces, not SDK territory.
4. `/ws/events` is documented in a small **AsyncAPI** document (OpenAPI does not model
   WebSocket protocols), including the `auth_required` handshake, the 5 s window, close
   code 4001, and the `AttestationEvent` schema.

---

## 8. Endpoint coverage matrix (completeness contract)

| Route | Rust | TS | Notes |
|---|---|---|---|
| `GET /health` | `health()` | `health()` | `{"status":"ok"}` |
| `GET /v1/config` | `public_config()` | `publicConfig()` | informational only |
| `GET /v1/network` | `network()` / `network_from()` | `network()` / `networkFrom()` | secret-free `NetworkVerificationConfig`; explicit TOFU fetch |
| `POST /v1/attestations` | `create_attestation()` | `createAttestation()` | idempotent on duplicate hash |
| `GET /v1/attestations/:hash` | `get_attestation()` | `getAttestation()` | |
| (poll loop) | `wait_for_confirmation()` | `waitForConfirmation()` | §5.6 semantics |
| `GET /v1/bundle/:hash` | `get_bundle()` | `getBundle()` | |
| `GET /v1/proof/:hash` | `get_proof()` | `getProof()` | type lifted per §5.1 |
| `GET /v1/anchors/:hash` | `get_anchors()` | `getAnchors()` | 404 ⇒ `NotFound` |
| `GET /v1/log/sth` | `sth()` | `sth()` | |
| `GET /v1/log/sth/:tree_size` | `sth_at_size()` | `sthAtSize()` | |
| `GET /v1/log/consistency` | `consistency()` | `consistency()` | `first ≥ 1`, `first ≤ second` |
| `GET /v1/log/proof` | `log_proof()` | `logProof()` | type lifted per §5.1 |
| `WS /ws/events` | `subscribe_events()` | `subscribeEvents()` | §6.4 handshake |
| `POST /v1/verify` | `verify_remote()` | `verifyRemote()` | **non-authoritative** |
| local verify | `verify*()` fns | `WitnessVerifier` | **default verification path** |
| `POST /v1/federation/anchor` | — | — | operator-only, out of scope |
| `/metrics`, `/admin/*` | — | — | operator-only, out of scope |

---

## 9. Version compatibility

| SDK | Gateway `/v1` wire | Notes |
|---|---|---|
| 0.8.x | as of workspace 0.8.0 | Phase 1/2 SDKs; publishable TypeScript package |
| bump rule | additive routes: none needed; any §3 change: SDK minor bump + new vectors | §3.9 |

Both package READMEs carry the pre-1.0 / unaudited / not-Byzantine-fault-tolerant
disclaimer and state that SDK publication is not an audit.

---

## 10. Implementation phases

- **Phase 0 — crypto path.** Golden-vector generator + checked-in vectors (§4.1–4.2);
  WASM feasibility prototype vs. noble prototype; decision recorded (§4.3).
  *Gate: vectors pass in Rust; decision documented.*
- **Phase 1 — Rust SDK.** §5.1 type moves (+ token-stripping regression tests),
  internal rename to `NodeClient` (§5.3), `crates/witness-client` with full §5.5
  surface, error model (§5.4), CLI refactor (§5.8), publish plumbing (§5.9).
  *Gate: CLI behavior unchanged; new tests accepted+rejected; four dev gates green.*
- **Phase 2 — TS SDK.** Typegen pipeline + drift CI (§6.6), client surface (§6.2),
  verifier per Phase-0 decision (§6.3), WS (§6.4), errors (§6.5), packaging (§6.1).
  *Gate: 100% vector parity; conformance suite green.*
- **Phase 3 — docs & release.** OpenAPI/AsyncAPI + drift tests (§7), READMEs,
  docs/release, CHANGELOG, compat matrix (§9), npm packaging, and security/codemap
  corrections published. *Gate: `npm pack --dry-run` contains only the intended
  dist/readme/license artifacts and all package checks pass.*

---

## 11. Acceptance criteria

1. `cargo add witness-client` works; a consumer submits, polls (or subscribes), fetches
   a bundle, and verifies **locally** — including reaching `VerificationLevel::Federated`
   via secret-free `network_from()` peer configs — with no raw HTTP and no
   `witness-core` internals.
2. `npm install @witness/sdk` works; the same lifecycle completes in TS, with local
   verification byte-parity proven by the checked-in golden vectors in CI. The
   package dry-run contains `dist/`, `README.md`, and Apache-2.0 `LICENSE`.
3. `waitForConfirmation` / `wait_for_confirmation` behave per §5.6, including typed
   `JobFailed` and timeout errors honoring `next_attempt_at`.
4. WebSocket events are consumable through the SDKs, including the token-auth
   handshake and 4001 handling — no consumer-written WS code.
5. TS types regenerate from `witness-core` serde definitions with a zero-diff CI gate.
6. The four apps' duplicated Witness adapters **and** their duplicated verification
   modules are deleted in favor of `@witness/sdk`.
7. Error handling is typed in both SDKs; no consumer string-matches error messages.
8. `witness-cli` builds on `witness-client`; its UX and local-verification verdicts
   are unchanged; the duplicate `WitnessClient` name no longer exists in the workspace.
9. Token-stripping regression tests prove `/v1/config` and `/v1/network` never
   serialize `auth_token` / federation tokens after the §5.1 type moves;
   `/v1/network` exposes `NetworkVerificationConfig` only.
10. READMEs document the pinned-config verification pattern first and carry the
    pre-1.0/unaudited disclaimer.
</content>
</invoke>
