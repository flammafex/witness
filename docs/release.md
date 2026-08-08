# Release Packaging

Witness releases are tag-driven. Use annotated version tags:

```bash
git tag -a v0.6.0 -m "Witness 0.6.0"
git push origin v0.6.0
```

Pushing a `v*` tag triggers the release workflow
(`.forgejo/workflows/release.yml`) which builds a native x86_64 Linux binary
archive and publishes it to the Forgejo releases page with SHA-256 checksums.
Public production deployments should pin version tags or image digests instead
of `latest`.

## Release Artifacts

Each release includes one tarball:

- `witness-v0.6.0-x86_64-linux-gnu.tar.gz`

Each tarball contains:

- `bin/witness-node`
- `bin/witness-gateway`
- `bin/witness`
- `bin/witness-auditor`
- `configs/`, `docs/`, `examples/`
- `README.md`, `PRODUCTION.md`, `TESTING.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE`

A `SHA256SUMS` file is published alongside the tarballs.

## Container Images

Container images are built separately by `.forgejo/workflows/docker.yml` on
pushes to `main` (not on tags). The workflow builds native `linux/amd64` images:

```text
git.carpocratian.org/sibyl/witness-node:<version>
git.carpocratian.org/sibyl/witness-gateway:<version>
```

Recommended tags:

- full version, such as `0.6.0`
- minor version, such as `0.6`
- commit SHA for every build

Production deployments should pin a version tag or digest.

The Docker workflow builds `linux/amd64` images with BuildKit provenance and
SBOM attestations. Image signing requires `COSIGN_PRIVATE_KEY` and signs the
pushed manifest digest with cosign.

## GitHub Mirror

The Forgejo repository mirrors to GitHub, but only git data syncs — branches,
tags, and commits. Release objects and binary assets are not mirrored. Download
binaries from the Forgejo releases page.

## Notable behavior changes

- **`AttestationSignatures` strict discrimination (spec §3.5):** deserialization
  now rejects ambiguous payloads (those carrying both the multi-sig `signatures`
  key and either aggregated key) as a `DecodeError`, instead of the previous
  `#[serde(untagged)]` first-variant-wins acceptance as `MultiSig`. `Serialize`
  output is byte-identical; only pathological inbound payloads are affected.
  Golden vectors regenerated (`wire.json` version 2). **Security-sensitive.**

- **Secret-free verification config:** `GET /v1/network` documents and returns
  the public `NetworkVerificationConfig` trust-anchor shape. Witness endpoints,
  witness bearer tokens, and federation authentication tokens are not part of
  the response. `GET /v1/config` remains informational only.
- **Federation guarantees:** a `Federated` proof requires valid cross-anchor
  signatures from configured peer networks and pinned peer verification
  configs. The configured peer threshold is an independent durability layer,
  not Byzantine consensus or protection from colluding operators.
- **TypeScript numeric/wire contract:** generated Rust `u64` fields are
  `U64 = number | bigint`; the central `lossless-json` codec preserves exact
  values through `u64::MAX`, emits unquoted bigint numbers and lowercase hash
  hex, and rejects unsafe numeric inputs. Query methods accept exact U64 values.
- **WebSocket contract:** `auth_required` is always recognized. A tokenless
  challenge raises `AuthRequiredError` without reconnecting; a supplied token
  is replied with and the stream continues. Explicit close/abort cancels
  reconnect timers.

## SDK Version Compatibility

The Witness SDKs (`witness-client` on crates.io, `@witness/sdk` on npm) are
versioned against the gateway's `/v1/*` wire protocol. The `/v1/*` routes are
versioned collectively (spec §3.9).

| SDK | Gateway `/v1` wire | Notes |
|---|---|---|
| 0.8.x | as of workspace 0.8.0 | current pre-1.0 release; TS package is publishable |
| bump rule | additive routes: none needed; any §3 change: SDK minor bump + new vectors | §3.9 |

**Bump rule (spec §3.9):** any change to the pinned wire/crypto parameters in
`docs/sdk-enhancement-spec.md` §3 is a breaking change — bump the SDK minor
version (pre-1.0 semver), regenerate the golden vectors in `sdk/vectors/`, and
note it in `docs/release` + `CHANGELOG.md`. Additive `/v1/*` routes do **not**
require a bump.

Both package READMEs (`crates/witness-client/README.md` and
`sdk/ts/README.md`) carry the pre-1.0 / unaudited / not-Byzantine-fault-tolerant
disclaimer and state that SDK publication is not an audit.

## SDK Publication

The Witness SDK work (spec `docs/sdk-enhancement-spec.md`) adds three
publishable artifacts alongside the existing binaries:

- **`witness-client`** (`crates/witness-client`) — the Rust client SDK. A
  library crate covering the full attestation lifecycle, the transparency-log
  read surface, optional WebSocket push, and local verification (thin wrappers
  over `witness-core`). `witness-cli` is built on it.
- **`@witness/sdk`** (`sdk/ts/`) — the TypeScript SDK. ESM-first package with a
  `./verify` subpath, a WASM-compiled local verifier, WebSocket support, and a
  typed error hierarchy. Types are generated from `witness-core` serde
  definitions (zero-diff CI gate). It uses the central lossless JSON codec for
  protocol responses, events, and WASM inputs; its strict signature-union
  decoder rejects ambiguous shapes.
- **`witness-core-wasm`** (`crates/witness-core-wasm`) — the WASM build of
  `witness-core`'s verification functions that backs `@witness/sdk`'s local
  verifier (single trust root, spec §4.3 Path A). Not published to crates.io;
  its `.wasm` is checked in and shipped inside `@witness/sdk`.

**Publication plan (spec §5.9):** publish `witness-core` and `witness-client`
to crates.io (names to be confirmed by maintainers) and `@witness/sdk` to npm.
Path+version workspace deps make the Rust publish mechanical. Pre-1.0 semver
policy: breaking changes bump the minor; `/v1/*` routes are versioned
collectively (§3.9). **Publishing does not imply a security audit** — both
package READMEs say so.

### TypeScript npm publication

From `sdk/ts/`, the npm release gate is intentionally repeatable and inspectable:

```sh
npm install
(cd ../.. && ./scripts/check-generated-drift.sh)
npm run build
npm test
npm run typecheck
npm pack --dry-run
npm publish --access public
```

`prepublishOnly` runs the build, tests, typecheck, and `npm pack --dry-run`.
The package is scoped-public, targets Node 22+, includes `dist/`, `README.md`,
and the repository's Apache-2.0 `LICENSE`, and remains subject to the pre-1.0
minor-bump policy. Review the dry-run file list for accidental secrets, source
artifacts, and missing WASM before publishing.

## Pre-Tag Checklist

- Update workspace crate versions in `Cargo.toml`.
- Update `Cargo.lock`.
- Update `CHANGELOG.md`.
- Run `cargo fmt --all -- --check`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Run `cargo test --workspace`.
- Run `cargo build --release --workspace`.
- From `sdk/ts/`, run `npm install`, `npm run build`, `npm test`,
  `npm run typecheck`, and `npm pack --dry-run` before `npm publish --access public`.
- Smoke-test Docker images if deployment assets changed.
- Exercise the example network with `./examples/setup.sh`,
  `./examples/start.sh`, `./examples/demo.sh`, and `./examples/stop.sh`.
- Test Freebird consuming mode against the current Freebird verifier.
- Check release archives for accidental secrets or generated local state.

## Verification

Before installing a release archive, verify checksums:

```bash
sha256sum -c SHA256SUMS
```

When image signing is enabled, verify image signatures before deployment and
record the digest in deployment manifests.

## Current Gaps

- Keyless signing is not configured; image signing currently expects a cosign
  private key secret.
- Binary releases are not signed (checksums only).

---

# SDK Phase 0 Decision — WASM vs. hand-port for the TypeScript crypto module

**Status:** Decision recorded. This is the Phase 0 deliverable of
`docs/sdk-enhancement-spec.md` §4.3. The TypeScript package README
(`sdk/ts/README.md`) references this section.

**Decision: Path A — WASM.** Compile `witness-core`'s verification functions to
`wasm32-unknown-unknown` and wrap them in `@witness/sdk`. Path B (hand port on
`@noble/curves`) is feasible but is **not** required, and per §4.3 is only
permitted if Path A is infeasible — it is not.

## Path A prototype result (WASM)

A throwaway prototype crate (outside the repo, under a temp dir) compiled
`witness-core` to `wasm32-unknown-unknown` in release mode.

- **Toolchain:** `wasm32-unknown-unknown` target installed; `wasm-pack` present;
  `wasm-bindgen` not installed (not needed for the feasibility probe).
- **Build: SUCCESS.** `witness-core` compiled to `wasm32-unknown-unknown`.
- **`blst` wasm status: SUPPORTED.** `blst`'s `build.rs` detects `wasm32` and
  switches to no-`std`, defines `__BLST_NO_ASM__` (no assembly), adds
  `-ffreestanding`, and sets `SCRATCH_LIMIT`. `blst` compiled cleanly for wasm.
- **Only blocker found: `getrandom`.** `witness-core`'s keygen functions
  (`generate_bls_keypair`, `generate_keypair`) use `rand::OsRng`, which pulls in
  `getrandom`. On `wasm32-unknown-unknown`, `getrandom` requires either its `js`
  feature (wasm-bindgen) or a custom shim. The **verification** functions never
  call OsRng, so a verification-only build can gate keygen behind a feature or
  provide a shim. This is a well-understood, solvable issue — **not** a
  feasibility blocker.
- **Toolchain note:** Apple's system `clang` lacks the `wasm32` target; the C
  compiler must be a wasm-capable clang (Homebrew `llvm` or `wasi-sdk`). This is
  a build-environment requirement, not a blocker.
- **Size:** 245,949 bytes raw (~240 KB); 91,279 bytes gzipped (~89 KB). This
  includes the **full** `witness-core` (all modules, including keygen,
  federation, and external anchors). A pruned verification-only subset would be
  smaller. Well under the 350 KB compressed criterion.
- **Runtime:** the module instantiates in Node 22+ with **no imports** (no JS
  shim required for the verification path). Browser + Node compatible.

## Path B feasibility assessment (`@noble/curves`)

- **Ed25519:** `@noble/curves/ed25519` — available.
- **BLS12-381:** `@noble/curves/bls12-381` — available. Its `shortSignatures`
  variant is exactly the `min_sig` orientation witness uses (48-byte G1
  signatures, 96-byte G2 public keys). Custom DST is supported via
  `hash(msg, DST)`.
- **SHA-256:** `@noble/hashes` — available.
- **Merkle / STH digest:** pure JS — available.
- **Audit status:** noble-curves has been independently audited (Cure53,
  Kudelski, Trail of Bits).

**Parameters that must be pinned for byte-parity** (from spec §3):

- BLS DST (byte-exact): `WITNESS_BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`
  (`crates/witness-core/src/bls.rs`).
- `min_sig` orientation: 48-byte G1 signatures, 96-byte G2 public keys.
- Subgroup checks enabled on signature and public key.
- Untagged-union discrimination (§3.5): presence of a `signatures` array ⇒
  multi-sig; presence of both `signature` and `signers` ⇒ aggregated; anything
  else (including payloads with both shapes' keys) ⇒ `DecodeError`.
- Hex encoding (§3.4): lowercase, no `0x` prefix; decoders accept mixed-case
  input and reject odd-length/non-hex strings; emitters canonicalize lowercase.
- RFC 9162 Merkle domain separators (§3.6): leaves `SHA-256(0x00 ‖ leaf)`,
  internal nodes `SHA-256(0x01 ‖ left ‖ right)`, positional (no sorting).
- STH domain separation (§3.7): `STH_DOMAIN = b"witness-sth-v1\x00"` +
  length-prefixed fields.
- Canonical signing message (§3.1): `hash(32) ‖ timestamp(8 LE) ‖
  network_id_len(4 LE) ‖ network_id ‖ sequence(8 LE)`.

**Verdict:** Path B is feasible with no hard blockers, but it doubles the crypto
audit surface and must pass the §4.2 vector-parity gate before any release.

## Decision rationale (against the §4.3 criteria, in priority order)

1. **Vector parity achievable — yes (both).** Path A trivially achieves parity
   because the exact Rust code ships to the browser; there is no reimplementation
   to drift. Path B would require the full §4.2 golden-vector gate.
2. **Single trust root preserved — Path A only.** Path A keeps all crypto
   semantics in `witness-core` (strongly preferred for a pre-1.0, unaudited
   codebase). Path B reimplements crypto in TS, doubling the audit surface.
3. **Bundle/toolchain cost — acceptable for Path A.** ~89 KB gzipped (well under
   350 KB), instantiates with no imports in Node and browsers. The only costs are
   a wasm-capable clang for the C compiler and gating/shimming `getrandom` for
   keygen — both mechanical.

## Open risks / blockers for the chosen path (Path A)

- **Keygen vs. verification split:** the wasm build must gate the keygen
  functions (which need `OsRng`/`getrandom`) behind a feature or provide a wasm
  shim. Verification is unaffected.
- **Toolchain:** CI/build machines need a clang with the `wasm32` target
  (Homebrew `llvm` or `wasi-sdk`); Apple's system clang lacks it.
- **`wasm-bindgen` glue:** not yet prototyped. The real wrapper needs
  `wasm-bindgen` (or a manual ABI) for ergonomic TS calls; `wasm-bindgen` is not
  currently installed.
- **Final bundle size:** the measured ~89 KB gzipped includes the full core; a
  pruned verification-only build should be re-measured in Phase 2 to confirm the
  final number.
- **`blst` no-`std` mode:** `blst` compiles in no-`std` mode for wasm; confirm the
  verification functions do not depend on `std`-only features that are disabled.

## Implementation status (Lane J)

The Phase 0 decision is now implemented in `crates/witness-core-wasm`:

- **Keygen gating:** `witness-core` gained a `keygen` feature (default on) that
  gates `generate_keypair` / `generate_bls_keypair` (the only `OsRng` users).
  `witness-core-wasm` depends on `witness-core` with `default-features = false`,
  so the wasm build never pulls in `getrandom`. Default behavior is unchanged.
- **Manual ABI:** the wasm crate uses `#[no_mangle] extern "C"` exports (no
  `wasm-bindgen` glue) with a small hand-rolled loader
  (`sdk/ts/src/wasm/loader.ts`). Inputs are JSON/hex strings passed as
  `(ptr, len)`; results are JSON read from a module-global buffer.
- **Build:** `CC=<wasm-capable clang> cargo build -p witness-core-wasm
  --target wasm32-unknown-unknown --release`. The `.wasm` is checked in at
  `sdk/ts/src/wasm/witness_core_wasm.wasm` (~527 KB raw / ~184 KB gzipped) and
  copied to `dist/wasm/` on `npm run build`.
- **Conformance:** `sdk/ts/test/conformance.test.ts` runs every golden vector in
  `sdk/vectors/` against the wasm verifier + TS decoder and passes 100% (§4.2
  release gate).

## Reconciliation — hex decode correction (spec §3.4)

**Spec correction, not a protocol change.** The original §3.4 wording ("TS
decoders must reject uppercase hex, matching `hex::decode`") was factually wrong:
Rust's `hex::decode` **accepts** uppercase. The pure-TS `decodeHex` was tightened
to reject uppercase, creating a Rust/TS divergence (the WASM verification path
already accepted uppercase via Rust).

Resolution (Option 1 — make TS accept uppercase):

- `sdk/ts/src/decode.ts` `hexVal` now accepts `A-F`; `decodeHex` accepts
  mixed-case hex and rejects odd-length strings and non-hex characters.
- Wire emission is unchanged (still lowercase); `Serialize` output is untouched.
- Golden vectors regenerated: `wire.json` gains `hex_adapters.decode` with
  accept cases (uppercase, mixed-case → pinned bytes + lowercase re-serialization)
  and reject cases (odd-length, non-hex).
- SDK minor version bumped to 0.8.0 (spec §3.9).

Also added the missing Rust `verify_log_inclusion` mirror to `witness-client`
(thin wrapper over `witness-core`) and a `tree_size`-vs-STH equality check in
both the TS and Rust inclusion verifiers (position-awareness, spec §3.6).
