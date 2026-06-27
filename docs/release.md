# Release Packaging

Witness releases are tag-driven. Use annotated version tags:

```bash
git tag -a v0.6.0 -m "Witness 0.6.0"
git push origin v0.6.0
```

Pushing a `v*` tag triggers the release workflow
(`.forgejo/workflows/release.yml`) which builds Linux binaries for x86_64 and
aarch64 (gnu and musl) and publishes them to the Forgejo releases page with
SHA-256 checksums. Public production deployments should pin version tags or
image digests instead of `latest`.

## Release Artifacts

Each release includes four tarballs:

- `witness-v0.6.0-x86_64-unknown-linux-gnu.tar.gz`
- `witness-v0.6.0-aarch64-unknown-linux-gnu.tar.gz`
- `witness-v0.6.0-x86_64-unknown-linux-musl.tar.gz`
- `witness-v0.6.0-aarch64-unknown-linux-musl.tar.gz`

Each tarball contains:

- `bin/witness-node`
- `bin/witness-gateway`
- `bin/witness`
- `bin/witness-auditor`
- `configs/`, `docs/`, `examples/`
- `README.md`, `PRODUCTION.md`, `TESTING.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE`

A `SHA256SUMS` file is published alongside the tarballs.

## Container Images

Container images are built separately by `.forgejo/workflows/docker.yml`:

```text
git.carpocratian.org/sibyl/witness-node:<version>
git.carpocratian.org/sibyl/witness-gateway:<version>
```

Recommended tags:

- full version, such as `0.6.0`
- minor version, such as `0.6`
- commit SHA for every build

Production deployments should pin a version tag or digest.

The Docker workflow builds `linux/amd64` and `linux/arm64` images with BuildKit
provenance and SBOM attestations. Tagged releases require `COSIGN_PRIVATE_KEY`
and sign the pushed manifest digest with cosign.

## GitHub Mirror

The Forgejo repository mirrors to GitHub, but only git data syncs — branches,
tags, and commits. Release objects and binary assets are not mirrored. Download
binaries from the Forgejo releases page.

## Pre-Tag Checklist

- Update workspace crate versions in `Cargo.toml`.
- Update `Cargo.lock`.
- Update `CHANGELOG.md`.
- Run `cargo fmt --all -- --check`.
- Run `cargo clippy --workspace --all-targets -- -D warnings`.
- Run `cargo test --workspace`.
- Run `cargo build --release --workspace`.
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
