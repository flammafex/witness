# Release Packaging

Witness releases are tag-driven. Use annotated version tags:

```bash
git tag -a v0.5.0 -m "Witness 0.5.0"
git push origin v0.5.0
```

Pushing a `v*` tag should build release binaries and container images. Public
production deployments should pin version tags or image digests instead of
`latest`.

## Release Artifacts

A complete release should include:

- `witness-node`
- `witness-gateway`
- `witness`
- `witness-auditor`
- README, license, security policy, changelog, production guide, and docs
- Docker image references
- SHA-256 checksums
- image signatures or provenance attestations

The release workflow publishes Linux `amd64` and `arm64` tarballs. Each tarball
contains `bin/`, documentation, examples, and server configuration templates.

## Container Images

The repository currently builds:

```text
git.carpocratian.org/sibyl/witness-node:<version>
git.carpocratian.org/sibyl/witness-gateway:<version>
```

Recommended tags:

- full version, such as `0.5.0`
- minor version, such as `0.5`
- commit SHA for every build

Production deployments should pin a version tag or digest.

The Docker workflow builds `linux/amd64` and `linux/arm64` images with BuildKit
provenance and SBOM attestations. Tagged releases require `COSIGN_PRIVATE_KEY`
and sign the pushed manifest digest with cosign.

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

- keyless signing is not configured; image signing currently expects a cosign
  private key secret
