# Changelog

All notable changes to Witness should be recorded here.

This project is pre-1.0. Minor versions may include breaking changes until a
stable API policy is published.

## Unreleased

### Changed

- Updated Freebird token handling to accept only the current token file shape
  with `token_b64`.
- Updated Witness-to-Freebird verifier requests to send the current
  `{ "token_b64": "..." }` contract.

### Added

- Added security policy, threat model, release packaging notes, contribution
  guide, and Freebird integration guidance.

### Fixed

- Applied Rust formatting across the workspace.
- Fixed clippy warnings in Merkle proof tests and gateway reconciler scaffolding.
