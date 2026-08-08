#!/usr/bin/env bash
# Regenerate every checked-in contract artifact and fail on any drift.
#
# This is intentionally a repository-root gate. CI and the TypeScript package
# publication gate both call this script; a dirty working tree is expected to
# make it fail when an intended generated output has not been committed.

set -euo pipefail

readonly SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd -P)"
cd "${REPO_ROOT}"

if [[ "$(git rev-parse --show-toplevel)" != "${REPO_ROOT}" ]]; then
  echo "error: expected repository root ${REPO_ROOT}" >&2
  exit 1
fi

for command_name in cargo git npm; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "error: required command not found: ${command_name}" >&2
    exit 1
  fi
done

readonly GENERATED_PATHS=(
  "sdk/ts/schema/schema.json"
  "sdk/ts/src/types.generated.ts"
  "sdk/vectors/bls.json"
  "sdk/vectors/ed25519.json"
  "sdk/vectors/merkle.json"
  "sdk/vectors/sth.json"
  "sdk/vectors/to_bytes.json"
  "sdk/vectors/wire.json"
  "docs/openapi.yaml"
)

for path in "${GENERATED_PATHS[@]}"; do
  if [[ ! -f "${path}" ]]; then
    echo "error: expected generated artifact is missing: ${path}" >&2
    exit 1
  fi
  if ! git ls-files --error-unmatch -- "${path}" >/dev/null 2>&1; then
    echo "error: expected generated artifact is not tracked: ${path}" >&2
    exit 1
  fi
done

echo "==> generating TypeScript schema"
cargo run --quiet -p witness-core --bin gen_ts_types
echo "==> generating TypeScript types"
npm --prefix sdk/ts run gen:types
echo "==> generating golden vectors"
cargo run --quiet -p witness-core --bin gen_vectors -- sdk/vectors
echo "==> generating OpenAPI"
cargo run --quiet -p witness-gateway --bin gen_openapi --features openapi

if ! git diff --quiet HEAD -- "${GENERATED_PATHS[@]}"; then
  echo "error: generated artifacts differ from HEAD:" >&2
  git diff --stat HEAD -- "${GENERATED_PATHS[@]}" >&2
  exit 1
fi

for path in "${GENERATED_PATHS[@]}"; do
  if [[ -n "$(git status --porcelain=v1 --untracked-files=all -- "${path}")" ]]; then
    echo "error: generated artifact has untracked state: ${path}" >&2
    exit 1
  fi
done

echo "generated artifact drift check passed"
