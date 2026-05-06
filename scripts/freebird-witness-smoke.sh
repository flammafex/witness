#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FREEBIRD_DIR="${FREEBIRD_DIR:-$(cd "$ROOT_DIR/.." && pwd)/freebird}"

ISSUER_PORT="${FREEBIRD_ISSUER_PORT:-18081}"
VERIFIER_PORT="${FREEBIRD_VERIFIER_PORT:-18082}"
GATEWAY_PORT="${WITNESS_GATEWAY_PORT:-18080}"
WITNESS_BASE_PORT="${WITNESS_BASE_PORT:-18100}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/witness-freebird-smoke.XXXXXX")"
PIDS=()
SUCCESS=0

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${PIDS[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
  if [ "$SUCCESS" = "1" ]; then
    rm -rf "$TMP_DIR"
  else
    echo "Smoke test failed. Logs preserved in $TMP_DIR" >&2
    for log in "$TMP_DIR"/*.log; do
      [ -f "$log" ] || continue
      echo >&2
      echo "==> $log" >&2
      tail -80 "$log" >&2 || true
    done
  fi
}
trap cleanup EXIT

wait_for_url() {
  url="$1"
  name="$2"
  for _ in $(seq 1 120); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for $name at $url" >&2
  return 1
}

require_freebird() {
  if [ ! -f "$FREEBIRD_DIR/Cargo.toml" ]; then
    echo "Freebird repo not found at $FREEBIRD_DIR" >&2
    echo "Set FREEBIRD_DIR=/path/to/freebird and retry." >&2
    exit 1
  fi
}

generate_witness_configs() {
  for i in 1 2 3; do
    output="$("$ROOT_DIR/target/release/witness-node" --generate-key 2>&1)"
    pubkey="$(printf '%s\n' "$output" | awk '/Public key:/ {print $3}')"
    privkey="$(printf '%s\n' "$output" | awk '/Private key:/ {print $3}')"
    token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    port="$((WITNESS_BASE_PORT + i))"

    cat > "$TMP_DIR/witness${i}.json" <<EOF
{
  "id": "witness-${i}",
  "private_key": "${privkey}",
  "port": ${port},
  "host": "127.0.0.1",
  "network_id": "smoke-network",
  "max_clock_skew": 300,
  "signing_auth_token": "${token}"
}
EOF

    eval "WITNESS${i}_PUBKEY=${pubkey}"
    eval "WITNESS${i}_TOKEN=${token}"
    eval "WITNESS${i}_PORT=${port}"
  done

  cat > "$TMP_DIR/network.json" <<EOF
{
  "id": "smoke-network",
  "threshold": 2,
  "witnesses": [
    {
      "id": "witness-1",
      "pubkey": "${WITNESS1_PUBKEY}",
      "endpoint": "http://127.0.0.1:${WITNESS1_PORT}",
      "auth_token": "${WITNESS1_TOKEN}"
    },
    {
      "id": "witness-2",
      "pubkey": "${WITNESS2_PUBKEY}",
      "endpoint": "http://127.0.0.1:${WITNESS2_PORT}",
      "auth_token": "${WITNESS2_TOKEN}"
    },
    {
      "id": "witness-3",
      "pubkey": "${WITNESS3_PUBKEY}",
      "endpoint": "http://127.0.0.1:${WITNESS3_PORT}",
      "auth_token": "${WITNESS3_TOKEN}"
    }
  ],
  "federation_peers": []
}
EOF
}

start_freebird() {
  freebird_key="$TMP_DIR/freebird/issuer_sk.bin"
  mkdir -p "$TMP_DIR/freebird"

  (
    cd "$FREEBIRD_DIR"
    ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
    BIND_ADDR="127.0.0.1:${ISSUER_PORT}" \
    ISSUER_ID=issuer:witness-smoke:v4 \
    ISSUER_SK_PATH="$freebird_key" \
    KEY_ROTATION_STATE_PATH="$TMP_DIR/freebird/key_rotation_state.json" \
    SYBIL_RESISTANCE=none \
    PUBLIC_BEARER_ENABLE=false \
    REQUIRE_TLS=false \
    CARGO_TARGET_DIR="$TMP_DIR/freebird-target" \
    cargo run -p freebird-issuer --bin freebird-issuer
  ) > "$TMP_DIR/freebird-issuer.log" 2>&1 &
  PIDS+=("$!")

  wait_for_url "http://127.0.0.1:${ISSUER_PORT}/.well-known/issuer" "Freebird issuer"

  (
    cd "$FREEBIRD_DIR"
    ADMIN_API_KEY=local-admin-key-must-be-at-least-32-chars \
    BIND_ADDR="127.0.0.1:${VERIFIER_PORT}" \
    VERIFIER_ID=verifier:witness-smoke:v4 \
    VERIFIER_AUDIENCE=witness-smoke \
    ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}/.well-known/issuer" \
    VERIFIER_SK_PATH="$freebird_key" \
    REFRESH_INTERVAL_MIN=1 \
    REQUIRE_TLS=false \
    CARGO_TARGET_DIR="$TMP_DIR/freebird-target" \
    cargo run -p freebird-verifier --bin freebird-verifier
  ) > "$TMP_DIR/freebird-verifier.log" 2>&1 &
  PIDS+=("$!")

  wait_for_url "http://127.0.0.1:${VERIFIER_PORT}/health" "Freebird verifier"
}

issue_freebird_token() {
  (
    cd "$TMP_DIR"
    FREEBIRD_ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
    FREEBIRD_VERIFIER_URL="http://127.0.0.1:${VERIFIER_PORT}" \
    CARGO_TARGET_DIR="$TMP_DIR/freebird-target" \
    cargo run --manifest-path "$FREEBIRD_DIR/Cargo.toml" -p freebird-interface -- --save
  ) > "$TMP_DIR/freebird-interface.log" 2>&1
}

start_witness() {
  generate_witness_configs

  for i in 1 2 3; do
    "$ROOT_DIR/target/release/witness-node" --config "$TMP_DIR/witness${i}.json" \
      > "$TMP_DIR/witness${i}.log" 2>&1 &
    PIDS+=("$!")
  done

  wait_for_url "http://127.0.0.1:$((WITNESS_BASE_PORT + 1))/health" "witness-1"
  wait_for_url "http://127.0.0.1:$((WITNESS_BASE_PORT + 2))/health" "witness-2"
  wait_for_url "http://127.0.0.1:$((WITNESS_BASE_PORT + 3))/health" "witness-3"

  FREEBIRD_VERIFIER_URL="http://127.0.0.1:${VERIFIER_PORT}" \
  FREEBIRD_REQUIRED=true \
  FREEBIRD_CONSUME_TOKENS=true \
  FREEBIRD_ALLOW_INSECURE_LOCAL=true \
  "$ROOT_DIR/target/release/witness-gateway" \
    --config "$TMP_DIR/network.json" \
    --host 127.0.0.1 \
    --port "$GATEWAY_PORT" \
    --database "$TMP_DIR/gateway.db" \
    > "$TMP_DIR/witness-gateway.log" 2>&1 &
  PIDS+=("$!")

  wait_for_url "http://127.0.0.1:${GATEWAY_PORT}/health" "Witness gateway"
}

main() {
  require_freebird

  echo "Building Witness release binaries..."
  (cd "$ROOT_DIR" && cargo build --release --workspace)

  echo "Starting Freebird issuer/verifier..."
  start_freebird

  echo "Issuing Freebird token..."
  issue_freebird_token

  echo "Starting Witness network with Freebird required..."
  start_witness

  echo "Timestamping with Freebird token..."
  "$ROOT_DIR/target/release/witness" \
    --gateway "http://127.0.0.1:${GATEWAY_PORT}" \
    timestamp \
    --hash "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" \
    --freebird-token "$TMP_DIR/token.json" \
    --output json \
    > "$TMP_DIR/attestation.json"

  if ! grep -q '"network_id": "smoke-network"' "$TMP_DIR/attestation.json"; then
    echo "Timestamp did not return a smoke-network attestation" >&2
    cat "$TMP_DIR/attestation.json" >&2
    exit 1
  fi

  if ! grep -q "Freebird token verified" "$TMP_DIR/witness-gateway.log"; then
    echo "Gateway did not verify the Freebird token" >&2
    exit 1
  fi

  echo "Freebird/Witness smoke test passed."
  SUCCESS=1
}

main "$@"
