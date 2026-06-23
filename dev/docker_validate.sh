#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VARIANT="${1:-release}"
COMPOSE_FILE="$ROOT/docker/compose.yml"

interop_env_args=()
for name in \
  ZQUIC_INTEROP_TARGET_URL \
  ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL \
  ZQUIC_INTEROP_EXTERNAL_SERVER_URL \
  ZQUIC_INTEROP_ZQUIC_CLIENT_CMD \
  ZQUIC_INTEROP_REQUIRE_RUN \
  ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE \
  QUICHE_CLIENT_CMD \
  NGTCP2_H3CLIENT_CMD \
  AIOQUIC_CLIENT_CMD \
  MSQUIC_CLIENT_CMD \
  QUICHE_VERSION_NEGOTIATION_CMD \
  NGTCP2_VERSION_NEGOTIATION_CMD \
  AIOQUIC_VERSION_NEGOTIATION_CMD \
  MSQUIC_VERSION_NEGOTIATION_CMD \
  STATELESS_RESET_INTEROP_CMD \
  RETRY_INTEROP_CMD \
  CONNECTION_CLOSE_INTEROP_CMD \
  DRAINING_INTEROP_CMD \
  HTTP3_SETTINGS_INTEROP_CMD \
  HTTP3_REQUEST_INTEROP_CMD \
  HTTP3_GOAWAY_INTEROP_CMD \
  HTTP3_CANCEL_INTEROP_CMD \
  HTTP3_MALFORMED_INTEROP_CMD \
  DOQ_LENGTH_INTEROP_CMD \
  DOQ_PIPELINE_INTEROP_CMD \
  DOQ_RCODE_INTEROP_CMD \
  DOQ_TIMEOUT_INTEROP_CMD
do
  if [ -n "${!name:-}" ]; then
    interop_env_args+=("-e" "$name=${!name}")
  fi
done

case "$VARIANT" in
  release)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-verify bash docker/run-verify.sh
    ;;
  valgrind)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-verify bash docker/valgrind-check.sh
    ;;
  interop)
    docker compose -f "$COMPOSE_FILE" run --rm "${interop_env_args[@]}" zquic-verify bash dev/interop_smoke.sh
    ;;
  shell)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-verify bash
    ;;
  *)
    echo "usage: $0 [release|valgrind|interop|shell]" >&2
    exit 64
    ;;
esac
