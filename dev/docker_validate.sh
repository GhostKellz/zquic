#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VARIANT="${1:-release}"
COMPOSE_FILE="$ROOT/docker/compose.yml"
script_args=("${@:2}")

interop_env_args=()
for name in \
  ZQUIC_INTEROP_TARGET_URL \
  ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL \
  ZQUIC_INTEROP_EXTERNAL_SERVER_URL \
  ZQUIC_INTEROP_ZQUIC_CLIENT_CMD \
  ZQUIC_INTEROP_REQUIRE_RUN \
  ZQUIC_INTEROP_REQUIRE_CLIENTS \
  ZQUIC_INTEROP_REQUIRE_VERSION_NEGOTIATION \
  ZQUIC_INTEROP_REQUIRE_SERVERS \
  ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE \
  ZQUIC_INTEROP_REQUIRE_HTTP3 \
  ZQUIC_INTEROP_REQUIRE_DOQ \
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
    docker compose -f "$COMPOSE_FILE" run --rm "${interop_env_args[@]}" zquic-verify bash dev/interop_smoke.sh "${script_args[@]}"
    ;;
  interop-tools)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-interop bash docker/interop-tools.sh
    ;;
  interop-source-tools)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-interop bash docker/interop-source-tools.sh
    ;;
  interop-debian)
    docker compose -f "$COMPOSE_FILE" run --rm "${interop_env_args[@]}" zquic-interop bash dev/interop_smoke.sh "${script_args[@]}"
    ;;
  interop-libs)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-verify bash docker/interop-library-smoke.sh
    ;;
  interop-zquic-server)
    docker compose -f "$COMPOSE_FILE" run --rm "${interop_env_args[@]}" zquic-interop bash docker/interop-zquic-server-smoke.sh
    ;;
  shell)
    docker compose -f "$COMPOSE_FILE" run --rm zquic-verify bash
    ;;
  *)
    echo "usage: $0 [release|valgrind|interop|interop-tools|interop-source-tools|interop-debian|interop-libs|interop-zquic-server|shell]" >&2
    exit 64
    ;;
esac
