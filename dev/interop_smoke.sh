#!/usr/bin/env bash
# QUIC interop smoke harness.
# Runs optional external-client/server checks when tools and endpoints exist.

set -u

SCRIPT_NAME="$(basename "$0")"
TARGET_URL="${ZQUIC_INTEROP_TARGET_URL:-}"
UNSUPPORTED_VERSION_URL="${ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL:-$TARGET_URL}"
EXTERNAL_SERVER_URL="${ZQUIC_INTEROP_EXTERNAL_SERVER_URL:-}"
ZQUIC_CLIENT_CMD="${ZQUIC_INTEROP_ZQUIC_CLIENT_CMD:-}"
REQUIRE_RUN="${ZQUIC_INTEROP_REQUIRE_RUN:-0}"
REQUIRE_TRANSPORT_CLOSE="${ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE:-0}"

ran=0
skipped=0
failed=0

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [--list] [--clients] [--servers] [--transport-close] [--all]

Environment:
  ZQUIC_INTEROP_TARGET_URL         URL external clients should request.
  ZQUIC_INTEROP_EXTERNAL_SERVER_URL URL for zquic-as-client checks.
  ZQUIC_INTEROP_ZQUIC_CLIENT_CMD   Command for zquic-as-client checks.
  QUICHE_CLIENT_CMD                quiche client override.
  NGTCP2_H3CLIENT_CMD              ngtcp2/nghttp3 h3 client override.
  AIOQUIC_CLIENT_CMD               aioquic client override.
  MSQUIC_CLIENT_CMD                MsQuic client override.
  QUICHE_VERSION_NEGOTIATION_CMD   Exact quiche unsupported-version command.
  NGTCP2_VERSION_NEGOTIATION_CMD   Exact ngtcp2 unsupported-version command.
  AIOQUIC_VERSION_NEGOTIATION_CMD  Exact aioquic unsupported-version command.
  MSQUIC_VERSION_NEGOTIATION_CMD   Exact MsQuic unsupported-version command.
  STATELESS_RESET_INTEROP_CMD      Exact external stateless-reset check command.
  RETRY_INTEROP_CMD                Exact external Retry check command.
  CONNECTION_CLOSE_INTEROP_CMD     Exact external CONNECTION_CLOSE check command.
  DRAINING_INTEROP_CMD             Exact external draining-behavior check command.
  HTTP3_SETTINGS_INTEROP_CMD       Exact external HTTP/3 SETTINGS check command.
  HTTP3_REQUEST_INTEROP_CMD        Exact external HTTP/3 request/response command.
  HTTP3_GOAWAY_INTEROP_CMD         Exact external HTTP/3 GOAWAY check command.
  HTTP3_CANCEL_INTEROP_CMD         Exact external HTTP/3 cancellation check command.
  HTTP3_MALFORMED_INTEROP_CMD      Exact external HTTP/3 malformed-frame command.
  DOQ_LENGTH_INTEROP_CMD           Exact external DoQ length-framing command.
  DOQ_PIPELINE_INTEROP_CMD         Exact external DoQ pipelining command.
  DOQ_RCODE_INTEROP_CMD            Exact external DoQ NXDOMAIN/SERVFAIL command.
  DOQ_TIMEOUT_INTEROP_CMD          Exact external DoQ timeout command.
  ZQUIC_INTEROP_REQUIRE_RUN=1      Fail when every case is skipped.
  ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1
                                   Fail unless at least one stateless-reset,
                                   Retry, close, or draining command runs.
EOF
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

resolve_cmd() {
    local override="$1"
    shift

    if [ -n "$override" ]; then
        printf '%s\n' "$override"
        return 0
    fi

    local candidate
    for candidate in "$@"; do
        if have_cmd "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

skip_case() {
    skipped=$((skipped + 1))
    printf 'SKIP %-28s %s\n' "$1" "$2"
}

run_case() {
    local name="$1"
    shift

    printf 'RUN  %-28s %s\n' "$name" "$*"
    if "$@"; then
        ran=$((ran + 1))
        printf 'PASS %-28s\n' "$name"
    else
        failed=$((failed + 1))
        printf 'FAIL %-28s\n' "$name"
    fi
}

run_shell_case() {
    local name="$1"
    local command_line="$2"

    printf 'RUN  %-28s %s\n' "$name" "$command_line"
    if bash -lc "$command_line"; then
        ran=$((ran + 1))
        printf 'PASS %-28s\n' "$name"
    else
        failed=$((failed + 1))
        printf 'FAIL %-28s\n' "$name"
    fi
}

list_tools() {
    local quiche_client ngtcp2_client aioquic_client msquic_client

    quiche_client="$(resolve_cmd "${QUICHE_CLIENT_CMD:-}" quiche-client quiche-client3 2>/dev/null || true)"
    ngtcp2_client="$(resolve_cmd "${NGTCP2_H3CLIENT_CMD:-}" h3client nghttp3-client 2>/dev/null || true)"
    aioquic_client="$(resolve_cmd "${AIOQUIC_CLIENT_CMD:-}" aioquic-client 2>/dev/null || true)"
    msquic_client="$(resolve_cmd "${MSQUIC_CLIENT_CMD:-}" quicinterop 2>/dev/null || true)"

    printf 'quiche client:  %s\n' "${quiche_client:-missing}"
    printf 'ngtcp2 client:  %s\n' "${ngtcp2_client:-missing}"
    if [ -n "$aioquic_client" ]; then
        printf 'aioquic client: %s\n' "$aioquic_client"
    elif have_cmd python3 && python3 -c 'import aioquic' >/dev/null 2>&1; then
        printf 'aioquic client: python3 -m aioquic.quic_client\n'
    else
        printf 'aioquic client: missing\n'
    fi
    printf 'MsQuic client:  %s\n' "${msquic_client:-missing}"
}

run_external_clients() {
    local quiche_client ngtcp2_client aioquic_client msquic_client

    if [ -z "$TARGET_URL" ]; then
        skip_case "external clients" "set ZQUIC_INTEROP_TARGET_URL to run client checks"
        return
    fi

    quiche_client="$(resolve_cmd "${QUICHE_CLIENT_CMD:-}" quiche-client quiche-client3 2>/dev/null || true)"
    if [ -n "$quiche_client" ]; then
        run_shell_case "quiche client" "$quiche_client --no-verify '$TARGET_URL'"
    else
        skip_case "quiche client" "quiche-client not found"
    fi

    ngtcp2_client="$(resolve_cmd "${NGTCP2_H3CLIENT_CMD:-}" h3client nghttp3-client 2>/dev/null || true)"
    if [ -n "$ngtcp2_client" ]; then
        run_shell_case "ngtcp2 h3client" "$ngtcp2_client --no-verify '$TARGET_URL'"
    else
        skip_case "ngtcp2 h3client" "h3client/nghttp3-client not found"
    fi

    aioquic_client="$(resolve_cmd "${AIOQUIC_CLIENT_CMD:-}" aioquic-client 2>/dev/null || true)"
    if [ -n "$aioquic_client" ]; then
        run_shell_case "aioquic client" "$aioquic_client --insecure '$TARGET_URL'"
    elif have_cmd python3 && python3 -c 'import aioquic' >/dev/null 2>&1; then
        run_case "aioquic module" python3 -m aioquic.quic_client --insecure "$TARGET_URL"
    else
        skip_case "aioquic client" "aioquic command/module not found"
    fi

    msquic_client="$(resolve_cmd "${MSQUIC_CLIENT_CMD:-}" quicinterop 2>/dev/null || true)"
    if [ -n "$msquic_client" ]; then
        run_shell_case "MsQuic client" "$msquic_client '$TARGET_URL'"
    else
        skip_case "MsQuic client" "set MSQUIC_CLIENT_CMD or install quicinterop"
    fi
}

run_version_negotiation_clients() {
    if [ -z "$UNSUPPORTED_VERSION_URL" ]; then
        skip_case "version negotiation" "set ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL to run unsupported-version checks"
        return
    fi

    if [ -n "${QUICHE_VERSION_NEGOTIATION_CMD:-}" ]; then
        run_shell_case "quiche version negotiation" "$QUICHE_VERSION_NEGOTIATION_CMD '$UNSUPPORTED_VERSION_URL'"
    else
        skip_case "quiche version negotiation" "set QUICHE_VERSION_NEGOTIATION_CMD with the implementation-specific unsupported-version flags"
    fi

    if [ -n "${NGTCP2_VERSION_NEGOTIATION_CMD:-}" ]; then
        run_shell_case "ngtcp2 version negotiation" "$NGTCP2_VERSION_NEGOTIATION_CMD '$UNSUPPORTED_VERSION_URL'"
    else
        skip_case "ngtcp2 version negotiation" "set NGTCP2_VERSION_NEGOTIATION_CMD with the implementation-specific unsupported-version flags"
    fi

    if [ -n "${AIOQUIC_VERSION_NEGOTIATION_CMD:-}" ]; then
        run_shell_case "aioquic version negotiation" "$AIOQUIC_VERSION_NEGOTIATION_CMD '$UNSUPPORTED_VERSION_URL'"
    else
        skip_case "aioquic version negotiation" "set AIOQUIC_VERSION_NEGOTIATION_CMD with the implementation-specific unsupported-version flags"
    fi

    if [ -n "${MSQUIC_VERSION_NEGOTIATION_CMD:-}" ]; then
        run_shell_case "MsQuic version negotiation" "$MSQUIC_VERSION_NEGOTIATION_CMD '$UNSUPPORTED_VERSION_URL'"
    else
        skip_case "MsQuic version negotiation" "set MSQUIC_VERSION_NEGOTIATION_CMD with the implementation-specific unsupported-version flags"
    fi
}

run_transport_close_cases() {
    local before_ran="$ran"

    if [ -n "${STATELESS_RESET_INTEROP_CMD:-}" ]; then
        run_shell_case "stateless reset" "$STATELESS_RESET_INTEROP_CMD"
    else
        skip_case "stateless reset" "set STATELESS_RESET_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${RETRY_INTEROP_CMD:-}" ]; then
        run_shell_case "retry" "$RETRY_INTEROP_CMD"
    else
        skip_case "retry" "set RETRY_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${CONNECTION_CLOSE_INTEROP_CMD:-}" ]; then
        run_shell_case "connection close" "$CONNECTION_CLOSE_INTEROP_CMD"
    else
        skip_case "connection close" "set CONNECTION_CLOSE_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${DRAINING_INTEROP_CMD:-}" ]; then
        run_shell_case "draining" "$DRAINING_INTEROP_CMD"
    else
        skip_case "draining" "set DRAINING_INTEROP_CMD for the installed external implementation"
    fi

    if [ "$REQUIRE_TRANSPORT_CLOSE" = "1" ] && [ "$ran" -eq "$before_ran" ]; then
        failed=$((failed + 1))
        printf 'FAIL %-28s %s\n' "transport close group" "no external stateless-reset/Retry/close/draining command ran"
    fi
}

run_http3_cases() {
    if [ -n "${HTTP3_SETTINGS_INTEROP_CMD:-}" ]; then
        run_shell_case "http3 settings" "$HTTP3_SETTINGS_INTEROP_CMD"
    else
        skip_case "http3 settings" "set HTTP3_SETTINGS_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${HTTP3_REQUEST_INTEROP_CMD:-}" ]; then
        run_shell_case "http3 request response" "$HTTP3_REQUEST_INTEROP_CMD"
    else
        skip_case "http3 request response" "set HTTP3_REQUEST_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${HTTP3_GOAWAY_INTEROP_CMD:-}" ]; then
        run_shell_case "http3 goaway" "$HTTP3_GOAWAY_INTEROP_CMD"
    else
        skip_case "http3 goaway" "set HTTP3_GOAWAY_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${HTTP3_CANCEL_INTEROP_CMD:-}" ]; then
        run_shell_case "http3 cancellation" "$HTTP3_CANCEL_INTEROP_CMD"
    else
        skip_case "http3 cancellation" "set HTTP3_CANCEL_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${HTTP3_MALFORMED_INTEROP_CMD:-}" ]; then
        run_shell_case "http3 malformed frame" "$HTTP3_MALFORMED_INTEROP_CMD"
    else
        skip_case "http3 malformed frame" "set HTTP3_MALFORMED_INTEROP_CMD for the installed external implementation"
    fi
}

run_doq_cases() {
    if [ -n "${DOQ_LENGTH_INTEROP_CMD:-}" ]; then
        run_shell_case "doq length framing" "$DOQ_LENGTH_INTEROP_CMD"
    else
        skip_case "doq length framing" "set DOQ_LENGTH_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${DOQ_PIPELINE_INTEROP_CMD:-}" ]; then
        run_shell_case "doq pipelining" "$DOQ_PIPELINE_INTEROP_CMD"
    else
        skip_case "doq pipelining" "set DOQ_PIPELINE_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${DOQ_RCODE_INTEROP_CMD:-}" ]; then
        run_shell_case "doq response codes" "$DOQ_RCODE_INTEROP_CMD"
    else
        skip_case "doq response codes" "set DOQ_RCODE_INTEROP_CMD for the installed external implementation"
    fi

    if [ -n "${DOQ_TIMEOUT_INTEROP_CMD:-}" ]; then
        run_shell_case "doq timeout" "$DOQ_TIMEOUT_INTEROP_CMD"
    else
        skip_case "doq timeout" "set DOQ_TIMEOUT_INTEROP_CMD for the installed external implementation"
    fi
}

run_external_servers() {
    if [ -z "$EXTERNAL_SERVER_URL" ]; then
        skip_case "external servers" "set ZQUIC_INTEROP_EXTERNAL_SERVER_URL to run server checks"
        return
    fi

    if [ -z "$ZQUIC_CLIENT_CMD" ]; then
        skip_case "zquic client" "set ZQUIC_INTEROP_ZQUIC_CLIENT_CMD until zquic has a stable network client CLI"
        return
    fi

    run_shell_case "zquic client" "$ZQUIC_CLIENT_CMD '$EXTERNAL_SERVER_URL'"
}

mode="all"
case "${1:-}" in
    "")
        ;;
    --all)
        mode="all"
        ;;
    --clients)
        mode="clients"
        ;;
    --servers)
        mode="servers"
        ;;
    --transport-close)
        mode="transport-close"
        ;;
    --list)
        list_tools
        exit 0
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage
        exit 2
        ;;
esac

echo "=== ZQUIC QUIC Interop Smoke ==="
echo "target URL: ${TARGET_URL:-unset}"
echo "unsupported-version URL: ${UNSUPPORTED_VERSION_URL:-unset}"
echo "external server URL: ${EXTERNAL_SERVER_URL:-unset}"
echo ""

case "$mode" in
    all)
        run_external_clients
        run_version_negotiation_clients
        run_transport_close_cases
        run_http3_cases
        run_doq_cases
        run_external_servers
        ;;
    clients)
        run_external_clients
        run_version_negotiation_clients
        run_transport_close_cases
        run_http3_cases
        run_doq_cases
        ;;
    servers)
        run_external_servers
        ;;
    transport-close)
        run_transport_close_cases
        ;;
esac

echo ""
echo "Summary: ran=$ran skipped=$skipped failed=$failed"

if [ "$failed" -ne 0 ]; then
    exit 1
fi

if [ "$ran" -eq 0 ] && [ "$REQUIRE_RUN" = "1" ]; then
    echo "ERROR: no interop cases ran and ZQUIC_INTEROP_REQUIRE_RUN=1"
    exit 1
fi

exit 0
