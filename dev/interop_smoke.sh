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
REQUIRE_CLIENTS="${ZQUIC_INTEROP_REQUIRE_CLIENTS:-0}"
REQUIRE_VERSION_NEGOTIATION="${ZQUIC_INTEROP_REQUIRE_VERSION_NEGOTIATION:-0}"
REQUIRE_SERVERS="${ZQUIC_INTEROP_REQUIRE_SERVERS:-0}"
REQUIRE_TRANSPORT_CLOSE="${ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE:-0}"
REQUIRE_HTTP3="${ZQUIC_INTEROP_REQUIRE_HTTP3:-0}"
REQUIRE_DOQ="${ZQUIC_INTEROP_REQUIRE_DOQ:-0}"

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
  MSQUIC_CLIENT_CMD                Exact MsQuic target-url client command.
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
  ZQUIC_INTEROP_REQUIRE_CLIENTS=1  Fail unless at least one external client
                                   command runs.
  ZQUIC_INTEROP_REQUIRE_VERSION_NEGOTIATION=1
                                   Fail unless at least one unsupported-version
                                   command runs.
  ZQUIC_INTEROP_REQUIRE_SERVERS=1  Fail unless the zquic-as-client external
                                   server check runs.
  ZQUIC_INTEROP_REQUIRE_TRANSPORT_CLOSE=1
                                   Fail unless at least one stateless-reset,
                                   Retry, close, or draining command runs.
  ZQUIC_INTEROP_REQUIRE_HTTP3=1    Fail unless at least one HTTP/3 interop
                                   command runs.
  ZQUIC_INTEROP_REQUIRE_DOQ=1      Fail unless at least one DoQ interop command
                                   runs.
EOF
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

have_python_module() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import importlib.util
import sys
raise SystemExit(0 if importlib.util.find_spec(sys.argv[1]) else 1)
PY
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
            command -v "$candidate"
            return 0
        fi
    done

    return 1
}

url_parts() {
    python3 - "$1" <<'PY'
from urllib.parse import urlparse
import sys

parsed = urlparse(sys.argv[1])
host = parsed.hostname or ""
port = parsed.port or (443 if parsed.scheme == "https" else 80)
path = parsed.path or "/"
if parsed.query:
    path = f"{path}?{parsed.query}"
if not host:
    raise SystemExit(1)
print(host)
print(port)
print(path)
PY
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

run_shell_case_reject_output() {
    local name="$1"
    local command_line="$2"
    local reject_pattern="$3"
    local output status

    printf 'RUN  %-28s %s\n' "$name" "$command_line"
    output="$(bash -lc "$command_line" 2>&1)"
    status=$?
    if [ -n "$output" ]; then
        printf '%s\n' "$output"
    fi
    if [ "$status" -eq 0 ] && [[ "$output" != *"$reject_pattern"* ]]; then
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
    ngtcp2_client="$(resolve_cmd "${NGTCP2_H3CLIENT_CMD:-}" h3client gtlsclient nghttp3-client 2>/dev/null || true)"
    aioquic_client="$(resolve_cmd "${AIOQUIC_CLIENT_CMD:-}" aioquic-client 2>/dev/null || true)"
    msquic_client="$(resolve_cmd "${MSQUIC_CLIENT_CMD:-}" 2>/dev/null || true)"

    printf 'quiche client:  %s\n' "${quiche_client:-missing}"
    printf 'ngtcp2 client:  %s\n' "${ngtcp2_client:-missing}"
    if [ -n "$aioquic_client" ]; then
        printf 'aioquic client: %s\n' "$aioquic_client"
    elif have_cmd python3 && have_python_module aioquic.quic_client; then
        printf 'aioquic client: python3 -m aioquic.quic_client\n'
    else
        printf 'aioquic client: missing\n'
    fi
    if have_cmd quicinterop; then
        printf 'MsQuic tool:    %s\n' "$(command -v quicinterop)"
    else
        printf 'MsQuic tool:    missing\n'
    fi
    printf 'MsQuic client:  %s\n' "${msquic_client:-set MSQUIC_CLIENT_CMD}"
}

run_external_clients() {
    local quiche_client ngtcp2_client aioquic_client msquic_client ngtcp2_client_name
    local before_ran="$ran"

    if [ -z "$TARGET_URL" ]; then
        skip_case "external clients" "set ZQUIC_INTEROP_TARGET_URL to run client checks"
        if [ "$REQUIRE_CLIENTS" = "1" ]; then
            failed=$((failed + 1))
            printf 'FAIL %-28s %s\n' "external clients group" "target URL is unset"
        fi
        return
    fi

    quiche_client="$(resolve_cmd "${QUICHE_CLIENT_CMD:-}" quiche-client quiche-client3 2>/dev/null || true)"
    if [ -n "$quiche_client" ]; then
        run_shell_case "quiche client" "$quiche_client --no-verify '$TARGET_URL'"
    else
        skip_case "quiche client" "quiche-client not found"
    fi

    ngtcp2_client="$(resolve_cmd "${NGTCP2_H3CLIENT_CMD:-}" h3client gtlsclient nghttp3-client 2>/dev/null || true)"
    if [ -n "$ngtcp2_client" ]; then
        ngtcp2_client_name="$(basename "${ngtcp2_client%% *}")"
        if [ "$ngtcp2_client_name" = "gtlsclient" ]; then
            mapfile -t ngtcp2_url < <(url_parts "$TARGET_URL")
            run_shell_case_reject_output "ngtcp2 gtlsclient" "$ngtcp2_client -q '${ngtcp2_url[0]}' '${ngtcp2_url[1]}' '$TARGET_URL'" "ERR_"
        else
            run_shell_case "ngtcp2 h3client" "$ngtcp2_client --no-verify '$TARGET_URL'"
        fi
    else
        skip_case "ngtcp2 h3client" "h3client/gtlsclient/nghttp3-client not found"
    fi

    aioquic_client="$(resolve_cmd "${AIOQUIC_CLIENT_CMD:-}" aioquic-client 2>/dev/null || true)"
    if [ -n "$aioquic_client" ]; then
        run_shell_case "aioquic client" "$aioquic_client --insecure '$TARGET_URL'"
    elif have_cmd python3 && have_python_module aioquic.quic_client; then
        run_case "aioquic module" python3 -m aioquic.quic_client --insecure "$TARGET_URL"
    else
        skip_case "aioquic client" "aioquic command/module not found"
    fi

    msquic_client="$(resolve_cmd "${MSQUIC_CLIENT_CMD:-}" 2>/dev/null || true)"
    if [ -n "$msquic_client" ]; then
        run_shell_case "MsQuic client" "$msquic_client '$TARGET_URL'"
    else
        skip_case "MsQuic client" "set MSQUIC_CLIENT_CMD; quicinterop is an interop matrix tool, not a generic target-url client"
    fi

    if [ "$REQUIRE_CLIENTS" = "1" ] && [ "$ran" -eq "$before_ran" ]; then
        failed=$((failed + 1))
        printf 'FAIL %-28s %s\n' "external clients group" "no external client command ran"
    fi
}

run_version_negotiation_clients() {
    local before_ran="$ran"

    if [ -z "$UNSUPPORTED_VERSION_URL" ]; then
        skip_case "version negotiation" "set ZQUIC_INTEROP_UNSUPPORTED_VERSION_URL to run unsupported-version checks"
        if [ "$REQUIRE_VERSION_NEGOTIATION" = "1" ]; then
            failed=$((failed + 1))
            printf 'FAIL %-28s %s\n' "version negotiation group" "unsupported-version URL is unset"
        fi
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

    if [ "$REQUIRE_VERSION_NEGOTIATION" = "1" ] && [ "$ran" -eq "$before_ran" ]; then
        failed=$((failed + 1))
        printf 'FAIL %-28s %s\n' "version negotiation group" "no unsupported-version command ran"
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
    local before_ran="$ran"

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

    if [ "$REQUIRE_HTTP3" = "1" ] && [ "$ran" -eq "$before_ran" ]; then
        failed=$((failed + 1))
        printf 'FAIL %-28s %s\n' "http3 group" "no HTTP/3 interop command ran"
    fi
}

run_doq_cases() {
    local before_ran="$ran"

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

    if [ "$REQUIRE_DOQ" = "1" ] && [ "$ran" -eq "$before_ran" ]; then
        failed=$((failed + 1))
        printf 'FAIL %-28s %s\n' "doq group" "no DoQ interop command ran"
    fi
}

run_external_servers() {
    local before_ran="$ran"

    if [ -z "$EXTERNAL_SERVER_URL" ]; then
        skip_case "external servers" "set ZQUIC_INTEROP_EXTERNAL_SERVER_URL to run server checks"
        if [ "$REQUIRE_SERVERS" = "1" ]; then
            failed=$((failed + 1))
            printf 'FAIL %-28s %s\n' "external servers group" "external server URL is unset"
        fi
        return
    fi

    if [ -z "$ZQUIC_CLIENT_CMD" ]; then
        skip_case "zquic client" "set ZQUIC_INTEROP_ZQUIC_CLIENT_CMD until zquic has a stable network client CLI"
        if [ "$REQUIRE_SERVERS" = "1" ]; then
            failed=$((failed + 1))
            printf 'FAIL %-28s %s\n' "external servers group" "zquic client command is unset"
        fi
        return
    fi

    run_shell_case "zquic client" "$ZQUIC_CLIENT_CMD '$EXTERNAL_SERVER_URL'"

    if [ "$REQUIRE_SERVERS" = "1" ] && [ "$ran" -eq "$before_ran" ]; then
        failed=$((failed + 1))
        printf 'FAIL %-28s %s\n' "external servers group" "zquic external-server command did not run"
    fi
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
