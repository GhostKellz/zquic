#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${ZQUIC_INTEROP_PROBE_PORT:-4433}"
URL="${ZQUIC_INTEROP_TARGET_URL:-https://127.0.0.1:${PORT}/}"
REQUIRE_CRYPTO="${ZQUIC_INTEROP_REQUIRE_CRYPTO:-1}"
REQUIRE_SERVER_CRYPTO_TX="${ZQUIC_INTEROP_REQUIRE_SERVER_CRYPTO_TX:-1}"
# Opt-in gates. They assert the strongest outcome of the Handshake-key phase and
# only hold for external clients that offer TLS 1.3 + X25519 + AES-128-GCM-SHA256
# in a single QUIC Initial, so they stay off by default.
REQUIRE_CLIENT_HELLO_ACCEPTED="${ZQUIC_INTEROP_REQUIRE_CLIENT_HELLO_ACCEPTED:-0}"
REQUIRE_HANDSHAKE_KEYS="${ZQUIC_INTEROP_REQUIRE_HANDSHAKE_KEYS:-0}"
REQUIRE_CONNECTION_STATE_REUSED="${ZQUIC_INTEROP_REQUIRE_CONNECTION_STATE_REUSED:-0}"
REQUIRE_SERVER_HANDSHAKE_FLIGHT="${ZQUIC_INTEROP_REQUIRE_SERVER_HANDSHAKE_FLIGHT:-0}"
REQUIRE_HANDSHAKE_CONFIRMED="${ZQUIC_INTEROP_REQUIRE_HANDSHAKE_CONFIRMED:-0}"
REQUIRE_APPLICATION_DECRYPT="${ZQUIC_INTEROP_REQUIRE_APPLICATION_DECRYPT:-0}"
REQUIRE_ACK_SENT="${ZQUIC_INTEROP_REQUIRE_ACK_SENT:-0}"
REQUIRE_ACK_RECEIVED="${ZQUIC_INTEROP_REQUIRE_ACK_RECEIVED:-0}"
REQUIRE_PTO_PROBE="${ZQUIC_INTEROP_REQUIRE_PTO_PROBE:-0}"
REQUIRE_CRYPTO_RETRANSMISSION="${ZQUIC_INTEROP_REQUIRE_CRYPTO_RETRANSMISSION:-0}"
REQUIRE_HANDSHAKE_TIMEOUT="${ZQUIC_INTEROP_REQUIRE_HANDSHAKE_TIMEOUT:-0}"
REQUIRE_HTTP3_RESPONSE="${ZQUIC_INTEROP_REQUIRE_HTTP3_RESPONSE:-0}"
REQUIRE_AIOQUIC_HTTP3_RESPONSE="${ZQUIC_INTEROP_REQUIRE_AIOQUIC_HTTP3_RESPONSE:-0}"
REQUIRE_QUICHE_HTTP3_RESPONSE="${ZQUIC_INTEROP_REQUIRE_QUICHE_HTTP3_RESPONSE:-0}"
VERBOSE_LOG="${ZQUIC_INTEROP_VERBOSE_LOG:-0}"
SCRATCH="$ROOT/.scratch/interop-zquic-server"
LOG="$SCRATCH/server.log"
DOWNLOAD_DIR="$SCRATCH/download"
EXPECTED_BODY="$SCRATCH/expected-body"
AIOQUIC_BODY="$SCRATCH/aioquic-body"
QUICHE_BODY="$SCRATCH/quiche-body"
SERVER_PID=""
ZIG_BIN="${ZIG_BIN:-zig}"

if ! command -v "$ZIG_BIN" >/dev/null 2>&1; then
    if [ -x /opt/zig/zig ]; then
        ZIG_BIN=/opt/zig/zig
    else
        echo "FAIL zig compiler not found; set ZIG_BIN or mount Zig at /opt/zig" >&2
        exit 1
    fi
fi

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    rm -rf "$SCRATCH"
}
trap cleanup EXIT INT TERM

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
mkdir -p "$DOWNLOAD_DIR"
printf 'zquic\n' >"$EXPECTED_BODY"

echo "=== zquic live interop probe ==="
echo "target URL: $URL"

"$ZIG_BIN" build -Dexamples=true --summary all

./zig-out/bin/zquic-interop-probe-server \
    --host 127.0.0.1 \
    --port "$PORT" \
    --duration-ms 45000 \
    --max-packets 64 \
    --qlog >"$LOG" 2>&1 &
SERVER_PID="$!"

for _ in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q 'listening' "$LOG" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    cat "$LOG" || true
    echo "FAIL zquic interop probe did not start" >&2
    exit 1
fi

set +e
QUICHE_CLIENT_CMD="${QUICHE_CLIENT_CMD:-/workspace/docker/bin/quiche-json-client --output=$QUICHE_BODY}" \
NGTCP2_H3CLIENT_CMD="${NGTCP2_H3CLIENT_CMD:-gtlsclient --timeout=1s --download=$DOWNLOAD_DIR}" \
AIOQUIC_CLIENT_CMD="${AIOQUIC_CLIENT_CMD:-/workspace/docker/bin/aioquic-client --timeout 1 --output=$AIOQUIC_BODY}" \
ZQUIC_INTEROP_TARGET_URL="$URL" \
bash dev/interop_smoke.sh --clients
client_status=$?
set -e

if [ "$REQUIRE_PTO_PROBE" = "1" ] || [ "$REQUIRE_CRYPTO_RETRANSMISSION" = "1" ] || [ "$REQUIRE_HANDSHAKE_TIMEOUT" = "1" ]; then
    wait "$SERVER_PID" >/dev/null 2>&1 || true
else
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
fi
SERVER_PID=""

if [ "$VERBOSE_LOG" = "1" ]; then
    cat "$LOG"
fi

if ! grep -q '"event":"packet_rx"\|"event":"packet_parse_error"' "$LOG"; then
    echo "FAIL zquic interop probe did not observe external client packets" >&2
    exit 1
fi

if ! grep -q '"event":"initial_decrypt_ok"' "$LOG"; then
    echo "FAIL zquic interop probe did not decrypt an external Initial packet" >&2
    exit 1
fi

# Either terminal outcome is acceptable baseline evidence. A connection whose
# ClientHello could not be negotiated is closed with an encrypted Initial
# CONNECTION_CLOSE; stronger handshake outcomes have separate opt-in gates.
if ! grep -q '"event":"initial_connection_close_tx"\|"event":"handshake_keys_installed"' "$LOG"; then
    echo "FAIL zquic interop probe neither installed Handshake keys nor sent an encrypted Initial CONNECTION_CLOSE" >&2
    exit 1
fi

if [ "$REQUIRE_CRYPTO" = "1" ] && ! grep -q '"event":"crypto_frame_rx"' "$LOG"; then
    echo "FAIL zquic interop probe did not observe a decrypted CRYPTO frame" >&2
    exit 1
fi

if [ "$REQUIRE_SERVER_CRYPTO_TX" = "1" ] && ! grep -q '"event":"server_hello_initial_crypto_tx"\|"event":"initial_connection_close_tx"' "$LOG"; then
    echo "FAIL zquic interop probe did not send any protected server Initial packet" >&2
    exit 1
fi

if [ "$REQUIRE_CLIENT_HELLO_ACCEPTED" = "1" ] && ! grep -q '"event":"client_hello_accepted"' "$LOG"; then
    echo "FAIL zquic interop probe did not accept an external ClientHello" >&2
    exit 1
fi

if [ "$REQUIRE_HANDSHAKE_KEYS" = "1" ] && ! grep -q '"event":"handshake_keys_installed"' "$LOG"; then
    echo "FAIL zquic interop probe did not install RFC 9001 Handshake keys" >&2
    exit 1
fi

if [ "$REQUIRE_CONNECTION_STATE_REUSED" = "1" ] && ! grep -q '"event":"connection_state_reused"' "$LOG"; then
    echo "FAIL zquic interop probe did not retain connection state across datagrams" >&2
    exit 1
fi

if [ "$REQUIRE_SERVER_HANDSHAKE_FLIGHT" = "1" ] && ! grep -q '"event":"server_handshake_flight_tx"' "$LOG"; then
    echo "FAIL zquic interop probe did not send the complete protected server Handshake flight" >&2
    exit 1
fi

if [ "$REQUIRE_HANDSHAKE_CONFIRMED" = "1" ] && ! grep -q '"event":"handshake_confirmed"' "$LOG"; then
    echo "FAIL zquic interop probe did not authenticate the external client Finished" >&2
    exit 1
fi

if [ "$REQUIRE_APPLICATION_DECRYPT" = "1" ] && ! grep -q '"event":"client_application_decrypt_ok"' "$LOG"; then
    echo "FAIL zquic interop probe did not decrypt an external 1-RTT packet" >&2
    exit 1
fi

if [ "$REQUIRE_ACK_SENT" = "1" ] && ! grep -q '"event":"ack_sent"' "$LOG"; then
    echo "FAIL zquic interop probe did not send an ACK to an external client" >&2
    exit 1
fi

if [ "$REQUIRE_ACK_RECEIVED" = "1" ] && ! grep -q '"event":"ack_received"' "$LOG"; then
    echo "FAIL zquic interop probe did not process an ACK from an external client" >&2
    exit 1
fi

if [ "$REQUIRE_PTO_PROBE" = "1" ] && ! grep -q '"event":"pto_probe_scheduled"' "$LOG"; then
    echo "FAIL zquic interop probe did not schedule a PTO probe" >&2
    exit 1
fi

if [ "$REQUIRE_CRYPTO_RETRANSMISSION" = "1" ] && ! grep -q '"event":"crypto_retransmission"' "$LOG"; then
    echo "FAIL zquic interop probe did not retransmit retained CRYPTO" >&2
    exit 1
fi

if [ "$REQUIRE_HANDSHAKE_TIMEOUT" = "1" ] && ! grep -q '"event":"handshake_timeout"' "$LOG"; then
    echo "FAIL zquic interop probe did not enter draining after handshake timeout" >&2
    exit 1
fi

if [ "$REQUIRE_HTTP3_RESPONSE" = "1" ]; then
    for event in h3_server_settings_sent h3_peer_settings_received h3_request_accepted h3_response_sent; do
        if ! grep -q "\"event\":\"$event\"" "$LOG"; then
            echo "FAIL zquic interop probe is missing required HTTP/3 event: $event" >&2
            exit 1
        fi
    done
    if [ ! -f "$DOWNLOAD_DIR/index.html" ] || ! cmp -s "$EXPECTED_BODY" "$DOWNLOAD_DIR/index.html"; then
        echo "FAIL ngtcp2/gtlsclient did not decode the expected HTTP/3 response body" >&2
        exit 1
    fi
    echo "PASS ngtcp2/gtlsclient decoded HTTP/3 status, content length, body, and request-stream FIN"
fi

if [ "$REQUIRE_AIOQUIC_HTTP3_RESPONSE" = "1" ]; then
    if [ ! -f "$AIOQUIC_BODY" ] || ! cmp -s "$EXPECTED_BODY" "$AIOQUIC_BODY"; then
        echo "FAIL aioquic did not decode the expected HTTP/3 response body" >&2
        exit 1
    fi
    echo "PASS aioquic decoded HTTP/3 status, body, and request-stream FIN"
fi

if [ "$REQUIRE_QUICHE_HTTP3_RESPONSE" = "1" ]; then
    if [ ! -f "$QUICHE_BODY" ] || ! cmp -s "$EXPECTED_BODY" "$QUICHE_BODY"; then
        echo "FAIL quiche did not decode the expected HTTP/3 response body" >&2
        exit 1
    fi
    echo "PASS quiche decoded HTTP/3 status, headers, body, and request-stream FIN"
fi

if [ "$REQUIRE_HTTP3_RESPONSE" = "1" ] || [ "$REQUIRE_AIOQUIC_HTTP3_RESPONSE" = "1" ] || [ "$REQUIRE_QUICHE_HTTP3_RESPONSE" = "1" ]; then
    echo "PASS zquic reached the required external HTTP/3 response boundary"
elif [ "$client_status" -eq 0 ]; then
    echo "PASS external clients completed against zquic probe"
else
    echo "PASS zquic probe reached the required packet/TLS evidence; HTTP/3 client success remains a separate boundary"
fi
