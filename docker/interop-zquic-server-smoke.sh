#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${ZQUIC_INTEROP_PROBE_PORT:-4433}"
URL="${ZQUIC_INTEROP_TARGET_URL:-https://127.0.0.1:${PORT}/}"
REQUIRE_CRYPTO="${ZQUIC_INTEROP_REQUIRE_CRYPTO:-1}"
REQUIRE_SERVER_CRYPTO_TX="${ZQUIC_INTEROP_REQUIRE_SERVER_CRYPTO_TX:-1}"
SCRATCH="$ROOT/.scratch/interop-zquic-server"
LOG="$SCRATCH/server.log"
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

echo "=== zquic live interop probe ==="
echo "target URL: $URL"

"$ZIG_BIN" build -Dexamples=true --summary all

./zig-out/bin/zquic-interop-probe-server \
    --host 127.0.0.1 \
    --port "$PORT" \
    --duration-ms 45000 \
    --max-packets 16 \
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
QUICHE_CLIENT_CMD="${QUICHE_CLIENT_CMD:-quiche-client}" \
NGTCP2_H3CLIENT_CMD="${NGTCP2_H3CLIENT_CMD:-gtlsclient --timeout=1s}" \
AIOQUIC_CLIENT_CMD="${AIOQUIC_CLIENT_CMD:-/workspace/docker/bin/aioquic-client --timeout 1}" \
ZQUIC_INTEROP_TARGET_URL="$URL" \
bash dev/interop_smoke.sh --clients
client_status=$?
set -e

wait "$SERVER_PID" >/dev/null 2>&1 || true
SERVER_PID=""

cat "$LOG"

if ! grep -q '"event":"packet_rx"\|"event":"packet_parse_error"' "$LOG"; then
    echo "FAIL zquic interop probe did not observe external client packets" >&2
    exit 1
fi

if ! grep -q '"event":"initial_decrypt_ok"' "$LOG"; then
    echo "FAIL zquic interop probe did not decrypt an external Initial packet" >&2
    exit 1
fi

if ! grep -q '"event":"initial_connection_close_tx"' "$LOG"; then
    echo "FAIL zquic interop probe did not send an encrypted Initial CONNECTION_CLOSE" >&2
    exit 1
fi

if [ "$REQUIRE_CRYPTO" = "1" ] && ! grep -q '"event":"crypto_frame_rx"' "$LOG"; then
    echo "FAIL zquic interop probe did not observe a decrypted CRYPTO frame" >&2
    exit 1
fi

if [ "$REQUIRE_SERVER_CRYPTO_TX" = "1" ] && ! grep -q '"event":"server_initial_crypto_tx"' "$LOG"; then
    echo "FAIL zquic interop probe did not send protected server Initial CRYPTO" >&2
    exit 1
fi

if [ "$client_status" -eq 0 ]; then
    echo "PASS external clients completed against zquic probe"
else
    echo "PASS zquic probe decrypted an external Initial, observed CRYPTO, sent protected server Initial CRYPTO, and sent encrypted Initial CONNECTION_CLOSE; full handshake/client success remains gated separately"
fi
