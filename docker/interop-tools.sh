#!/usr/bin/env bash
set -euo pipefail

echo "=== zquic interop tool audit ==="
if [ -f /etc/alpine-release ]; then
    echo "os: Alpine $(cat /etc/alpine-release)"
elif [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "os: ${PRETTY_NAME:-unknown}"
else
    echo "os: unknown"
fi
echo

check_cmd() {
    local name="$1"
    if command -v "$name" >/dev/null 2>&1; then
        printf 'FOUND command %-24s %s\n' "$name" "$(command -v "$name")"
    else
        printf 'MISS  command %-24s\n' "$name"
    fi
}

check_pkg() {
    local name="$1"
    local version

    if [ -f /lib/apk/db/installed ]; then
        version="$(
            awk -v pkg="$name" '
                BEGIN { RS = "" }
                {
                    found = 0
                    ver = ""
                    count = split($0, lines, "\n")
                    for (i = 1; i <= count; i++) {
                        if (lines[i] == "P:" pkg) found = 1
                        if (substr(lines[i], 1, 2) == "V:") ver = substr(lines[i], 3)
                    }
                    if (found) {
                        print pkg "-" ver
                        exit
                    }
                }
            ' /lib/apk/db/installed
        )"
    elif command -v dpkg-query >/dev/null 2>&1; then
        version="$(dpkg-query -W -f='${Package}-${Version}\n' "$name" 2>/dev/null || true)"
    else
        version=""
    fi
    if [ -n "$version" ]; then
        printf 'FOUND package %-24s %s\n' "$name" "$version"
    else
        printf 'MISS  package %-24s\n' "$name"
    fi
}

if [ -f /lib/apk/db/installed ]; then
    for pkg in py3-aioquic ngtcp2 ngtcp2-gnutls nghttp3 ngtcp2-dev nghttp3-dev libmsquic libmsquic-dev; do
        check_pkg "$pkg"
    done
elif command -v dpkg-query >/dev/null 2>&1; then
    for pkg in python3-aioquic ngtcp2-client ngtcp2-server libngtcp2-dev libngtcp2-crypto-gnutls-dev libnghttp3-dev; do
        check_pkg "$pkg"
    done
fi

echo
for cmd in aioquic-client h3client gtlsclient nghttp3-client ngtcp2-client quiche-client quiche-server quiche-client3 quicinterop quicinteropserver quicsample; do
    check_cmd "$cmd"
done

echo
python3 - <<'PY'
import importlib.util
for name in ("aioquic", "aioquic.quic.connection", "aioquic.quic_client"):
    print(f"{'FOUND' if importlib.util.find_spec(name) else 'MISS '} python module {name}")
PY

echo
echo "Notes:"
echo "- aioquic-client is a repo-provided command backed by the image's aioquic package."
echo "- Debian trixie provides gtlsclient through ngtcp2-client."
echo "- Alpine and Debian do not package quiche-client in these images."
echo "- MsQuic packages are currently available in the Alpine verifier image, not Debian trixie."
echo "- Use dev/interop_smoke.sh with explicit *_CMD variables for source-built or mounted clients."
