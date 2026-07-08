#!/usr/bin/env bash
set -euo pipefail

echo "=== zquic source-built interop tools ==="

check_tool() {
    local name="$1"
    shift
    local path

    path="$(command -v "$name")"
    printf 'FOUND %-20s %s\n' "$name" "$path"
    if ldd "$path" 2>&1 | grep -q 'not found'; then
        ldd "$path" 2>&1
        return 1
    fi
    "$name" "$@" >/dev/null 2>&1 || true
}

check_tool quiche-client --help
check_tool quiche-server --help
check_tool quicinterop -help
check_tool quicinteropserver -help
check_tool quicsample -help

echo "PASS source-built interop tools"
