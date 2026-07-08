#!/usr/bin/env bash
# Local CLI smoke for installed/demo zquic binaries.

set -euo pipefail

echo "=== ZQUIC CLI Smoke ==="

if [ "${ZQUIC_CLI_SMOKE_SKIP_BUILD:-0}" != "1" ]; then
    zig build -Dexamples=true
fi

for binary in zquic zquic-client zquic-server; do
    path="./zig-out/bin/$binary"
    if [ ! -x "$path" ]; then
        echo "FAIL $binary missing at $path" >&2
        exit 1
    fi

    echo "RUN  $binary"
    "$path" >/dev/null
    echo "PASS $binary"
done

echo "CLI smoke passed"
