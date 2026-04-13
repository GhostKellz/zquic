#!/usr/bin/env bash
set -euo pipefail

echo "=== Valgrind Memory Analysis ==="

# Build with baseline CPU for valgrind compatibility
echo "Building with baseline CPU target..."
zig build -Doptimize=ReleaseSafe -Dpost-quantum=false -Dcpu=baseline

BINARIES=(
    "zig-out/bin/zquic"
    "zig-out/bin/zquic-client"
    "zig-out/bin/zquic-server"
    "zig-out/bin/zquic-http3-server"
    "zig-out/bin/zquic-doq-server"
)

VALGRIND_OPTS=(
    --leak-check=full
    --show-leak-kinds=definite,possible
    --track-origins=yes
    --errors-for-leak-kinds=definite
)

pass=0
fail=0

for bin in "${BINARIES[@]}"; do
    if [[ -x "$bin" ]]; then
        name=$(basename "$bin")
        echo -n "Checking: $name ... "

        # Run binary under valgrind, capture stderr (where valgrind writes)
        output=$(timeout 5s valgrind "${VALGRIND_OPTS[@]}" "$bin" 2>&1 || true)

        # Check for clean memory (valgrind writes summary to stderr)
        if echo "$output" | grep -q "no leaks are possible"; then
            echo "PASS (no leaks)"
            pass=$((pass + 1))
        elif echo "$output" | grep -q "definitely lost: 0 bytes"; then
            echo "PASS (0 bytes lost)"
            pass=$((pass + 1))
        elif echo "$output" | grep -q "ERROR SUMMARY: 0 errors"; then
            echo "PASS (0 errors)"
            pass=$((pass + 1))
        else
            echo "FAIL"
            echo "$output" | grep -E "(definitely|indirectly|possibly) lost:" || true
            fail=$((fail + 1))
        fi
    else
        echo "Skip: $bin (not found)"
    fi
done

echo
echo "=== Results: $pass passed, $fail failed ==="
exit $fail
