#!/usr/bin/env bash
# Run ZQUIC tests
# Run from project root: ./dev/test.sh

set -euo pipefail

echo "=== ZQUIC Test Suite ==="
echo ""

run_step() {
    local label="$1"
    shift
    echo "$label"
    if "$@"; then
        echo "  Done."
    else
        echo "  Failed. See output above."
        exit 1
    fi
    echo ""
}

run_step "[1/4] Building..." zig build
run_step "[2/4] Running unit tests (zig build test)..." zig build test
run_step "[3/4] Running integration tests..." zig build integration-tests

if [ -n "${CI:-}" ]; then
    echo "CI detected; skipping fuzz harness to avoid long runtimes." && echo ""
else
    run_step "[4/4] Running fuzz harness..." zig build fuzz-tests
fi

echo "=== Test Complete ==="
