#!/usr/bin/env bash
# Full release validation matrix
# Run from project root: ./dev/validate.sh

set -euo pipefail

if [ -z "${ZIG:-}" ]; then
    if [ -x /opt/zig-dev/zig ]; then
        ZIG=/opt/zig-dev/zig
    else
        ZIG=zig
    fi
fi
echo "========================================"
echo "  ZQUIC Full Validation"
echo "========================================"
echo ""
echo "Zig: $("$ZIG" version)"
echo ""

run_step() {
    local label="$1"
    shift

    echo "$label"
    "$@"
    echo "  Done."
    echo ""
}

# Clean - use find + xargs for robustness on busy filesystems
echo "[1/9] Cleaning local outputs..."
if [ -d "zig-out" ]; then
    find zig-out -type f -delete 2>/dev/null || true
    find zig-out -type d -empty -delete 2>/dev/null || true
    rm -rf zig-out 2>/dev/null || true
fi
if [ -d ".zig-cache" ]; then
    find .zig-cache -type f -delete 2>/dev/null || true
    find .zig-cache -type d -empty -delete 2>/dev/null || true
    rm -rf .zig-cache 2>/dev/null || true
fi
echo "  Done."
echo ""

run_step "[2/9] Default build..." "$ZIG" build --summary all
run_step "[3/9] Default tests..." "$ZIG" build test --summary all
run_step "[4/9] Integration tests..." "$ZIG" build integration-tests --summary all
run_step "[5/9] Fuzz tests..." "$ZIG" build fuzz-tests --summary all
run_step "[6/9] Minimal build..." "$ZIG" build -Dhttp3=false -Ddoq=false -Dservices=false -Dvpn=false -Dexamples=false --summary all
run_step "[7/9] Full feature build..." "$ZIG" build -Dservices=true -Dvpn=true -Dmonitoring=true --summary all
run_step "[8/9] Experimental PQ tests..." "$ZIG" build test -Dpost-quantum=true -Dexperimental-crypto=true --summary all
run_step "[9/9] Experimental PQ build..." "$ZIG" build -Dpost-quantum=true -Dexperimental-crypto=true --summary all

echo "Build summary:"
echo "  Binaries:"
if [ -d "zig-out/bin" ]; then
    ls -lh zig-out/bin/ 2>/dev/null | tail -n +2 || echo "  (none)"
else
    echo "  (none)"
fi
echo ""

echo "========================================"
echo "  Validation PASSED"
echo "========================================"
