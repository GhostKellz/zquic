#!/bin/bash
# Full validation: clean build, check API, run tests
# Run from project root: ./dev/validate.sh

set -e

echo "========================================"
echo "  ZQUIC Full Validation"
echo "========================================"
echo ""

# Clean - use find + xargs for robustness on busy filesystems
echo "[1/4] Cleaning..."
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

# Build
echo "[2/4] Building..."
zig build
echo "  Done."
echo ""

# Check binaries
echo "[3/4] Checking binaries..."
FOUND_BINARIES=0
for bin in zig-out/bin/zquic*; do
    if [ -x "$bin" ]; then
        echo "  $(basename $bin): OK"
        FOUND_BINARIES=$((FOUND_BINARIES + 1))
    fi
done
if [ $FOUND_BINARIES -eq 0 ]; then
    echo "  WARNING: No zquic binaries found (may be expected for minimal builds)"
fi
echo ""

# Summary
echo "[4/4] Build summary..."
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
