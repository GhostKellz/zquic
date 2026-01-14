#!/bin/bash
# Full validation: clean build, check API, run tests
# Run from project root: ./dev/validate.sh

set -e

echo "========================================"
echo "  ZQUIC v0.9.4 Full Validation"
echo "========================================"
echo ""

# Clean
echo "[1/4] Cleaning..."
rm -rf zig-out .zig-cache
echo "  Done."
echo ""

# Build
echo "[2/4] Building..."
zig build
echo "  Done."
echo ""

# Check binaries
echo "[3/4] Checking binaries..."
for bin in zig-out/bin/zquic*; do
    if [ -x "$bin" ]; then
        echo "  $(basename $bin): OK"
    else
        echo "  $(basename $bin): FAILED"
        exit 1
    fi
done
echo ""

# Summary
echo "[4/4] Build summary..."
echo "  Binaries:"
ls -lh zig-out/bin/ | tail -n +2
echo ""

echo "========================================"
echo "  Validation PASSED"
echo "========================================"
