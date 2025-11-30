#!/bin/bash
# ZQUIC Smoke Test Script
# Quick validation that core builds work
# Run from project root: ./dev/smoke_test.sh

set -e

echo "=== ZQUIC v0.9.3 Smoke Test ==="
echo "Zig version: $(zig version)"
echo ""

# Build
echo "[1/3] Building all targets..."
zig build
echo "Build complete!"
echo ""

# List binaries
echo "[2/3] Built binaries:"
ls -lh zig-out/bin/
echo ""

# Check binary headers
echo "[3/3] Verifying binaries..."
for bin in zig-out/bin/zquic*; do
    if [ -x "$bin" ]; then
        echo "  $bin: OK (executable)"
    else
        echo "  $bin: FAILED (not executable)"
        exit 1
    fi
done

echo ""
echo "=== Smoke Test PASSED ==="
