#!/bin/bash
# ZQUIC Release Build Script
# Run from project root: ./dev/build_release.sh

set -e

echo "=== ZQUIC Release Build ==="
echo "Zig version: $(zig version)"
echo ""

# Clean
echo "[1/3] Cleaning..."
rm -rf zig-out 2>/dev/null || true

# Release build
echo "[2/3] Building release (ReleaseFast)..."
zig build -Doptimize=ReleaseFast

# Report
echo "[3/3] Release binaries:"
if [ -d "zig-out/bin" ]; then
    ls -lh zig-out/bin/
    echo ""
    echo "Total size:"
    du -sh zig-out/
else
    echo "No binaries found"
fi

echo ""
echo "=== Release Build Complete ==="
