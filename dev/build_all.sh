#!/bin/bash
# Build all configurations
# Run from project root: ./dev/build_all.sh

set -e

echo "=== Building all ZQUIC configurations ==="
echo ""

echo "[1/4] Debug build..."
zig build
echo "  Done."

echo ""
echo "[2/4] Release build..."
zig build -Doptimize=ReleaseFast
echo "  Done."

echo ""
echo "[3/4] Release with debug info..."
zig build -Doptimize=ReleaseSafe
echo "  Done."

echo ""
echo "[4/4] Size optimized..."
zig build -Doptimize=ReleaseSmall
echo "  Done."

echo ""
echo "=== All builds completed ==="
ls -lh zig-out/bin/
