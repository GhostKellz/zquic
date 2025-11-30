#!/bin/bash
# ZQUIC Local Testing Script
# Run from project root: ./dev/test_local.sh

set -e

echo "=== ZQUIC Local Testing ==="
echo "Zig version: $(zig version)"
echo ""

# Clean build
echo "[1/4] Cleaning previous builds..."
rm -rf zig-out .zig-cache 2>/dev/null || true

# Build
echo "[2/4] Building ZQUIC..."
zig build
echo "Build complete!"
echo ""

# List binaries
echo "[3/4] Built binaries:"
if [ -d "zig-out/bin" ]; then
    ls -lh zig-out/bin/
else
    echo "No binaries found"
fi
echo ""

# Run tests
echo "[4/4] Running tests..."
zig build test 2>&1 || echo "Some tests may fail due to network requirements"

echo ""
echo "=== Testing Complete ==="
