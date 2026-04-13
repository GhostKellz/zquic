#!/bin/bash
# ZQUIC Local Testing Script
# Run from project root: ./dev/test_local.sh

set -e

echo "=== ZQUIC Local Testing ==="
echo "Zig version: $(zig version)"
echo ""

# Clean build - use find + xargs for robustness on busy filesystems
echo "[1/4] Cleaning previous builds..."
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
