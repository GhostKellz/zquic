#!/usr/bin/env bash
# Run ZQUIC tests
# Run from project root: ./dev/test.sh

set -euo pipefail

echo "=== ZQUIC Test Suite ==="
echo ""

echo "[1/4] Building..."
zig build
echo "  Done."
echo ""

echo "[2/4] Running unit tests (zig build test)..."
zig build test
echo "  Done."
echo ""

echo "[3/4] Running integration tests..."
zig build integration-tests
echo "  Done."
echo ""

echo "[4/4] Running fuzz harness..."
zig build fuzz-tests
echo "  Done."
echo ""

echo "=== Test Complete ==="
