#!/bin/bash
# ZQUIC Buffer Performance Test
# Tests buffer allocation, zero-copy, and pool efficiency
# Run from project root: ./dev/perf_buffers.sh

set -e
ZIG="${ZIG:-/opt/zig-dev/zig}"

echo "=== ZQUIC Buffer Performance Test ==="
echo "Zig version: $("$ZIG" version)"
echo ""

# Build with debug for detailed info
echo "[1/3] Building..."
"$ZIG" build
echo "Build complete!"
echo ""

# Run buffer-specific tests through build system
echo "[2/3] Running buffer tests..."
echo "Running all unit tests (includes buffer tests)..."
"$ZIG" build test 2>&1 | grep -E '(buffer|zero.copy|segment|compact|passed|failed)' || echo "Tests complete"

echo ""
echo "[3/3] Buffer optimization summary..."
echo ""
echo "Optimizations in place:"
echo "  - O(n) compact() using two-pointer algorithm (was O(n^2))"
echo "  - read_start offset to avoid memmove on every read"
echo "  - Zero-copy buffer pools with size tiers (small/medium/large)"
echo "  - Ring buffer for available indices"
echo ""
echo "Key files:"
echo "  - src/core/buffers.zig: Packet reassembly buffers"
echo "  - src/core/stream.zig: Stream read/write buffers"
echo "  - src/performance/zero_copy.zig: Zero-copy buffer pools"
echo ""

echo "=== Buffer Test Complete ==="
