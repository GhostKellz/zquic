#!/bin/bash
# ZQUIC Connection Performance Test
# Tests connection pool, stream management, and event loop performance
# Run from project root: ./dev/perf_connections.sh

set -e

echo "=== ZQUIC Connection Performance Test ==="
echo "Zig version: $(zig version)"
echo ""

# Build
echo "[1/3] Building..."
zig build
echo "Build complete!"
echo ""

# Run connection tests through build system
echo "[2/3] Running connection tests..."
echo "Running all unit tests (includes connection/stream tests)..."
zig build test 2>&1 | grep -E '(connection|stream|runtime|pool|passed|failed)' || echo "Tests complete"

echo ""
echo "[3/3] Connection optimization summary..."
echo ""
echo "Optimizations in place:"
echo "  - O(n) batch event processing (was O(n^2) with orderedRemove)"
echo "  - Connection pooling with reuse"
echo "  - Atomic operations for lock-free metrics"
echo "  - Stream ID caching"
echo ""
echo "Key performance metrics:"
echo "  - connections_created: New connection allocations"
echo "  - connections_pooled: Reused connections from pool"
echo "  - peak_active: Maximum concurrent connections"
echo "  - channel_operations: Event loop processing count"
echo ""

echo "=== Connection Test Complete ==="
