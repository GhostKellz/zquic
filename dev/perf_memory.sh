#!/bin/bash
# ZQUIC Memory Performance Test
# Tests for memory leaks using GeneralPurposeAllocator diagnostics
# Run from project root: ./dev/perf_memory.sh

set -e

echo "=== ZQUIC Memory Performance Test ==="
echo "Zig version: $(zig version)"
echo ""

# Build with debug info for better leak detection
echo "[1/4] Building with debug info..."
zig build -Doptimize=Debug
echo "Build complete!"
echo ""

# Run unit tests with GPA leak detection
echo "[2/4] Running tests with memory leak detection..."
zig build test 2>&1 | tee /tmp/zquic_memory_test.log
echo ""

# Check for leak reports in test output
echo "[3/4] Analyzing test output for memory issues..."
if grep -i "leak" /tmp/zquic_memory_test.log; then
    echo "WARNING: Potential memory leaks detected!"
    echo "Review the output above for details."
else
    echo "No obvious memory leaks in test output."
fi
echo ""

# Memory usage stats if valgrind is available
echo "[4/4] Checking memory usage stats..."
if command -v valgrind &> /dev/null; then
    echo "Valgrind available - running memory check on demo binary..."
    if [ -f "zig-out/bin/zquic-pq-demo" ]; then
        timeout 5s valgrind --leak-check=summary --error-exitcode=0 \
            zig-out/bin/zquic-pq-demo 2>&1 | tail -20 || true
    else
        echo "Demo binary not found, skipping valgrind check"
    fi
else
    echo "Valgrind not installed - skipping detailed memory analysis"
    echo "Install with: apt install valgrind (Debian/Ubuntu)"
fi

echo ""
echo "=== Memory Test Complete ==="
