#!/bin/bash
# ZQUIC Comprehensive Performance Test Suite
# Runs all performance tests in sequence
# Run from project root: ./dev/perf_all.sh

set -e
ZIG="${ZIG:-/opt/zig-dev/zig}"
export ZIG

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       ZQUIC Comprehensive Performance Suite                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Zig version: $("$ZIG" version)"
echo "Date: $(date -Iseconds)"
echo "Platform: $(uname -s) $(uname -m)"
echo ""

RESULTS_DIR="/tmp/zquic_perf_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
echo "Results directory: $RESULTS_DIR"
echo ""

# 1. Memory Performance
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│ [1/4] Memory Performance Test                                │"
echo "└──────────────────────────────────────────────────────────────┘"
./dev/perf_memory.sh 2>&1 | tee "$RESULTS_DIR/memory.log"
echo ""

# 2. Buffer Performance
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│ [2/4] Buffer Performance Test                                │"
echo "└──────────────────────────────────────────────────────────────┘"
./dev/perf_buffers.sh 2>&1 | tee "$RESULTS_DIR/buffers.log"
echo ""

# 3. Connection Performance
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│ [3/4] Connection Performance Test                            │"
echo "└──────────────────────────────────────────────────────────────┘"
./dev/perf_connections.sh 2>&1 | tee "$RESULTS_DIR/connections.log"
echo ""

# 4. Release Benchmark
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│ [4/4] Release Benchmark                                      │"
echo "└──────────────────────────────────────────────────────────────┘"
./dev/perf_bench.sh 2>&1 | tee "$RESULTS_DIR/benchmark.log"
echo ""

# Summary
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Performance Summary                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Test Results saved to: $RESULTS_DIR"
echo ""
echo "Files:"
ls -lh "$RESULTS_DIR"
echo ""

# Count test results
PASSED=$(grep -rh 'passed\|OK\|complete' "$RESULTS_DIR" 2>/dev/null | wc -l || echo 0)
FAILED=$(grep -rih 'fail\|error\|leak' "$RESULTS_DIR" 2>/dev/null | wc -l || echo 0)

echo "Quick Stats:"
echo "  Success indicators: $PASSED"
echo "  Warning indicators: $FAILED"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo "⚠️  Some warnings detected. Review logs for details."
else
    echo "✓ All performance tests completed successfully!"
fi

echo ""
echo "=== Performance Suite Complete ==="
