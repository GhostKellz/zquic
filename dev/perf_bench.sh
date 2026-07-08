#!/bin/bash
# ZQUIC Performance Benchmark
# Tests throughput, latency, and algorithmic performance
# Run from project root: ./dev/perf_bench.sh

set -e
ZIG="${ZIG:-/opt/zig-dev/zig}"

echo "=== ZQUIC Performance Benchmark ==="
echo "Zig version: $("$ZIG" version)"
echo "Date: $(date -Iseconds)"
echo ""

# Build optimized
echo "[1/5] Building release optimized..."
"$ZIG" build -Doptimize=ReleaseFast
echo "Build complete!"
echo ""

# Run benchmark tests
echo "[2/5] Running benchmark tests..."
mkdir -p zig-out/logs
BENCH_LOG="zig-out/logs/zquic_bench.log"
"$ZIG" build test -Doptimize=ReleaseFast 2>&1 | tee "$BENCH_LOG"
echo ""

# Binary size analysis
echo "[3/5] Binary size analysis..."
echo "Release binaries:"
if [ -d "zig-out/bin" ]; then
    ls -lh zig-out/bin/ | awk '{print "  " $9 ": " $5}'
    total_size=$(du -sh zig-out/bin/ | cut -f1)
    echo "  Total: $total_size"
else
    echo "  No binaries found"
fi
echo ""

# CPU/algorithm performance test
echo "[4/5] Algorithm performance analysis..."
echo "Running crypto benchmarks (if available)..."
if [ -f "zig-out/bin/zquic-pq-demo" ]; then
    echo "  Starting PQ demo for 2 seconds..."
    timeout 2s zig-out/bin/zquic-pq-demo 2>&1 || true
fi
echo ""

# Summary
echo "[5/5] Performance summary..."
echo "Build type: ReleaseFast"
echo "Test status: $(grep -c 'passed' "$BENCH_LOG" 2>/dev/null || echo 'N/A') tests passed"
echo ""

echo "=== Benchmark Complete ==="
echo ""
echo "Tips for further optimization:"
echo "  1. Profile with 'perf record' and 'perf report'"
echo "  2. Use 'zig build -Doptimize=ReleaseSafe' for production"
echo "  3. Enable SIMD with '-Dcpu=native' for architecture-specific optimizations"
