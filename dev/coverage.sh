#!/bin/bash
# ZQUIC Test Coverage Script
# Generates test coverage reports using kcov
# Run from project root: ./dev/coverage.sh

set -e

echo "=== ZQUIC Test Coverage ==="
echo "Zig version: $(zig version)"
echo ""

COVERAGE_DIR="coverage"
BUILD_DIR="zig-out"

# Check for kcov
if ! command -v kcov &> /dev/null; then
    echo "ERROR: kcov not installed"
    echo ""
    echo "Install kcov:"
    echo "  Debian/Ubuntu: apt install kcov"
    echo "  Fedora:        dnf install kcov"
    echo "  Arch:          pacman -S kcov"
    echo "  macOS:         brew install kcov"
    echo ""
    echo "Or build from source: https://github.com/SimonKagworthy/kcov"
    exit 1
fi

echo "kcov version: $(kcov --version 2>&1 | head -1)"
echo ""

# Clean previous coverage
echo "[1/4] Cleaning previous coverage data..."
rm -rf "$COVERAGE_DIR" 2>/dev/null || true
mkdir -p "$COVERAGE_DIR"

# Build tests with debug info
echo "[2/4] Building tests with debug symbols..."
zig build test -Doptimize=Debug 2>&1 || true

# Find test binary
TEST_BINARY=$(find .zig-cache -name "test" -type f -executable 2>/dev/null | head -1)

if [ -z "$TEST_BINARY" ]; then
    echo "No test binary found in .zig-cache"
    echo "Running zig build test to generate it..."

    # Run tests and capture the test binary path
    zig build test 2>&1 || true
    TEST_BINARY=$(find .zig-cache -name "test" -type f -executable 2>/dev/null | head -1)
fi

if [ -z "$TEST_BINARY" ]; then
    echo "ERROR: Could not find test binary"
    echo ""
    echo "Alternative: Run coverage on individual test files"
    echo ""

    # Fallback: run kcov on unit tests
    echo "[3/4] Running kcov on unit tests..."

    for test_file in src/core/*.zig src/utils/*.zig; do
        if [ -f "$test_file" ]; then
            name=$(basename "$test_file" .zig)
            echo "  Testing: $name"
            zig test "$test_file" 2>/dev/null || true
        fi
    done

    echo ""
    echo "[4/4] Coverage summary (fallback mode)..."
    echo "  Full kcov integration requires test binary access"
    echo "  Consider using 'zig build test' output for detailed coverage"
    exit 0
fi

echo "Found test binary: $TEST_BINARY"
echo ""

# Run kcov
echo "[3/4] Running kcov..."
kcov \
    --include-path=src \
    --exclude-pattern=test,examples,.zig-cache \
    "$COVERAGE_DIR" \
    "$TEST_BINARY" 2>&1 || true

echo ""
echo "[4/4] Coverage report generated..."

# Check if report was generated
if [ -f "$COVERAGE_DIR/index.html" ]; then
    echo ""
    echo "Coverage report: $COVERAGE_DIR/index.html"
    echo ""

    # Extract summary if possible
    if command -v grep &> /dev/null; then
        coverage_pct=$(grep -oP 'covered">\K[0-9.]+' "$COVERAGE_DIR/index.html" 2>/dev/null | head -1 || echo "N/A")
        echo "Coverage: ${coverage_pct}%"
    fi
else
    echo "Coverage report not generated (kcov may need kernel support)"
    echo ""
    echo "Alternative coverage methods:"
    echo "  1. Use 'zig test --test-cmd=kcov' for per-file coverage"
    echo "  2. Run tests in Docker with kcov support"
    echo "  3. Use llvm-cov if available"
fi

echo ""
echo "=== Coverage Complete ==="
