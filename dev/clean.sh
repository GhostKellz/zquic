#!/bin/bash
# Clean build artifacts
# Run from project root: ./dev/clean.sh

set -e

echo "=== Cleaning ZQUIC build artifacts ==="

rm -rf zig-out .zig-cache

echo "Cleaned: zig-out/ .zig-cache/"
echo "Done."
