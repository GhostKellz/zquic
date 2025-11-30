#!/bin/bash
# Format all Zig source files
# Run from project root: ./dev/fmt.sh

set -e

echo "=== Formatting ZQUIC source ==="

zig fmt src/
zig fmt examples/
zig fmt tests/ 2>/dev/null || true

echo "Done."
