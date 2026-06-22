#!/bin/bash
# Format all Zig source files
# Run from project root: ./dev/fmt.sh

set -e
ZIG="${ZIG:-/opt/zig-dev/zig}"

echo "=== Formatting ZQUIC source ==="

"$ZIG" fmt src/
"$ZIG" fmt examples/
"$ZIG" fmt tests/ 2>/dev/null || true

echo "Done."
