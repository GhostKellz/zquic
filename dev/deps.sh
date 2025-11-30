#!/bin/bash
# Check and fetch dependencies
# Run from project root: ./dev/deps.sh

set -e

echo "=== ZQUIC Dependencies ==="
echo ""

echo "Fetching dependencies..."
zig fetch --save git+https://github.com/chrischtel/zcrypto#main 2>&1 || echo "zcrypto: using cached"
zig fetch --save git+https://github.com/chrischtel/zsync#main 2>&1 || echo "zsync: using cached"

echo ""
echo "Current dependency hashes (from build.zig.zon):"
grep -A2 "zcrypto\|zsync" build.zig.zon | grep -E "(url|hash)" || echo "Check build.zig.zon manually"

echo ""
echo "Done."
