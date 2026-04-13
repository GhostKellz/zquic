#!/bin/bash
# Check dependencies are fetchable (validates pinned hashes)
# Run from project root: ./dev/deps.sh

set -e

echo "=== ZQUIC Dependencies ==="
echo ""

echo "Verifying pinned dependencies can be fetched..."
# Use zig build --fetch to validate without modifying build.zig.zon
zig build --fetch 2>&1 && echo "Dependencies verified." || {
    echo "Failed to fetch dependencies. Check network and build.zig.zon hashes."
    exit 1
}

echo ""
echo "Current dependency (from build.zig.zon):"
grep -A2 "zcrypto" build.zig.zon | grep -E "(url|hash)" || echo "Check build.zig.zon manually"

echo ""
echo "Done."
