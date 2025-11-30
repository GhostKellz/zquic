#!/bin/bash
# Line count statistics
# Run from project root: ./dev/loc.sh

echo "=== ZQUIC Line Count Statistics ==="
echo ""

echo "Source (src/):"
find src -name "*.zig" -exec cat {} + 2>/dev/null | wc -l | xargs printf "  %'d lines\n"

echo ""
echo "Examples (examples/):"
find examples -name "*.zig" -exec cat {} + 2>/dev/null | wc -l | xargs printf "  %'d lines\n"

echo ""
echo "Tests (tests/):"
find tests -name "*.zig" -exec cat {} + 2>/dev/null | wc -l | xargs printf "  %'d lines\n"

echo ""
echo "By directory:"
for dir in src/core src/crypto src/http3 src/doq src/vpn src/services src/net src/async src/performance; do
    if [ -d "$dir" ]; then
        count=$(find "$dir" -name "*.zig" -exec cat {} + 2>/dev/null | wc -l)
        printf "  %-25s %'6d lines\n" "$dir:" "$count"
    fi
done

echo ""
echo "Total .zig files:"
find . -name "*.zig" -not -path "./.zig-cache/*" | wc -l | xargs printf "  %'d files\n"

echo ""
echo "Total lines:"
find . -name "*.zig" -not -path "./.zig-cache/*" -exec cat {} + 2>/dev/null | wc -l | xargs printf "  %'d lines\n"
