#!/bin/bash
# Check for deprecated Zig API patterns
# Run from project root: ./dev/check_api.sh

echo "=== Checking for deprecated Zig 0.16 API patterns ==="
echo ""

echo "[1] Old time API (milliTimestamp/nanoTimestamp):"
matches=$(rg "milliTimestamp|nanoTimestamp" --type zig -l 2>/dev/null)
if [ -n "$matches" ]; then
    echo "$matches"
else
    echo "  None found ✓"
fi
echo ""

echo "[2] toOwnedSlice() without allocator (might be valid for unmanaged):"
matches=$(rg "\.toOwnedSlice\(\)" --type zig -l 2>/dev/null)
if [ -n "$matches" ]; then
    echo "$matches"
else
    echo "  None found ✓"
fi
echo ""

echo "[3] Old ArrayList.init(allocator) pattern:"
matches=$(rg "ArrayList\([^)]+\)\.init\(allocator" --type zig -l 2>/dev/null)
if [ -n "$matches" ]; then
    echo "$matches"
else
    echo "  None found ✓"
fi
echo ""

echo "[4] Bare 'allocator' variable (should be self.allocator in methods):"
# This is a heuristic - may have false positives
matches=$(rg "append\(allocator," --type zig -l 2>/dev/null)
if [ -n "$matches" ]; then
    echo "  Found potential issues in:"
    echo "$matches"
else
    echo "  None found ✓"
fi
echo ""

echo "[5] Build validation:"
if zig build 2>&1 | tee /tmp/zig-build.log | grep -q "error:"; then
    echo "  Build FAILED:"
    cat /tmp/zig-build.log
    exit 1
else
    echo "  Build OK ✓"
fi
echo ""

echo "=== Check Complete ==="
