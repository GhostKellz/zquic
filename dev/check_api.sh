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

echo "[5] Deprecated zcrypto patterns (pre-v1.0.0):"
# Check for old zcrypto namespace patterns
deprecated_patterns="zcrypto\.aead\.|zcrypto\.block\.|zcrypto\.stream\.|zcrypto\.symmetric\.|zcrypto\.random\.|zcrypto\.utils\.|zcrypto\.signatures\.|zcrypto\.key_exchange\.|zcrypto\.ecc\."
matches=$(rg "$deprecated_patterns" --type zig -l 2>/dev/null || true)
if [ -n "$matches" ]; then
    echo "  WARNING: Found deprecated zcrypto patterns in:"
    echo "$matches"
    echo "  (Use zcrypto.{hash,sym,asym,kdf,rand,util,kex} instead)"
else
    echo "  None found ✓"
fi
echo ""

echo "[6] Build validation:"
if zig build; then
    echo "  Build OK ✓"
else
    echo "  Build FAILED"
    exit 1
fi
echo ""

echo "=== Check Complete ==="
