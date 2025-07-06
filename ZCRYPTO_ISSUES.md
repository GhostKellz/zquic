# ZCrypto Issues for v0.5.0

This document tracks actual compilation issues found in the zcrypto v0.5.0 dependency that need to be addressed.

## Real Issues Found During ZQUIC v0.4.0 Development

### 1. Ed25519 SecretKey Type Mismatch in FFI

**File:** `/src/ffi.zig:127`
**Issue:** 
```zig
const keypair = std.crypto.sign.Ed25519.KeyPair{
    .secret_key = priv_key,  // Type mismatch
    .public_key = pub_key,
};
```
**Problem:** The `priv_key` type doesn't match the expected `Ed25519.SecretKey` type in recent Zig versions.

**Fix:** Need to properly construct the SecretKey type or update to match current Zig std.crypto API.

### 2. Ed25519.verify Method API Change

**File:** `/src/ffi.zig:157`
**Issue:**
```zig
std.crypto.sign.Ed25519.verify(sig, message_slice, pub_key) catch {
    return CryptoResult.failure(FFI_ERROR_VERIFICATION_FAILED);
};
```
**Problem:** The `Ed25519.verify` method signature has changed in recent Zig versions.

**Fix:** Update to use the current Zig std.crypto.sign.Ed25519 API (likely needs PublicKey type).

### 3. Pointer Type Casting Issue in FFI Tests

**File:** `/src/ffi.zig:872`
**Issue:** Related to pointer casting in the FFI test functions.
**Problem:** Pointer type casting incompatible with current Zig version.

**Fix:** Update pointer casting to match current Zig type system.

## Impact on ZQUIC

These FFI compatibility issues prevent clean compilation of ZQUIC v0.4.0 when zcrypto's FFI layer is used. The issues are related to Zig standard library API changes between different Zig versions.

## Root Cause

The zcrypto v0.5.0 FFI layer was developed against an earlier version of Zig's `std.crypto` API. Recent Zig versions have modified:
- `Ed25519.KeyPair` construction requirements
- `Ed25519.verify` method signature  
- Pointer type system and casting rules

## Workaround

ZQUIC v0.4.0 can be built successfully by:
1. Not using zcrypto's FFI layer directly
2. Using zcrypto's pure Zig APIs instead of C FFI exports
3. Building with a compatible Zig version

The core ZQUIC functionality works perfectly - only the FFI C exports are affected.

## Recommendation

The zcrypto library maintainers should:
1. Update FFI layer to use current Zig std.crypto API
2. Test against Zig 0.15+ versions  
3. Ensure C FFI exports work with modern Zig

## Status

- **Identified:** 2025-07-06 during ZQUIC v0.4.0 development
- **Affected ZQUIC Version:** v0.4.0 (FFI layer only)
- **ZCrypto Version:** v0.5.0
- **Severity:** Medium (FFI exports broken, core library works)
- **Priority:** High (needed for Rust integration)
- **Resolution:** ✅ **FIXED** - 2025-07-06 - FFI issues resolved in zcrypto

## ✅ Resolution Confirmed

The ZCrypto FFI compatibility issues have been **resolved**! 

**What was fixed:**
- Ed25519 SecretKey type compatibility with modern Zig
- Ed25519.verify method signature updated
- Pointer type casting issues resolved

**Impact:**
- ZQUIC v0.4.0 now builds cleanly without warnings
- Full Rust integration via FFI layer now works
- C exports for cross-language integration functional

---

*Issues resolved - ZQUIC v0.4.0 + ZCrypto integration now fully functional! 🎉*