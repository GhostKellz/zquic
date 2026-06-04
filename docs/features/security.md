# ZQUIC Security Features

This document describes the security features and hardening measures in ZQUIC.

## Cryptographic Security

### AEAD Encryption
All data encryption uses authenticated encryption with associated data (AEAD):
- **ChaCha20-Poly1305**: Primary cipher for packet encryption
- **AES-128-GCM / AES-256-GCM**: Alternative cipher suites
- Proper nonce construction using IV XOR packet number (QUIC specification)

### Key Material Handling
- **Secure Zeroization**: All key material is wiped using `std.crypto.secureZero()` to prevent compiler optimization from removing cleanup
- **No Placeholder Crypto**: Production builds reject any placeholder or simulated cryptographic operations
- **HKDF Key Derivation**: Keys derived using HKDF-SHA256/SHA384 as per TLS 1.3

### Post-Quantum Cryptography
- **ML-KEM-768**: Post-quantum key encapsulation (NIST FIPS 203)
- **ML-DSA-65**: Post-quantum digital signatures (NIST FIPS 204)
- **Hybrid Mode**: X25519 + ML-KEM for forward-secure key exchange

## TLS 1.3 Implementation

### Certificate Verification
- Full certificate chain parsing and storage
- CertificateVerify signature validation (RSA-PSS, ECDSA, Ed25519)
- Finished message HMAC verification using transcript hash

### Session Security
- Session ticket MAC verification
- Resumption secret protection
- Anti-replay measures for 0-RTT data

## HTTP/3 Security

### Authentication Middleware
- **Full JWT Validation**: HMAC-SHA256 signature verification on all auth paths
- **Constant-Time Comparison**: Token validation uses `std.crypto.timing_safe.eql()` to prevent timing attacks
- **Unified Verification**: Single canonical verifier for both direct and middleware authentication

### Path Traversal Protection
- Directory traversal detection (`..`, encoded variants)
- Null byte injection rejection
- Backslash (Windows-style) path rejection
- URL-encoded path segment validation
- Symlink escape detection

### Security Headers
Modern security header baseline:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (configurable)
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy` (restrictive defaults)

Note: `X-XSS-Protection` is intentionally omitted as it's deprecated and can cause issues in modern browsers.

### Rate Limiting
- Per-client request tracking
- Configurable request limits
- Automatic counter reset for memory management

## Build Security

### Dependency Management
Dependencies are fetched from pinned URLs with integrity hashes:
- `zcrypto`: Cryptographic primitives
- `zsync`: Synchronization utilities

### Compile-Time Safety
- `allow_simplified_verification = false` in production
- `allow_placeholder_crypto = false` guards on test-only code
- No silent failure paths in cryptographic operations

## Security Checklist for Deployment

### Before Production
- [ ] Verify all placeholder crypto is disabled (search for `allow_placeholder`)
- [ ] Enable HSTS only over HTTPS connections
- [ ] Configure appropriate CSP policy for your application
- [ ] Review rate limit settings for your traffic patterns
- [ ] Ensure certificate verification is enabled

### Ongoing
- [ ] Monitor for failed authentication attempts
- [ ] Review logs for path traversal attempts
- [ ] Keep dependencies updated
- [ ] Run security regression tests

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly. Do not open public issues for security vulnerabilities.

## Security Testing

Run the security regression tests:
```bash
# AEAD tamper test
zig build test -Dtest-filter="tamper"

# Path traversal tests
zig build test -Dtest-filter="path"

# JWT validation tests
zig build test -Dtest-filter="jwt"
```
