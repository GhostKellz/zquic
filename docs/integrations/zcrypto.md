# zcrypto v1.0.1 Integration Guide

ZQUIC uses [`zcrypto`](https://github.com/ghostkellz/zcrypto) for cryptographic operations. This document covers the stable v1.0.1 API contract and build configuration.

## Stable Core Modules

These modules are always available and form the stable API:

| Module | Purpose |
|--------|---------|
| `zcrypto.hash` | SHA-256, SHA-384, SHA-512, HMAC |
| `zcrypto.blake3` | Blake3 hashing (separate module) |
| `zcrypto.sym` | AES-GCM, ChaCha20-Poly1305 |
| `zcrypto.asym` | Ed25519 signatures |
| `zcrypto.kdf` | HKDF-SHA256, HKDF-SHA512, hkdfExpandLabel |
| `zcrypto.rand` | Cryptographically secure random bytes |
| `zcrypto.util` | Secure memory, constant-time compare |
| `zcrypto.kex` | X25519 key exchange |
| `zcrypto.quic_crypto` | QUIC packet encryption (RFC 9001) |

## Build Flags

### Core flags forwarded to zcrypto:

```bash
# Stable build (default)
zig build

# With VPN features
zig build -Dvpn=true

# Full build with PQ support (experimental)
zig build -Dpost-quantum=true -Dexperimental-crypto=true
```

### Flag reference:

| Flag | Default | Description |
|------|---------|-------------|
| `-Dpost-quantum` | `false` | Enable ML-KEM-768 key exchange |
| `-Dexperimental-crypto` | `false` | Required for PQ features |
| `-Dvpn` | `false` | Enable VPN crypto helpers |

**Important**: Post-quantum cryptography requires both flags:
```bash
zig build -Dpost-quantum=true -Dexperimental-crypto=true
```

## Example Usage

### Hash functions
```zig
const zcrypto = @import("zcrypto");

// Streaming API (v1.0.1 uses .init() without args)
var hasher = zcrypto.hash.Sha256.init();
hasher.update(chunk1);
hasher.update(chunk2);
const digest = hasher.final();  // returns [32]u8

// SHA-384 (new in v1.0.1)
var sha384 = zcrypto.hash.Sha384.init();
sha384.update(data);
const hash384 = sha384.final();  // returns [48]u8

// Blake3 is in separate module
var blake = zcrypto.blake3.Blake3.init();
blake.update(data);
const blake_hash = blake.final();
```

### Key derivation
```zig
const allocator = std.heap.page_allocator;
const okm = try zcrypto.kdf.hkdfSha256(allocator, ikm, salt, info, 32);
defer allocator.free(okm);
```

### Random bytes
```zig
var buffer: [32]u8 = undefined;
zcrypto.rand.fill(&buffer);  // v1.0.1 uses .fill()
```

### Key exchange (X25519)
```zig
const keypair = try zcrypto.kex.X25519.generateKeypair();
const shared = try zcrypto.kex.X25519.computeSharedSecret(
    keypair.private_key,
    peer_public_key,
);
```

### Signatures (Ed25519)
```zig
const keypair = zcrypto.asym.ed25519.generate();
const sig = try zcrypto.asym.signEd25519(message, keypair.private_key);
const valid = zcrypto.asym.verifyEd25519(message, sig, keypair.public_key);
```

### Secure memory
```zig
var sensitive: [64]u8 = undefined;
// ... use sensitive data ...
zcrypto.util.secureZero(&sensitive);

// Constant-time comparison
const equal = zcrypto.util.constantTimeCompare(&a, &b);
```

## Experimental Features (PQ Crypto)

Post-quantum modules require `-Dpost-quantum=true -Dexperimental-crypto=true`:

- `zcrypto.post_quantum.ML_KEM_768` - ML-KEM key encapsulation (stdlib-backed)
- `zcrypto.post_quantum.pq.slh_dsa.SLH_DSA_128s` - SLH-DSA signatures

**Important caveats:**

1. These APIs may change between releases
2. The ZQUIC PQ integration (`src/crypto/pq_quic.zig`, `src/crypto/hybrid_pq_tls.zig`) is **experimental scaffolding**
3. Do not rely on the PQ path for production cryptographic security until explicitly marked stable
4. The hybrid classical+PQ key exchange uses real X25519 and ML-KEM-768 primitives, but the overall integration is still under development

### ZQUIC PQ Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| ML-KEM-768 | Real | Uses zcrypto's stdlib-backed ML-KEM-768 (1184-byte keys) |
| ML-KEM-1024 | Real | Uses zcrypto's stdlib-backed ML-KEM-1024 (1568-byte keys) |
| X25519 | Real | Uses zcrypto's X25519 implementation |
| SLH-DSA-128s | Real | Uses zcrypto's SLH-DSA implementation |

**Note**: The `ml_kem_1024_x25519_sha384` cipher suite uses real ML-KEM-1024 for post-quantum security and X25519 for classical security. The former X448 suite was renamed to accurately reflect the classical algorithm used.

## TLS Configuration

For QUIC connections, configure the TLS profile:

```zig
// Standard TLS 1.3 with X25519
const suite = zquic.CipherSuite.aes_256_gcm_sha384;

// Post-quantum (when enabled)
const pq_suite = zquic.PQCipherSuite{
    .kem = .ml_kem_768,
    .sig = .slh_dsa_sha2_128f,
};
```

## Migration from v1.0.0 to v1.0.1

Key changes in zcrypto v1.0.1:

| v1.0.0 | v1.0.1 |
|--------|--------|
| `zcrypto.hash.Sha256.init(.{})` | `zcrypto.hash.Sha256.init()` |
| `hasher.finalResult()` | `hasher.final()` |
| `zcrypto.rand.fillBytes()` | `zcrypto.rand.fill()` |
| No SHA-384 | `zcrypto.hash.Sha384` available |
| `zcrypto.hash.Blake3` | `zcrypto.blake3.Blake3` |

### ML-KEM API changes (v1.0.1)

```zig
// v1.0.0 (old)
const keypair = try ML_KEM_768.generateKeypair();

// v1.0.1 (new - seed-based)
var seed: [32]u8 = undefined;
zcrypto.rand.fill(&seed);
const keypair = ML_KEM_768.KeyPair.generate(seed);
```

## Migration from v0.9.x

If upgrading from zcrypto v0.9.x, update these deprecated namespaces:

| Old (deprecated) | New (v1.0.1) |
|------------------|--------------|
| `zcrypto.aead` | `zcrypto.sym` |
| `zcrypto.block` | Use `std.crypto.core.aes` |
| `zcrypto.stream` | Use `std.crypto.stream` |
| `zcrypto.symmetric` | `zcrypto.sym` |
| `zcrypto.random` | `zcrypto.rand` |
| `zcrypto.utils` | `zcrypto.util` |
| `zcrypto.signatures` | `zcrypto.asym` or `zcrypto.kex` |
| `zcrypto.key_exchange` | `zcrypto.kex` |
| `zcrypto.ecc` | `zcrypto.kex.X25519` |
