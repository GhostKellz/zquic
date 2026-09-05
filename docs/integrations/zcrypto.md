# zcrypto Integration Guide

ZQUIC uses [`zcrypto v1.0.6`](https://github.com/ghostkellz/zcrypto) for cryptographic operations. This document covers the current stable API contract and build configuration.

## v1.0.6 Contract

The default zquic build consumes the stable `zcrypto` surface only. Experimental
post-quantum code is compiled only when both zquic flags are enabled:
`-Dpost-quantum=true -Dexperimental-crypto=true`.
`zcrypto` also pins `zsync v0.8.4`, but zquic forwards `async=false` and does
not consume zcrypto's zsync-backed async wrappers.

zquic expects these `zcrypto` build features:

| zcrypto feature | zquic default | Reason |
|-----------------|---------------|--------|
| `tls` | enabled | QUIC TLS and packet crypto helpers |
| `hardware-accel` | enabled | AEAD/hash acceleration where available |
| `async` | disabled | zquic owns its runtime path |
| `vpn` | follows `-Dvpn` | Optional VPN helper surface |
| `post-quantum` | requires both PQ flags | Experimental ML-KEM/ML-DSA paths |
| `experimental-crypto` | follows `-Dexperimental-crypto` | Gate for non-default crypto APIs |

Unsupported algorithm claims are intentionally excluded from the stable
contract. In this release line, do not document RSA, SLH-DSA, or X448 support
unless the code and tests have been added.

## Stable Core Modules

These modules are always available and form the stable API:

| Module | Purpose |
|--------|---------|
| `zcrypto.core` | Stable error and core type definitions |
| `zcrypto.CryptoError` | Alias for `zcrypto.core.CryptoError` |
| `zcrypto.hash` | SHA-256, SHA-384, SHA-512, HMAC |
| `zcrypto.blake3` | Blake3 hashing (separate module) |
| `zcrypto.sym` | AES-GCM, ChaCha20-Poly1305, `SymError`, and key wrappers |
| `zcrypto.auth` | HMAC helpers and `HmacKey` |
| `zcrypto.asym` | Ed25519 signatures |
| `zcrypto.kdf` | HKDF-SHA256, HKDF-SHA512, hkdfExpandLabel |
| `zcrypto.rand` | Cryptographically secure random bytes |
| `zcrypto.util` | Secure memory, constant-time compare |
| `zcrypto.kex` | X25519 key exchange |
| `zcrypto.quic_crypto` | QUIC packet encryption (RFC 9001) |
| `zcrypto.quic` | QUIC packet crypto convenience surface |
| `zcrypto.key_rotation` | Key rotation helpers |

Direct stable `zcrypto.sym` AEAD decrypt helpers return `zcrypto.sym.SymError![]u8`.
Authentication failures are reported as `zcrypto.sym.SymError.DecryptionFailed`.
TLS wrapper callsites may still expose compatibility behavior, but direct
`sym` decrypt calls should not be treated as optional plaintext.

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

// Streaming API
var hasher = zcrypto.hash.Sha256.init();
hasher.update(chunk1);
hasher.update(chunk2);
const digest = hasher.final();  // returns [32]u8

// SHA-384
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
zcrypto.rand.fill(&buffer);
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

### Stable key wrappers
```zig
var aes_key = zcrypto.sym.Aes256GcmKey.random();
defer aes_key.zeroize();

var chacha_key = zcrypto.sym.ChaCha20Poly1305Key.random();
defer chacha_key.zeroize();

var hmac_key = try zcrypto.auth.HmacKey.fromBytes(allocator, "deployment-key");
defer hmac_key.deinit();
```

## Experimental Features (PQ Crypto)

Post-quantum modules require `-Dpost-quantum=true -Dexperimental-crypto=true`:

- `zcrypto.post_quantum.pq.ml_kem.ML_KEM_768` - ML-KEM key encapsulation (stdlib-backed)
- `zcrypto.post_quantum.pq.ml_dsa.ML_DSA_65` - ML-DSA-65 signatures (FIPS 204, stdlib-backed)

**Important caveats:**

1. These APIs may change between releases
2. The ZQUIC PQ integration (`src/crypto/pq_quic.zig`, `src/crypto/hybrid_pq_tls.zig`) is **experimental scaffolding**
3. Do not rely on the PQ path for production cryptographic security until explicitly marked stable
4. The hybrid classical+PQ key exchange uses real X25519 and ML-KEM-768 primitives, but the overall integration is still under development
5. RSA and SLH-DSA are not part of the zquic v0.9.17 crypto contract

### ZQUIC PQ Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| ML-KEM-768 | Real | Uses zcrypto's stdlib-backed ML-KEM-768 (1184-byte keys) |
| ML-KEM-1024 | Real | Uses zcrypto's stdlib-backed ML-KEM-1024 (1568-byte keys) |
| X25519 | Real | Uses zcrypto's X25519 implementation |
| ML-DSA-65 | Real | Uses zcrypto's stdlib-backed ML-DSA-65 implementation |

**Note**: The `ml_kem_1024_x25519_sha384` cipher suite uses real ML-KEM-1024 for post-quantum security and X25519 for classical security.

### PQ Transcript Binding

`src/crypto/pq_quic.zig` defines `PQHandshakeTranscript` for the experimental
PQ path. This is an internal binder contract, not a QUIC wire format.

The current transcript domain is `zquic pq transcript v1`. The transcript hash
binds:

- transcript version
- PQ cipher-suite id
- client/server role
- experimental-crypto feature flag
- ML-KEM public key
- optional X25519 public key for hybrid suites
- ML-KEM ciphertext

Client and server hashes are role-separated. Secret agreement checks require the
expected client/server roles, matching suite and binder material, and equal
derived secrets.

### PQ Ticket Issuer Rotation

PQ-capable connection pooling uses authenticated resumption tickets when
`src/performance/crypto_connection_multiplexer.zig` is compiled behind the PQ
flags. The default issuer is process-local random material, which is safe for
tests and single-process evaluation but intentionally invalidates tickets after
restart.

Deployments that need ticket continuity can configure explicit issuer material:

```zig
const zero_rtt = zquic.zero_rtt_resumption;
const crypto_pool = zquic.performance.CryptoConnectionMultiplexer;

const active = zero_rtt.TicketIssuerMaterial.init(active_key_id, active_mac_key);
const previous = zero_rtt.TicketIssuerMaterial.init(previous_key_id, previous_mac_key);

var mux = crypto_pool.CryptoConnectionMultiplexer.init(allocator, .{
    .enable_post_quantum = true,
    .enable_zero_rtt = true,
    .pq_ticket_issuer = active,
    .pq_previous_ticket_issuer = previous,
});
defer mux.deinit();
```

New tickets are signed with the active issuer. The previous issuer is
validation-only and should be retained no longer than the maximum ticket
lifetime. Remove it after the rotation window closes.

Operational rules:

- Generate `key_id` as a non-secret identifier and `mac_key` from a
  cryptographically secure random source.
- Store issuer material in a secret manager or equivalent deployment secret
  store, not in source control, metrics, tracing, or debug logs.
- Persist active issuer material only when tickets must survive process
  restarts; otherwise use the process-local random default.
- Rotate by installing a new active issuer and moving the old active issuer to
  `pq_previous_ticket_issuer`.
- Retain the previous issuer for no longer than the maximum ticket lifetime,
  then remove it so stale tickets fail closed.
- For incident invalidation, remove previous material immediately and replace
  the active issuer before issuing new tickets.
- Logs may include issuer key IDs for diagnosis. They must not include MAC
  keys, resumption secrets, PQ binders, ticket MACs, or full serialized tickets.

The Phase 5 review checklist for these rules lives in
[`docs/security/pq-review.md`](../security/pq-review.md).

## TLS Configuration

For QUIC connections, configure the TLS profile:

```zig
// Standard TLS 1.3 with X25519
const suite = zquic.CipherSuite.aes_256_gcm_sha384;

// Post-quantum key exchange (when enabled)
const pq_suite = zquic.PQCipherSuite.ml_kem_768_x25519_sha256;
```

## Migration Notes

Key changes in the current stable zcrypto API:

| Older API | Current API |
|-----------|-------------|
| `zcrypto.hash.Sha256.init(.{})` | `zcrypto.hash.Sha256.init()` |
| `hasher.finalResult()` | `hasher.final()` |
| `zcrypto.rand.fillBytes()` | `zcrypto.rand.fill()` |
| No SHA-384 | `zcrypto.hash.Sha384` available |
| `zcrypto.hash.Blake3` | `zcrypto.blake3.Blake3` |
| Optional direct `sym` decrypt result | `zcrypto.sym.SymError![]u8` |
| Raw `[32]u8` key only | `Aes256GcmKey`, `ChaCha20Poly1305Key`, `HmacKey` wrappers |

### ML-KEM API changes

```zig
// Older API
const keypair = try ML_KEM_768.generateKeypair();

// Current API (seed-based)
var seed: [32]u8 = undefined;
zcrypto.rand.fill(&seed);
const keypair = ML_KEM_768.KeyPair.generate(seed);
```

## Migration from v0.9.x

If upgrading from zcrypto v0.9.x, update these deprecated namespaces:

| Old (deprecated) | Current |
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
