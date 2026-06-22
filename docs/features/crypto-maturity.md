# Crypto Module Maturity

This page describes the release posture of zquic crypto modules for v0.9.14.
It is a support boundary, not a standards certification.

## Stable Production Defaults

| Module | Status | Notes |
|--------|--------|-------|
| `src/core/crypto.zig` | Supported | QUIC AEAD/header-protection helper with bounds checks and tamper tests. |
| `src/crypto/tls.zig` | Compatibility utility | Minimal TLS-facing key container used by examples and SSH/QUIC wrapper paths. |
| `tests/zcrypto_stable_test.zig` | Supported test contract | Runs without PQ flags and covers stable zcrypto primitives. |

## Experimental Or Draft-Gated Surfaces

| Module | Status | Release boundary |
|--------|--------|------------------|
| `src/crypto/ssh_quic.zig` | Draft integration | Implements pre-derived SSH/QUIC secret injection for experimentation with `draft-denis-ssh-quic`. It does not perform SSH KEX, transcript validation, replay control, or draft compatibility negotiation. |
| `src/crypto/enhanced_tls.zig` | QUIC TLS utility | Provides zcrypto-backed key derivation, packet AEAD, and header-protection helpers. It is used by PQ integration tests, but it is not a full TLS stack. |
| `src/crypto/comprehensive_tls.zig` | Experimental scaffold | Broad TLS 1.3 model with simplified verification disabled by default. Treat as a development surface until certificate validation, transcript handling, interop vectors, and handshake coverage mature. |
| `src/crypto/hybrid_pq_tls.zig` | Experimental PQ scaffold | Requires `-Dpost-quantum=true -Dexperimental-crypto=true`. Current contract is ML-KEM-768 + X25519 experimentation, not production TLS deployment guidance. |
| `src/crypto/pq_quic.zig` | Experimental PQ integration | Gated behind PQ and experimental crypto flags. Includes a versioned internal transcript binder for role, suite, feature flag, key, and ciphertext binding. Tests cover ML-KEM/ML-DSA happy paths, tamper cases, downgrade checks, and wrong-role transcript failures. |
| `src/performance/crypto_connection_multiplexer.zig` | Preview PQ pooling | Opt-in PQ-capable pooling with authenticated resumption tickets, PQ binder checks, configured active/previous issuer keys, and default 0-RTT suppression. Still requires independent interop/security review before production-default use. |
| `src/crypto/zero_rtt_resumption.zig` | Preview PQ resumption | Classical 0-RTT remains available; hybrid-PQ tickets carry explicit policy, PQ binder material, issuer key IDs, and HMAC-SHA256 ticket MACs. Deployments can persist active issuer material and keep one previous issuer during a bounded rotation window. |

## Release Rules

- Default builds must remain on stable zcrypto primitives and must not compile PQ code.
- PQ paths must require both `-Dpost-quantum=true` and `-Dexperimental-crypto=true`.
- PQ pooling and PQ resumption must reject invalid issuer, MAC, binder, policy,
  and expiry state before accepting reuse.
- New tickets must be signed by the active issuer; previous issuers are
  validation-only and should be retained no longer than the ticket lifetime.
- SSH/QUIC must reject zero or reused directional secrets.
- Draft integrations must be documented as draft/experimental until interop tests and replay/key-update behavior are in place.
- Unsupported algorithms such as RSA, SLH-DSA, and X448 are out of the v0.9.14 crypto contract unless a later release implements and tests them.
