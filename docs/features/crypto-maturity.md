# Crypto Module Maturity

This page describes the release posture of zquic crypto modules for v0.9.15.
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
| `src/crypto/comprehensive_tls.zig` | Bounded experimental engine | Exposes maturity markers, zcrypto-backed TLS ciphertext record parsing, delegated zcrypto X.509 verification with caller-supplied roots, traffic-key/session-ticket helpers, key update helpers, EncryptedExtensions ALPN validation for `h3`, required EncryptedExtensions QUIC transport-parameter decoding, caller-supplied raw Ed25519 public-key verification, and transcript-bound raw Ed25519 CertificateVerify processing. It is still not a production TLS stack; full record-layer handshake orchestration and external interop vectors remain future work. |
| `src/crypto/hybrid_pq_tls.zig` | Experimental PQ scaffold | Requires `-Dpost-quantum=true -Dexperimental-crypto=true`. Current contract is ML-KEM-768 + X25519 experimentation, not production TLS deployment guidance. |
| `src/crypto/pq_quic.zig` | Experimental PQ integration | Gated behind PQ and experimental crypto flags. Includes a versioned internal transcript binder for role, suite, feature flag, key, and ciphertext binding. Tests cover ML-KEM/ML-DSA happy paths, tamper cases, downgrade checks, and wrong-role transcript failures. |
| `src/performance/crypto_connection_multiplexer.zig` | Preview PQ pooling | Opt-in PQ-capable pooling with authenticated resumption tickets, PQ binder checks, configured active/previous issuer keys, and default 0-RTT suppression. Still requires independent interop/security review before production-default use. |
| `src/crypto/zero_rtt_resumption.zig` | Preview PQ resumption | Classical 0-RTT remains available; hybrid-PQ tickets carry explicit policy, PQ binder material, issuer key IDs, remembered transport parameters, ALPN hash, application policy ID, and HMAC-SHA256 ticket MACs. Deployments can persist active issuer material and keep one previous issuer during a bounded rotation window. |

## Certificate Validation Posture

zquic does not currently provide production-complete TLS certificate
verification. The current surfaces have these boundaries:

| Surface | Implemented | Not implemented |
|---------|-------------|-----------------|
| `src/crypto/tls.zig` | Stores synthetic handshake/certificate bytes for compatibility tests and examples. | X.509 parsing, chain building, hostname validation, trust-anchor validation, revocation checks, and production CertificateVerify handling. |
| `src/crypto/enhanced_tls.zig` | Provides key derivation, packet AEAD, and header-protection helpers. | Certificate parsing or verification. This is not a standalone TLS stack. |
| `src/crypto/comprehensive_tls.zig` | Parses TLS ciphertext record framing via `zcrypto.tls.record`; delegates X.509 DER parsing, hostname checks, and caller-supplied root validation to `zcrypto.tls.config`; validates EncryptedExtensions ALPN as `h3`; requires, decodes, and retains QUIC transport parameters from EncryptedExtensions; verifies caller-supplied raw Ed25519 public-key certificates with validity bounds; verifies TLS 1.3 CertificateVerify signatures for raw Ed25519 certificates against the transcript hash; authenticates scaffold session tickets with HMAC; stores DER blobs as local containers and rejects local DER verification with `NotSupported`; rejects simplified RSA/ECDSA paths because `allow_simplified_verification` is false. | Full TLS record-layer handshake orchestration, complete certificate-chain policy, revocation posture, network-fed transport-parameter policy in the live TLS path, and external TLS interop vectors. |
| Application/server examples | Accept certificate paths or demo certificate data where relevant. | They do not turn zquic into a production TLS verifier; deployments must terminate TLS with a verified stack or supply their own validation boundary until this module matures. |

Documentation and examples must not claim "full certificate verification" until
the missing validation pieces above are implemented and covered by negative
tests and external interop evidence.

## Release Rules

- Default builds must remain on stable zcrypto primitives and must not compile PQ code.
- PQ paths must require both `-Dpost-quantum=true` and `-Dexperimental-crypto=true`.
- PQ pooling and PQ resumption must reject invalid issuer, MAC, binder, policy,
  and expiry state before accepting reuse.
- New tickets must be signed by the active issuer; previous issuers are
  validation-only and should be retained no longer than the ticket lifetime.
- 0-RTT early data must be accepted only when ticket authenticity, anti-replay,
  ALPN, application policy, and remembered transport parameters all match.
- SSH/QUIC must reject zero or reused directional secrets.
- Draft integrations must be documented as draft/experimental until interop tests and replay/key-update behavior are in place.
- Certificate validation must be documented as incomplete unless the caller
  supplies an external validation boundary or uses the delegated zcrypto X.509
  verification helper with explicit trust anchors.
- Unsupported algorithms such as RSA, SLH-DSA, and X448 are out of the v0.9.15 crypto contract unless a later release implements and tests them.

## TLS Fixtures

- `tests/fixtures/tls/record-handshake.json` pins a minimal TLS 1.3
  handshake-record byte sequence that is parsed through `zcrypto.tls.record`.
- `tests/fixtures/tls/certificate-verify-ed25519.json` pins the exact TLS 1.3
  CertificateVerify input for the deterministic transcript
  `server hello transcript`; tests sign and verify that input with a raw
  Ed25519 certificate.
