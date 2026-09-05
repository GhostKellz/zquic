# Crypto Module Maturity

This page describes the release posture of zquic crypto modules for v0.9.17.
It is a support boundary, not a standards certification.

## Stable Production Defaults

| Module | Status | Notes |
|--------|--------|-------|
| `src/core/crypto.zig` | Supported | QUIC AEAD/header-protection helper with bounds checks, tamper tests, offset-aware header-protection helpers, and RFC 9001 Appendix A header-protection vectors. |
| `src/core/packet_crypto.zig` | Supported helper facade | Packet encryption/decryption facade backed by `src/core/crypto.zig`; imports available `EnhancedTlsContext` Initial/Handshake/Application keys, emits constrained raw QUIC packets with variable-length packet numbers, including 0-RTT packet-boundary coverage, and retains deterministic helper keys only as a not-yet-derived fallback. |
| `src/core/connection.zig` | Supported orchestration surface | Exposes protected payload helpers that use `PacketCrypto`, dispatch decrypted STREAM/connection frames, route CRYPTO frames through `HandshakeManager`, apply Comprehensive TLS peer transport parameters, retain owned raw packet queues, schedule flow-control/PTO/ACK/STREAM frames into protected datagrams, reassemble CRYPTO bytes by encryption level, rejects 0-RTT application data by default unless explicitly enabled, and tracks packet crypto stats. |
| `src/crypto/tls.zig` | Compatibility utility | Minimal TLS-facing key container used by examples and SSH/QUIC wrapper paths; stores generated handshake bytes so local orchestration tests can derive matching transcript-bound packet keys. |
| `tests/zcrypto_stable_test.zig` | Supported test contract | Runs without PQ flags and covers stable zcrypto primitives. |

## Experimental Or Draft-Gated Surfaces

| Module | Status | Release boundary |
|--------|--------|------------------|
| `src/crypto/handshake.zig` | Local orchestration bridge | Coordinates the compatibility TLS flow and can derive Enhanced TLS packet keys from the stored CRYPTO transcript into `PacketCrypto`. This proves local handshake-to-packet-key wiring, not production certificate-validated TLS record-layer interop. |
| `src/crypto/ssh_quic.zig` | Draft integration | Implements pre-derived SSH/QUIC secret injection for experimentation with `draft-denis-ssh-quic`. It does not perform SSH KEX, transcript validation, replay control, or draft compatibility negotiation. |
| `src/crypto/enhanced_tls.zig` | QUIC TLS utility | Provides zcrypto-backed key derivation, packet AEAD, and header-protection helpers. It is used by PQ integration tests, but it is not a full TLS stack. |
| `src/crypto/tls13_key_schedule.zig` | Supported leaf helper | Implements HKDF-Expand-Label, `Derive-Secret`, Finished verify data, the TLS 1.3 handshake and application traffic-secret schedules, and RFC 9001 `quic key` / `quic iv` / `quic hp` derivation for SHA-256 + AES-128-GCM. Verified against RFC 8448 §3 vectors. Early-data, exporter, resumption, and key-update secrets remain out of scope. |
| `src/crypto/tls13_messages.zig` | Supported leaf helper | Strict length-bounded ClientHello parsing and ServerHello construction for the single supported parameter set. It rejects truncation, overflow, every duplicate extension type, inconsistent `supported_groups` / `key_share` offers, and trailing bytes. It is a message codec only: it holds no state, no keys, and no transcript. |
| `src/crypto/tls13_identity.zig` | Probe fixture helper | Generates ephemeral self-signed Ed25519 and ECDSA P-256 certificates for external interop clients. These are process-local test credentials, not a production identity or certificate lifecycle API. |
| `src/crypto/comprehensive_tls.zig` | Bounded experimental engine | Provides bounded QUIC CRYPTO deframing and a strict server path for TLS 1.3, AES-128-GCM-SHA256, X25519, Ed25519, `h3`, and QUIC transport parameters. It emits a transcript-bound complete server flight, verifies peer Finished, and exposes application keys only after authentication. The probe path interoperates through external 1-RTT decryption, but the engine is not production TLS: its supported parameter set and certificate policy are intentionally narrow, and exporter/resumption/key-update plus HTTP/3 orchestration remain incomplete. |
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
| `src/crypto/comprehensive_tls.zig` | Parses TLS ciphertext record framing via `zcrypto.tls.record`; decrypts TLSInnerPlaintext for supported traffic keys after AEAD tag verification; delegates X.509 DER, hostname, and caller-supplied root validation to `zcrypto.tls.config`; exposes explicit production/raw-public-key/test certificate policy modes; validates `h3` ALPN and QUIC transport parameters; and drives the probe-only Ed25519/ECDSA P-256 server flight through authenticated Finished. External clients verify the generated flight, and configured signing keys must match their leaf certificates. | Complete certificate-chain and revocation policy, production credential lifecycle, broad signature/cipher negotiation, SAN policy owned by zquic, client-side TLS orchestration, and application key update. |
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
  ALPN, application policy, and remembered transport parameters all match; the
  connection dispatcher rejects early application data by default.
- SSH/QUIC must reject zero or reused directional secrets.
- Draft integrations must be documented as draft/experimental until interop tests and replay/key-update behavior are in place.
- Certificate validation must be documented as incomplete unless the caller
  supplies an external validation boundary or uses the delegated zcrypto X.509
  verification helper with explicit trust anchors.
- Unsupported algorithms such as RSA, SLH-DSA, and X448 are out of the v0.9.17 crypto contract unless a later release implements and tests them.

## TLS Fixtures

- `tests/fixtures/tls/record-handshake.json` pins a minimal TLS 1.3
  handshake-record byte sequence that is parsed through `zcrypto.tls.record`.
- `tests/fixtures/tls/certificate-verify-ed25519.json` pins the exact TLS 1.3
  CertificateVerify input for the deterministic transcript
  `server hello transcript`; tests sign and verify that input with a raw
  Ed25519 certificate.
