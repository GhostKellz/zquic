# RFC 9001 Crypto Audit

This audit tracks the v0.9.15 gap between zquic's crypto helpers and a
production-grade RFC 9001 QUIC-TLS integration. It is intentionally strict:
passing helper tests is not the same as completing the QUIC handshake, packet
protection, key update, 0-RTT, Retry, and certificate-validation lifecycle.

## Scope

| Area | Current status | Target files | Gap |
|------|----------------|--------------|-----|
| AEAD packet protection | `AeadOps` implements AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 with QUIC nonce construction and AAD input. Negative tests cover bad keys, IVs, tags, AAD, packet numbers, and buffers. | `src/core/crypto.zig` | Needs RFC vectors and integration with full packet-number reconstruction and TLS-derived secrets. |
| Header protection | AES and ChaCha20 masks exist in `HeaderProtection` and `EnhancedHeaderProtection`. | `src/core/crypto.zig`, `src/crypto/enhanced_tls.zig` | Some alternate helpers in `src/crypto/keys.zig` remain simplified and should be quarantined or replaced. |
| Initial secrets | `EnhancedTlsContext.initializeInitialKeys()` uses the QUIC v1 initial salt and HKDF extract from the destination connection ID. | `src/crypto/enhanced_tls.zig` | Label usage needs RFC 9001 vector verification for client/server initial secrets, keys, IVs, and header-protection keys. |
| TLS handshake | `TlsContext` and `HandshakeManager` model a minimal message flow with synthetic handshake bytes. `ComprehensiveTlsContext` contains a broader experimental state machine with expected-message validation, transcript-preserving rejection, zcrypto-backed TLS ciphertext record parsing, EncryptedExtensions ALPN validation for `h3`, and required EncryptedExtensions QUIC transport-parameter decoding. | `src/crypto/tls.zig`, `src/crypto/handshake.zig`, `src/crypto/comprehensive_tls.zig`, `tests/fixtures/tls/*` | Full TLS record-layer handshake orchestration is not wired into the live network path. |
| Transport parameters in TLS | Standalone encode/decode validation exists, plus handshake-facing peer-role validation for remembered original destination CID, initial/retry source CID, migration disablement policy, and invalid active CID limits. `ComprehensiveTlsContext` decodes and retains QUIC transport parameters from EncryptedExtensions, and `Connection.applyPeerTransportParameters()` validates them against handshake context before retaining an owned connection snapshot. | `src/core/transport_parameters.zig`, `src/core/connection.zig`, `src/crypto/comprehensive_tls.zig`, `tests/handshake_integration_test.zig` | The live TLS record-layer handshake still needs to feed network-derived EncryptedExtensions into this connection policy end-to-end. |
| Key update | `KeyManager` and `ComprehensiveTlsContext.CryptoKeys.updateKeys()` expose key-update helpers. Focused tests cover overlapping update rejection, pending/confirmed phase lookup, old-phase discard, rollback rejection, packet-number continuity, and wrong-key decrypt failures. | `src/crypto/keys.zig`, `src/core/crypto.zig`, `src/crypto/comprehensive_tls.zig` | The key-update policy is still not wired through a full TLS handshake with ACK-based old-key discard timing. |
| 0-RTT | Ticket authenticity, issuer rotation, PQ binder checks, and early-data policy helpers exist. Early-data validation now checks authenticated remembered transport parameters, ALPN, and application policy before anti-replay accepts the packet number. | `src/crypto/zero_rtt_resumption.zig`, `src/core/connection_migration.zig` | Address validation and full TLS handshake integration remain future work. |
| Retry integrity | Retry parsing and CID validation are covered; Retry integrity tag computation now uses the QUIC v1 RFC 9001 AES-128-GCM key/nonce over the Retry pseudo-packet and is pinned by a local vector. | `src/core/packet.zig`, `src/crypto/keys.zig`, `tests/fixtures/interop/retry-integrity.json` | Needs external-stack Retry packet validation before release evidence can claim interop. |
| Certificate validation | `comprehensive_tls.zig` exposes explicit maturity markers, delegates X.509 DER/hostname/root validation to `zcrypto.tls.config`, verifies caller-supplied raw Ed25519 public-key certificates with validity bounds, verifies raw Ed25519 CertificateVerify signatures against TLS 1.3 transcript input, rejects local DER verification with `NotSupported`, and rejects simplified RSA/ECDSA paths when `allow_simplified_verification` is false. | `src/crypto/comprehensive_tls.zig`, `docs/features/crypto-maturity.md`, `tests/fixtures/tls/certificate-verify-ed25519.json` | Complete certificate-chain policy, revocation posture, RSA/ECDSA CertificateVerify in zquic, record-layer interop, and external TLS CertificateVerify vectors are not production-complete. |
| Packet crypto facade | `PacketCrypto` exposes packet encrypt/decrypt/protect APIs. | `src/core/packet_crypto.zig` | The local `QuicCrypto.QuicConnection` stub returns payload lengths without encrypting; do not treat this facade as production packet protection until replaced or wired to `src/core/crypto.zig`. |

## Module Posture

| Module | Posture | Notes |
|--------|---------|-------|
| `src/core/crypto.zig` | Active helper surface | Best current target for RFC 9001 packet-protection hardening. It already has real AEAD/header-protection logic and negative tests. |
| `src/crypto/enhanced_tls.zig` | QUIC TLS utility | Useful for HKDF, AEAD, and header-protection helpers. It is not a standalone TLS implementation. |
| `src/crypto/tls.zig` | Compatibility utility | Uses synthetic handshake messages and simplified derivation. Keep for examples/tests only unless replaced. |
| `src/crypto/handshake.zig` | Minimal coordinator | Coordinates the compatibility `TlsContext`; not a complete QUIC TLS handshake. |
| `src/core/packet_crypto.zig` | Facade/scaffold | Needs replacement of internal no-op crypto before production claims. |
| `src/crypto/keys.zig` | Mixed key lifecycle helpers | Key update state is useful, but simplified derivation/header protection must not be presented as RFC 9001-complete. |
| `src/crypto/comprehensive_tls.zig` | Bounded experimental engine | TLS record framing delegates to zcrypto; X.509 validation delegates to zcrypto with explicit trust anchors; EncryptedExtensions requires `h3` ALPN and QUIC transport parameters; raw Ed25519 public-key and transcript-bound CertificateVerify verification are implemented; production TLS orchestration remains incomplete. |
| `src/crypto/zero_rtt_resumption.zig` | Preview resumption policy | Ticket authenticity, issuer rotation, PQ binders, ALPN, application policy, and remembered transport parameters are enforced before early-data acceptance. Full TLS handshake wiring and address validation remain future work. |

## Next Work Items

1. Add RFC 9001 initial-secret vectors for client/server Initial secrets, keys,
   IVs, header-protection keys, protected packet bytes, and decrypted payloads.
2. Move packet protection call sites toward `src/core/crypto.zig` or replace
   the no-op `PacketCrypto` internals before adding new facade features.
3. Broaden key phase coverage from helper-level tests into the full connection
   path, including ACK-based old-key discard timing and peer-initiated updates.
4. Feed network-derived EncryptedExtensions transport parameters into
   `Connection.applyPeerTransportParameters()` from the live TLS handshake path.
5. Broaden delegated X.509 validation with real certificate-chain fixtures,
   trust-policy tests, hostname/SAN edge cases, and interop vectors.
6. Extend 0-RTT acceptance into the full TLS handshake path and add address
   validation policy once live handshake state is available.
7. Exercise RFC 9001 Retry integrity against external Retry packets from at
   least one maintained QUIC implementation.

## Telemetry Hooks

`src/monitoring/prometheus_exporter.zig` exposes counters for the Phase 3
security events that callers need to wire into live paths:

| Event | Metric |
|-------|--------|
| Handshake failure | `zquic_handshake_failures_total` |
| Key update | `zquic_key_updates_total` |
| Rejected 0-RTT | `zquic_zero_rtt_rejected_total` |
| Bad transport parameters | `zquic_bad_transport_parameters_total` |
| Retry | `zquic_retry_events_total` |
| Stateless reset | `zquic_stateless_reset_events_total` |

## Release Claim

For v0.9.15, zquic can claim packet crypto helper coverage and an explicit RFC
9001 audit. It must not claim complete QUIC-TLS interoperability, production
certificate validation, full key-update lifecycle, or 0-RTT acceptance safety
until the gaps above are implemented and tested against external vectors or
stacks.
