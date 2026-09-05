# RFC 9001 Crypto Audit

This audit tracks the v0.9.17 gap between zquic's crypto helpers and a
production-grade RFC 9001 QUIC-TLS integration. It is intentionally strict:
passing helper tests is not the same as completing the QUIC handshake, packet
protection, key update, 0-RTT, Retry, and certificate-validation lifecycle.

## Scope

| Area | Current status | Target files | Gap |
|------|----------------|--------------|-----|
| AEAD packet protection | `AeadOps` implements AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 with QUIC nonce construction and AAD input. Negative tests cover bad keys, IVs, tags, AAD, packet numbers, and buffers. `SuperConnection` can decrypt protected payloads through `PacketCrypto` and dispatch parsed frames. RFC 9001 Initial key derivation is pinned to Appendix A.1 vectors. | `src/core/crypto.zig`, `src/core/connection.zig`, `src/crypto/enhanced_tls.zig` | Full protected-payload RFC packet decrypt vectors and external stack evidence remain open. |
| Header protection | AES and ChaCha20 masks exist in `HeaderProtection` and `EnhancedHeaderProtection`. `HeaderProtection` now exposes offset-aware long/short header helpers pinned against RFC 9001 Appendix A client Initial, server Initial, and ChaCha20 short-header vectors. | `src/core/crypto.zig`, `src/crypto/enhanced_tls.zig` | Some alternate helpers in `src/crypto/keys.zig` remain simplified and should be quarantined or replaced. |
| Initial secrets | `deriveRfc9001InitialKeys()` uses the QUIC v1 initial salt, RFC 9001 HKDF labels, and Appendix A.1 vectors for client/server Initial secrets, keys, IVs, and header-protection keys. `EnhancedTlsContext.initializeInitialKeys()` remains the compatibility context helper. | `src/crypto/enhanced_tls.zig` | Initial packet protection vectors still need to be pinned above the helper-key level. |
| TLS handshake | The strict server path negotiates the supported ClientHello subset, emits ServerHello plus a complete transcript-bound Ed25519 or ECDSA P-256 server flight, verifies peer Finished, and installs directional RFC 9001 application keys only afterward. quiche, ngtcp2/gtlsclient, and aioquic reach authenticated Finished, 1-RTT decryption, and the fixed HTTP/3 response in the live probe. | `src/crypto/comprehensive_tls.zig`, `src/crypto/tls13_identity.zig`, `src/crypto/tls13_messages.zig`, `src/crypto/tls13_key_schedule.zig`, `src/core/connection.zig`, `tests/handshake_integration_test.zig` | The probe identities are ephemeral/self-signed, the TLS parameter set is narrow, and production certificate lifecycle, key update, broad HTTP/3, and a stable accept path remain incomplete. |
| Transport parameters in TLS | Standalone encode/decode validation exists, plus handshake-facing peer-role validation for remembered original destination CID, initial/retry source CID, migration disablement policy, and invalid active CID limits. `ComprehensiveTlsContext` decodes and retains peer QUIC transport parameters, and `SuperConnection.applyPeerTransportParametersFromTls()` validates them against handshake context before retaining an owned connection snapshot. The external server probe exercises ClientHello transport parameters on the socket path. | `src/core/transport_parameters.zig`, `src/core/connection.zig`, `src/crypto/comprehensive_tls.zig`, `tests/handshake_integration_test.zig` | Client-side EncryptedExtensions coverage and broader external parameter combinations remain. |
| Key update | `KeyManager` and `ComprehensiveTlsContext.CryptoKeys.updateKeys()` expose key-update helpers. Focused tests cover overlapping update rejection, pending/confirmed phase lookup, old-phase discard, rollback rejection, packet-number continuity, wrong-key decrypt failures, and a connection raw-packet rollover case where old packets fail after receiver key movement until the sender moves too. | `src/crypto/keys.zig`, `src/core/crypto.zig`, `src/crypto/comprehensive_tls.zig`, `tests/handshake_integration_test.zig` | The key-update policy is still not wired through a full TLS handshake with ACK-based old-key discard timing. |
| 0-RTT | Ticket authenticity, issuer rotation, PQ binder checks, and early-data policy helpers exist. Early-data validation now checks authenticated remembered transport parameters, ALPN, and application policy before anti-replay accepts the packet number. `PacketCrypto` also covers 0-RTT long-header raw packet protection/deprotection at the packet boundary. `SuperConnection` rejects early data by default unless `ConnectionParams.accept_early_data` is explicitly enabled. | `src/crypto/zero_rtt_resumption.zig`, `src/core/connection_migration.zig`, `src/core/packet_crypto.zig`, `src/core/connection.zig` | Address validation and integration with the live TLS resumption handshake remain future work. |
| Retry integrity | Retry parsing and CID validation are covered; Retry integrity tag computation now uses the QUIC v1 RFC 9001 AES-128-GCM key/nonce over the Retry pseudo-packet and is pinned by a local vector. | `src/core/packet.zig`, `src/crypto/keys.zig`, `tests/fixtures/interop/retry-integrity.json` | Needs external-stack Retry packet validation before release evidence can claim interop. |
| Certificate validation | `comprehensive_tls.zig` exposes explicit maturity markers, delegates X.509 DER/hostname/root validation to `zcrypto.tls.config`, exposes production/raw-public-key/test certificate policy hooks that fail closed unless the selected policy is satisfied, verifies caller-supplied raw Ed25519 public-key certificates with validity bounds, and rejects simplified verification. The probe signs transcript-bound CertificateVerify with an ephemeral Ed25519 or ECDSA P-256 leaf whose private key is checked against the certificate. | `src/crypto/comprehensive_tls.zig`, `src/crypto/tls13_identity.zig`, `docs/features/crypto-maturity.md`, `tests/fixtures/tls/certificate-verify-ed25519.json` | Complete certificate-chain and revocation policy, production credential lifecycle, client-side certificate verification, and broad signature-algorithm coverage are not production-complete. |
| Packet crypto facade | `PacketCrypto` exposes packet encrypt/decrypt/protect APIs. `SuperConnection` has protected payload send/process helpers that call the facade and dispatch decrypted QUIC frames. Constrained short-header, long-header Initial, long-header Handshake, and 0-RTT raw packet paths now protect/unprotect headers at the actual packet-number offset, emit and reconstruct variable-length packet numbers, schedule flow-control/control/PTO probe/ACK/STREAM frames, track sent packet spaces, process incoming ACK frames, and feed owned raw packet queues. `UdpMultiplexer` routes full datagrams into those queues, supports nonblocking receive routing, and flushes connection-owned raw packets to the peer address. | `src/core/packet_crypto.zig`, `src/core/connection.zig`, `src/net/multiplexer.zig`, `src/core/recovery.zig`, `src/core/flow_control.zig`, `tests/handshake_integration_test.zig` | A stable live client/server CLI and external stack interop still need to converge into one end-to-end path. |

## Module Posture

| Module | Posture | Notes |
|--------|---------|-------|
| `src/core/crypto.zig` | Active helper surface | Best current target for RFC 9001 packet-protection hardening. It already has real AEAD/header-protection logic and negative tests. |
| `src/crypto/enhanced_tls.zig` | QUIC TLS utility | Useful for HKDF, AEAD, and header-protection helpers. It is not a standalone TLS implementation. |
| `src/crypto/tls.zig` | Compatibility utility | Uses synthetic handshake messages and simplified derivation. Keep for examples/tests only unless replaced. |
| `src/crypto/handshake.zig` | Minimal coordinator | Coordinates the compatibility `TlsContext` and can synchronize transcript-derived Enhanced TLS packet keys into `PacketCrypto`; not a complete production QUIC TLS handshake. |
| `src/core/packet_crypto.zig` | Facade/hardening target | Uses the core crypto helper path for packet protection and imports available `EnhancedTlsContext` Initial/Handshake/Application keys, including keys supplied by the handshake manager bridge. |
| `src/core/connection.zig` | Live orchestration target | Routes Initial and Handshake CRYPTO through the strict TLS path, schedules the complete server flight in the correct packet spaces, authenticates peer Finished, applies peer transport parameters, installs directional application keys, dispatches protected 1-RTT frames, and drives bounded ACK/PTO/CRYPTO retransmission behavior. Production application orchestration remains separate. |
| `src/crypto/keys.zig` | Mixed key lifecycle helpers | Key update state is useful, but simplified derivation/header protection must not be presented as RFC 9001-complete. |
| `src/crypto/comprehensive_tls.zig` | Bounded experimental engine | QUIC CRYPTO deframing is bounded; accepted messages commit atomically; the strict server path builds the full flight, signs CertificateVerify, computes both Finished values at their exact transcript boundaries, and withholds application keys until peer authentication. Production trust policy and broader TLS negotiation remain intentionally outside this probe boundary. |
| `src/crypto/zero_rtt_resumption.zig` | Preview resumption policy | Ticket authenticity, issuer rotation, PQ binders, ALPN, application policy, and remembered transport parameters are enforced before early-data acceptance. Live TLS resumption wiring and address validation remain future work. |

## Next Work Items

1. Add RFC 9001 Initial protected payload decrypt vectors beyond the currently
   pinned header-protection vectors.
2. Continue moving packet protection call sites toward `src/core/crypto.zig`
   and keep facade tests focused on real AEAD/header-protection behavior.
3. Broaden key phase coverage from helper-level tests into the full connection
   path, including ACK-based old-key discard timing and peer-initiated updates.
4. Add the client-side TLS path that consumes network-derived EncryptedExtensions
   transport parameters and applies them to the connection.
5. Broaden delegated X.509 validation with real certificate-chain fixtures,
   trust-policy tests, SAN edge cases, and interop vectors.
6. Extend 0-RTT acceptance into the full TLS handshake path and add address
   validation policy once live handshake state is available.
7. Exercise RFC 9001 Retry integrity against external Retry packets from at
   least one maintained QUIC implementation.
8. Move the probe-validated scheduler, ACK, and loss behavior into a stable UDP
   client/server accept path.
9. Replace the local loopback test with a stable CLI-driven loopback smoke that
   exercises connection startup, request payload, ACK feedback, and shutdown.
10. Add pinned RFC 9001 Initial packet vectors before claiming vector-level
    packet protection compliance.

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

For v0.9.17, zquic can claim packet crypto helper coverage, an explicit RFC
9001 audit, and a narrow probe-only server handshake plus fixed HTTP/3 exchange
against three external clients. It must not claim broad QUIC-TLS
interoperability, production certificate validation, a full key-update
lifecycle, or general HTTP/3 server support until the gaps above are closed.
