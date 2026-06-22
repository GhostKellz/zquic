# Future Features

This document tracks larger features that are intentionally **not** part of the current release bar but are being scoped toward a more complete future release.

## Production PQC Roadmap

The next major push is not "turn PQ on everywhere." The goal is to make
post-quantum support a serious, auditable QUIC feature with stable defaults,
clear interop behavior, and no unsupported algorithm claims.

Release gates for production PQC:

- keep a versioned PQ handshake transcript for zquic's experimental path
- maintain deterministic test vectors for ML-KEM-768/1024, ML-DSA-65, and
  transcript hash binding
- maintain negative vectors for bad ML-KEM ciphertext, bad ML-DSA signature,
  replayed/tampered transcript, wrong role, wrong packet number, and downgraded
  feature flags
- document key schedule labels and compare them against the current zcrypto API
- add interop-style packet traces that can be replayed without network timing
- keep default builds classical/stable until the PQ path has independent review
- provide a migration note for downstream users that already consume zcrypto

Candidate implementation areas:

- `src/crypto/pq_quic.zig` should remain the narrow PQ entry point
- `src/crypto/hybrid_pq_tls.zig` now rejects implicit classical-only fallback,
  validates key-share lengths before fixed-array conversion, and has cleanup
  regression tests; it still needs independent review before graduation
- `src/performance/crypto_connection_multiplexer.zig` now has opt-in PQ-capable
  pooling, authenticated resumption tickets, configured active/previous issuer
  keys, and default 0-RTT suppression; it still needs independent interop and
  lifecycle review before production graduation
- release validation should include default, minimal, full, and PQ matrices on
  the same Zig dev toolchain

Current transcript contract:

- `src/crypto/pq_quic.zig` exposes `PQHandshakeTranscript` as an internal,
  versioned binder input, not a QUIC wire format.
- The current domain label is `zquic pq transcript v1`.
- The hash binds transcript version, cipher-suite id, role, experimental-crypto
  flag, ML-KEM public key, optional X25519 public key, and ML-KEM ciphertext.
- Client and server transcript hashes are intentionally role-separated.
- Secret agreement helpers require client/server roles, matching suite, matching
  binder material, and equal derived secrets.

## PQ Multiplexer Support

Post-quantum support inside `src/performance/crypto_connection_multiplexer.zig`
is now wired as an opt-in preview feature, not a default production profile.

Current release posture:

- `enable_post_quantum` in the multiplexer remains disabled by default
- enabling it creates explicit PQ-capable pooled connections instead of silently
  returning a classical pooled connection
- pooled PQ tickets are authenticated with issuer key IDs and HMAC-SHA256 MACs
- deployments can provide persistent active issuer material plus one previous
  issuer for a bounded rotation window; new tickets are signed only by the
  active issuer
- PQ resumption policy suppresses early data by default and requires explicit
  policy agreement before accepting early data
- users should treat pooled PQ support as preview-grade and keep production
  deployments behind their own review, validation, and issuer-key rotation plan

Why this is not yet a production default:

- it still needs external interop coverage and security review
- the hard part is proving correct lifecycle semantics for:
  - connection creation
  - handshake completion
  - pooling eligibility
  - connection reuse
  - resumption
  - 0-RTT interaction

The detailed implementation and release constraints live here:

- `../tasks/pq_spec.md`

That spec is the source of truth for any future implementation.

## Release Boundary

For the current release line, the correct behavior is:

- advertise PQ-aware pooled connections only as explicit preview functionality
- keep PQ multiplexer requests behind explicit flags and fail closed on invalid
  ticket, binder, issuer, rotation, or policy state
- keep the PQ surface separately verified and disabled in default builds

For a future `v1.0.0`-grade release, PQ multiplexer support should only be added when the handshake and pooling semantics are explicitly implemented and tested.
