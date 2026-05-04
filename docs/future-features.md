# Future Features

This document tracks larger features that are intentionally **not** part of the current `v0.9.11` release bar but are being scoped toward a more complete future release.

## PQ Multiplexer Support

Post-quantum support inside `src/performance/crypto_connection_multiplexer.zig` is **not** currently wired as a real feature.

Current release posture:

- `enable_post_quantum` in the multiplexer remains disabled by default
- enabling it currently produces a warning/no-op rather than a negotiated PQ pooled connection
- users should use the explicit experimental PQ paths (`pq_quic.zig`, `hybrid_pq_tls.zig`) instead of assuming pooled PQ support exists

Why this is deferred:

- this is not just a small plumbing patch
- the hard part is defining correct lifecycle semantics for:
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

For `v0.9.11`, the correct behavior is:

- do not advertise PQ-aware pooled connections
- keep the current warning/no-op behavior honest
- finish documentation and stable-surface cleanup first

For a future `v1.0.0`-grade release, PQ multiplexer support should only be added when the handshake and pooling semantics are explicitly implemented and tested.
