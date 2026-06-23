# PQ Preview Review Checklist

This checklist is required before any future claim that zquic post-quantum
paths have graduated beyond preview status. It is not a certification record.

## Build And Scope Gates

- Default builds keep PQ code disabled.
- PQ code requires both `-Dpost-quantum=true` and
  `-Dexperimental-crypto=true`.
- Public docs describe PQ as experimental or preview until external review is
  complete.
- Release notes list every enabled PQ suite and every known unsupported suite.

## Transcript And Interop Evidence

- Deterministic traces cover ML-KEM-768/X25519 and ML-KEM-1024/X25519.
- Negative traces cover changed feature flags, changed roles, changed transport
  parameters, replayed ciphertext, and tampered transcript fields.
- Trace format is documented as an internal replay fixture, not a QUIC wire
  format.
- External interop notes name tested implementations, skipped implementations,
  versions, and observed gaps.

## Ticket Issuer Operations

- Active issuer material is generated from a cryptographically secure random
  source and stored outside logs, metrics, crash dumps, and source control.
- Deployments persist active issuer material when tickets must survive process
  restarts.
- Rotation promotes a new active issuer and retains exactly one previous issuer
  for no longer than the maximum ticket lifetime.
- Incident invalidation removes previous issuer material immediately and
  replaces the active issuer before new tickets are issued.
- Logs may include issuer key IDs and ticket IDs, but never MAC keys,
  resumption secrets, PQ binders, or ticket MAC values.

## Resumption Rejection Gates

- Expired tickets are rejected and removed from the local session table.
- Unknown issuers are rejected.
- Previous issuers outside the retention window are rejected.
- Early-data policy mismatches are rejected before anti-replay state is
  consumed.
- Binder mismatches are rejected.
- Migration posture mismatches in remembered transport parameters are rejected.

## Pool Lifecycle Gates

- PQ pooled connections are reusable only after handshake completion.
- PQ pooled connections do not support migration unless an implementation
  explicitly marks them migration-capable.
- 0-RTT is suppressed for PQ unless policy explicitly allows it.
- Pool reuse fails closed after key-policy, issuer, ticket, MAC, or binder
  mismatch.

## External Review Record

- Reviewer identity, date, zquic commit, zcrypto version, Zig version, and build
  flags are recorded.
- Findings distinguish correctness bugs, cryptographic design concerns,
  operational risks, and documentation overclaims.
- Fixes link to tests or docs that would have failed before the fix.
- Remaining risks are documented before release tagging.
