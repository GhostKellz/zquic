# QPACK Interop Fixtures

These fixtures document zquic's current QPACK posture for v0.9.15.

The implementation is intentionally literal-only today. Fixtures therefore use
zquic's deterministic literal header block format rather than claiming full RFC
9204 dynamic-table support. Dynamic table usage is documented as disabled and
must remain rejected or absent until the decoder implements it deliberately.

Fixture result values:

- `accept`: decode succeeds and `expected_headers` must match exactly.
- `reject`: decode fails with `HeaderError`.
- `reject_invalid_data`: decode fails with `InvalidData`.

