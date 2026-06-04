# Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| `0.9.13` | Supported |
| `main` | Best effort |
| `< 0.9.13` | Not supported |

Security fixes are targeted at the current release line first.

## Reporting a Vulnerability

Please do **not** open a public issue for an unpatched security vulnerability.

Preferred reporting path:

1. Use GitHub Security Advisories / private vulnerability reporting for this repository if it is enabled.
2. If private reporting is not available, contact the maintainer directly through the repository owner contact channel.

Please include:

- affected version / commit
- target OS and Zig version
- feature flags used for the build
- whether the issue affects default builds, optional modules, or experimental crypto
- proof of concept, repro steps, logs, or failing tests if available
- whether the issue is memory safety, crypto correctness, authentication, transport, or docs/claim mismatch

We will try to acknowledge reports quickly and triage based on impact and reproducibility.

## Scope

This policy covers vulnerabilities in:

- QUIC transport implementation
- HTTP/3, DoQ, VPN, and service modules shipped in this repository
- FFI bindings exposed by this repository
- build/test/release artifacts produced from this repository

It also includes integration risks where `zquic` misuses dependencies in a way that creates a security issue, especially `zcrypto`.

## Crypto Status

`zquic` uses `zcrypto v1.0.4` for parts of its cryptographic implementation.

Current support posture:

- stable/default builds are the primary supported security target
- post-quantum support is **experimental** and requires both `-Dpost-quantum=true` and `-Dexperimental-crypto=true`
- experimental PQ code should not be treated as production-grade cryptographic assurance unless explicitly documented otherwise

Known boundary conditions matter for responsible reporting:

- claims that exceed the actual implementation are security issues
- cryptographic correctness bugs in key exchange, KDF, packet protection, or authentication are security issues even if builds/tests pass
- configuration/default mismatches that make experimental crypto look stable should be reported

## What To Report

Examples of in-scope issues:

- authentication bypass
- memory corruption, use-after-free, double-free, or out-of-bounds access
- cryptographic misuse or incorrect key exchange / packet protection
- request smuggling, path traversal, or privilege bypass in HTTP/3 or services
- incorrect feature gating that exposes experimental crypto as supported/secure
- secret leakage in logs, telemetry, panic output, or FFI boundaries

Examples that are usually lower priority unless they have real impact:

- purely theoretical issues without a realistic trigger path
- missing hardening that does not create an exploit path
- dependency version churn without a demonstrated effect on `zquic`

## Disclosure Expectations

- Please allow time for investigation and a fix before public disclosure.
- Coordinated disclosure is preferred.
- If a report turns out to be caused by an experimental PQ path, we still want the report; the experimental label does not make correctness bugs unimportant.

## Hardening Guidance

For production deployments:

- use the latest supported Zig toolchain for this release line
- prefer the default stable crypto path unless you are intentionally evaluating PQ features
- do not enable experimental PQ features in production without your own review and validation
- keep certificates, keys, and private material out of the repository and test fixtures
- run the full local validation/test workflow before shipping changes

## Non-Goals

This file is not a promise that every optional or experimental module has the same maturity level.
`SECURITY.md` defines reporting expectations and support posture; the actual implementation status is defined by the code, tests, and release notes.
