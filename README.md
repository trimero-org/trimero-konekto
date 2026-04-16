# Trimero Konekto

> Sovereign European identity layer — privacy-first, post-quantum ready, open source.

Konekto is the authentication and identity infrastructure powering the Trimero ecosystem.
It is the zero-trust, GDPR-native backbone that lets any European citizen, company,
or institution manage their digital identity with full sovereignty.

---

## Why Konekto exists

Today, your digital identity belongs to Google, Apple, or Microsoft.
You log in with their button. They hold your data. You have no real choice.

Konekto is the European alternative:
- **You own your identity** — Konekto verifies it, never holds it
- **Three isolated contexts** — personal, professional, civic life never mix
- **No ads, no data monetization, ever** — it is in our statutes
- **Post-quantum cryptography** — built for the next 50 years, not just today

---

## Architecture

A Konekto identity has one root and three derived contexts,
cryptographically isolated from each other:
Root Identity (never stored in plaintext)
├── Vivo    — personal life   (derived key A)
├── Laboro  — professional    (derived key B)
└── Socio   — civic life      (derived key C)

No service can access data from another context.
This isolation is cryptographic, not just logical.

---

## Technical foundations

| Layer | Choice | Rationale |
|---|---|---|
| Language | Rust | Memory safety, zero CVE classes, ANSSI recommended |
| Classical crypto | `aws-lc-rs` | Audited, BoringSSL-based, production-proven |
| Post-quantum KEM | `ml-kem` (ML-KEM-768) | NIST FIPS 203, 2024 standard |
| Post-quantum signatures | `ml-dsa` (ML-DSA-65) | NIST FIPS 204, 2024 standard |
| Strategy | Hybrid classical + PQ | Both must succeed — if one is broken, the other holds |
| Authentication | Passkeys / FIDO2 | No passwords by default |
| Protocols | OAuth 2.1 + OIDC | Universal SSO standard |
| HTTP framework | Axum | Async, tokio-native, ergonomic |
| Database | PostgreSQL | Mature, sovereign, zero vendor lock-in |
| Hosting | OVHcloud / Scaleway | European jurisdiction only, contractually guaranteed |

---

## Project structure
trimero-konekto/
├── crates/
│   ├── konekto-core/     # Domain logic, crypto, identity model
│   ├── konekto-api/      # Axum HTTP server, OpenAPI spec
│   ├── konekto-grpc/     # Tonic gRPC inter-service
│   ├── konekto-db/       # SQLx migrations, repository layer
│   └── konekto-sdk/      # Client SDK for Trimero apps
├── docs/
│   ├── adr/              # Architecture Decision Records
│   └── threat-model.md   # Living threat model
├── migrations/           # PostgreSQL migrations
├── tests/                # Integration tests
└── .github/
└── workflows/        # CI: clippy, rustfmt, tests, coverage

---

## Principles

**Security by design**
Every cryptographic operation uses audited crates only.
Zero custom primitives. Zero secrets in source code.

**GDPR by design**
Data minimization is an architectural constraint, not a policy.
Every data field must be justified. Export and deletion are first-class features.

**Maintainability first**
Code is written to be read by a future engineer who has never seen this codebase.
Explicit over implicit. No clever code.

**Open source**
License: AGPL-3.0
The core will always be open, auditable, and forkable.

---

## Status

> 🚧 Pre-alpha — foundational architecture in progress.

This project is in its earliest stage. No production-ready code yet.
Follow the [ADRs](docs/adr/) to understand the decisions being made.

---

## Part of the Trimero ecosystem

Konekto is the identity backbone of [Trimero](https://trimero.app) —
a suite of sovereign European alternatives to dominant American platforms.
Trimero
├── Vivo    — personal apps (messaging, social, email...)
├── Laboro  — professional suite (productivity, storage, contracts...)
└── Socio   — civic infrastructure (health, voting, public services...)

All powered by a single Konekto identity.

---

## License

[AGPL-3.0](LICENSE) — core infrastructure
[MIT](LICENSE-MIT) — client SDKs

---

*Trimero Konekto is built on the belief that digital sovereignty
is a fundamental right for every European citizen.*
