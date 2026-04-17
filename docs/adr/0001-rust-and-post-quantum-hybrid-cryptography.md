# ADR-0001 — Rust as primary language and hybrid post-quantum cryptography

**Status:** Accepted
**Date:** 2026-04-16
**Author:** Hadrien MORTIER

---

## Context

Konekto is an identity infrastructure that will handle authentication
and personal data for potentially millions of European citizens.

A compromise at this layer is catastrophic — not just for Trimero,
but for every user who has entrusted us with their digital identity.

Two foundational decisions had to be made before writing a single line of code:
1. Which language to use for the core implementation
2. Which cryptographic strategy to adopt

---

## Decision 1 — Rust as primary language

We use **Rust** for all core Konekto components.

### Why Rust

- **Memory safety by design** — entire classes of vulnerabilities
  (buffer overflow, use-after-free, null pointer dereference) cannot exist in safe Rust.
  These vulnerabilities account for ~70% of CVEs in C/C++ security-critical software.
- **Zero-cost abstractions** — performance equivalent to C, without the unsafety
- **No garbage collector** — predictable latency, critical for auth flows
- **Institutional recognition** — the NSA, ANSSI (French national cybersecurity agency),
  and the White House ONCD all explicitly recommend Rust for security-critical software
- **Ecosystem maturity** — audited crates exist for every cryptographic primitive we need

### Alternatives considered

| Language | Rejected because |
|---|---|
| Go | GC-induced latency, weaker memory safety guarantees |
| C / C++ | Entire classes of memory vulnerabilities, unacceptable for this use case |
| Java / Kotlin | JVM overhead, GC, not idiomatic for crypto-layer code |
| Python | Interpreted, not suitable for performance-critical security infrastructure |

---

## Decision 2 — Hybrid classical + post-quantum cryptography

We adopt a **hybrid cryptographic strategy** combining classical and
post-quantum algorithms in parallel for all key exchange and signature operations.

### The post-quantum threat

Cryptographically Relevant Quantum Computers (CRQCs) will break RSA and
elliptic curve cryptography (ECDH, ECDSA). Timeline estimates vary (2030–2040),
but "harvest now, decrypt later" attacks are happening today:
adversaries collect encrypted data now to decrypt it once quantum computers exist.

An identity infrastructure built today must be secure for decades.

### Our hybrid strategy
Key exchange:  X25519       + ML-KEM-768  (NIST FIPS 203)
Signatures:    Ed25519      + ML-DSA-65   (NIST FIPS 204)
Symmetric:     AES-256-GCM  (quantum-resistant at current key sizes)

**Both algorithms must succeed for any operation to succeed.**
If classical cryptography is broken by a quantum computer, ML-KEM/ML-DSA holds.
If a flaw is discovered in the new PQ algorithms, X25519/Ed25519 holds.

### Why these specific algorithms

- **ML-KEM** (formerly Kyber) and **ML-DSA** (formerly Dilithium) are the
  NIST-standardized post-quantum algorithms as of 2024 (FIPS 203 and FIPS 204).
  They are the only PQ algorithms with full NIST standardization at time of writing.
- **X25519 and Ed25519** are the modern, widely-audited classical alternatives
  to RSA and ECDSA, with a strong security track record.

### Crates used

All cryptographic operations use audited crates exclusively.
Zero custom cryptographic primitives — ever.

| Primitive | Crate | Audit status |
|---|---|---|
| Classical crypto | `aws-lc-rs` | AWS internal audit, BoringSSL-based |
| ML-KEM | `ml-kem` | Based on NIST reference implementation |
| ML-DSA | `ml-dsa` | Based on NIST reference implementation |
| Passkeys / FIDO2 | `webauthn-rs` | Community-audited, widely deployed |

### Alternatives considered

| Approach | Rejected because |
|---|---|
| Classical only | Vulnerable to quantum harvest-now-decrypt-later attacks |
| Post-quantum only | PQ algorithms are newer, less battle-tested classically |
| Custom implementation | Never. Cryptography is not invented, it is used. |

---

## Consequences

- Slightly larger key sizes and signature sizes compared to classical-only
- Minor performance overhead from running both algorithm families in parallel
- Full compliance with ANSSI post-quantum migration recommendations
- Ready for eIDAS 2.0 integration when PQ is mandated at EU level
- Positioned as the first European identity infrastructure natively post-quantum ready

---

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [ANSSI — Post-quantum cryptography recommendations](https://www.ssi.gouv.fr)
