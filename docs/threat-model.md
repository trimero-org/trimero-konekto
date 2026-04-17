# Trimero Konekto — Threat Model (v0)

**Status:** Living document — v0
**Last updated:** 2026-04-16
**Scope:** V1 architecture (`konekto-core`, `konekto-api`, `konekto-db`)

---

## 1. Purpose & methodology

This document enumerates the assets, actors, trust assumptions, and
threats that Konekto V1 must address. It is deliberately imperfect:
v0 is meant to expose gaps, not close them. Every *Open question* at
the end of this document is a pending decision that should either
become an ADR or update this model.

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information
disclosure, Denial of service, Elevation of privilege) per component,
plus cryptographic-specific concerns (key compromise, quantum
harvest-now-decrypt-later, context leakage).

**Non-goals for v0:**
- Formal verification of cryptographic protocols
- Supply-chain threat model (tracked separately once CI exists)
- Physical-security threats against hosting provider facilities

---

## 2. Assets

Ranked by blast radius if compromised.

| # | Asset | Sensitivity | Where it lives |
|---|---|---|---|
| A1 | **Root identity material** (entropy from which Vivo/Laboro/Socio keys derive) | Critical — single compromise breaks all three contexts for one user | Never stored in plaintext; derived on-demand from user-held factor (passkey + server-side wrapping) |
| A2 | **Context keys** (Vivo, Laboro, Socio) | High — compromise breaks one context for one user | Derived via HKDF at session time; never persisted |
| A3 | **Passkey public keys + WebAuthn credential metadata** | Medium (public, but identifying) | PostgreSQL, per-user |
| A4 | **Session tokens / refresh tokens** | High — grants impersonation until expiry/revocation | Redis (sessions), signed tokens to client |
| A5 | **PII minimized** (email for recovery, nothing else by default) | Medium — GDPR-sensitive | PostgreSQL, encrypted at rest |
| A6 | **Audit logs** (authentication events, consent grants, cross-context access) | High — integrity matters more than confidentiality | Append-only store (V1: PostgreSQL table; V2: consider WORM storage) |
| A7 | **Server-side signing keys** (for ID tokens, OIDC) | Critical — compromise enables mass impersonation | HSM or KMS (decision pending — see Open questions) |
| A8 | **Database at rest** (all of the above, structurally) | Critical | PostgreSQL on OVHcloud/Scaleway |

---

## 3. Actors

| Actor | Capabilities | In-scope? |
|---|---|---|
| **Legitimate user** | Holds a passkey; interacts via browser/OS WebAuthn | Yes — but may be phished, coerced, or have their device compromised |
| **Legal person (organization)** | Has an `OrgIdentity` anchored to SIREN; acts via its admins and delegated collaborators | Yes — squatting, malicious admin, all-admin loss (ADR-0005) |
| **Org admin** | Holds a wrap of the `OrgKey` under their Laboro context key; can invite/revoke admins and collaborators | Yes — rotation, revocation, break-glass recovery modeled explicitly |
| **Org collaborator** | Holds one or more `Delegation` capabilities scoped to a specific org | Yes — scoped, audited, revocable |
| **Konekto operator (break-glass)** | Under dual-control and HSM enforcement, can re-wrap a frozen org's key for a legally authorized claimant | Yes — explicit trust boundary (ADR-0005 §8) |
| **Unauthenticated network attacker** | Can intercept, replay, or modify TLS-protected traffic if TLS is misconfigured; can spam endpoints | Yes |
| **Authenticated attacker (low-priv)** | Has a legitimate Konekto identity; tries to escalate or pivot across contexts | Yes |
| **Malicious relying party** | A service that uses Konekto for SSO and tries to extract data beyond its scope | Yes |
| **Insider — infrastructure operator** | SSH/DB access on prod; read-only or read-write | Yes, partial mitigation |
| **Insider — Konekto maintainer** | Can merge code | Yes, partial mitigation (code review, signed commits) |
| **Hosting provider** (OVHcloud / Scaleway) | Can access physical hosts, disks, hypervisors | Yes, trusted-but-verified — European jurisdiction is a legal mitigation, not a technical one |
| **State-level adversary (signals intelligence)** | Passive network capture at scale; subpoena power in some jurisdictions | Partially — harvest-now-decrypt-later is explicitly addressed by hybrid PQ |
| **Future quantum attacker (CRQC)** | Breaks X25519, Ed25519, RSA in polynomial time | Yes — hybrid PQ crypto is the primary mitigation |
| **Supply-chain attacker** | Compromises a crate, a build artifact, or CI | Out of scope for v0 (tracked separately) |

---

## 4. Trust assumptions

These are assumptions that, if violated, invalidate parts of this model.
Every one of them is a future candidate for a compensating control.

1. **The user's device is not fully compromised at passkey-creation time.** A backdoored OS at enrollment can exfiltrate the passkey private key. Konekto cannot defend against this; we rely on the WebAuthn authenticator's security boundary.
2. **The WebAuthn authenticator behaves per spec.** Platform authenticators (Face ID, Windows Hello) and roaming authenticators (YubiKey) are trusted to enforce user presence/verification honestly.
3. **Audited crates are actually trustworthy.** `aws-lc-rs`, `ml-kem`, `ml-dsa`, `webauthn-rs` are assumed to correctly implement their primitives. Konekto does not independently verify this.
4. **The hosting provider does not actively attack us.** OVHcloud/Scaleway could technically read disk contents on a live host. We rely on contractual and jurisdictional protections, plus encryption at rest, to narrow this risk.
5. **PostgreSQL and Redis are patched.** Zero-day in the datastore is out of scope; timely patching is an operational (not architectural) concern.
6. **TLS 1.3 is correctly configured.** Downgrade, weak cipher negotiation, or misconfigured HSTS invalidates transport-layer assumptions.
7. **The relying party uses PKCE correctly.** OAuth clients that store `code_verifier` insecurely, or fail to bind sessions, expose their users — Konekto cannot force correctness on third parties beyond requiring PKCE.

---

## 5. STRIDE per component (V1)

### 5.1 `konekto-core` — crypto & identity logic

| Threat | Example | Mitigation (V1) | Residual risk |
|---|---|---|---|
| **S**poofing | Forged key derivation inputs | Type-system separation: `RootKey`, `ContextKey<Vivo>`, `ContextKey<Laboro>`, `ContextKey<Socio>` as distinct types; no `From` implementations across contexts | Low — requires `unsafe` or bug in derivation code |
| **T**ampering | In-process memory tampering | `zeroize` on drop for all key material; no `Debug` impl on secret types | Low for remote; high if attacker has local code exec |
| **I**nformation disclosure | Timing side-channels in crypto comparisons | Use `subtle` / constant-time primitives from `aws-lc-rs` | Low |
| **I**nformation disclosure | Secrets in panics / logs | Custom `Debug`/`Display` that redacts; `#![deny(clippy::dbg_macro)]`; forbid `unwrap`/`expect` in prod paths | Medium — discipline-dependent |
| **E**levation | Cross-context key derivation | HKDF info parameter bound to context enum; distinct types prevent mix-ups statically | Low |
| **Quantum harvest** | Captured handshake decrypted in 2035 | Hybrid X25519 + ML-KEM-768 on every key exchange | Accepted — depends on PQ algorithm durability |

### 5.2 `konekto-api` — Axum HTTP server

| Threat | Example | Mitigation (V1) | Residual risk |
|---|---|---|---|
| **S**poofing | Replay of WebAuthn assertion | WebAuthn challenge is single-use, bound to session; `webauthn-rs` enforces | Low |
| **S**poofing | Cross-site request forgery on state-changing endpoints | SameSite=Strict cookies; CSRF token on non-idempotent ops; Origin header validation | Low |
| **T**ampering | Request body mutation in transit | TLS 1.3 only, HSTS, certificate pinning at reverse proxy | Low |
| **R**epudiation | User denies having authorized cross-context access | Every cross-context consent is logged with user-signed payload (Ed25519 + ML-DSA) in audit log A6 | Low |
| **I**nformation disclosure | Verbose errors leak internals | Errors typed via `thiserror`; external responses return opaque error codes, full context logged internally only | Medium — discipline |
| **I**nformation disclosure | Enumeration via error-message divergence | Unified error for "unknown user" and "invalid credential"; constant-time response timing within reason | Medium |
| **D**enial of service | Credential-stuffing / brute-force | Per-IP and per-account rate limiting (`tower` middleware); exponential backoff; Argon2 cost calibrated to make brute-force economically infeasible | Medium — DDoS at network layer is provider-dependent |
| **D**enial of service | Unbounded request bodies / slowloris | Request size limits, read/write timeouts, connection caps | Low |
| **E**levation | Token confusion between contexts | Tokens carry explicit context claim; API handlers are context-typed; no "root" token issued to clients | Low |
| **E**levation | JWT `alg: none` / algorithm confusion | Server-side key lookup by `kid`; fixed algorithm allowlist; reject tokens with unexpected `alg` | Low |

### 5.3 `konekto-db` — PostgreSQL repository layer

| Threat | Example | Mitigation (V1) | Residual risk |
|---|---|---|---|
| **S**poofing | Application connects to a rogue DB | TLS cert validation on DB connection; credentials in a secret store (not env vars bare) | Low if secret store in place |
| **T**ampering | Direct DB write bypassing application logic | DB role for app has least-privilege grants; audit log is append-only (trigger blocks UPDATE/DELETE); row-level security for context isolation where applicable | Medium — infra operator can still bypass |
| **I**nformation disclosure | Disk image leak | Transparent at-rest encryption at storage layer + application-layer encryption for A5 (PII) with keys in KMS | Medium — key management is the weak link |
| **I**nformation disclosure | SQL injection | `sqlx` with compile-time-checked queries; no dynamic SQL construction | Low |
| **D**enial of service | Expensive queries / connection exhaustion | `deadpool-postgres` with bounded pool; per-request statement timeout; slow-query alerting | Low |
| **E**levation | App user has DDL/DROP | Separate migration role (used only by `sqlx migrate`) from runtime role (SELECT/INSERT only on its tables) | Low |

---

## 6. Cross-cutting risks

### 6.1 Key management (highest residual risk)

Server-side signing keys (A7) are the single most catastrophic asset. V1 must decide:
- HSM (e.g., YubiHSM 2, CloudHSM equivalents on sovereign clouds) vs software KMS
- Rotation cadence and dual-control for rotation
- Break-glass recovery procedure

This is tracked as **Open question OQ-1**.

### 6.2 Context isolation enforcement

Cryptographic separation via HKDF is necessary but not sufficient — the type system must prevent the application from ever holding two context keys simultaneously without a logged, user-consented cross-context grant. V1 requires:
- `ContextKey<C>` generic over a phantom `Context` marker
- Cross-context operations gated behind a consent receipt type that cannot be constructed without a logged audit event

Tracked as **OQ-2** — **addressed by [ADR-0002](adr/0002-context-key-type-system-encoding.md)** (Proposed).

### 6.3 Post-quantum algorithm durability

ML-KEM and ML-DSA are NIST-standardized but young. A cryptanalytic break would not instantly expose users (classical half of the hybrid still holds), but would force a migration. V1 must be able to rotate the PQ algorithm without breaking existing sessions.

Tracked as **OQ-3** — cryptographic agility.

### 6.4 GDPR Article 17 (right to erasure) vs audit log integrity

An append-only audit log contains records about users who may later invoke their right to erasure. V1 must design the audit schema such that user identifiers can be cryptographically shredded (key deletion) while preserving log integrity for non-PII content.

Tracked as **OQ-4**.

---

## 7. Risks — status

| # | Risk | Status | Owner |
|---|---|---|---|
| R1 | Hybrid PQ crypto correctness | Mitigated (audited crates) | core |
| R2 | Cross-context key leakage | Mitigated by design (types + HKDF) — ADR-0002 (Proposed) | core |
| R3 | Server signing key compromise | **Open** — OQ-1 | infra |
| R4 | Credential stuffing / brute force | Mitigated (rate limit + Argon2); session binding via ADR-0003 | api |
| R5 | Enumeration via error divergence | Mitigated (unified errors) | api |
| R6 | SQL injection | Mitigated (sqlx compile-time queries) | db |
| R7 | Audit log tamper by insider | Partial (append-only triggers; insider with DB superuser can still bypass) | db |
| R8 | PQ algorithm break | Accepted + OQ-3 (crypto agility) | core |
| R9 | GDPR erasure vs audit integrity | Partial — crypto-shredding specified in ADR-0004; log schema still open (OQ-4) | db |
| R10 | Supply-chain attack on crates | Out of scope for v0 | — |
| R11 | Hosting provider compelled disclosure | Partial (EU jurisdiction, at-rest encryption); residual is accepted | infra |
| R12 | Recovery code theft, coercion, or shoulder-surfing at enrollment display | Mitigated (Argon2id cost, one-time display, opt-out via Option B, rotation on use) — ADR-0004 | api |
| R13 | Malicious or compromised org admin exfiltrates org data before revocation | Mitigated (append-only audit, immediate revocation, optional dual-admin approval) — ADR-0005 | api |
| R14 | Dormant-org squatting (attaching a SIREN one does not represent) | Mitigated (verified LegalAnchor required for Active state; creator-of-record logged) — ADR-0005 | api |
| R15 | Delegation privilege escalation beyond granted scope | Mitigated (server-side enforced, type-encoded scopes, no client-side expansion) — ADR-0005 | api |
| R16 | Org permanently unrecoverable (sovereign-mode with all admins lost) | Accepted for sovereign-mode orgs; default orgs have break-glass | api |
| R17 | Break-glass misuse by Konekto operator | Mitigated (HSM dual-control, full audit, documented procedure); residual accepted and monitored | infra |

---

## 8. Open questions (→ future ADRs)

- **OQ-1:** HSM vs cloud KMS for server signing keys? Which sovereign-cloud offering?
- **OQ-2:** ~~Exact type-system encoding of `ContextKey<C>` and the consent-receipt pattern.~~ **Addressed by [ADR-0002](adr/0002-context-key-type-system-encoding.md) (Proposed).**
- **OQ-3:** Cryptographic agility — how is the wire format versioned so ML-KEM can be replaced?
- **OQ-4:** Audit log schema that is append-only AND GDPR-erasable. **Crypto-shredding mechanism addressed by [ADR-0004](adr/0004-identity-lifecycle.md) (Proposed); exact column layout and append-only enforcement remain open.**
- **OQ-5:** ~~Session model — stateful (Redis) vs stateless (signed JWT) vs hybrid.~~ **Addressed by [ADR-0003](adr/0003-session-model.md) (Proposed).**
- **OQ-6:** ~~Root identity recovery — what happens when the user loses all passkeys?~~ **Addressed by [ADR-0004](adr/0004-identity-lifecycle.md) (Proposed): recovery code (BIP-39, Argon2id-wrapped) by default, opt-out available. Social recovery deferred to V2+.**
- **OQ-7:** Rate-limiting scope — per IP, per account, per (IP × account), and how are behind-NAT users handled?
- **OQ-8:** Logging policy — what counts as PII in a log line? How are user identifiers pseudonymized in structured logs?

---

## 9. Revision history

| Version | Date | Change |
|---|---|---|
| v0 | 2026-04-16 | Initial draft — scope V1, STRIDE per crate, 11 risks, 8 open questions |
| v0.1 | 2026-04-17 | ADR-0002/0003/0004 landed. R12 added (recovery-code theft). OQ-2/5/6 closed; OQ-4 partially closed |
| v0.2 | 2026-04-17 | ADR-0005 lands org identity. R13–R17 added. New actors: legal person, org admin, org collaborator, Konekto break-glass operator. Cross-ADR coherence fixes applied to 0003 and 0004 (RootKey lifecycle unified, cross-context re-UV specified) |
