# ADR-0005 — Organizational identity: legal persons, admins, delegations, lifecycle

**Status:** Proposed
**Date:** 2026-04-17
**Author:** Trimero Konekto team
**Addresses:** Product gap identified 2026-04-17 — Laboro must accommodate *personnes morales* (legal persons / organizations), not only natural persons. Unblocks the B2B story for Laboro.

---

## Context

ADRs 0001–0004 specify a Konekto identity as belonging to a natural
person with three cryptographically isolated contexts (Vivo, Laboro,
Socio). This works for individuals but fails to model the Laboro
product requirement: legal persons — companies, associations,
institutions — must have their own identity, distinct from any human
member, and must survive founder turnover, acquisitions, and
succession events.

This ADR introduces **organizational identity** as a first-class
concept alongside the natural-person identity, with a separate
cryptographic root, a dedicated lifecycle, an admin model, and a
delegation mechanism that lets natural persons act on the
organization's behalf.

The product shape is fixed by the answers given by the project owner
on 2026-04-17:

1. **One Konekto login, an organization selector inside Laboro.**
   Analogous to Slack workspaces or GitHub org switcher.
2. **The organization's identity does not depend on any single
   natural person.** Director succession, resignation, and
   acquisition preserve the organization's identity and history.
3. **Dormant organizations are valid.** A legal person can exist in
   Konekto before any of its representatives has a Konekto account
   (created by an accountant, a greffe, or a partner).

---

## Decision

### 1. `OrgIdentity` is a distinct identity type, not a fourth context

```rust
pub enum Identity {
    Natural(NaturalIdentity),     // ADRs 0002, 0004
    Organizational(OrgIdentity),  // this ADR
}
```

- Natural and organizational identities share no key material.
- Natural identities keep their three-context isolation (Vivo /
  Laboro / Socio) unchanged.
- Organizations have a single cryptographic root (`OrgKey`) scoped to
  Laboro — organizations do not have Vivo or Socio contexts in V1.
  (Socio may gain org-identity semantics in V2+ for institutions;
  out of scope here.)
- The sealed `Context` trait from ADR-0002 is unchanged: three
  contexts, closed universe. Organizations are a *different* axis.

### 2. Legal anchor — SIREN + registry verification (V1: France)

Every `OrgIdentity` is anchored to an **official legal identifier**:

```rust
pub struct LegalAnchor {
    kind: AnchorKind,            // Siren (V1); Siret, EUID, ... (V2+)
    value: String,               // canonicalized
    registry: RegistryRef,       // Infogreffe (V1)
    verified_at: SystemTime,
    attestation: VerifiedAttestation,
}
```

V1 supports **France only**: SIREN + Infogreffe attestation. European
expansion via BRIS (Business Registers Interconnection System) is
V2+; the type is shaped to accommodate this without migration.

No organization reaches the *Active* state without a verified
`LegalAnchor` — this prevents squatting of well-known company names.
During the *Dormant* state, the anchor is present but unverified
(seeded by a trusted third party — notary, accountant — whose role
as a creator is itself logged).

### 3. Lifecycle states

```
  Dormant ──► Pending ──► Active ──► Operational ──┐
     ▲           │           ▲                      │
     │           │           │                      ▼
  Archived ◄────┴───────── Frozen ◄───────── (all admins lost)
```

| State | Enter when | Allowed actions |
|---|---|---|
| **Dormant** | Org created by third party (notary, accountant, automated flow) with a legal anchor; no admin yet | Read metadata; invite an admin |
| **Pending** | First admin has started enrollment but second admin has not yet accepted | Limited admin operations; cannot attach collaborators |
| **Active** | Minimum two verified admins present | All admin operations |
| **Operational** | Collaborators attached, Laboro apps consuming the identity | All operations |
| **Frozen** | Zero active admins (last admin revoked, died, or lost access) | Read-only access to each collaborator's *own* personal data (fiches de paie, attestations); no write actions |
| **Archived** | Org dissolved per registry | Retain data per legal retention periods; no further operations |

**The two-admin rule is structurally enforced:** the system refuses
to promote an org from *Pending* to *Active* until a second admin
has completed enrollment and wrapped the `OrgKey` under their own
Laboro context key. This is a type-level constraint in
`konekto-core`, not a policy check in `konekto-api`.

### 4. `OrgKey` cryptographic model

When an org transitions from *Pending* to *Active*:

```
# At activation (triggered by second admin's acceptance):
org_key         ← CSPRNG(32 bytes)                     # the org's root material
for each admin a in {admin_1, admin_2}:
    salt_a           ← CSPRNG(16 bytes)
    wrap_key_a       ← HKDF-SHA256(
                          ContextKey<Laboro>(a),
                          info = "konekto.orgkey.wrap.v1" || org_id || salt_a
                      )
    wrapped_org_key_a ← AES-256-GCM.seal(
                          key = wrap_key_a,
                          nonce = CSPRNG(12),
                          aad = org_id || admin_id_a || version,
                          plaintext = org_key
                      )
```

The server stores one `(org_id, admin_id, salt, nonce,
wrapped_org_key)` row per admin. The `org_key` is zeroized
immediately after the two wraps are computed.

This is the same *multi-wrap-of-one-root* pattern as a natural
person's multiple passkeys (ADR-0004 §3): each admin can independently
unlock the org; losing one admin does not lose the org.

**Adding a third admin** follows the same flow as adding a second
device in ADR-0004: an existing admin authenticates, materializes
the `org_key`, and produces a new wrap under the new admin's Laboro
context key.

**Revoking an admin**: delete their `wrapped_org_key` row. If that
leaves fewer than two admins, the org transitions to *Pending* (a
warning) or *Frozen* (if zero remain).

### 5. Admin and collaborator roles

V1 defines **two roles**, kept deliberately minimal:

```rust
pub trait OrgRole: sealed::Sealed + Copy + 'static {
    const LABEL: &'static str;
}

pub struct Admin;
pub struct Collaborator;

impl OrgRole for Admin       { const LABEL: &'static str = "admin"; }
impl OrgRole for Collaborator { const LABEL: &'static str = "collaborator"; }
```

- **Admin** — can invite/revoke admins and collaborators, issue
  delegations, act on behalf of the org in all app surfaces. All
  admins are equivalent; there is no "super-admin" above them.
- **Collaborator** — cannot invite anyone; acts only within the
  scope of delegations issued to them.

Fine-grained RBAC (e.g., accountant-only, HR-only, read-only auditor)
is a V2+ concern. V1's flat model matches the user's stated intent
("les collaborateurs peuvent travailler le lendemain d'une
démission si au moins un autre admin est désigné") — any admin can
perform any admin action, which guarantees operational continuity.

### 6. Delegation model

A `Delegation` is how a natural person gains the capability to act on
behalf of an org:

```rust
pub struct Delegation<R: OrgRole> {
    id: DelegationId,
    org_id: OrgId,
    holder: NaturalUserId,
    scope: DelegationScope,    // which capabilities
    issued_by: AdminId,
    issued_at: SystemTime,
    expires_at: SystemTime,    // default: 12 months, auto-renewing on activity
    revoked: bool,
    audit_id: AuditId,
    _role: PhantomData<R>,
}
```

- Server-side stored (PostgreSQL), not a client-held signed
  capability. Revocation is therefore immediate — no TTL-bound
  latency like access tokens.
- Each delegation has a bounded `DelegationScope` enumerating which
  org-scoped resources and actions it authorizes.
- When a natural person selects an org in their Laboro session (see
  §7), the API loads their active delegations for that org and
  builds a capability set for the request.

**Acceptance:** delegations are issued by an admin but only take
effect once the holder explicitly accepts them in their Konekto
account. Unaccepted delegations expire after 14 days.

### 7. Multi-org session model (extends ADR-0003)

The Laboro context session (ADR-0003) gains one additional piece of
state: an **optional active org pointer**.

```
session:{opaque_id} -> {
  ...existing fields from ADR-0003...
  context: "laboro",
  active_org: Option<OrgId>,     // None = acting as self (freelance/personal-pro)
  org_key_wrapped: Option<..>,   // KMS-wrapped OrgKey for active_org, if any
}
```

User-facing shape:
1. User logs in once (Konekto identity, ADR-0004 flow).
2. User enters Laboro context (ADR-0003 flow).
3. User sees an org selector listing: `[Self (freelance)] +
   [ACME SAS — comptable] + [Dupont & Fils — consultant]`.
4. Selecting `Self` leaves `active_org = None`; selecting an org
   triggers:
   a. Server unwraps the user's `wrapped_org_key_a` row (using the
      session's `ContextKey<Laboro>`).
   b. Server re-wraps the materialized `OrgKey` under the KMS master
      key for the session lifetime (same pattern as
      `ContextKey<C>` wrapping in ADR-0003).
   c. Server loads the user's delegations for this org.
5. Switching orgs drops the previous `OrgKey` wrap immediately and
   repeats the unwrap for the new org.

Badge UX ("Tu agis en tant que ACME SAS"), org-scoped data isolation
(ACME never sees Dupont's data, never sees the user's Vivo data), and
the "never log in twice" guarantee all fall out of this structurally.

### 8. Succession, transfer, and frozen state

| Event | Mechanism |
|---|---|
| **Admin resigns** | The admin revokes their own adminship. If two or more admins remain, org stays *Active*. If one remains, org drops to *Pending* until a second admin is added. If zero remain, org enters *Frozen*. |
| **Admin dies** | A remaining admin revokes the deceased via the standard revocation flow. If no admin remains, see *Frozen* recovery below. |
| **Acquisition / sale** | Outgoing admins issue admin roles to incoming admins; incoming admins produce their own `wrapped_org_key` rows. Once incoming admins are *Active*, outgoing admins are revoked. The org identity, history, and `OrgKey` are preserved across the transfer. |
| **Zero admins → Frozen** | See below. |

**Frozen-state recovery.** An organization in *Frozen* state has no
admin able to unwrap its `OrgKey`. Recovery requires a legally
authoritative attestation that a specific natural person is entitled
to take over. V1 supports this via a **manual attestation flow**:

1. The claimant submits a Kbis extract dated within 30 days, or a
   notarial act, proving their legal authority over the entity.
2. A Konekto operator (human review, logged) verifies the document
   against Infogreffe.
3. Upon validation, the operator triggers an **emergency
   re-wrap**: a server-side, dual-control, audited ceremony that
   decrypts `wrapped_org_key_admin_N` using a break-glass KEK stored
   in the HSM (per OQ-1), and re-wraps it under the claimant's newly
   enrolled Laboro context key.
4. The `OrgKey` material is never exposed to the operator; the
   re-wrap happens inside the HSM.

This creates an explicit trust-boundary exception — Konekto operators
can, with dual control and full audit, recover a frozen org. This is
documented transparently to organizations at onboarding. An
organization that refuses this trust boundary can opt into
*sovereign-mode* where no break-glass wrap exists (the org becomes
unrecoverable if all admins are lost — analogous to Option B in
ADR-0004 for natural persons). Default is break-glass enabled,
because the business cost of permanent loss is very high for legal
entities.

**V2+:** automated succession via the Socio filiale, consuming Kbis
or European equivalent as a signed attestation without human review.

### 9. Threats introduced — delta to threat model

| # | New risk | Mitigation (V1) |
|---|---|---|
| **R13** | Malicious or compromised admin exfiltrates org data before revocation | Admin actions are append-only audit-logged; revocation is immediate (§6); critical actions require dual-admin approval (deferred config, opt-in V1 / default V2) |
| **R14** | Dormant-org squatting (creating an org with a SIREN the creator does not represent) | Active state requires a verified `LegalAnchor`; dormant state allows only read and one admin invitation; creator-of-record is logged and its authority is later verifiable |
| **R15** | Delegation privilege escalation — collaborator acts beyond granted scope | Scope is enforced server-side against an enumerated capability set; scopes are type-encoded; no client-side scope expansion possible |
| **R16** | Org becomes permanently unrecoverable if break-glass is disabled and all admins are lost | Accepted for *sovereign-mode* orgs; clearly surfaced at onboarding. Default orgs have break-glass enabled. |
| **R17** | Break-glass misuse by Konekto operator | Dual-control requirement, HSM-enforced separation, full audit, documented procedure. Residual risk accepted; monitored. |

### 10. Out of scope for V1 (V2+)

- Pan-European registries via BRIS
- Automated succession via Socio
- Fine-grained RBAC beyond Admin / Collaborator
- Threshold cryptography for `OrgKey` (e.g., 2-of-3 admin unlock)
- Signed capability delegations (client-cacheable)
- Org-to-org delegations (subsidiaries delegating to parent)

---

## Alternatives considered

| Approach | Rejected because |
|---|---|
| **Orgs as a fourth context** (`Context::Org`) | Breaks ADR-0002's closed 3-context universe; orgs are a different axis, not another context of one person's identity |
| **Org key stored server-side only, no admin wrap** | Server compromise = all-orgs takeover; violates sovereignty principle |
| **Threshold cryptography for OrgKey (N-of-M admins to unlock)** | Strong properties but operationally brutal for routine actions; UX unacceptable at V1 scale. Worth revisiting for high-sensitivity orgs in V2 |
| **Signed capability tokens for delegations (JWT-like)** | Revocation latency. Server-stored delegations give immediate revocation at the cost of a DB lookup — the right trade for role-bearing artifacts |
| **No break-glass recovery at all (uniform sovereign-mode)** | Realistic business cost of losing a company's identity is very high; most orgs want the safety net. Exposing it as an explicit choice (default on, opt-out available) balances both worlds |
| **Dormant mode requires a Konekto-certified third party (notary, TSP accountant) by mandate** | Correct long-term but introduces V1 dependency on certification programs that don't yet exist. V1 allows self-declared third-party creation with the creator logged and later verifiable |

---

## Consequences

### Positive

- Laboro's B2B story now has a coherent cryptographic and legal model.
- Natural person identities remain unchanged; ADRs 0001–0004 are
  extended, not contradicted.
- Organizational continuity survives any single-person event
  (death, resignation, acquisition).
- Dormant orgs let the product be seeded by partners (accountants,
  greffes) without forcing premature personal enrollment.
- The multi-org UX falls out structurally from the session model —
  no special-case code to maintain isolation.

### Negative — and accepted

- **Break-glass recovery introduces a trust boundary.** Konekto
  operators, under dual control, can recover a frozen org. This is
  accepted and surfaced at onboarding; sovereign-mode users opt out.
- **Admin rotation after RootKey recovery.** If a natural person
  admin rotates their `RootKey` via ADR-0004 recovery, their
  `wrapped_org_key` rows become unreadable. They must be re-onboarded
  to each org by a remaining admin. This is operational overhead,
  not a security flaw.
- **Dormant-org creation is a trust-granting moment.** Whoever
  seeds a dormant org (notary, accountant) vouches, implicitly, that
  the SIREN they attach corresponds to a legitimate intent. Logged
  and auditable; not cryptographically prevented in V1.
- **V1 is France-only.** European expansion requires BRIS
  integration and per-member-state attestation formats.

### Neutral — follow-ups

- **Fine-grained RBAC** (OQ-new): scope vocabulary for delegations
  needs a dedicated ADR once the Laboro apps have concrete resources
  to protect.
- **Organizational audit log** — the audit shape for org-scoped
  actions (who acted, under which delegation, for which org) folds
  into the broader OQ-4 (audit schema).
- **Tax/legal residency handling** for pan-European orgs — V2+.
- **Interaction with consent receipts for cross-context grants**
  (ADR-0002): an org does not cross contexts because it lives only
  in Laboro. No new type needed at V1. If V2 grants Socio-scoped org
  identities, revisit.

---

## References

- [ADR-0001 — Rust and hybrid post-quantum cryptography](0001-rust-and-post-quantum-hybrid-cryptography.md)
- [ADR-0002 — Context-key type-system encoding](0002-context-key-type-system-encoding.md)
- [ADR-0003 — Session model](0003-session-model.md)
- [ADR-0004 — Identity lifecycle](0004-identity-lifecycle.md)
- Threat model v0 — [new risks R13–R17](../threat-model.md)
- [Infogreffe — French trade and companies register](https://www.infogreffe.fr/)
- [BRIS — Business Registers Interconnection System](https://e-justice.europa.eu/content_business_registers_at_european_level-105-en.do)
- [eIDAS trust service providers (TSP)](https://eur-lex.europa.eu/eli/reg/2014/910/oj) — for future certification of third-party org creators
