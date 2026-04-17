# ADR-0004 — Identity lifecycle: enrollment, multi-device, recovery, deletion

**Status:** Proposed
**Date:** 2026-04-17
**Author:** Trimero Konekto team
**Addresses:** Threat model v0 — OQ-6, OQ-4 (partial), A1, R9 (partial); closes the implicit gap in ADR-0002 and ADR-0003 on the origin and lifecycle of `RootKey`

---

## Context

ADR-0002 defines `RootKey::derive<C>()` and ADR-0003 mentions "the
user's WebAuthn assertion unwraps the server-held secret that,
combined with server-side material, produces the `RootKey`". Neither
specifies:

1. How the `RootKey` is created at enrollment
2. How multiple passkeys bind to the same identity
3. What happens when a user loses every passkey
4. How an identity is deleted in a way that satisfies GDPR Article 17
5. Which eIDAS assurance level Konekto V1 targets

Leaving these unspecified means every future handler that touches
identity material is implicitly making its own decision. This ADR
fixes the lifecycle end-to-end so that `konekto-core`,
`konekto-api`, and `konekto-db` can be written against a single,
coherent model.

---

## Decision

### 1. `RootKey` origin — server CSPRNG at enrollment

The `RootKey` is 256 bits of output from the server's CSPRNG,
generated **once at enrollment** and never regenerated for the same
identity. It is deliberately **not derived from the WebAuthn
credential** itself, for three reasons:

- Credentials are replaceable; the identity must outlive any single
  credential.
- A credential-derived root would bind the identity to one
  authenticator's internal secret — losing that authenticator would
  destroy the root permanently, even if other authenticators exist.
- Credential rotation would force root rotation, cascading to every
  context key and every downstream artifact signed under them.

The `RootKey` exists in plaintext only inside `konekto-core` during
four bounded request scopes: (a) enrollment, (b) login, (c)
multi-device re-binding, and (d) cross-context operations requiring
a `CrossContextGrant` (see ADR-0003 §6). In all four cases it is
held in a `Zeroizing` buffer and dropped before the request
completes.

### 2. Wrapping scheme — WebAuthn PRF (hmac-secret) per credential

Each passkey registered for an identity stores one independent
wrapping of the same `RootKey`. The wrapping key comes from the
**WebAuthn PRF extension** (`hmac-secret`):

```
# At enrollment or at second-device binding:
salt_c          ← CSPRNG(16 bytes)                     # per-credential
prf_c           ← authenticator.PRF(credential_c, salt_c)   # 32 bytes
wrap_key_c      ← HKDF-SHA256(prf_c, info="konekto.rootkey.wrap.v1")
wrapped_root_c  ← AES-256-GCM.seal(
                      key = wrap_key_c,
                      nonce = CSPRNG(12 bytes),
                      aad = credential_id || version,
                      plaintext = RootKey
                  )
```

The server stores `(user_id, credential_id, salt_c, nonce_c,
wrapped_root_c)`. It never sees `prf_c` or `wrap_key_c` in storable
form — both are derived in-memory at login and zeroized.

**Requirement:** Konekto V1 requires passkeys that support the
WebAuthn PRF extension. Authenticators without PRF support cannot
enroll. This excludes some legacy hardware tokens; the constraint is
documented in the user-facing enrollment page and the RP integration
guide.

### 3. Multi-device binding

A user can bind additional passkeys to an existing identity. The
flow:

1. User authenticates with an existing passkey (produces `RootKey`
   in memory for the duration of the request).
2. User initiates `POST /credentials/add`; server issues a WebAuthn
   registration challenge.
3. User completes WebAuthn registration on the new authenticator.
4. Server requests a PRF output with a freshly generated salt on
   the new credential.
5. Server derives `wrap_key_new`, seals the in-memory `RootKey`
   with it, writes the new `wrapped_root_new` row.
6. `RootKey` zeroized. Response returned.

No credential is "master" — every bound credential is equivalent.
Revoking any one credential removes its wrapping row; the others
continue to grant access to the same `RootKey`.

### 4. Recovery — explicit choice at enrollment

At enrollment, the user must explicitly choose one of:

**Option A — Recovery code (default).** The server generates a second
256-bit secret, encoded as a 24-word BIP-39-style phrase, shown to
the user once and never stored. The server derives a wrap key via
Argon2id (`m=256 MiB, t=4, p=2`, calibrated for a physical user
typing the phrase) and stores an additional `wrapped_root_recovery`
row tagged as `credential_type=recovery_code`.

Recovery flow:
1. User presents the 24-word phrase on the recovery page.
2. Server derives wrap key, decrypts `wrapped_root_recovery` →
   obtains `RootKey`.
3. User is forced through an immediate enrollment of a new passkey
   (step 2 of §2), binding it to the recovered `RootKey`.
4. The `wrapped_root_recovery` row is rotated: a new recovery
   phrase is generated and displayed, the old one invalidated.

**Option B — No recovery.** The user explicitly accepts that loss of
every passkey means permanent loss of identity. The server stores a
`recovery_policy=none` flag and no `wrapped_root_recovery` row.
Recommended for users who prioritize sovereignty over resilience and
for testnet / pseudonymous identities.

**Default:** Option A, because a mass-consumer deployment without
recovery produces unmanageable support load. Option B is exposed in
the enrollment UI with clear warning copy, not hidden in settings.

The recovery code is treated as an additional high-value credential
in the threat model (see *Consequences* below).

### 5. Deletion — crypto-shredding

`DELETE /identity` performs an operation that is irreversible and
auditable:

1. Verify the request (authenticated session with fresh user
   verification).
2. Delete every `wrapped_root_*` row for this `user_id`. After this
   point, the `RootKey` is cryptographically unreachable.
3. Delete the per-user PII columns that are application-layer
   encrypted under a per-user KEK; also delete the KEK. Same
   crypto-shredding property applies.
4. Replace `user_id` references in the audit log with a one-way
   tombstone hash `H(user_id || deletion_salt)` where
   `deletion_salt` is itself destroyed. Audit-log integrity for
   non-PII fields (timestamps, event types, IP hashes) is preserved.
5. Issue a deletion certificate (signed tombstone) to the user on
   completion — proves the deletion happened without retaining the
   identity it deleted.

This design satisfies GDPR Art. 17 while preserving enough audit
integrity for incident response and anti-abuse (timestamps and event
types remain queryable, actors do not).

**Legal exceptions** (GDPR Art. 17 §3 — public interest, legal
claims, etc.) are not expected to apply to Konekto-held data; if
they do, they must be documented on a per-field basis in a future
ADR and surfaced in the privacy policy.

### 6. Assurance level — eIDAS LoA substantial in V1

Konekto V1 targets **Level of Assurance: Substantial** per eIDAS /
Commission Implementing Regulation 2015/1502.

- Passkey registration requires `userVerification: "required"`.
- Authentication requires `userVerification: "required"` on every
  login (no "discoverable only" shortcut without UV).
- Passkey attestation (`attestation: "indirect"`) is collected at
  enrollment and retained for certification audits; not used for
  authorization decisions.

LoA High requires additional verification (e.g., in-person identity
proofing, qualified trust service providers). Out of scope for V1;
tracked as a V2+ concern.

---

## Alternatives considered

| Approach | Rejected because |
|---|---|
| **RootKey derived from WebAuthn credential key** | Ties identity to a single authenticator; credential rotation would destroy the identity. |
| **No PRF — server stores a per-user KEK in KMS, credential is only an authenticator** | The KMS KEK becomes a mass-compromise vector. PRF keeps the unwrap key inside the authenticator, narrowing the blast radius of any server-side breach. |
| **PRF output used directly as RootKey** | Couples RootKey to credential lifetime. Credential rotation would change the RootKey. HKDF + wrap indirection lets the RootKey outlive credentials. |
| **One "master" credential + subordinates** | Creates a hierarchy and a single point of failure. Equivalent credentials are simpler and safer. |
| **No recovery option at all** | Sovereignty-aligned but creates massive support burden at scale. Offering it as an explicit user choice (Option B) preserves the principle without mandating it. |
| **Recovery via email / SMS one-time code** | Reintroduces dependency on exactly the centralized, non-sovereign providers Konekto exists to avoid. |
| **Social recovery (N-of-M guardians)** | Strong properties, but UX complexity is prohibitive for V1. Worth revisiting in V2 as an additional option, not a replacement. |
| **Tombstone the identity row but keep it queryable** | Does not satisfy GDPR Art. 17 — data "archived but not erased" has been ruled insufficient by multiple DPAs. |
| **Target LoA High in V1** | Requires in-person proofing or qualified trust infrastructure that Konekto does not yet have. Stage-gated. |

---

## Consequences

### Positive

- `RootKey` lifecycle is now fully specified from creation to
  destruction — ADR-0002 and ADR-0003 rest on a concrete foundation.
- Credential loss and credential rotation are orthogonal to identity
  continuity: losing a passkey loses that wrapping, not the identity.
- Deletion is genuinely irreversible (crypto-shredding), defensible
  against GDPR audit.
- Recovery is an opt-in user choice, not a hidden policy — aligned
  with the sovereignty principle.

### Negative — and how they are accepted

- **Authenticator compatibility narrowed.** Non-PRF authenticators
  cannot enroll. Accepted: PRF support is present in every major
  platform authenticator (iCloud Keychain, Google Password Manager,
  Windows Hello on current builds) and in current YubiKey firmware.
  Explicit check at enrollment; clear error message directs users
  to a compatible authenticator.
- **Recovery code is a high-value credential.** If stolen, it
  grants full access. Threat-model delta: add **R12 — Recovery code
  theft or coercion**. Mitigation: Argon2id cost deliberately high,
  displayed once and never stored, explicit user warning to store
  offline, surfaced prominently in the post-enrollment audit review.
- **No recovery for Option-B users.** Accepted consequence; flagged
  in enrollment UI with unambiguous copy.
- **Deletion cannot be undone.** If a user triggers deletion
  accidentally, the identity is gone. Mitigation: deletion requires
  fresh WebAuthn UV and a 24-hour cool-off period during which the
  identity is suspended but not yet crypto-shredded. User can cancel
  during the cool-off. After 24 h, execution is automatic and
  irreversible.

### Neutral — follow-ups

- **OQ-1 stays open.** This ADR does not specify where the per-user
  application-layer KEK (for PII encryption) lives — `konekto-db`
  calls the `KeyStore` abstraction.
- **Audit log schema (OQ-4)** is partially addressed: crypto-shredding
  via tombstone hashes is decided here. The exact column layout and
  the append-only enforcement mechanism remain for a DB-focused ADR.
- **Social recovery** remains a V2+ candidate; this ADR does not
  preclude adding it as a third enrollment option later.
- **Attestation policy** — currently `attestation: "indirect"` stored
  for audit. Whether to enforce specific AAGUID allowlists (e.g., for
  LoA High in V2) is not decided.

---

## Threat-model delta

This ADR introduces one new risk and refines two existing ones.

| # | Change | Where |
|---|---|---|
| R2 | Unchanged; reinforced by the fact that `RootKey` only materializes inside `konekto-core` during bounded request scopes | core |
| R9 | Partially addressed: crypto-shredding design specified. Schema enforcement still open. | db |
| **R12 (new)** | Recovery code theft, coercion, or shoulder-surfing at enrollment display time. Mitigations: Argon2id cost, one-time display, explicit opt-out (Option B), rotation on each use. | api |

The threat model document is updated accordingly.

---

## References

- [ADR-0001 — Rust and hybrid post-quantum cryptography](0001-rust-and-post-quantum-hybrid-cryptography.md)
- [ADR-0002 — Context-key type-system encoding](0002-context-key-type-system-encoding.md)
- [ADR-0003 — Session model](0003-session-model.md)
- Threat model v0 — [OQ-6, OQ-4, R9, R12](../threat-model.md)
- [W3C WebAuthn Level 3 — PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [FIDO2 CTAP 2.1 — hmac-secret extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension)
- [eIDAS Commission Implementing Regulation 2015/1502 — assurance levels](https://eur-lex.europa.eu/eli/reg_impl/2015/1502/oj)
- [GDPR Article 17 — Right to erasure ("right to be forgotten")](https://gdpr-info.eu/art-17-gdpr/)
- [BIP-39 — Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
