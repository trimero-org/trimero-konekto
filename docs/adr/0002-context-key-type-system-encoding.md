# ADR-0002 — Type-system encoding of context keys and cross-context consent

**Status:** Proposed
**Date:** 2026-04-16
**Author:** Trimero Konekto team
**Addresses:** Threat model v0 — OQ-2, R2

---

## Context

Konekto enforces a three-way isolation between a user's Vivo (personal),
Laboro (professional), and Socio (civic) contexts. Cryptographic
separation via HKDF from the root identity is the mechanism of last
resort — but by the time a key derivation happens, the application has
already decided which context it is operating on. If that decision is
wrong (a bug, a confused deputy, a misrouted handler), the cryptography
cannot save us.

The threat model identifies this as R2 (cross-context key leakage) and
asks, under OQ-2, for a design in which:

1. A `ContextKey` for one context **cannot be passed** to code that
   expects a key for a different context — enforced at compile time,
   not by convention.
2. Any operation that legitimately needs to cross contexts can only
   be expressed by constructing an explicit *consent receipt* that
   cannot exist without a logged audit event.

This ADR fixes the type-level shape of those guarantees before any
code is written. It does not fix the wire format of the audit event
or the exact session mechanism — those are tracked separately
(OQ-4, OQ-5).

---

## Decision

### 1. Contexts are zero-sized marker types behind a sealed trait

```rust
// konekto-core/src/context.rs
pub mod context {
    pub struct Vivo;
    pub struct Laboro;
    pub struct Socio;

    mod sealed { pub trait Sealed {} }

    /// A Konekto identity context. Sealed: the three contexts listed
    /// in this module are the only ones that will ever exist.
    pub trait Context: sealed::Sealed + Copy + 'static {
        /// HKDF `info` parameter — versioned and domain-separated.
        const LABEL: &'static [u8];
    }

    impl sealed::Sealed for Vivo {}
    impl Context for Vivo {
        const LABEL: &'static [u8] = b"konekto.context.vivo.v1";
    }
    // ... Laboro, Socio identically
}
```

The sealed trait pattern guarantees that no downstream crate — and no
future `konekto-*` crate — can introduce a fourth context without
editing this module and triggering an explicit review.

### 2. `ContextKey<C>` is generic over the context marker

```rust
use zeroize::Zeroizing;
use std::marker::PhantomData;

pub struct ContextKey<C: Context> {
    material: Zeroizing<[u8; 32]>,
    _context: PhantomData<C>,
}
```

- `PhantomData<C>` makes `ContextKey<Vivo>` and `ContextKey<Laboro>`
  **distinct, non-coercible types** at compile time.
- `Zeroizing` wipes the material on drop.
- No `Debug`, `Display`, `Serialize`, `Deserialize`, `Clone`, or `Copy`
  impls — keys move by value or by reference, never accidentally.
- A hand-written `fmt::Debug` prints only the context label, never the
  bytes (so `tracing` spans cannot leak material even with
  `?contextKey`).

Generic crypto operations are expressed as methods on `ContextKey<C>`
with a `C: Context` bound — shared code, distinct types.

### 3. Derivation is the only way to obtain a `ContextKey<C>`

```rust
impl RootKey {
    /// Derive the context-specific key for `C` via HKDF-SHA256.
    ///
    /// The `info` parameter is `C::LABEL`, providing domain separation
    /// between contexts. See ADR-0001 for the cryptographic rationale.
    pub fn derive<C: Context>(&self) -> ContextKey<C> { /* ... */ }
}
```

- `ContextKey::new(...)` does not exist publicly.
- `unsafe fn from_raw(...)` does not exist. `konekto-core` enforces
  `#![forbid(unsafe_code)]`; any attempt to `transmute` between
  `ContextKey<A>` and `ContextKey<B>` is a compile error.
- Tests that need a `ContextKey<C>` for a known value use a
  `#[cfg(test)]` constructor that is unreachable from production code.

### 4. Cross-context access requires a `CrossContextGrant<From, To>`

```rust
pub struct CrossContextGrant<From: Context, To: Context> {
    audit_id: AuditId,
    scope: GrantScope,
    issued_at: SystemTime,
    expires_at: SystemTime,
    _from: PhantomData<From>,
    _to: PhantomData<To>,
}

impl AuditLog {
    /// The **only** way to construct a `CrossContextGrant`.
    ///
    /// Verifies the user's signature over `(scope, ttl, nonce)`,
    /// writes an audit record, and returns a grant valid for `ttl`.
    pub fn issue_cross_context_grant<From: Context, To: Context>(
        &mut self,
        user_sig: UserSignature,
        scope: GrantScope,
        ttl: Duration,
    ) -> Result<CrossContextGrant<From, To>, GrantError> { /* ... */ }
}
```

- The `CrossContextGrant` struct's fields are private.
- `issue_cross_context_grant` is the sole constructor.
- That function's implementation writes to the audit log **before**
  returning the grant. The grant therefore encodes, at the type level,
  the invariant "an audit record exists for this access".
- Functions that perform cross-context work take the grant by value or
  by reference and match its `From`/`To` type parameters against their
  own signatures — so `copy_contacts(from: &ContextKey<Vivo>, to:
  &ContextKey<Laboro>, grant: &CrossContextGrant<Vivo, Laboro>)` cannot
  be called with a `Vivo → Socio` grant.

### 5. No ambient `RootKey` in the API layer

`konekto-api` handlers never hold a `RootKey`. They receive a
`ContextKey<C>` for the context the route is scoped to, derived at the
edge (session middleware) and dropped as early as possible. A handler
that needs a second context must call the audit log to obtain a grant,
then derive the second key inside the scope of that grant.

---

## Alternatives considered

| Approach | Rejected because |
|---|---|
| **Runtime enum** (`ContextKey { ctx: Context, bytes: [u8;32] }`) | Mix-ups become runtime errors. The whole point of moving to Rust is to make these impossible, not merely detectable. |
| **Three unrelated structs** (`VivoKey`, `LaboroKey`, `SocioKey` with no shared trait) | Duplicates every crypto operation three times. No generic code. The sealed-trait-plus-phantom approach gives the same compile-time guarantees with one implementation. |
| **Open `Context` trait** (no sealing) | A future crate could `impl Context for SomeNewThing` and introduce a context that the threat model has never reviewed. Closed universe is a non-negotiable audit property. |
| **Consent as a boolean flag in the audit log** | Decouples the "audit record exists" invariant from the "we are allowed to act" check. The type-level grant binds them — the audit event is a prerequisite of the grant's existence, not a parallel concern. |
| **Capability-based tokens (e.g., macaroons) inside the process** | Useful for external delegation; overkill for in-process enforcement where the type system already provides unforgeable tokens for free. Revisit if/when cross-service delegation (V2) appears. |

---

## Consequences

### Positive

- R2 (cross-context key leakage) is reduced to a narrow surface:
  either a bug in `konekto-core`'s derivation/grant code, or a bug in
  `unsafe` code elsewhere — and `#![forbid(unsafe_code)]` in
  `konekto-core` prevents the latter.
- Every cross-context operation leaves an audit trail by construction.
  It is structurally impossible to perform one without one.
- API handlers become self-documenting: a signature containing
  `ContextKey<Vivo>` tells a reviewer exactly what context is in play.

### Negative

- Every function that handles a context key must be generic over `C`,
  which spreads `<C: Context>` bounds through signatures. This is
  boilerplate, but it is boilerplate that carries meaning.
- Some operations that would naturally be "for any context key"
  (e.g., "encrypt this blob with whichever key the user just
  authenticated with") become awkward. The intended answer is that
  there is no such operation — the key is chosen at the session
  boundary and flows inward, not the reverse.
- Testing requires a `#[cfg(test)]` constructor. This must be behind
  a `cfg` gate that cannot be activated in release builds; enforced
  by a lint or CI check.

### Neutral — tracked as follow-ups

- **Grant revocation:** an issued grant may need to be invalidated
  before its TTL elapses. This ADR does not specify the revocation
  mechanism; it is a concern of OQ-5 (session model).
- **Grant scope shape:** `GrantScope` is a placeholder here. Its exact
  structure (which fields/operations a grant authorizes) deserves its
  own ADR once the API surface is better defined.
- **Serialization boundary:** when a grant must travel outside the
  process (e.g., to another service in V2), it must be re-encoded
  with a signature. Out of scope for V1, which has a single service.

---

## References

- [ADR-0001 — Rust and hybrid post-quantum cryptography](0001-rust-and-post-quantum-hybrid-cryptography.md)
- Threat model v0 — [OQ-2, R2](../threat-model.md)
- Rust sealed trait pattern — [rust-lang RFC 2145 discussion](https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed)
- `zeroize` crate — [RustCrypto/utils](https://github.com/RustCrypto/utils/tree/master/zeroize)
