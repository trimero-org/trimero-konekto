# ADR-0006 — Hybrid JWS session-token implementation

**Status:** Proposed
**Date:** 2026-04-24
**Author:** Trimero Konekto team
**Addresses:** ADR-0003 Phase A (access-token surface)

---

## Context

ADR-0003 fixes the Konekto session model: a hybrid JWS carrying two
signatures (Ed25519 + ML-DSA-65) over the same protected payload, with
a `ctx` claim that binds the token to exactly one of `Vivo`, `Laboro`,
`Socio`. It does not fix *how* we encode and sign the token, where
the signing keys live, or how the verifier wires into axum.

This ADR captures the implementation choices for **Phase A**: the
primitive that emits and verifies access tokens in `konekto-core`, the
`AuthedContext<C>` extractor that enforces the `ctx` claim in
`konekto-api`, and the three `GET /{ctx}/whoami` endpoints that make
the context isolation visible end-to-end.

Items explicitly **out of scope** for Phase A — each deferred to a
later increment with a dedicated ADR or to follow-up work on ADR-0003:

- Refresh tokens, revocation, Redis session store
- JWKS publication, key rotation
- DPoP / proof-of-possession binding
- Where signing keys live in production (OQ-1: KMS / HSM)
- First-party session cookie (ADR-0003 §1)
- Per-relying-party `sub` salting (ADR-0003 §5)
- OAuth / OIDC endpoints (authorization code, token exchange)

---

## Decision

### 1. Wire format: JWS JSON General Serialization, hand-rolled

Tokens are serialized as JWS JSON **General** Serialization (RFC 7515
§7.2.1). A token is a JSON object with a single `payload` (base64url
of the canonical claims JSON) and exactly two `signatures` entries —
one per algorithm:

```json
{
  "payload": "<b64url(claims_json)>",
  "signatures": [
    { "protected": "<b64url({\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"<kid>\"})>",
      "signature": "<b64url(ed25519_sig)>" },
    { "protected": "<b64url({\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\",\"kid\":\"<kid>\"})>",
      "signature": "<b64url(mldsa_sig)>" }
  ]
}
```

Both signatures MUST verify for the token to be accepted. No
short-circuit, no "first match wins", no single-algorithm fallback.

**Why hand-rolled.** None of the mainstream JOSE crates
(`jsonwebtoken`, `josekit`) support General Serialization with a
provisional `ML-DSA-65` algorithm. Compact Serialization is
single-signature only, so it cannot carry a hybrid token at all.
Wrapping a classical-JWT crate and bolting a detached ML-DSA
signature on top would fork the canonicalization and give verifiers
two signing inputs to keep consistent — more subtle, not less.
Implementing RFC 7515 §7.2.1 directly is ≈200 LOC of string slicing
and base64url, every step unit-tested.

**Envelope size.** An ML-DSA-65 signature is 3293 bytes; Ed25519 is
64 bytes. With headers and payload the serialized token lands around
5–6 KB. That fits in a single `Authorization: Bearer …` header under
nginx's default 8 KB client-header limit. Tokens will not fit in a
4 KB cookie, but Konekto access tokens are never delivered in a
cookie — the first-party cookie (ADR-0003 §1) carries an opaque
session ID, not a JWS.

### 2. Bootstrap: env-var seeds with ephemeral fallback

Signing keys are loaded at boot from two base64url environment
variables:

- `TOKEN_SIGNING_ED25519_SK` — the 32-byte Ed25519 seed.
- `TOKEN_SIGNING_MLDSA_SK`   — the 32-byte ML-DSA-65 seed.

Both must be present together, or both absent. When both are absent,
the binary calls `SigningKeys::generate_ephemeral()` and logs a loud
`tracing::warn!` — useful for local development, but explicitly not a
production mode because every restart issues a fresh `kid` and
invalidates all outstanding tokens.

Persisting the signing keys in Postgres was considered and rejected
for Phase A: it moves a hot-path cryptographic secret into the same
blast radius as the user data, and creates an unwrap-key-on-boot
bootstrap problem that just moves the secret one level further out.
The correct long-term answer is a KMS/HSM, tracked as ADR-0003 OQ-1.

### 3. `kid` is deterministic from the public keys

`Kid = base64url(BLAKE2s_128(ed25519_pk || ml_dsa_pk))`.

Computing it from public-key material means two instances brought up
with the same pair of env seeds have byte-identical `kid`s. That in
turn means a cluster rollout doesn't invalidate outstanding tokens
just because every node computed its own nonce — the `kid` is a
function of the keys, not of the node. It also means tokens are
introspectable: given the published `kid`, a verifier can tell which
key pair was used without trusting the `iss` claim alone.

BLAKE2s-128 was chosen over SHA-256 because it's the smallest
collision-resistant VAR-output hash we already pull in (through
`blake2`), and 128 bits of `kid` collision resistance is plenty for a
deployment with O(1) active keys. The label `kid` is a hint, not a
security control.

### 4. Claim shape — V1 is frozen

```rust
pub struct Claims {
    pub iss: String,            // "konekto-<env>"
    pub sub: String,            // identity_id.to_string() — see §5
    pub ctx: ContextLabel,      // "vivo" | "laboro" | "socio"
    pub iat: i64, pub nbf: i64, pub exp: i64,
    pub jti: String,            // 128 random bits, base64url
    pub amr: Vec<String>,       // ["pwd"] in V1
    pub ver: u32,               // 1
    pub aud: Option<String>,
    pub acr: Option<String>,
    pub cnf: Option<serde_json::Value>,
}
```

`ver` is the schema version. Verifier rejects anything other than
`TOKEN_VERSION = 1`, so bumping the shape is a breaking wire change
(fail-closed). `aud`, `acr`, `cnf` are optional now and pre-wired for
later phases (OIDC audience, auth-context class, DPoP jkt).

### 5. `sub` is `identity_id.to_string()` in V1

Per-relying-party salting of `sub` (ADR-0003 §5) is deferred. In V1
there is one relying-party (Konekto itself — the whoami endpoints),
and the `sub` is just the identity UUID. When the OAuth/OIDC surface
ships, `sub` becomes `salted_hash(identity_id, rp_id)` and the
existing V1 tokens will be invalidated by the `ver` bump.

### 6. `ml-dsa 0.1.0-rc.8` accepted; isolation point is `sign_mldsa.rs`

`ml-dsa` has not cut 1.0 yet. We accept the rc dependency because
the alternative — `pqcrypto-dilithium` — is a different crate family,
uses different APIs, and will eventually need the same port to a
stabilized FIPS-204 crate anyway. All calls into `ml-dsa` are isolated
in `konekto-core/src/token/sign_mldsa.rs` so the rc → 1.0 bump touches
one file.

ML-DSA-65 signing allocates large intermediate matrices on the stack —
the computation overflows the 2 MiB default Rust test-thread stack.
We set `RUST_MIN_STACK = 8388608` (8 MiB) in a workspace
`.cargo/config.toml` so `cargo test` works out of the box. In
production, tokio worker threads inherit the same `RUST_MIN_STACK`
because the binary starts under `cargo run` / systemd env. A future
change to reduce the stack footprint — either heap-allocating
`ExpandedSigningKey` in upstream or wrapping signing in a dedicated
thread with a larger stack — is tracked as a follow-up.

Signing keys are stored as the **32-byte seed**, which is the
canonical FIPS 204 representation (`SigningKey::to_seed()` in the
`ml-dsa` API, what `key_gen` emits, and what we emit for env-var
round-trips). We do not cache the expanded signing key, accepting the
per-call expansion cost in exchange for the smaller storage footprint.

### 7. Clock is a trait, injected as a generic parameter

`TokenIssuer<K: Clock>` and `TokenVerifier<K: Clock>` are parameterized
over a `Clock` trait:

```rust
pub trait Clock: Send + Sync + 'static {
    fn now_unix_secs(&self) -> i64;
}
```

Production uses `SystemClock` (unit struct backed by `SystemTime`);
tests use `FixedClock` (backed by `AtomicI64`). The trait is
parameterised on the type, not boxed as `dyn Clock`, so monomorphization
removes the indirection. `FixedClock` lives behind `pub` (not
`cfg(test)`) so `konekto-api`'s expired-token integration test can
build a router with it.

### 8. Context bridging: `Context::CONTEXT_LABEL`

The sealed `Context` trait (`Vivo`, `Laboro`, `Socio`) gains one
constant:

```rust
pub trait Context: private::Sealed + Copy + Clone + Debug + 'static {
    const LABEL: &'static [u8];
    const CONTEXT_LABEL: crate::token::ContextLabel;
}
```

`AuthedContext<C>` (axum `FromRequestParts`) checks
`claims.ctx == C::CONTEXT_LABEL` before constructing itself. A
`laboro` token presented on `/vivo/whoami` is rejected with `401`
before the handler body runs — the ADR-0002 context-isolation
guarantee extends to the HTTP edge.

A companion `ContextTagged` trait in `konekto-api` was considered and
rejected — one more trait to keep in sync with no payoff, since the
coupling is internal to the workspace.

### 9. Error surface: opaque 401 at HTTP boundary

`TokenError` has eleven discriminants internally
(`InvalidFormat`, `InvalidSignature`, `AlgMismatch`, `KidMismatch`,
`Expired`, `NotYetValid`, `IssuerMismatch`, `UnsupportedVersion`,
`Base64`, `PayloadEncoding`, `SigningFailed`, `EnvConfig`). Everything
that's a verifier-side rejection collapses to one HTTP response:
`401 { "error": "unauthorized" }`. The variant that fired is logged
at `tracing::warn!` for operators; never in the body. This matches
the enumeration-oracle argument in ADR-0003: distinguishing
"signature is bad" from "clock is wrong" from "ctx claim is wrong"
gives a caller a distinguisher we don't owe them.

Issuance-side errors (`SigningFailed`, `PayloadEncoding`,
`EnvConfig`) map to `500` and are logged at `error` — they indicate a
server misconfiguration, not a caller problem.

---

## Alternatives considered

- **`jsonwebtoken` / `josekit` + detached companion signature.**
  Requires canonicalizing the signing input ourselves anyway, splits
  the signing-input construction between two libraries, and loses
  the General Serialization's property that all signatures are
  present in one document. Rejected.

- **Postgres-persisted signing keys.** Moves a hot-path secret into
  the same blast radius as user data and forces an unwrap-key at
  boot, which just pushes the secret one level further out. The
  correct answer is a KMS/HSM (ADR-0003 OQ-1).

- **`Arc<dyn Clock>` instead of a generic parameter.** A vtable
  indirection on every `iat`/`exp` call, plus an `Arc::clone` on
  every request for no payoff — clock choice is known at compile
  time on both production and test paths. Rejected.

- **A dedicated `ContextTagged` trait in `konekto-api` bridging
  `Context` ↔ `ContextLabel`.** One more trait to keep in sync, no
  payoff. Rejected in favour of a single `CONTEXT_LABEL` constant
  on the existing `Context` trait.

---

## Deferred / follow-ups

- **JWKS endpoint + key rotation.** Not required to verify tokens
  while the workspace is internally trusted. Phase B.
- **Refresh tokens + Redis session store.** ADR-0003 §2–§3. Phase B.
- **DPoP proof-of-possession.** ADR-0003 §4. Phase C.
- **Per-RP `sub` salting.** Deferred with a `ver` bump as the
  trigger (§5).
- **KMS / HSM-resident signing keys.** ADR-0003 OQ-1.
- **`alg: "ML-DSA-65"` IANA registration.** Placeholder until IANA
  registers the algorithm string; update the header literal in one
  place (`sign_block` / verifier match arm) when that lands.
- **ML-DSA stack-footprint reduction.** Either upstream
  `ExpandedSigningKey` heap allocation, or a signing worker thread
  with an explicit stack size. For now we set `RUST_MIN_STACK = 8 MiB`
  workspace-wide.
