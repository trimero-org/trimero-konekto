# ADR-0003 — Session model, token format, and revocation strategy

**Status:** Proposed
**Date:** 2026-04-17
**Author:** Trimero Konekto team
**Addresses:** Threat model v0 — OQ-5, R4 (partial), A4, A7

---

## Context

Konekto is an OAuth 2.1 / OIDC identity provider. It must hold a
session state between user authentications and maintain refresh
credentials for relying parties, while satisfying four constraints
that pull in different directions:

1. **Revocation must be near-immediate.** If a device is lost, a
   passkey is revoked, a cross-context grant is withdrawn, or a user
   clicks "log out", the effect must propagate in seconds, not in the
   token's remaining lifetime.
2. **The hot path must not stamp a datastore on every request.** An
   identity provider is an infrastructure service; a roundtrip per
   API call does not scale to ecosystem-wide SSO.
3. **Context isolation (ADR-0002) must extend to tokens.** A token
   issued for Vivo cannot be accepted by a Laboro endpoint. The token
   carries a context claim that the type system verifies at the edge.
4. **All server-issued signatures must be hybrid post-quantum
   (ADR-0001).** Classical-only JWTs are not acceptable for an
   infrastructure intended to run for decades.

This ADR fixes the session-and-token shape. It does not decide where
signing keys live (OQ-1) or how a user recovers a lost authenticator
(OQ-6); both are referenced where they intersect.

---

## Decision

### 1. Two session surfaces, not one

Konekto exposes two distinct kinds of session:

- **First-party session** — a user interacting directly with Konekto
  (managing passkeys, reviewing audit log, consenting to a relying
  party). Backed by an **opaque session ID** in a
  `HttpOnly; Secure; SameSite=Strict` cookie; state held in Redis.
  Every request is validated against Redis, which is the trade we
  accept for instant revocation on self-managed endpoints.

- **OAuth / OIDC tokens** — issued to relying parties on behalf of a
  user. Follows the hybrid model below.

Separating these surfaces means the heavy revocation story
(Redis-backed) applies where we need it most (the user's own
management plane), while the scaling story (signature-verified) applies
to the high-volume relying-party traffic.

### 2. OAuth / OIDC hybrid token model

| Token | Format | TTL | State | Purpose |
|---|---|---|---|---|
| **Access token** | Hybrid-signed JWS | 5 min | Stateless | Presented by relying party on resource requests |
| **ID token** | Hybrid-signed JWS | 5 min | Stateless | OIDC standard; identity assertion for the RP |
| **Refresh token** | Opaque (32 bytes) | 30 days idle / 90 days absolute | Redis | Redeemed for a new access+refresh pair |

**Consequences of this shape:**
- The hot path (access-token verification) requires only the JWKS —
  no Redis roundtrip.
- Revocation latency is bounded by access-token TTL: **≤ 5 minutes**.
  High-value endpoints that need stricter freshness use the
  introspection endpoint (stateful check, opt-in).
- Refresh-token rotation is **single-use**: each refresh invalidates
  the presented refresh token and issues a new one. Re-presentation
  of a rotated token is treated as theft and revokes the entire
  refresh-token family (per OAuth 2.1 §4.3.1).

### 3. JWS shape — hybrid classical + PQ signatures

Konekto emits JWS in **JSON General Serialization** with two
signatures per token:

```json
{
  "payload": "<base64url(claims)>",
  "signatures": [
    { "protected": "<ed25519-header>",   "signature": "<...>" },
    { "protected": "<ml-dsa-65-header>", "signature": "<...>" }
  ]
}
```

Verifiers MUST validate **both** signatures. A verifier that cannot
validate the ML-DSA signature (e.g., a legacy OIDC library) fails
closed — this is the intended behavior and is documented in the
relying-party integration guide.

JOSE algorithm identifiers:
- Ed25519: `EdDSA` (RFC 8037)
- ML-DSA-65: `ML-DSA-65` (pending IANA registration; tracked)

Until IANA registers ML-DSA JOSE identifiers, Konekto uses the
provisional identifier and the integration guide notes this. A schema
version field (`ver`) in the payload lets us migrate without breaking
existing tokens.

### 4. Claims — context-typed tokens

Every Konekto-issued token carries these claims:

| Claim | Meaning | Notes |
|---|---|---|
| `iss` | `https://konekto.trimero.app` | Fixed |
| `sub` | Pseudonymous user id for this RP | Per-RP salting prevents cross-RP correlation (GDPR) |
| `aud` | Relying party client id | |
| `ctx` | `vivo` \| `laboro` \| `socio` | Maps to `Context` marker at the edge |
| `iat`, `exp`, `nbf`, `jti` | Standard JWT timing/identity | |
| `amr` | `["webauthn"]` or equivalent | OIDC |
| `acr` | Authentication context class reference | OIDC |
| `cnf` | dPoP JWK thumbprint (RFC 9449) | For proof-of-possession tokens |
| `ver` | Konekto token schema version | Migration hook |

**No PII.** No email, no name, no display string. The `sub` is a
salted hash of (user_id, rp_id), opaque to the RP and unlinkable
across RPs.

At the API edge, `ctx` is parsed into a `Context` marker and the
handler type signature (`fn handler(key: ContextKey<Vivo>)`) enforces
that the token's context matches the route's context. Context
mismatch is a 401, not a runtime cast.

### 5. First-party session record (Redis)

```
session:{opaque_id} -> {
  user_id,                   // stable internal id, pseudonymized in logs
  context,                   // the single active context for this session
  context_key_wrapped,       // KMS-wrapped ContextKey<C>; see §6
  created_at,
  last_seen_at,
  idle_expires_at,           // sliding: 30 min
  absolute_expires_at,       // hard: 12 h
  amr,
  dpop_jkt,                  // thumbprint of the client's dPoP key
  audit_parent_id,           // links every session event to the audit log
}
```

The opaque ID is 32 bytes of CSPRNG output, base64url-encoded. Redis
TTL is set to `min(idle_expires_at, absolute_expires_at)` and refreshed
on each request that resets idle.

### 6. Context-key materialization in a session

The `RootKey` lifecycle is defined in **ADR-0004**; this section
specifies only how a session-scoped `ContextKey<C>` is produced and
held.

- At authentication, the `RootKey` is briefly materialized per
  ADR-0004 §2 (WebAuthn PRF-based unwrap of the credential's
  `wrapped_root` row).
- The `RootKey` is used to derive the `ContextKey<C>` for the session's
  active context, **then immediately zeroized**.
- The `ContextKey<C>` is wrapped under the Konekto KMS master key and
  stored as `context_key_wrapped` in the session record.
- On each request, the API middleware unwraps the key, passes it to
  the handler, and drops it at the end of the request.

**One active context per session.** Switching context requires **fresh
user verification** (WebAuthn assertion) — the new session is a new
record, not a mutation.

**Cross-context operations also require fresh user verification.**
A `CrossContextGrant<From, To>` (ADR-0002) is necessary but not
sufficient: the session only holds `ContextKey<From>`, so the server
cannot derive `ContextKey<To>` without re-materializing the `RootKey`.
The operation flow is therefore:

1. User presents a fresh WebAuthn assertion (same UV policy as login).
2. Server re-materializes the `RootKey` for the duration of the request
   only, derives both `ContextKey<From>` and `ContextKey<To>`, and
   zeroizes the `RootKey` before the response returns.
3. The `CrossContextGrant<From, To>` is verified against the audit
   log and against the UV freshness claim.
4. The operation executes under the grant; both context keys are
   dropped at end of request.

This preserves the ADR-0004 invariant (`RootKey` only materializes at
enrollment, login, multi-device binding, and cross-context operations)
while honoring the ADR-0002 grant mechanism. Cross-context work is
therefore deliberately more costly than intra-context work — which
matches the security posture we want.

Consequence: the wrapped context key persists at rest in Redis for
the session's lifetime. This is a deliberate trade against OQ-1 — if
the KMS master key is compromised, all active sessions are at risk.
The compensating controls are short session TTLs, KMS audit logging,
and a break-glass key-rotation procedure that invalidates every
session (tracked under OQ-1).

### 7. dPoP — proof of possession

Konekto adopts **dPoP (RFC 9449)** as the default binding mechanism
for tokens issued to public clients. Confidential clients use mTLS
instead (RFC 8705). The effect:

- A stolen refresh token cannot be redeemed without the private key
  held by the original client.
- A stolen access token cannot be replayed at a resource server
  without a matching dPoP proof.

The exact dPoP-key lifecycle (generation, rotation on refresh) is
left to the integration guide; this ADR commits only to the mechanism.

### 8. Revocation mechanisms

| Event | Mechanism | Latency |
|---|---|---|
| User logs out (first-party) | Delete Redis session | Immediate |
| User logs out (OAuth) | Revoke refresh token family | Immediate for new refreshes; ≤ 5 min for access tokens |
| User clicks "log out everywhere" | Revoke all refresh-token families + delete all sessions for user | Immediate / ≤ 5 min |
| Passkey revoked | Revoke all sessions and refresh-token families tied to that `amr` | Immediate / ≤ 5 min |
| Admin-forced revocation (incident) | Rotate signing key → all outstanding access tokens invalid | ≤ JWKS cache TTL (default 60 s) |
| `CrossContextGrant` revoked | Remove grant record; grant-check fails | Immediate |

The JWKS endpoint caches for 60 seconds by default. In an incident
requiring mass-invalidation, key rotation + short JWKS cache is the
lever. Relying parties that cache JWKS longer than 60 s violate the
integration contract.

### 9. Signing-key rotation

- Signing keys (classical + PQ pair) rotate every **90 days**.
- The JWKS endpoint publishes current + previous; overlap window is
  the access-token TTL (5 min) plus a safety margin (10 min).
- `kid` in the JWS protected header identifies the pair.
- Key material lives in the answer to OQ-1 (HSM vs KMS) and is
  not further specified here.

---

## Alternatives considered

| Approach | Rejected because |
|---|---|
| **Fully stateless (signed tokens everywhere, no refresh state)** | Revocation latency equals token TTL. Either tokens become very short-lived (DoS-amplifying refresh traffic) or revocation takes hours. Unacceptable for an IdP. |
| **Fully stateful (opaque tokens, lookup on every resource request)** | Every relying-party request would cross Konekto's datastore. Scaling concern, and it forces RPs into a synchronous dependency on Konekto availability for every API call. |
| **Single-signature JWTs (classical only)** | Violates ADR-0001. Harvest-now-decrypt-later applies to signed tokens too (a forged historical token could be used to prove a lie about past authentication). |
| **PASETO v4 or Biscuit tokens** | Interesting for their simpler threat surface, but both are classical-only today. If/when they adopt PQ signatures, reconsider. |
| **Refresh tokens as JWTs with a deny-list** | Deny-lists are stateful anyway; opaque tokens with a single-use rotation scheme are simpler and auditable. |
| **Multi-context sessions (one session, multiple contexts)** | Defeats ADR-0002's structural isolation. A session holds one `ContextKey<C>`; anything else requires an explicit `CrossContextGrant`. |

---

## Consequences

### Positive

- Revocation bounded by 5 min on the OAuth plane and immediate on the
  first-party plane — the tight bound is where users interact
  directly, the looser bound is where traffic is high.
- Every token is hybrid-signed; a cryptanalytic break in either
  family does not invalidate past authentications.
- Stolen refresh tokens are useless without the dPoP key.
- Single-use refresh rotation gives automatic theft detection.

### Negative

- Off-the-shelf OIDC libraries that do not understand multi-signature
  JWS will fail to verify Konekto tokens. This is intentional (fail
  closed) but raises the integration bar. Mitigation: publish a
  reference verifier in the (V2) SDK and document the JOSE shape
  exhaustively in the integration guide.
- Redis is on the hot path for first-party sessions and for every
  OAuth refresh. Redis availability is a first-order dependency;
  capacity planning and replication matter from day one.
- Wrapped context keys at rest in Redis create a dependency on the
  KMS master key's integrity. Compromise of the master key compromises
  active sessions. Tracked under OQ-1.

### Neutral — tracked as follow-ups

- **dPoP key lifecycle for mobile clients** — regeneration on device
  change, keystore bindings. Out of scope here; integration-guide
  concern.
- **Introspection endpoint policy** — which claims it returns, rate
  limits, caching rules. Deferred to API-design ADR.
- **Long-lived offline tokens** (e.g., for a backup client) — not
  supported in V1. Any use case will need its own ADR.

---

## References

- [ADR-0001 — Rust and hybrid post-quantum cryptography](0001-rust-and-post-quantum-hybrid-cryptography.md)
- [ADR-0002 — Context-key type-system encoding](0002-context-key-type-system-encoding.md)
- Threat model v0 — [OQ-5, R4, A4, A7](../threat-model.md)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (dPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication](https://datatracker.ietf.org/doc/html/rfc8705)
- [OAuth 2.1 draft — refresh token rotation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [RFC 7515 — JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515) (JSON General Serialization)
- [RFC 8037 — CFRG EdDSA / Ed25519 for JOSE](https://datatracker.ietf.org/doc/html/rfc8037)
