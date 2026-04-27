# ADR-0008 — JWKS publication endpoint

**Status:** Proposed
**Date:** 2026-04-27
**Author:** Trimero Konekto team
**Addresses:** ADR-0006 §8 deferred (JWKS endpoint)

---

## Context

ADR-0006 shipped Phase A: a hybrid Ed25519 + ML-DSA-65 access-token
primitive with deterministic `kid`. Phase B (ADR-0007) shipped
session and refresh-token storage. Both phases left token verification
strictly **in-process**: `konekto-api` holds the only `VerifyingKeys`
bundle, so any consumer of a Konekto access token is, in practice,
the issuer itself.

This ADR delivers the smallest increment that turns the access token
into a token a *third party* can verify: a public JWKS endpoint
(`/.well-known/jwks.json`) that exposes the current verifying-key
pair under their shared `kid`. After this lands, an external relying
party (RP) can fetch JWKS over HTTP and validate the EdDSA leg with
any RFC 8037-aware library; the ML-DSA-65 leg follows whatever PQ
JOSE shape the IANA registration finalises.

Items explicitly **out of scope** for Phase C and tracked here as
follow-ups:

- **Key rotation** — multi-kid signer/verifier state, primary
  selection, retirement window. Phase D.
- **OIDC discovery document** (`/.well-known/openid-configuration`) —
  pulls in the OAuth/OIDC endpoint surface (ADR-0002 §208), out of
  V1 scope.
- **Signed JWKS** — JWKS-over-JWS so consumers can authenticate the
  bundle without fully trusting the TLS path. Defensible only once
  rotation makes JWKS a moving target; today the bundle is static
  per-process.
- **IANA JWK registration for ML-DSA-65** — tracks the working group
  draft; we publish under the in-flight `AKP` shape and swap when
  registration lands.

---

## Decision

### 1. Single-kid hybrid pair, exactly two JWKs

The JWK Set always contains **two** entries — one for `EdDSA`, one
for `ML-DSA-65` — and **both share the same `kid`**. This reflects
the wire-level invariant from ADR-0006 §1: a Konekto access token is
the *pair*, never a single signature, so the `kid` identifies the
hybrid bundle, not an individual key.

A consumer that understands only one algorithm picks its half by
filtering on `alg`; a consumer that understands both must verify
*both* signatures (per ADR-0006 §2 — no first-match-wins) and uses
`kid` only to confirm the bundle hasn't rolled.

### 2. Ed25519 JWK shape — RFC 8037 §2 verbatim

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "use": "sig",
  "alg": "EdDSA",
  "kid": "<kid>",
  "x": "<b64url(public_key)>"
}
```

`x` is the 32-byte Ed25519 public key, base64url-encoded without
padding. This is exactly what every mainstream JOSE library accepts
out of the box — `josekit`, `jsonwebtoken`, `jose` (node), `pyjwt`,
go-jose. No translation layer needed on the RP side.

### 3. ML-DSA-65 JWK shape — in-flight `AKP` draft

There is no IANA-registered JWK shape for ML-DSA at the time of
writing. Two working-group drafts are in flight:

- `draft-ietf-jose-fully-specified-algorithms` defines the alg
  literal (`ML-DSA-65`).
- `draft-ietf-jose-pqc-mldsa` defines the key shape and proposes
  `kty="AKP"` ("Algorithm Key Pair", parametric on `alg`).

We publish under that in-flight shape:

```json
{
  "kty": "AKP",
  "alg": "ML-DSA-65",
  "use": "sig",
  "kid": "<kid>",
  "pub": "<b64url(public_key_1952_bytes)>"
}
```

Three upgrade paths exist when registration lands:

1. The working group blesses `AKP` and the `pub` field name —
   nothing changes.
2. The working group renames the field (e.g., `x`) — we change
   one literal in `konekto-core::token::jwks` and keep the
   `kid` stable.
3. The working group picks an entirely different `kty` — we change
   two literals and bump the deferred follow-up in ADR-0006 §6
   (which also tracks the `alg` literal change).

All three paths are local to `konekto-core::token::jwks` and to the
ADR-0006 §6 deferred entry. The wire shape of the access token is
unaffected — the `alg` already tracks ADR-0006's literal.

### 4. Endpoint path, content type, and caching

- **Path:** `/.well-known/jwks.json` — the conventional location
  even outside OIDC, supported by every OAuth client and JWT helper
  out of the box.
- **Method:** `GET` only.
- **Auth:** none. Verifying keys are public information; gating them
  would just slow legitimate RPs without protecting anything.
- **`Content-Type`:** `application/jwk-set+json` — RFC 7517 §8.5.1.
- **`Cache-Control`:** `public, max-age=300`.

The 5-minute cache is the trade-off knob. Lower → keys can rotate
faster without RPs holding stale verifications. Higher → less load
on the issuer, slower RP convergence on rotation. 5 minutes is a
defensible default for the pre-alpha posture: keys are ephemeral on
restart anyway (ADR-0006 §3), so RPs caching for 5 minutes will see
401s for at most ~5 minutes after a binary restart. When ADR-0007's
Redis backend lands and keys persist across restarts, this number
will tighten to track Phase D's rotation cadence.

### 5. JWKS reads from the verifier, not from a separate state slot

`AppState` already carries `Arc<TokenVerifier<K>>`. The JWKS handler
calls `verifier.verifying_keys()` and runs the bytes through
`konekto_core::token::to_jwk_set`. The verifying-key bundle held by
the verifier is, by construction, the bundle that will accept the
tokens issued by the matching `TokenIssuer` — so JWKS can never
publish a key set that's out of sync with what's actually in flight,
and `kid` rotation (Phase D) becomes a single-point change on the
issuer/verifier pair.

Two small `pub` accessors land on `VerifyingKeys`:
`ed25519_public_key() -> &[u8; 32]` and
`mldsa_public_key() -> Vec<u8>`. Both already existed `pub(crate)`;
we promote them rather than re-export the underlying verifier types,
so the `konekto-core` surface stays focused on what callers actually
need.

`TokenVerifier::verifying_keys() -> &VerifyingKeys` is also promoted
to `pub` for the same reason.

### 6. Pure function on the verifying bundle

`to_jwk_set(&VerifyingKeys) -> serde_json::Value` is a pure function:
no I/O, no clock, no state. The handler is a one-liner that wraps it
in the response headers from §4. Consequence: every JWKS test that
matters lives in `konekto-core` (shape, b64url round-trip, kid match)
and the API layer carries only the integration tests that exercise
the headers and the route registration.

### 7. The published bundle proves the active bundle (round-trip test)

A dedicated integration test takes the published Ed25519 `x`,
reconstructs an `Ed25519Verifier` from the raw bytes, and verifies
the EdDSA signature on a token freshly issued by the same router.
This replaces a documentation-level claim ("RPs can verify out of
process") with a wire-level proof in CI.

ML-DSA-65 round-trip lives only in `konekto-core` unit tests because
the API layer would have to import the ML-DSA verifier through the
public surface to do the same exercise, and the API layer should
not need a PQ verifier at runtime — JWKS is a publication path, not
a verification path.

---

## Alternatives considered

- **Single `/jwks.json` instead of `/.well-known/jwks.json`.** Ergonomic
  for hand-typing but breaks autodiscovery: every JWT library defaults
  to the `.well-known` path. Rejected — typing one extra slash once is
  cheaper than every consumer overriding a default.

- **OIDC discovery document with embedded `jwks_uri`.** The natural
  long-term shape, but pulls in `issuer` claim alignment and forces
  decisions on `authorization_endpoint`, `token_endpoint`, et al. that
  belong in ADR-0002's OAuth/OIDC scope. Rejected for V1 — JWKS works
  standalone; OIDC discovery is additive.

- **Signed JWKS (JWKS-over-JWS).** Lets RPs authenticate the bundle
  without fully trusting TLS or DNS to the issuer. Defensible only
  once the bundle changes — today it's a single static set per
  process, and self-signing it would force a chicken-and-egg around
  *which* signing key authenticates the JWKS endpoint. Rejected as
  premature; revisit alongside Phase D rotation.

- **Single-key JWKS variant (`.../jwks/{alg}.json`).** Lets a strict
  RP fetch only the half it understands. Adds two URLs and a routing
  layer for no payoff: a JWK Set with one ignored entry costs the
  RP nothing and keeps the `kid` invariant trivially observable.
  Rejected.

- **Cache-Control `no-store`.** Forces every RP to refetch on every
  verification. Wrong default — JWKS is the canonical "small, public,
  highly-cacheable" response shape. Rejected.

- **Embed the JWK Set inside `AppState` at boot.** Skips one
  `to_jwk_set` call per request. Negligible win — the function is a
  handful of base64 encodes — and it would force a `RwLock` once
  Phase D rotation arrives. Rejected: keep the bundle the single
  source of truth on every read.

- **Inline the public-key bytes accessors in the handler instead
  of promoting them on `VerifyingKeys`.** Saves two `pub` items but
  scatters the JWK shape across the API crate, where it doesn't
  belong (the JWK shape is a property of the cryptographic bundle,
  not of the HTTP layer). Rejected — the accessor is the right shape.

- **Publish the ML-DSA-65 entry under `kty="ML-DSA-65"` instead of
  `kty="AKP"`.** Easier to read, and avoids tying the `kty` to a
  parametric draft. But every fully-specified PQ JWK draft we've
  seen uses `AKP`, and reading a stable `kty="AKP"` + `alg="ML-DSA-65"`
  pair is closer to where IANA registration is heading than a
  one-off `kty` literal. Rejected.

---

## Deferred / follow-ups

- **Key rotation** (ADR-0006 §8). Phase D. Multi-kid signer with a
  primary + retired set; verifier accepts any kid currently in the
  publication window; JWKS publishes the union; an `nbf`-style
  retirement schedule expires old keys. Drives the Redis-backed
  signing-key store under ADR-0007.
- **OIDC discovery** at `/.well-known/openid-configuration`. Phase
  E (alongside the `/oauth/token` and `/oauth/authorize` endpoints
  from ADR-0002 §208).
- **Signed JWKS / JOSE-protected JWKS**. Re-evaluate after Phase D
  lands — signing makes sense once the bundle rotates, less so when
  it's static.
- **IANA JWK registration for ML-DSA-65**. Follow
  `draft-ietf-jose-pqc-mldsa` to its RFC. The `to_jwk_set` shape
  changes locally when the draft locks; the wire shape of the
  access token is governed by the `alg` literal and tracked
  separately under ADR-0006 §6.
- **Cache-Control tuning per environment**. The 5-minute default is
  an env-var knob away from being deployment-specific. Holding off
  until rotation gives us a real reason to differ across deployments.
- **CORS headers.** Browser-side RPs (e.g., a SPA validating tokens
  client-side, which we wouldn't recommend but RPs may try)
  currently can't fetch the endpoint cross-origin. Trivial to add
  when we know which origins to allow; today the only consumers are
  server-side.
