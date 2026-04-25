# ADR-0007 — Session and refresh-token storage

**Status:** Proposed
**Date:** 2026-04-25
**Author:** Trimero Konekto team
**Addresses:** ADR-0003 Phase B (refresh tokens, first-party session cookie)

---

## Context

ADR-0003 fixes Konekto's session model: two distinct surfaces, each
with its own bearer.

- **First-party session** — opaque, cookie-bound, instant revocation
  required. ADR-0003 §1 specifies `HttpOnly; Secure; SameSite=Strict`,
  state held in a server-side store.
- **OAuth refresh token** — opaque, body-borne, single-use rotation
  with theft detection. ADR-0003 §2 specifies a 30-day sliding /
  90-day absolute window and family-wide revocation when a rotated
  member is replayed.

ADR-0006 implemented the access-token leg (Phase A). This ADR captures
the storage choices that land Phase B: the bearer secrets, their hash
representation, the trait we expose to handlers, the in-memory backend
that ships with the pre-alpha binary, and the cookie attribute set
written by `/dev/login`.

Items explicitly **out of scope** for Phase B and tracked here as
follow-ups:

- Redis-backed `SessionStore` implementation.
- Cross-region replication and durability story.
- DPoP proof-of-possession (ADR-0003 §4).
- JWKS endpoint and signing-key rotation (ADR-0006 follow-ups).
- Authorization-code grant and OIDC endpoints (ADR-0002 §208).
- Per-relying-party `sub` salting (ADR-0003 §5).

---

## Decision

### 1. Two newtypes for the wire-side bearer secrets

`SessionId` (cookie value) and `RefreshTokenSecret` (refresh-token
body field) are structurally identical — 32-byte CSPRNG output,
base64url-encoded, no padding (43 ASCII chars) — but live on disjoint
surfaces with different TTL policies.

Distinct types make accidental cross-use a compile error rather than
a runtime confusion: the bearer presented at `/dev/refresh` cannot
silently be looked up against the session table, and vice versa.
Construction is gated through `::generate()` (CSPRNG) and
`::from_wire(String) -> Option<Self>` (validates non-empty); a forged
value that survives `from_wire` simply fails to match any stored hash.

`Debug` is redacted: the wire string never appears in logs or panic
messages.

### 2. Hashed storage with BLAKE2s-256

The store sees only `[u8; 32]` digests, never the raw secrets. On
each presentation the server hashes the wire value and looks the hash
up. This limits the blast radius of a storage leak — raw bearers
cannot be reconstructed from a database dump.

We picked **BLAKE2s-256** over SHA-256 because we already use BLAKE2
for the `Kid` derivation in ADR-0006 (one less hash family in the
build) and over Argon2id because the secret is itself 256 bits of
CSPRNG entropy — there is no offline guess to slow down. A fast hash
is correct here; a slow hash would be cargo-culted from password
storage.

### 3. Single `SessionStore` trait covering both surfaces

The trait sits in `konekto-db`, takes `&self` everywhere, and is
async via `async-trait`. It exposes:

- `create_session` / `get_session` / `touch_session` / `logout` for
  the first-party surface;
- `create_refresh` / `rotate_refresh` / `revoke_family` for the
  OAuth surface.

Both surfaces share one trait because production has a single
canonical backend (Redis) and bundling them avoids carrying two
clients per process. The clock is **not** absorbed into the trait —
`now: i64` is passed explicitly. Tests inject a `FixedClock` at the
HTTP layer and pass its output through; the store does not own the
time source.

A separate trait `IdentityStore` already covers the Postgres-resident
identity surface; bundling sessions into it would force every test or
future deployment to carry both backends, when the canonical
production targets diverge.

### 4. `&self` everywhere, internal synchronization

Production Redis impls naturally borrow shared state through a
connection pool — `&self` is the right shape there. The pre-alpha
in-memory implementation matches this signature with an
`Arc<Mutex<HashMap<…>>>`. `&mut self` would force every handler to
hold an exclusive borrow across the request, which `axum` does not
permit anyway.

Mutex poisoning falls through to `PoisonError::into_inner`. A
poisoned mutex means a handler panicked under the lock; the next
request taking the lock will observe potentially partial state. The
trade is intentional — we prefer fail-open observability (the next
request still gets a consistent answer) over fail-closed denial of
service. A real Redis backend will not have this concern.

### 5. Refresh rotation: lifecycle states + theft detection

Each refresh-token record carries one of three states:

- `Active` — the only state for which rotation succeeds. The presented
  hash is moved to `Rotated`, and the new hash is inserted in the
  same family with `now` as `created_at` and the clamped sliding
  bound. Absolute expiry is carried unchanged (rotation does not
  extend the family ceiling — ADR-0003 §2).
- `Rotated` — single-use rotation already happened. A second
  presentation triggers theft detection: the entire family is moved
  to `Revoked` and the caller sees an opaque 401.
- `Revoked` — explicitly revoked (logout, prior theft detection, or a
  family-wide revocation). Any presentation returns 401.

`RefreshOutcome::{Rotated, Theft, Revoked, Expired, Unknown}` exposes
the five distinguishable cases internally. At the HTTP boundary they
all collapse to `401 { "error": "unauthorized" }` for the same
enumeration-oracle reason as ADR-0006 §9 — a caller does not need to
distinguish "we never minted this" from "you replayed it".

A `family_id` is generated at login and threaded through every
rotation. `revoke_family(family_id)` flips every member at once and
backs both the theft-detection cascade and the logout cascade in §6.

### 6. Logout cascade across both surfaces

`SessionRecord::linked_refresh_family: Option<Uuid>` is set at
`/dev/login`. When `/dev/logout` runs, the session is removed and
`revoke_family` is called for the linked family in the same call.
Tearing down both surfaces atomically means an attacker holding only
the refresh token cannot keep a stolen session alive after the user
logs out from the first-party surface, and vice versa.

`/dev/logout` is **idempotent on the wire**: an unknown or already
expired session still returns 204. This avoids an oracle that would
distinguish "this cookie was real" from "this cookie was fake".

### 7. Cookie attributes (RFC 6265 / ADR-0003 §1)

`/dev/login` writes:

```
Set-Cookie: konekto_session=<value>; HttpOnly; SameSite=Strict; Path=/;
            Max-Age=43200; Secure
```

Every attribute except `Secure` is fixed in code. `Secure` is gated
by `CookieConfig`, which reads `KONEKTO_COOKIE_SECURE` at boot:

- `true` (default) — production posture; cookie never crosses an
  untrusted transport.
- `false` — HTTP localhost development only. Logged at `tracing::warn!`
  at boot.
- any other value — boot fails.

`/dev/logout` writes the same cookie name with empty value and
`Max-Age=0`, mirroring the attribute set so clients clear it
deterministically.

`SameSite=Strict` is preferred to `Lax` because Konekto's first-party
surface is not invoked from third-party top-level navigations; OAuth
redirect flows live behind the relying-party handshake (Phase C),
not the management plane.

### 8. Sliding idle, capped by absolute

Both surfaces have two TTLs:

| Surface | Idle (sliding) | Absolute (hard) |
|---|---|---|
| Session  |   30 min |   12 h  |
| Refresh  |   30 days |  90 days |

`touch_session` slides the idle window forward; `rotate_refresh`
slides the refresh idle window. **Neither extends the absolute
window.** The store applies `idle = min(idle_candidate, absolute)`
on every update so a long-lived session cannot be kept alive past
its hard ceiling by repeated touches.

A request observed past the idle bound triggers eviction as a
side-effect of the lookup so the next presentation sees `Unknown`,
not stale state.

### 9. In-memory implementation ships in the binary

V1 ships with `InMemorySessionStore` wired into the production
binary. The trade is explicit and logged at boot:
process-local state, no replication, sessions and refresh tokens are
invalidated on restart. This matches the existing posture in
ADR-0006: ephemeral signing keys also disappear on restart unless
seeded from env.

For pre-alpha — single-region, single-replica, no live users — the
operational simplification is worth more than the durability we'd
buy from a dedicated Redis. When that calculus flips, the trait
boundary is in place; only `main.rs` changes.

### 10. Two distinct extractors at the HTTP boundary

`AuthedContext<C: Context>` (Phase A) reads
`Authorization: Bearer <jws>`. `AuthedSession` (Phase B) reads the
`konekto_session` cookie. Both are axum `FromRequestParts`, so they
compose with `Json<T>`; both collapse every internal failure to
`ApiError::Unauthorized` with a `tracing::warn!` carrying the actual
variant. Handlers that take the wrong extractor do not compile.

Cookie parsing is hand-rolled (one screen of code) rather than
pulling `tower-cookies`: we need exactly one cookie name, with
case-sensitive RFC 6265 §4.1.1 matching that rejects substring
collisions like `xkonekto_session=` or `konekto_session_other=`.

---

## Alternatives considered

- **Two separate traits, one per surface.** Cleaner separation but
  bundles two backend clients into the deployment surface for no
  payoff: the same Redis (or in-memory map) serves both. Rejected.

- **Raw token storage.** Simpler; lets the store evict by exact
  match. But every storage leak becomes a session-and-refresh leak.
  Rejected — the BLAKE2s hash is one cheap step that turns a leak
  into a non-event.

- **Argon2id-like hash for the stored bearer.** Cargo-cult from
  password storage. The bearer is already 256 bits of CSPRNG; an
  attacker has nothing to brute-force offline that a fast hash
  doesn't already gate. Rejected.

- **Postgres-backed `SessionStore`.** Postgres is on the request
  path for identity already, so reuse the connection pool. Rejected
  for V1 because session writes happen on every authenticated
  request (idle slide), and an OAuth fleet that survives ecosystem
  scale needs to keep that hot path off the same database the audit
  log is writing to. Redis is the canonical answer in ADR-0003 §1.

- **Bundle Clock into SessionStore.** A `&self` trait that owns its
  own clock can never be driven from a `FixedClock` in a test
  without a separate mock. Passing `now: i64` keeps the store
  logic-only and the time source at the layer that already manages
  it (the `TokenVerifier`). Rejected the bundled form.

- **Lax SameSite + CSRF token.** More compatible with embedded
  third-party flows but introduces a second secret per session and
  a second wire path. ADR-0003 §1 already constrains us to Strict;
  flows that need cross-site land on the OAuth surface, which
  doesn't depend on the cookie at all. Rejected.

- **Stateful access-token revocation list.** Would let us revoke an
  individual access token before its 5-minute expiry. Too coarse
  (it would re-introduce the per-request datastore lookup the
  hybrid model exists to avoid) for the value (5 minutes is the
  worst-case window already). Rejected per ADR-0003 §2 — the
  refresh family is the revocation handle.

---

## Deferred / follow-ups

- **Redis-backed `SessionStore`.** Drop-in implementation of the
  same trait. Adds a `redis = "*"` dep to `konekto-db` behind a
  cargo feature, plus connection-string env config in `main.rs`.
  Tracked as the V1 → V1.1 promotion gate.
- **DPoP proof-of-possession** (ADR-0003 §4). Bumps the access-token
  shape (`cnf` claim), a per-request signature header, and adds an
  anti-replay nonce surface. Phase C.
- **OAuth/OIDC authorization-code endpoints**. Phase C. The grant
  table sits in Postgres alongside identity; the refresh token it
  mints uses this storage.
- **Cross-context grant tokens.** ADR-0002 §4 specifies short-lived
  grant tokens distinct from access tokens; storage TBD when the
  grant flow lands.
- **Session listing / per-device revocation UI.** The store already
  has the data; the management surface is post-V1.
- **Proper Mutex behavior under panic.** The current
  `PoisonError::into_inner` posture is acceptable for the in-memory
  backend; the Redis backend doesn't expose this concern.
