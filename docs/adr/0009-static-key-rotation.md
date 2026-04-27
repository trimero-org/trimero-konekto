# ADR-0009 — Static keyring rotation

**Status:** Proposed
**Date:** 2026-04-28
**Author:** Trimero Konekto team
**Addresses:** ADR-0006 §8 deferred (key rotation), ADR-0008 §"Deferred"

---

## Context

ADR-0006 (Phase A) shipped a single hybrid signing/verifying pair held
by `konekto-api` for the lifetime of the process. ADR-0008 (Phase C)
exposed the *active* pair over `/.well-known/jwks.json` so external
relying parties (RPs) could verify access tokens out of process. Both
left the same gap: there is exactly one `kid` in flight at any time, so
*rolling* the signing keys means an immediate flag-day cut-over —
every RP that cached the old JWKS sees 401s until it refetches, and
every access token minted under the previous `kid` becomes
unverifiable the instant the binary restarts with new keys.

This ADR closes that gap with the smallest increment that still earns
the word "rotation": a **static keyring** loaded at boot, with one
**primary** verifying bundle (which also signs new tokens) and zero or
more **retired** bundles (which only verify). Operators rotate by
restarting the binary three times, walking the new bundle through
"introduce" → "promote" → "drop". After this lands, an operator can
roll the signing keys without invalidating tokens that are still
within their 5-minute access TTL, and JWKS publishes the union of
every bundle in the keyring so any RP that fetched within the cache
window can keep verifying.

Items explicitly **out of scope** for Phase D and tracked here as
follow-ups:

- **Dynamic rotation** — runtime key roll without a restart, driven
  either by an admin endpoint, a config-watcher, or a scheduler.
  Static rotation is enough to validate the multi-kid invariants in
  the verifier and the JWKS surface; dynamic rotation can layer on
  top once the storage backend (ADR-0007 Redis) is ready to hold
  signing keys across instances.
- **Automatic primary rotation schedule** — a "swap primary every N
  days" daemon. Defensible only once dynamic rotation lands; today
  it would still require a restart and a config change, so it would
  not actually be automatic.
- **Signed JWKS** — see ADR-0008 §"Deferred". The bundle now changes
  on rotation, which makes signed JWKS more interesting, but signing
  it requires nominating *which* bundle authenticates the JWKS
  endpoint. Belongs in a follow-up alongside the OIDC discovery work.
- **Per-RP `kid` filtering** — letting each RP fetch only the JWKs
  whose `kid`s it intends to accept. Premature optimisation; the
  union JWKS is small (<10 KB even with 3 bundles) and RPs already
  ignore unknown `kid`s.

---

## Decision

### 1. Two-set model: one primary, N retired

A `Keyring` holds:

- exactly one **primary** `VerifyingKeys` bundle — the issuer signs
  new tokens with the matching `SigningKeys`, and freshly minted
  tokens stamp the primary's `kid` into both protected headers;
- zero or more **retired** `VerifyingKeys` bundles — verify-only.
  The signer never references them.

Retired bundles are carried as `VerifyingKeys`, not as
`SigningKeys` — see §3 — so even a leak of the env that holds them
cannot mint new tokens.

The retired list is a `Vec` rather than a fixed capacity: the operator
playbook in §4 only ever needs one retired bundle at a time, but the
verifier and JWKS code don't care about the count, and capping the
slot count would force the operator into a tighter rotation schedule
for no benefit.

### 2. Verifier looks up the bundle by `kid`

`TokenVerifier::verify` parses the `kid` from each of the two
signature blocks' protected headers, requires both blocks to carry the
same `kid` (the kid identifies the *hybrid pair*, ADR-0008 §1), then
calls `Keyring::find(kid)` to pick the bundle. Both signatures verify
against the same bundle:

- a token whose `kid` is the primary's → verifies against the primary;
- a token whose `kid` is in the retired set → verifies against that
  retired bundle (so tokens minted before the latest rotation still
  work for their remaining TTL);
- a token whose `kid` is unknown to the keyring → `KidMismatch`,
  collapsed to opaque 401 at the HTTP boundary as before.

Two consequences worth pinning:

- The verifier no longer holds a privileged "active" `kid` to compare
  against. The `Keyring` itself is the source of truth, and the
  primary is just "the bundle the issuer was paired with at boot".
  Splitting issuer and verifier `kid`s is meaningless: the issuer
  signs only with the primary's matching secret, so any `kid` it
  emits is the primary's `kid` by construction.
- Both signature blocks **must** carry the same `kid`. Forging a
  token by splicing one block from bundle A and the other from
  bundle B (when A and B are both in the keyring) is rejected at
  parse time. Tested.

### 3. Retired bundles carry public keys only

Operators load retired bundles from the env via raw public-key bytes,
not via signing seeds. The shape:

```
TOKEN_RETIRED_VERIFIERS=<ed25519_pk_b64>:<mldsa_pk_b64>,<ed25519_pk_b64>:<mldsa_pk_b64>
```

Each entry is `<32-byte ed25519 public key, base64url>:<1952-byte
ML-DSA-65 public key, base64url>`, comma-separated. Whitespace around
commas and inside entries is tolerated. Any of:

- an entry that is not in `<ed_pk_b64>:<ml_pk_b64>` shape;
- a leg whose decoded length is wrong;
- an empty entry (stray comma);
- a `kid` collision (two retired bundles with identical `kid`s, or a
  retired bundle whose `kid` matches the primary)

→ fails the boot, with a `tracing::error!`-rendered cause string and
a non-zero exit. There is no "skip the bad entry and warn"
fall-back: a misconfigured retired list is operator error and we
prefer to stop the binary rather than silently publish a JWKS that
omits half the bundles the operator intended.

A new constructor on `VerifyingKeys` — `from_public_bytes(ed25519_pk:
&[u8], mldsa_pk: &[u8]) -> Result<Self, TokenError>` — takes raw
public bytes (not seeds) and recomputes the deterministic `kid`. This
is what the operator playbook in §4 produces from the previous
deployment: when an operator promotes a new primary, they read the
*public* key bytes off the retiring binary's logs (or a
`/.well-known/jwks.json` snapshot), and ship those — never the seed.

### 4. Operator playbook — three deploys

A safe rotation walks the new bundle through three deploys. The
walkthrough assumes a single instance; multi-instance fleets repeat
each step on every instance before moving to the next.

| Deploy | `TOKEN_SIGNING_*` (primary) | `TOKEN_RETIRED_VERIFIERS` (verify-only) |
|--------|------------------------------|-----------------------------------------|
| 0 (steady state) | seed for bundle **A**            | empty                            |
| 1 ("introduce")  | seed for bundle **B** (new!)     | A's public bytes                 |
| 2 ("wait")       | seed for bundle **B**            | A's public bytes                 |
| 3 ("drop")       | seed for bundle **B**            | empty                            |

Between deploys 1 and 3 the operator must wait at least
`DEFAULT_ACCESS_TTL` (5 min, ADR-0006) plus `DEFAULT_CLOCK_LEEWAY`
(30 s) **plus** the longest JWKS cache window any RP might be holding
(`Cache-Control: public, max-age=300` per ADR-0008 §4 → 5 min). 11
minutes is the conservative floor; in practice ~15 minutes between
deploys 1 and 3 keeps the steady state clean.

Why three deploys, not two? Two deploys would either (a) drop A's
verifying material before all access tokens minted under A have
expired, or (b) leave A still able to *sign* (because A's
`SigningKeys` would still be loaded). Three deploys cleanly separate
"introduce B as primary, keep A as verify-only" from "drop A".

### 5. JWKS publishes the keyring union

`konekto_core::token::to_jwk_set_from_keyring(&Keyring) ->
serde_json::Value` emits two JWKs per bundle (Ed25519 + ML-DSA-65,
sharing a `kid`), in primary-first iteration order. The HTTP handler
at `/.well-known/jwks.json` switches from `to_jwk_set(&VerifyingKeys)`
to this. Three consequences:

- An RP that fetched JWKS during deploy 1's window sees
  `[B_ed, B_ml, A_ed, A_ml]` — four keys — and verifies tokens minted
  under either `kid` for the cache window's lifetime.
- An RP that fetched during deploy 0's window only knows A's `kid`s.
  Tokens minted under B in deploy 1 will fail until the RP refetches
  (≤ 5 min after deploy 1, given the cache window).
- An RP that fetched during deploy 3's window only knows B's `kid`s.
  Tokens minted under A and still alive (within their 5 min TTL)
  will fail. This is intentional — by deploy 3, no such tokens
  should exist.

The single-bundle `to_jwk_set(&VerifyingKeys)` helper stays available
because tests (and the ADR-0008 round-trip integration test) still
exercise it as the source-of-truth for the per-bundle shape. A
keyring with only a primary publishes a wire-identical JWK Set to
the single-bundle helper — checked in a unit test.

### 6. Backward compatibility via `impl From<VerifyingKeys> for Keyring`

`TokenVerifier::new` and `with_leeway` accept `impl Into<Keyring>`.
A blanket `impl From<VerifyingKeys> for Keyring` (which yields a
keyring with `retired = []`) means every existing call site that
passes a `VerifyingKeys` keeps compiling and behaves identically.
Tests, the binary's bootstrap, and any future caller can migrate to
explicit `Keyring` construction without a flag-day rename.

`TokenVerifier::verifying_keys() -> &VerifyingKeys` is replaced by
`TokenVerifier::keyring() -> &Keyring`. The replacement is a strict
generalisation — the only previous caller (the JWKS handler) needed
the keyring anyway — so no compatibility shim is justified.

### 7. Boot-time logging

When at least one retired bundle is loaded, the binary emits

```
INFO retired_count=N retired verifier bundles loaded (verify-only)
```

at boot. This is the operator's confirmation that a rotation is in
flight. The signing-key info-line (ADR-0006 §3) already prints the
primary's `kid`; together they render "current primary + how many
retired bundles" without exposing public-key material on stdout.

---

## Alternatives considered

- **Multi-`kid` signer (sign with a chosen kid per request).** The
  natural shape for an admin-driven cut-over: keep both A and B as
  signers, route based on per-request policy. Rejected for V1 — it
  drags in a request-scoped policy plane and an admin endpoint, and
  the static-rotation playbook delivers the same RP-side guarantees
  with a single restart per phase. Revisit in dynamic rotation.

- **Symmetric rotation: retired entries carry seeds, not public
  bytes.** Smaller env shape (one secret per bundle, not two
  separately-base64'd public keys). Rejected: the only privilege the
  operator needs to grant a retired bundle is "verify"; carrying the
  seed means a leaked retired-bundles env grants signing privilege
  on legacy `kid`s, which is an unnecessary widening of the threat
  model for zero ergonomic gain.

- **Single env var carrying a JSON array.** `TOKEN_RETIRED_VERIFIERS=[
  {"ed":"…","ml":"…"}, … ]`. Less ambiguous than the
  comma-and-colon form, but operators editing env-var lists in
  Kubernetes / docker-compose / .env files universally treat them as
  flat strings; introducing JSON encoding per env entry trades a
  parser bug-class for a quoting-rule bug-class. Rejected — the
  comma-and-colon form has worked for `PATH` for forty years.

- **Drop retired bundles on a per-`kid` schedule (TTL per entry).**
  Each retired entry would carry its own "drop after" timestamp,
  removing the need for the deploy-3 step. Rejected: timestamps in
  env vars are a notorious foot-gun (clock drift, time-zone mistakes,
  non-trivial parser surface), and the operator playbook is short
  enough that a third deploy is cheaper than a date format.

- **Maintain a single signing key but rotate JWKS publication
  unilaterally.** Lets RPs see two `kid`s before the issuer rolls.
  Pointless — the verifier still trusts only one `kid`, so any token
  that did somehow surface under the new `kid` would fail. The
  invariant "JWKS publishes exactly the bundles the verifier
  accepts" is what makes rotation legible; breaking it to make
  rotation "look easier" earns nothing.

- **Rename `VerifyingKeys` → `VerifyingKey` to match `Keyring`.**
  Reads cleaner, but burns a one-shot rename across every caller for
  zero behavioural difference and makes the diff harder to review.
  Rejected — keep `VerifyingKeys` (the *bundle* nature is real: it
  carries Ed25519 *and* ML-DSA-65 verifiers).

- **Keep `TokenVerifier::verifying_keys()` as a `&VerifyingKeys`
  alias for backward compat.** Rejected: the only existing caller is
  the JWKS handler, which strictly needs the full keyring once
  rotation lands. Carrying both accessors invites future code to
  read the primary alone and silently miss retired tokens. Better to
  break the shape now (one caller, one fix) than to leave a foot-gun.

---

## Deferred / follow-ups

- **Dynamic rotation.** Hot-swap the primary without a restart, or
  add/drop retired bundles via an admin endpoint. Drives the Redis
  -backed signing-key store under ADR-0007. Most likely shape: an
  admin route that reads new key material from a sealed Vault path,
  validates it through the same `from_public_bytes` /
  `from_encoded` path, and atomically swaps the `Arc<Keyring>` /
  `Arc<TokenIssuer>` behind the verifier.
- **Automatic primary rotation.** A daemon (or external scheduler)
  that triggers the three-deploy playbook on a calendar. Belongs
  on top of dynamic rotation.
- **Signed JWKS** (ADR-0008 §"Deferred"). Now that the JWK Set
  changes between deploys, the threat model for signing JWKS is
  more concrete. Re-evaluate after dynamic rotation makes JWKS a
  high-frequency surface.
- **Per-deployment `Cache-Control` tuning.** The 5-minute default is
  the lower bound on the operator's "wait between deploys 1 and 3"
  window. A deployment that wants a tighter rotation cadence can
  drop this; one that prizes RP cache hits can raise it. Holding off
  until rotation is dynamic and the right value is observable.
- **Telemetry on per-`kid` verification counts.** Useful for
  validating that traffic has actually drained off a retired `kid`
  before deploy 3. Today the operator just waits the cache window;
  with metrics, "is anyone still presenting an A-kid token?" becomes
  observable.
- **Operator tooling for the playbook.** A `konekto-keyrotate` CLI
  that prints a compose / k8s diff for each of the three deploys
  given the current state. Rejected as ADR scope (ADRs document
  decisions, not tools); track separately.
