# Changelog

All notable changes to Trimero Konekto are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Cargo workspace layout with `konekto-core` and `konekto-db` crates.
- `konekto-core`: type-system skeleton for context isolation (ADR-0002).
  - Sealed `Context` trait with `Vivo`, `Laboro`, `Socio` zero-sized markers.
  - `RootKey` and `ContextKey<C>` types with zeroize-on-drop semantics,
    redacted `Debug` impls, and no `Clone` / `Copy` / `Serialize`.
- `konekto-core`: cryptographic derivation via `aws-lc-rs`.
  - `RootKey::generate()` draws a fresh 256-bit root key from the
    system CSPRNG (ADR-0004 §2 — enrollment entry point).
  - `RootKey::derive::<C>()` derives a `ContextKey<C>` via HKDF-SHA256,
    with the versioned `Context::LABEL` carrying domain separation.
- `konekto-core`: cross-context grant scaffolding (ADR-0002 §4).
  - `CrossContextGrant<From, To>`: move-only, `Debug`-redacted,
    with private fields and no public constructor outside
    `AuditLog::issue`.
  - `AuditLog` trait: concrete implementors provide `record_grant`
    (durable audit write) and inherit the grant-construction
    default method. This binds grant existence to audit durability
    at the type level.
  - Supporting types: `AuditId`, `AuditWriteError`, `GrantScope`
    (`#[non_exhaustive]`), `GrantRecord`, `GrantError`.
- `konekto-core`: AEAD wrapping of the root key (ADR-0004 §3–§4).
  - `WrappingKey`: 256-bit opaque secret, move-only, zeroize-on-drop.
    Accepts caller-supplied material from upstream KDFs (WebAuthn
    PRF, Argon2id) or draws one from the CSPRNG.
  - `WrappedRootKey`: fixed 61-byte wire format
    (`version || nonce || ciphertext || tag`), serializable via
    `as_bytes`/`from_bytes`. Version-tagged and AAD-bound so a
    v1 blob can never be interpreted under a future variant.
  - `RootKey::wrap` / `RootKey::unwrap`: AES-256-GCM with a
    fresh 96-bit nonce per wrap and the fixed AAD
    `konekto.rootkey.wrap.v1`.
  - Errors: `Error::InvalidWrappedFormat`, `Error::UnwrapAuthFailed`.
- `konekto-core`: Argon2id passphrase KDF (ADR-0004 §4).
  - `PassphraseParams` with `::DEFAULT` at OWASP 2024 minimums
    (19 MiB / 2 iters / p=1) and `::new` validating against
    Argon2's accepted ranges.
  - `PassphraseParams::derive_wrapping_key` produces a
    `WrappingKey` from a caller-supplied passphrase and salt.
    Enforces `MIN_PASSPHRASE_LEN = 8` and `MIN_SALT_LEN = 16` at
    the boundary.
  - Errors: `Error::InvalidKdfInput`, `Error::KdfFailed`.
- `konekto-db`: persistence layer scaffolding.
  - Record types: `IdentityRecord`, `CredentialRecord`,
    `WrappedRootRecord` (with `WrapKind` enum +
    `KdfParamsRecord`), `AuditRecord` (with `AuditEventKind`).
  - `InMemoryAuditLog`: a process-local implementation of
    `konekto_core::AuditLog` suitable for tests and dev-mode
    deployments.
  - `DbError`: `NotFound`, `Conflict`, `StorageWriteFailed`,
    `StorageReadFailed`.
  - Initial Postgres schema (`migrations/0001_initial.sql`):
    identities, credentials, wrapped_roots, audit_log, with
    CHECK constraints enforcing the KDF/PRF wrap-kind invariant
    and a partial unique index limiting each identity to one
    recovery-passphrase wrap.
- `konekto-core`: public CSPRNG helpers `fill_random` and
  `random_bytes` so downstream crates that need entropy (salts,
  nonces) do not pull `aws-lc-rs` directly.
- `konekto-db`: dev-mode identity flow end-to-end.
  - `IdentityStore` trait bundling identity, credential,
    wrapped-root, and audit-event storage.
  - `InMemoryStore` implementing `IdentityStore` and
    `konekto_core::AuditLog` in a single process-local backend.
  - `enroll_dev_password`: generates a `RootKey`, derives a
    `WrappingKey` from `Argon2id(passphrase, salt)`, wraps and
    persists the root, records an `Enrollment` audit event,
    returns the new identity id.
  - `login_dev_password::<C>`: loads the wrap, re-derives the
    wrapping key, unwraps the root (AEAD-authenticated — wrong
    passphrase surfaces as `LoginError::BadPassphrase`), derives
    and returns the `ContextKey<C>`, records a `Login` event.
  - `EnrollmentOutcome`, `EnrollmentError`, `LoginError`.
- `konekto-db`: Postgres-backed `IdentityStore` and `AuditLog`
  (`postgres` cargo feature, new `pg` module).
  - `PgIdentityStore`: wraps a `sqlx::PgPool`, implements both
    `IdentityStore` and `konekto_core::AuditLog` against the same
    pool. `Clone` is cheap (pool is internally `Arc`-shared), so
    handlers clone the store per-request to satisfy the `&mut self`
    trait contract.
  - Embedded migrations via `sqlx::migrate!("./migrations")`, applied
    idempotently by `PgIdentityStore::migrate`.
  - Enum-typed columns (`status`, `wrap_kind`, `kind`, `grant_scope`)
    persist as canonical lower-snake-case text; `kdf_params` as JSONB;
    `konekto_core::AuditId` as 16-byte big-endian `BYTEA` so numeric
    order matches lexicographic byte order.
- Integration tests against a live Postgres container via
  `testcontainers-modules`. Nine `#[ignore]`-gated tests cover
  migration idempotency, enroll→login round-trip, wrong-passphrase
  rejection, per-context key distinctness, identity + wrapped-root
  field preservation, audit-event persistence, cross-context grant
  writes, and unique-violation conflict mapping.
- `konekto-core`: `AuditLog` trait is now async via `async-trait`.
  `record_grant` and the default `issue` method return futures so
  real backends can do I/O. `InMemoryAuditLog` and `InMemoryStore`
  migrated accordingly; callers of `enroll_dev_password` and
  `login_dev_password` now `.await` them.
- Workspace-level lints: forbid `unsafe_code`; deny `clippy::all` and
  `clippy::pedantic`; warn on `missing_docs`.
- CI workflow: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.
- `konekto-api`: HTTP surface for the dev-mode identity flow
  (axum 0.8).
  - `POST /dev/enroll` — provision a new identity from a passphrase,
    returns `{"identity_id": "<uuid>"}`.
  - `POST /dev/login` — authenticate and derive a `ContextKey<C>` for
    a requested context (`"vivo"` | `"laboro"` | `"socio"`). Runtime
    selector dispatches to the compile-time `login_dev_password::<C, _>`
    so ADR-0002 context isolation applies end-to-end. Response does
    NOT carry the key material.
  - `ApiStore` capability trait: blanket `IdentityStore + AuditLog +
    Clone + Send + Sync + 'static`. Router is generic over it so
    tests wire up an `Arc<tokio::sync::Mutex<InMemoryStore>>`
    adapter and production wires up `PgIdentityStore`.
  - `AppState<S>` generic app state plus configurable
    `PassphraseParams` (tests use cheap Argon2id params; production
    bootstrap uses `PassphraseParams::DEFAULT`).
  - Opaque error surface (ADR-0003): every internal error funnels
    through `ApiError` with stable snake-case codes
    (`invalid_request`, `unauthorized`, `internal_error`). Unknown
    identity and wrong passphrase collapse to the same 401 response
    to avoid an identity-enumeration oracle.
  - Binary: tracing-subscriber + sqlx `PgPool` + embedded migrations
    via `PgIdentityStore::migrate`, `BIND_ADDR` / `DATABASE_URL` /
    `RUST_LOG` env config, graceful shutdown on Ctrl-C / SIGTERM.
  - Five end-to-end tests via `tower::ServiceExt::oneshot`:
    enroll→login happy path, per-context login dispatch, wrong
    passphrase 401, unknown identity 401 (oracle check), short
    passphrase 400.

- `konekto-core`: hybrid JWS session-token primitive
  (ADR-0003 Phase A, ADR-0006).
  - `token::Claims` / `ContextLabel` — V1 claim shape (`iss`, `sub`,
    `ctx`, `iat`, `nbf`, `exp`, `jti`, `amr`, `ver` plus optional
    `aud`, `acr`, `cnf`). `TOKEN_VERSION = 1` is enforced at verify
    time so bumping the shape is a fail-closed wire change.
  - `token::SigningKeys` / `VerifyingKeys` — Ed25519 (`aws-lc-rs`) +
    ML-DSA-65 (`ml-dsa 0.1.0-rc.8`) bundles with a deterministic
    `Kid` = `BLAKE2s-128(ed25519_pk || ml_dsa_pk)`. `generate_ephemeral`
    for dev bootstrap; `from_env` / `from_encoded` for reusable keys
    across restarts. ML-DSA signing keys are stored as the 32-byte
    canonical seed.
  - `token::TokenIssuer<K>` / `TokenVerifier<K>` — parameterized over
    a `Clock` trait (`SystemClock` in prod, `FixedClock` in tests).
    Emits / consumes JWS JSON General Serialization (RFC 7515 §7.2.1)
    with exactly two signatures; both MUST verify, no short-circuit.
    Verifies `ver`, `iss`, `nbf`, `exp` with leeway.
    `DEFAULT_ACCESS_TTL = 5 min`, `DEFAULT_CLOCK_LEEWAY = 30 s`.
  - `token::TokenError` — eleven internal variants, collapsed to an
    opaque 401 at the HTTP boundary so token-shape details don't leak.
  - Extends `Context` trait with `const CONTEXT_LABEL: ContextLabel`
    so the type-level context marker projects onto the wire claim.
- `konekto-api`: access-token minting and `AuthedContext<C>` extractor.
  - `POST /dev/login` response additively gains `access_token`,
    `token_type` (`"Bearer"`), and `expires_in` (seconds). Existing
    `identity_id` and `context` fields are preserved.
  - `auth::AuthedContext<C>`: axum `FromRequestParts` extractor that
    reads `Authorization: Bearer <jws>`, verifies the token, and
    compares `claims.ctx` against `C::CONTEXT_LABEL`. Any mismatch,
    missing header, bad signature, or expired token surfaces as a
    uniform `401 { "error": "unauthorized" }`.
  - Three context-typed endpoints —
    `GET /vivo/whoami`, `GET /laboro/whoami`, `GET /socio/whoami` —
    each returns `{ identity_id, context, expires_at }`. A `vivo`
    token presented to `/laboro/whoami` is rejected before the
    handler body runs.
  - `AppState<S, K: Clock = SystemClock>`: gains `Arc<TokenIssuer<K>>`
    + `Arc<TokenVerifier<K>>` fields. Generic over `Clock` so tests
    can wire `FixedClock` to drive the expired-token path.
  - Binary bootstrap (`src/main.rs`): reads
    `TOKEN_SIGNING_ED25519_SK` + `TOKEN_SIGNING_MLDSA_SK` env vars as
    base64url seeds, or generates an ephemeral keypair with a
    `tracing::warn!`. `KONEKTO_ISSUER` (default `konekto-dev`)
    controls the `iss` claim.
  - Nine additional `tower::ServiceExt::oneshot` tests: JWS shape,
    login-response compat, happy-path whoami, cross-context rejection
    (vivo token → laboro endpoint, socio token → laboro endpoint),
    missing header, malformed bearer, tampered ML-DSA signature, and
    expired-token-via-`FixedClock`.
- Workspace `.cargo/config.toml` sets `RUST_MIN_STACK = 8 MiB` so
  `cargo test` does not overflow ML-DSA-65's large intermediate
  stack allocations on the 2 MiB default test-thread stack.
- `docs/adr/0006-hybrid-jws-token-implementation.md`: records the
  wire-format choice (hand-rolled General Serialization), key
  bootstrap strategy, `Kid` derivation, clock abstraction,
  `Context::CONTEXT_LABEL` bridge, and the deferred items
  (JWKS / rotation / refresh / DPoP / KMS / IANA alg registration).

### Changed
- `konekto-api`: `POST /dev/login` response body is extended with
  `access_token`, `token_type`, `expires_in`. The existing
  `identity_id` and `context` fields retain their previous shapes and
  semantics — the change is purely additive for consumers that only
  read those two fields.
- `konekto-core::Context`: trait gains a required
  `const CONTEXT_LABEL: ContextLabel` associated constant. Impacts
  only in-crate implementors (`Vivo` / `Laboro` / `Socio`); the trait
  is sealed, so this is not a breaking change for downstream crates.
- `konekto-db`: `audit_log.id` column changed from `NUMERIC(39,0)` to
  `BYTEA CHECK (octet_length = 16)` (pre-alpha, safe to edit migration
  0001). Avoids a `bigdecimal` dependency in the Postgres driver and
  makes `u128 ↔ DB` round-trip trivial via `to_be_bytes`.
