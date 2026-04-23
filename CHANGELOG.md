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
- Workspace-level lints: forbid `unsafe_code`; deny `clippy::all` and
  `clippy::pedantic`; warn on `missing_docs`.
- CI workflow: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.
