# Changelog

All notable changes to Trimero Konekto are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Cargo workspace layout with `konekto-core` as the first crate.
- `konekto-core`: type-system skeleton for context isolation (ADR-0002).
  - Sealed `Context` trait with `Vivo`, `Laboro`, `Socio` zero-sized markers.
  - `RootKey` and `ContextKey<C>` types with zeroize-on-drop semantics,
    redacted `Debug` impls, and no `Clone` / `Copy` / `Serialize`.
- `konekto-core`: cryptographic derivation via `aws-lc-rs`.
  - `RootKey::generate()` draws a fresh 256-bit root key from the
    system CSPRNG (ADR-0004 §2 — enrollment entry point).
  - `RootKey::derive::<C>()` derives a `ContextKey<C>` via HKDF-SHA256,
    with the versioned `Context::LABEL` carrying domain separation.
- Workspace-level lints: forbid `unsafe_code`; deny `clippy::all` and
  `clippy::pedantic`; warn on `missing_docs`.
- CI workflow: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.
