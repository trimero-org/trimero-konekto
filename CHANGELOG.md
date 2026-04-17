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
- Workspace-level lints: forbid `unsafe_code`; deny `clippy::all` and
  `clippy::pedantic`; warn on `missing_docs`.
- CI workflow: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.

### Notes
- Cryptographic derivation (HKDF-SHA256 via `aws-lc-rs`) is intentionally
  not yet implemented. This increment establishes the type-level
  invariants; crypto lands in the next increment.
