//! Trimero Konekto — persistence layer.
//!
//! This crate owns the storage side of the identity platform:
//!
//! - The Rust record types that pair with each durable table
//!   ([`records`]).
//! - Backends for `konekto-core`'s storage-shaped traits — most
//!   importantly, [`audit::InMemoryAuditLog`] implementing
//!   [`konekto_core::AuditLog`].
//! - The schema (SQL migrations under `migrations/`) that the
//!   Postgres-backed implementations will bind to in a follow-up
//!   increment.
//!
//! # Layering
//!
//! `konekto-db` depends on `konekto-core` for domain types
//! ([`konekto_core::WrappedRootKey`], [`konekto_core::AuditLog`],
//! [`konekto_core::GrantScope`]) but MUST NOT perform any
//! cryptographic work itself. Wrapping, unwrapping, KDF stretching,
//! and context-key derivation all happen in `konekto-core`. This
//! crate only moves bytes between memory and storage.
//!
//! # Stability
//!
//! Record struct fields, SQL column names, and migration ordering
//! are part of the durable wire contract. Changes must be additive
//! or carry a versioned migration.

pub mod audit;
pub mod identity;
#[cfg(feature = "postgres")]
pub mod pg;
pub mod records;

mod error;
pub use error::DbError;
