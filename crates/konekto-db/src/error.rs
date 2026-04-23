//! Database-layer errors.

use thiserror::Error;

/// Errors produced by `konekto-db` operations.
///
/// Per AGENTS.md and ADR-0003, external error responses must map
/// these to opaque error codes — the HTTP layer never leaks the
/// inner variant.
#[derive(Debug, Error)]
pub enum DbError {
    /// The requested record was not found.
    #[error("record not found")]
    NotFound,

    /// A uniqueness constraint was violated (e.g., re-registering an
    /// existing credential id).
    #[error("uniqueness conflict")]
    Conflict,

    /// A durable write failed at the storage layer.
    #[error("storage write failed")]
    StorageWriteFailed,

    /// A durable read failed at the storage layer.
    #[error("storage read failed")]
    StorageReadFailed,
}
