//! Error types for `konekto-core`.

use thiserror::Error;

/// Errors produced by core identity and cryptographic operations.
///
/// Per ADR-0003 and AGENTS.md, external error responses (produced by
/// `konekto-api`) must map these to opaque error codes — callers of
/// this crate get the full variant, but HTTP clients never do.
#[derive(Debug, Error)]
pub enum Error {
    /// A key-material buffer had the wrong length at a boundary.
    /// Should be structurally impossible inside this crate; indicates
    /// a deserialization or interop bug at the edge.
    #[error("invalid key material length")]
    InvalidKeyLength,

    /// A wrapped-key blob did not parse: wrong length, unknown
    /// version byte, or otherwise malformed layout.
    #[error("invalid wrapped-key format")]
    InvalidWrappedFormat,

    /// AEAD authentication failed when unwrapping. Indicates a wrong
    /// wrapping key, tampered ciphertext, or incorrect AAD binding.
    /// MUST be treated as an unrecoverable security event by
    /// callers (not a recoverable protocol error).
    #[error("wrapped-key authentication failed")]
    UnwrapAuthFailed,
}
