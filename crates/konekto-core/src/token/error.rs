//! Errors produced by token issuance and verification.
//!
//! Variants are intentionally fine-grained to support diagnostic
//! logging inside `konekto-core`, but the HTTP boundary
//! (`konekto-api`) collapses all of them to a single opaque
//! `unauthorized` response so that clients cannot distinguish a
//! malformed token from an expired one from a signature failure
//! (ADR-0003).

use thiserror::Error;

/// Errors from the hybrid-JWS token primitive.
#[derive(Debug, Error)]
pub enum TokenError {
    /// The token was not a parseable JWS JSON Serialization object
    /// (wrong structure, missing required fields, unexpected type of
    /// a field, etc.).
    #[error("invalid token format")]
    InvalidFormat,

    /// One or both signatures failed cryptographic verification.
    #[error("invalid token signature")]
    InvalidSignature,

    /// The set of `alg` values across the two signature blocks did
    /// not match the required `{EdDSA, ML-DSA-65}` or a duplicate
    /// `alg` appeared.
    #[error("token alg set mismatch")]
    AlgMismatch,

    /// A protected-header `kid` did not match the verifier's `kid`.
    #[error("token kid mismatch")]
    KidMismatch,

    /// `now` is past `exp + leeway`.
    #[error("token expired")]
    Expired,

    /// `now` is before `nbf - leeway`.
    #[error("token not yet valid")]
    NotYetValid,

    /// The token's `iss` claim did not match the verifier's expected
    /// issuer.
    #[error("token issuer mismatch")]
    IssuerMismatch,

    /// The token's `ver` claim does not match the schema version this
    /// implementation supports.
    #[error("unsupported token version")]
    UnsupportedVersion,

    /// A base64url-decoded field did not parse.
    #[error("base64url decoding failed")]
    Base64,

    /// A JSON payload (claims or protected header) did not
    /// encode / decode correctly.
    #[error("token payload encoding failed")]
    PayloadEncoding,

    /// The signing backend refused to produce a signature. Indicates
    /// an environment-level crypto failure.
    #[error("signing failed")]
    SigningFailed,

    /// Key bootstrapping from the environment failed (missing or
    /// malformed `TOKEN_SIGNING_*` variables).
    #[error("token key environment configuration error")]
    EnvConfig,
}
