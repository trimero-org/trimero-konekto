//! HTTP error surface.
//!
//! Per ADR-0003 and `AGENTS.md`, error responses crossing the HTTP
//! boundary MUST be opaque: HTTP clients never see which inner crate
//! error variant fired. This module funnels every internal error
//! through [`ApiError`], which carries:
//!
//! - a stable, machine-readable [`error code`](ApiError::code),
//!   documented for clients, and
//! - a corresponding HTTP status.
//!
//! The full internal error is logged via `tracing` at the boundary,
//! so operators keep diagnosability without leaking it on the wire.
//!
//! Response body shape is stable:
//!
//! ```json
//! { "error": "bad_passphrase" }
//! ```
//!
//! No inner error messages, no stack traces, no hints about whether
//! the identity exists.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use konekto_core::Error as CryptoError;
use konekto_db::identity::{EnrollmentError, LoginError};
use konekto_db::DbError;
use serde::Serialize;
use thiserror::Error;

/// Opaque HTTP-facing error surface.
///
/// Every variant carries a stable snake-case code exposed to clients.
/// New variants are additive; existing codes must not change meaning.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The request body was syntactically invalid JSON or violated
    /// a documented shape / length constraint. Maps to 400.
    #[error("invalid request")]
    InvalidRequest,

    /// The caller did not prove control of the identity (wrong
    /// passphrase, AEAD auth failure). Maps to 401. Deliberately does
    /// not distinguish "no such identity" from "wrong passphrase" —
    /// both collapse to the same response to avoid an enumeration
    /// oracle.
    #[error("unauthorized")]
    Unauthorized,

    /// An internal error (storage failure, crypto environment error,
    /// state invariant violation). Maps to 500. Details logged, never
    /// surfaced.
    #[error("internal error")]
    Internal,
}

impl ApiError {
    /// Stable machine-readable code for this error variant.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Internal => "internal_error",
        }
    }

    /// HTTP status this error maps to.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Serialize)]
struct ApiErrorBody {
    error: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status(), Json(ApiErrorBody { error: self.code() })).into_response()
    }
}

impl From<EnrollmentError> for ApiError {
    fn from(err: EnrollmentError) -> Self {
        match err {
            // KDF input boundary failures (short passphrase, short salt,
            // out-of-range params) are the only `Crypto` variants that
            // the enrollment flow can produce from caller input. Treat
            // as client error.
            EnrollmentError::Crypto(CryptoError::InvalidKdfInput) => Self::InvalidRequest,
            EnrollmentError::Crypto(_) | EnrollmentError::Storage(_) => {
                tracing::error!(error = %err, "enrollment failed");
                Self::Internal
            }
        }
    }
}

impl From<LoginError> for ApiError {
    fn from(err: LoginError) -> Self {
        match err {
            // Wrong passphrase and unknown identity MUST return the same
            // response — distinguishing them leaks enrollment state
            // (identity-enumeration oracle).
            LoginError::BadPassphrase | LoginError::NotFound => Self::Unauthorized,
            LoginError::Crypto(CryptoError::InvalidKdfInput) => Self::InvalidRequest,
            LoginError::WrongWrapKind
            | LoginError::MissingDevMetadata
            | LoginError::Crypto(_)
            | LoginError::Storage(_) => {
                tracing::error!(error = %err, "login failed");
                Self::Internal
            }
        }
    }
}

impl From<DbError> for ApiError {
    fn from(err: DbError) -> Self {
        tracing::error!(error = %err, "db error at api boundary");
        Self::Internal
    }
}
