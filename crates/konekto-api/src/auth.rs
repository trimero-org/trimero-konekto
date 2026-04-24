//! `AuthedContext<C>` — `FromRequestParts` extractor enforcing
//! context-typed authentication at the HTTP boundary.
//!
//! A handler that takes `AuthedContext<Vivo>` only runs if the
//! incoming `Authorization: Bearer …` header carries a token whose
//! `ctx` claim matches `<Vivo as Context>::CONTEXT_LABEL`. A `laboro` token
//! presented on `/vivo/whoami` is rejected with `401` before the
//! handler body executes — the ADR-0002 context-isolation guarantee
//! is enforced by the type system plus the extractor, not by
//! ad-hoc runtime checks sprinkled across handlers.

use std::marker::PhantomData;

use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use konekto_core::token::{Claims, Clock};
use konekto_core::Context;

use crate::error::ApiError;
use crate::state::{ApiStore, AppState};

/// Successful context-typed authentication.
///
/// The generic `C` ties this extraction to one specific context
/// marker — construction is only possible via the
/// [`axum::extract::FromRequestParts`] impl, which verifies the
/// token's `ctx` claim matches `C::CONTEXT_LABEL`.
#[derive(Debug)]
pub struct AuthedContext<C: Context> {
    /// Verified claims from the access token.
    pub claims: Claims,
    _context: PhantomData<C>,
}

impl<C, S, K> axum::extract::FromRequestParts<AppState<S, K>> for AuthedContext<C>
where
    C: Context,
    S: ApiStore,
    K: Clock,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<S, K>,
    ) -> Result<Self, Self::Rejection> {
        let bearer = extract_bearer(&parts.headers).ok_or(ApiError::Unauthorized)?;

        let claims = state.verifier.verify(bearer.as_bytes()).map_err(|err| {
            tracing::warn!(?err, "token verification failed");
            ApiError::Unauthorized
        })?;

        if claims.ctx != C::CONTEXT_LABEL {
            tracing::warn!(
                expected = ?C::CONTEXT_LABEL,
                actual = ?claims.ctx,
                "context mismatch",
            );
            return Err(ApiError::Unauthorized);
        }

        Ok(Self {
            claims,
            _context: PhantomData,
        })
    }
}

/// Parse an `Authorization: Bearer …` header into its token string.
///
/// Returns `None` if the header is missing, non-ASCII, or does not
/// start with the case-sensitive `Bearer ` prefix required by
/// RFC 6750 §2.1.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

#[cfg(test)]
mod tests {
    use super::extract_bearer;
    use axum::http::{header, HeaderMap, HeaderValue};

    fn make_headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(value).expect("valid header"),
        );
        h
    }

    #[test]
    fn extract_bearer_returns_inner_token() {
        let h = make_headers("Bearer abc.def.ghi");
        assert_eq!(extract_bearer(&h).as_deref(), Some("abc.def.ghi"));
    }

    #[test]
    fn extract_bearer_requires_case_sensitive_prefix() {
        let h = make_headers("bearer abc");
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let h = make_headers("Bearer ");
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_missing_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_bearer(&h).is_none());
    }
}
