//! Request-level authentication extractors.
//!
//! Two distinct surfaces, each with its own extractor (ADR-0003 §1):
//!
//! - [`AuthedContext<C>`] — the OAuth-style bearer surface. A handler
//!   that takes `AuthedContext<Vivo>` only runs if the
//!   `Authorization: Bearer …` header carries a hybrid-JWS token whose
//!   `ctx` claim matches `<Vivo as Context>::CONTEXT_LABEL`. A
//!   `laboro` token presented on `/vivo/whoami` is rejected with `401`
//!   before the handler body executes — the ADR-0002 context-isolation
//!   guarantee is enforced by the type system plus the extractor, not
//!   by ad-hoc runtime checks sprinkled across handlers.
//!
//! - [`AuthedSession`] — the first-party cookie surface. A handler
//!   that takes `AuthedSession` only runs if the `konekto_session`
//!   cookie carries an opaque ID whose hash matches a live, non-expired
//!   session record. Sliding idle is bumped on every successful
//!   extraction.
//!
//! Both extractors collapse every internal failure mode to
//! [`ApiError::Unauthorized`] — clients see one bit, operators see
//! the variant via `tracing::warn!`.

use std::marker::PhantomData;

use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use konekto_core::token::{Claims, Clock, ContextLabel, SessionId, SESSION_IDLE_TTL_SECS};
use konekto_core::Context;
use konekto_db::session::{SessionLookup, SessionStore};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::{ApiStore, AppState};

/// Name of the first-party session cookie.
pub const SESSION_COOKIE_NAME: &str = "konekto_session";

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

impl<C, S, Sess, K> axum::extract::FromRequestParts<AppState<S, Sess, K>> for AuthedContext<C>
where
    C: Context,
    S: ApiStore,
    Sess: SessionStore,
    K: Clock,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<S, Sess, K>,
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

/// Successful first-party-session authentication.
///
/// Construction is only possible via the
/// [`axum::extract::FromRequestParts`] impl, which:
///
/// 1. extracts the `konekto_session` cookie from the `Cookie` header,
/// 2. hashes its value and looks the hash up in the session store,
/// 3. rejects expired or unknown sessions with [`ApiError::Unauthorized`],
/// 4. slides the idle window forward.
#[derive(Debug, Clone)]
pub struct AuthedSession {
    /// Identity bound to the session.
    pub identity_id: Uuid,
    /// Single context the session is scoped to.
    pub ctx: ContextLabel,
    /// Sliding idle expiry after the touch performed by extraction.
    pub idle_expires_at: i64,
    /// Hard absolute expiry (unchanged by touch).
    pub absolute_expires_at: i64,
}

impl<S, Sess, K> axum::extract::FromRequestParts<AppState<S, Sess, K>> for AuthedSession
where
    S: ApiStore,
    Sess: SessionStore,
    K: Clock,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<S, Sess, K>,
    ) -> Result<Self, Self::Rejection> {
        let raw = extract_session_cookie(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let session_id = SessionId::from_wire(raw).ok_or(ApiError::Unauthorized)?;
        let now = state.verifier.clock().now_unix_secs();
        let new_idle = now.saturating_add(SESSION_IDLE_TTL_SECS);

        match state
            .sessions
            .touch_session(session_id.hash(), now, new_idle)
            .await?
        {
            SessionLookup::Active(record) => Ok(Self {
                identity_id: record.identity_id,
                ctx: record.ctx,
                idle_expires_at: record.idle_expires_at,
                absolute_expires_at: record.absolute_expires_at,
            }),
            SessionLookup::Expired => {
                tracing::warn!("session expired");
                Err(ApiError::Unauthorized)
            }
            SessionLookup::Unknown => {
                tracing::warn!("session unknown");
                Err(ApiError::Unauthorized)
            }
        }
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

/// Parse the `Cookie` header for the `konekto_session` cookie value.
///
/// Returns `None` if the header is missing, malformed, or the cookie
/// is absent. RFC 6265 §5.4 cookie-pair list parsing — split on
/// `;`, trim, match the name case-sensitively (cookie names are
/// case-sensitive per §4.1.1).
pub(crate) fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(SESSION_COOKIE_NAME).and_then(|rest| {
            // Must be `=value`, not `<name><suffix>=`.
            rest.strip_prefix('=')
        }) {
            if value.is_empty() {
                return None;
            }
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{extract_bearer, extract_session_cookie};
    use axum::http::{header, HeaderMap, HeaderValue};

    fn header_map(name: header::HeaderName, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).expect("valid header"));
        h
    }

    #[test]
    fn extract_bearer_returns_inner_token() {
        let h = header_map(header::AUTHORIZATION, "Bearer abc.def.ghi");
        assert_eq!(extract_bearer(&h).as_deref(), Some("abc.def.ghi"));
    }

    #[test]
    fn extract_bearer_requires_case_sensitive_prefix() {
        let h = header_map(header::AUTHORIZATION, "bearer abc");
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let h = header_map(header::AUTHORIZATION, "Bearer ");
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_missing_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_session_cookie_returns_value() {
        let h = header_map(header::COOKIE, "konekto_session=ABC123");
        assert_eq!(extract_session_cookie(&h).as_deref(), Some("ABC123"));
    }

    #[test]
    fn extract_session_cookie_in_multivalued_header() {
        let h = header_map(
            header::COOKIE,
            "tracking=xyz; konekto_session=ABC123; other=ok",
        );
        assert_eq!(extract_session_cookie(&h).as_deref(), Some("ABC123"));
    }

    #[test]
    fn extract_session_cookie_missing_returns_none() {
        let h = header_map(header::COOKIE, "tracking=xyz; other=ok");
        assert!(extract_session_cookie(&h).is_none());
    }

    #[test]
    fn extract_session_cookie_empty_value_returns_none() {
        let h = header_map(header::COOKIE, "konekto_session=");
        assert!(extract_session_cookie(&h).is_none());
    }

    #[test]
    fn extract_session_cookie_substring_match_rejected() {
        // Must not match `xkonekto_session=...` or
        // `konekto_session_other=...`.
        let h = header_map(header::COOKIE, "xkonekto_session=evil");
        assert!(extract_session_cookie(&h).is_none());
        let h = header_map(header::COOKIE, "konekto_session_other=evil");
        assert!(extract_session_cookie(&h).is_none());
    }

    #[test]
    fn extract_session_cookie_no_cookie_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_session_cookie(&h).is_none());
    }
}
