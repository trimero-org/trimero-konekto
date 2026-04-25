//! Trimero Konekto — HTTP API.
//!
//! This crate exposes the dev-mode identity flow over HTTP:
//!
//! - `POST /dev/enroll`    — provision a new identity from a passphrase.
//! - `POST /dev/login`     — authenticate, mint a context-bound access
//!   token + refresh token, and bind a first-party session cookie.
//! - `POST /dev/refresh`   — rotate a refresh token.
//! - `GET  /dev/me`        — read the first-party session.
//! - `POST /dev/logout`    — drop the first-party session and revoke
//!   any linked refresh family.
//! - `GET  /vivo/whoami`   — echo authenticated Vivo identity.
//! - `GET  /laboro/whoami` — echo authenticated Laboro identity.
//! - `GET  /socio/whoami`  — echo authenticated Socio identity.
//!
//! The router is generic over any [`ApiStore`], any
//! [`konekto_db::session::SessionStore`], and any
//! [`konekto_core::token::Clock`]. In production the binary wires up
//! [`konekto_db::pg::PgIdentityStore`],
//! [`konekto_db::session::InMemorySessionStore`], and
//! [`konekto_core::token::SystemClock`]; the in-crate tests wire up an
//! in-memory adapter via `SharedInMemoryStore` and may substitute
//! [`konekto_core::token::FixedClock`] to drive expiration paths.

pub mod auth;
pub mod error;
pub mod handlers;
pub mod state;

pub use auth::{AuthedContext, AuthedSession};
pub use error::ApiError;
pub use state::{ApiStore, AppState, CookieConfig};

use axum::routing::{get, post};
use axum::Router;
use konekto_core::token::Clock;
use konekto_db::session::SessionStore;

/// Build the top-level axum router wired against `state`.
///
/// Wire-level invariants:
/// - Bodies are JSON; malformed JSON yields axum's default 400.
/// - Semantic errors flow through [`ApiError`] and are serialized
///   as `{"error": "<code>"}` with a stable snake-case code set.
/// - No endpoint ever leaks a context key or wrapped-root blob.
/// - The three `/{ctx}/whoami` routes each require a token whose
///   `ctx` claim matches the URL segment; a mismatch yields an
///   opaque 401 before the handler body runs.
/// - `/dev/login` writes a `konekto_session` cookie; `/dev/me` and
///   `/dev/logout` consume it.
pub fn build_router<S: ApiStore, Sess: SessionStore, K: Clock>(
    state: AppState<S, Sess, K>,
) -> Router {
    Router::new()
        .route("/dev/enroll", post(handlers::enroll::<S, Sess, K>))
        .route("/dev/login", post(handlers::login::<S, Sess, K>))
        .route("/dev/refresh", post(handlers::refresh::<S, Sess, K>))
        .route("/dev/me", get(handlers::me))
        .route("/dev/logout", post(handlers::logout::<S, Sess, K>))
        .route("/vivo/whoami", get(handlers::whoami_vivo))
        .route("/laboro/whoami", get(handlers::whoami_laboro))
        .route("/socio/whoami", get(handlers::whoami_socio))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    //! HTTP-level tests.
    //!
    //! These exercise the router end-to-end via `tower::ServiceExt::oneshot`,
    //! against a `SharedInMemoryStore` adapter that wraps
    //! [`konekto_db::identity::InMemoryStore`] in `Arc<tokio::sync::Mutex<_>>`.
    //! The adapter is test-only: it satisfies `Clone + Send + Sync + 'static`
    //! (required by `axum::extract::State`) without forcing a `Clone`
    //! impl on `InMemoryStore` itself.
    //!
    //! Sessions and refresh tokens use the production
    //! [`InMemorySessionStore`] directly — that impl is already
    //! `Clone + Send + Sync + 'static`.

    use super::{build_router, AppState, CookieConfig};
    use axum::body::Body;
    use axum::http::{header, HeaderValue, Method, Request, StatusCode};
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use konekto_core::token::{
        FixedClock, SigningKeys, SystemClock, TokenIssuer, TokenVerifier, DEFAULT_ACCESS_TTL,
    };
    use konekto_core::{AuditId, AuditLog, AuditWriteError, GrantRecord, PassphraseParams};
    use konekto_db::identity::{IdentityStore, InMemoryStore};
    use konekto_db::records::{
        AuditRecord, CredentialRecord, IdentityRecord, WrapKind, WrappedRootRecord,
    };
    use konekto_db::session::InMemorySessionStore;
    use konekto_db::DbError;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tower::ServiceExt;
    use uuid::Uuid;

    const TEST_ISS: &str = "konekto-test";

    /// Process-local adapter that makes [`InMemoryStore`] usable as
    /// an [`super::ApiStore`]. Production uses
    /// [`konekto_db::pg::PgIdentityStore`] instead — its `Clone` is
    /// cheap (the pool is internally `Arc`-shared), so the adapter
    /// only exists for tests.
    #[derive(Clone, Default)]
    struct SharedInMemoryStore {
        inner: Arc<Mutex<InMemoryStore>>,
    }

    impl SharedInMemoryStore {
        fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait::async_trait]
    impl IdentityStore for SharedInMemoryStore {
        async fn create_identity(&mut self, record: &IdentityRecord) -> Result<(), DbError> {
            self.inner.lock().await.create_identity(record).await
        }

        async fn get_identity(&self, id: Uuid) -> Result<IdentityRecord, DbError> {
            self.inner.lock().await.get_identity(id).await
        }

        async fn save_credential(&mut self, record: &CredentialRecord) -> Result<(), DbError> {
            self.inner.lock().await.save_credential(record).await
        }

        async fn save_wrapped_root(&mut self, record: &WrappedRootRecord) -> Result<(), DbError> {
            self.inner.lock().await.save_wrapped_root(record).await
        }

        async fn find_wrapped_root(
            &self,
            identity_id: Uuid,
            wrap_kind: WrapKind,
        ) -> Result<WrappedRootRecord, DbError> {
            self.inner
                .lock()
                .await
                .find_wrapped_root(identity_id, wrap_kind)
                .await
        }

        async fn record_audit_event(&mut self, record: &AuditRecord) -> Result<(), DbError> {
            self.inner.lock().await.record_audit_event(record).await
        }
    }

    #[async_trait::async_trait]
    impl AuditLog for SharedInMemoryStore {
        async fn record_grant(&mut self, record: &GrantRecord) -> Result<AuditId, AuditWriteError> {
            self.inner.lock().await.record_grant(record).await
        }
    }

    /// Cheap Argon2id params — full OWASP defaults (19 MiB / 2 iters)
    /// make unit tests noticeably slower for no additional coverage.
    fn fast_params() -> PassphraseParams {
        PassphraseParams::new(8, 1, 1).expect("fast argon2 params")
    }

    fn make_issuer_verifier_pair() -> (
        Arc<TokenIssuer<SystemClock>>,
        Arc<TokenVerifier<SystemClock>>,
    ) {
        let keys = Arc::new(SigningKeys::generate_ephemeral().expect("ephemeral keys"));
        let verifying = keys.verifying_keys();
        let issuer = Arc::new(TokenIssuer::new(
            Arc::clone(&keys),
            SystemClock,
            TEST_ISS,
            DEFAULT_ACCESS_TTL,
        ));
        let verifier = Arc::new(TokenVerifier::new(verifying, SystemClock, TEST_ISS));
        (issuer, verifier)
    }

    fn test_state() -> AppState<SharedInMemoryStore, InMemorySessionStore> {
        let (issuer, verifier) = make_issuer_verifier_pair();
        AppState::new(
            SharedInMemoryStore::new(),
            InMemorySessionStore::new(),
            issuer,
            verifier,
        )
        .with_passphrase_params(fast_params())
        // Tests run over plain HTTP — clear the Secure attribute so
        // the cookie value remains usable after round-trip.
        .with_cookie_config(CookieConfig::insecure_dev())
    }

    fn get_request(uri: &str, bearer: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().method(Method::GET).uri(uri);
        if let Some(tok) = bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {tok}"));
        }
        req.body(Body::empty()).expect("build get request")
    }

    fn get_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("build cookie request")
    }

    fn post_with_cookie(uri: &str, cookie: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .expect("build cookie post request")
    }

    /// Run an `enroll → login` pair and return
    /// `(identity_id, access_token, refresh_token, raw_session_cookie)`.
    /// `raw_session_cookie` is the string that should be sent back in
    /// a subsequent `Cookie` header (i.e. `konekto_session=<value>`),
    /// already trimmed of the `Set-Cookie` attributes.
    async fn enroll_then_login(app: &axum::Router, ctx: &str) -> (String, String, String, String) {
        let passphrase = format!("passphrase-for-{ctx}");
        let enroll_resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": passphrase }),
            ))
            .await
            .expect("enroll");
        let identity_id = body_json(enroll_resp).await["identity_id"]
            .as_str()
            .expect("identity_id")
            .to_string();

        let login_resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": identity_id,
                    "passphrase": passphrase,
                    "context": ctx,
                }),
            ))
            .await
            .expect("login");
        assert_eq!(login_resp.status(), StatusCode::OK);
        let cookie = extract_cookie_pair(login_resp.headers().get(header::SET_COOKIE));
        let body = body_json(login_resp).await;
        let token = body["access_token"]
            .as_str()
            .expect("access_token present")
            .to_string();
        let refresh_token = body["refresh_token"]
            .as_str()
            .expect("refresh_token present")
            .to_string();
        (identity_id, token, refresh_token, cookie)
    }

    /// Pull the `name=value` pair out of a `Set-Cookie` header,
    /// stripping the attributes after the first `;`.
    fn extract_cookie_pair(header: Option<&HeaderValue>) -> String {
        let raw = header
            .expect("Set-Cookie present")
            .to_str()
            .expect("ascii cookie");
        let pair = raw.split(';').next().expect("name=value pair");
        pair.trim().to_string()
    }

    fn json_request(method: Method, uri: &str, body: &Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).expect("serialize")))
            .expect("build request")
    }

    async fn body_bytes(resp: axum::response::Response) -> Bytes {
        resp.into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes()
    }

    async fn body_json(resp: axum::response::Response) -> Value {
        let bytes = body_bytes(resp).await;
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn enroll_then_login_vivo_returns_200() {
        let app = build_router(test_state());

        let enroll_resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "correct-horse-battery" }),
            ))
            .await
            .expect("enroll call");
        assert_eq!(enroll_resp.status(), StatusCode::OK);

        let enroll_body = body_json(enroll_resp).await;
        let identity_id = enroll_body
            .get("identity_id")
            .and_then(Value::as_str)
            .expect("identity_id present");
        let _ = Uuid::parse_str(identity_id).expect("identity_id is a uuid");

        let login_resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": identity_id,
                    "passphrase": "correct-horse-battery",
                    "context": "vivo",
                }),
            ))
            .await
            .expect("login call");
        assert_eq!(login_resp.status(), StatusCode::OK);

        let login_body = body_json(login_resp).await;
        assert_eq!(login_body["identity_id"], json!(identity_id));
        assert_eq!(login_body["context"], json!("vivo"));
    }

    #[tokio::test]
    async fn login_each_context_succeeds_independently() {
        let app = build_router(test_state());

        let enroll_resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "multi-context-passphrase" }),
            ))
            .await
            .expect("enroll call");
        let enroll_body = body_json(enroll_resp).await;
        let identity_id = enroll_body["identity_id"].as_str().unwrap().to_string();

        for ctx in ["vivo", "laboro", "socio"] {
            let resp = app
                .clone()
                .oneshot(json_request(
                    Method::POST,
                    "/dev/login",
                    &json!({
                        "identity_id": identity_id,
                        "passphrase": "multi-context-passphrase",
                        "context": ctx,
                    }),
                ))
                .await
                .expect("login call");
            assert_eq!(resp.status(), StatusCode::OK, "login failed for {ctx}");
            let body = body_json(resp).await;
            assert_eq!(body["context"], json!(ctx));
        }
    }

    #[tokio::test]
    async fn login_with_wrong_passphrase_returns_401_unauthorized() {
        let app = build_router(test_state());

        let enroll_resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "real-passphrase-value" }),
            ))
            .await
            .expect("enroll");
        let identity_id = body_json(enroll_resp).await["identity_id"]
            .as_str()
            .unwrap()
            .to_string();

        let resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": identity_id,
                    "passphrase": "wrong-passphrase-value",
                    "context": "vivo",
                }),
            ))
            .await
            .expect("login");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await, json!({ "error": "unauthorized" }));
    }

    #[tokio::test]
    async fn login_with_unknown_identity_also_returns_401_unauthorized() {
        // An enumeration oracle would let a caller distinguish
        // "no such identity" from "wrong passphrase". Both must
        // produce the same response.
        let app = build_router(test_state());

        let resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": Uuid::new_v4().to_string(),
                    "passphrase": "any-passphrase-here",
                    "context": "vivo",
                }),
            ))
            .await
            .expect("login");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await, json!({ "error": "unauthorized" }));
    }

    #[tokio::test]
    async fn enroll_with_short_passphrase_returns_400_invalid_request() {
        let app = build_router(test_state());

        let resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "short" }),
            ))
            .await
            .expect("enroll");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(resp).await, json!({ "error": "invalid_request" }));
    }

    #[tokio::test]
    async fn login_response_contains_parseable_jws_with_two_signatures() {
        let app = build_router(test_state());
        let (_id, token, _r, _c) = enroll_then_login(&app, "vivo").await;
        let wire: Value = serde_json::from_str(&token).expect("token is JSON");
        let sigs = wire["signatures"].as_array().expect("signatures array");
        assert_eq!(sigs.len(), 2, "token must carry two signatures");
        assert!(wire["payload"].as_str().is_some(), "payload is a string");
    }

    #[tokio::test]
    async fn dev_login_response_still_carries_identity_id_and_context_fields() {
        // Backward-compat with the pre-token response shape.
        let app = build_router(test_state());
        let enroll = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "compat-passphrase" }),
            ))
            .await
            .expect("enroll");
        let identity_id = body_json(enroll).await["identity_id"]
            .as_str()
            .unwrap()
            .to_string();

        let login = app
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": identity_id,
                    "passphrase": "compat-passphrase",
                    "context": "laboro",
                }),
            ))
            .await
            .expect("login");
        let body = body_json(login).await;
        assert_eq!(body["identity_id"], json!(identity_id));
        assert_eq!(body["context"], json!("laboro"));
        assert_eq!(body["token_type"], json!("Bearer"));
        assert!(body["expires_in"].is_number(), "expires_in is a number");
        assert!(
            body["refresh_token"].as_str().is_some(),
            "refresh_token is a string",
        );
    }

    #[tokio::test]
    async fn whoami_vivo_with_vivo_token_returns_200_echoing_identity_id() {
        let app = build_router(test_state());
        let (identity_id, token, _r, _c) = enroll_then_login(&app, "vivo").await;
        let resp = app
            .oneshot(get_request("/vivo/whoami", Some(&token)))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["identity_id"], json!(identity_id));
        assert_eq!(body["context"], json!("vivo"));
    }

    #[tokio::test]
    async fn whoami_vivo_with_laboro_token_returns_401_unauthorized() {
        let app = build_router(test_state());
        let (_id, laboro_token, _r, _c) = enroll_then_login(&app, "laboro").await;
        let resp = app
            .oneshot(get_request("/vivo/whoami", Some(&laboro_token)))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_json(resp).await, json!({ "error": "unauthorized" }));
    }

    #[tokio::test]
    async fn whoami_laboro_with_socio_token_returns_401() {
        let app = build_router(test_state());
        let (_id, socio_token, _r, _c) = enroll_then_login(&app, "socio").await;
        let resp = app
            .oneshot(get_request("/laboro/whoami", Some(&socio_token)))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn whoami_without_authorization_header_returns_401() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(get_request("/vivo/whoami", None))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn whoami_with_malformed_bearer_returns_401() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(get_request("/vivo/whoami", Some("not a jws")))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn whoami_with_tampered_mldsa_signature_returns_401() {
        let app = build_router(test_state());
        let (_id, token, _r, _c) = enroll_then_login(&app, "vivo").await;
        let mut wire: Value = serde_json::from_str(&token).expect("json");
        // Flip the last byte of the ML-DSA signature block.
        let sig = wire["signatures"][1]["signature"]
            .as_str()
            .expect("sig str")
            .to_string();
        let mut sig_bytes = sig.into_bytes();
        let last = sig_bytes.last_mut().expect("sig not empty");
        *last = if *last == b'A' { b'B' } else { b'A' };
        wire["signatures"][1]["signature"] =
            Value::String(String::from_utf8(sig_bytes).expect("utf8"));
        let tampered = serde_json::to_string(&wire).expect("ser");
        let resp = app
            .oneshot(get_request("/vivo/whoami", Some(&tampered)))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn whoami_with_expired_token_returns_401() {
        // Wire two AppStates that share signing keys + session store.
        // The first mints at T0; the second verifies at T0 + 10 min.
        const T0: i64 = 1_800_000_000;
        let keys = Arc::new(SigningKeys::generate_ephemeral().expect("ephemeral keys"));
        let store = SharedInMemoryStore::new();
        let sessions = InMemorySessionStore::new();

        let early_issuer = Arc::new(TokenIssuer::new(
            Arc::clone(&keys),
            FixedClock::new(T0),
            TEST_ISS,
            DEFAULT_ACCESS_TTL,
        ));
        let early_verifier = Arc::new(TokenVerifier::new(
            keys.verifying_keys(),
            FixedClock::new(T0),
            TEST_ISS,
        ));
        let early_state: AppState<SharedInMemoryStore, InMemorySessionStore, FixedClock> =
            AppState::new(
                store.clone(),
                sessions.clone(),
                early_issuer,
                early_verifier,
            )
            .with_passphrase_params(fast_params())
            .with_cookie_config(CookieConfig::insecure_dev());
        let early_app = build_router(early_state);
        let (_id, token, _r, _c) = enroll_then_login(&early_app, "vivo").await;

        let late_issuer = Arc::new(TokenIssuer::new(
            Arc::clone(&keys),
            FixedClock::new(T0 + 600),
            TEST_ISS,
            DEFAULT_ACCESS_TTL,
        ));
        let late_verifier = Arc::new(TokenVerifier::new(
            keys.verifying_keys(),
            FixedClock::new(T0 + 600),
            TEST_ISS,
        ));
        let late_state: AppState<SharedInMemoryStore, InMemorySessionStore, FixedClock> =
            AppState::new(store, sessions, late_issuer, late_verifier)
                .with_passphrase_params(fast_params())
                .with_cookie_config(CookieConfig::insecure_dev());
        let late_app = build_router(late_state);

        let resp = late_app
            .oneshot(get_request("/vivo/whoami", Some(&token)))
            .await
            .expect("whoami");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ---- Phase B: refresh / cookie / me / logout ----

    #[tokio::test]
    async fn login_sets_session_cookie_with_required_attributes() {
        let app = build_router(test_state());
        let enroll = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "session-cookie-passphrase" }),
            ))
            .await
            .expect("enroll");
        let identity_id = body_json(enroll).await["identity_id"]
            .as_str()
            .unwrap()
            .to_string();

        let login = app
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": identity_id,
                    "passphrase": "session-cookie-passphrase",
                    "context": "vivo",
                }),
            ))
            .await
            .expect("login");
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .expect("Set-Cookie present")
            .to_str()
            .expect("ascii")
            .to_string();
        assert!(cookie.starts_with("konekto_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=43200"));
    }

    #[tokio::test]
    async fn login_sets_secure_attribute_when_configured() {
        let (issuer, verifier) = make_issuer_verifier_pair();
        let state = AppState::new(
            SharedInMemoryStore::new(),
            InMemorySessionStore::new(),
            issuer,
            verifier,
        )
        .with_passphrase_params(fast_params())
        .with_cookie_config(CookieConfig::production());
        let app = build_router(state);

        let enroll = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/enroll",
                &json!({ "passphrase": "secure-cookie-passphrase" }),
            ))
            .await
            .expect("enroll");
        let identity_id = body_json(enroll).await["identity_id"]
            .as_str()
            .unwrap()
            .to_string();

        let login = app
            .oneshot(json_request(
                Method::POST,
                "/dev/login",
                &json!({
                    "identity_id": identity_id,
                    "passphrase": "secure-cookie-passphrase",
                    "context": "vivo",
                }),
            ))
            .await
            .expect("login");
        let cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .expect("Set-Cookie present")
            .to_str()
            .expect("ascii")
            .to_string();
        assert!(cookie.contains("Secure"));
    }

    #[tokio::test]
    async fn me_with_valid_session_cookie_returns_identity() {
        let app = build_router(test_state());
        let (identity_id, _t, _r, cookie) = enroll_then_login(&app, "vivo").await;

        let resp = app
            .oneshot(get_with_cookie("/dev/me", &cookie))
            .await
            .expect("me");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["identity_id"], json!(identity_id));
        assert_eq!(body["context"], json!("vivo"));
        assert!(body["idle_expires_at"].is_number());
        assert!(body["absolute_expires_at"].is_number());
    }

    #[tokio::test]
    async fn me_without_cookie_returns_401() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/dev/me")
                    .body(Body::empty())
                    .expect("build"),
            )
            .await
            .expect("me");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn me_with_unknown_cookie_returns_401() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(get_with_cookie(
                "/dev/me",
                "konekto_session=this-session-was-never-issued",
            ))
            .await
            .expect("me");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_rotates_and_returns_new_pair() {
        let app = build_router(test_state());
        let (_id, _t, refresh_token, _c) = enroll_then_login(&app, "vivo").await;

        let resp = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": refresh_token }),
            ))
            .await
            .expect("refresh");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let new_refresh = body["refresh_token"]
            .as_str()
            .expect("new refresh")
            .to_string();
        assert_ne!(
            new_refresh, refresh_token,
            "rotation must mint a fresh secret",
        );
        assert!(body["access_token"].as_str().is_some());
        assert_eq!(body["token_type"], json!("Bearer"));

        // The new access token verifies — round-trip via /vivo/whoami.
        let access = body["access_token"].as_str().expect("access").to_string();
        let whoami = app
            .oneshot(get_request("/vivo/whoami", Some(&access)))
            .await
            .expect("whoami");
        assert_eq!(whoami.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn refresh_replay_triggers_theft_and_revokes_family() {
        let app = build_router(test_state());
        let (_id, _t, refresh_token, _c) = enroll_then_login(&app, "vivo").await;

        // First rotation succeeds.
        let first = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": refresh_token }),
            ))
            .await
            .expect("refresh 1");
        assert_eq!(first.status(), StatusCode::OK);
        let new_refresh = body_json(first).await["refresh_token"]
            .as_str()
            .unwrap()
            .to_string();

        // Replay the original token: theft detected.
        let replay = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": refresh_token }),
            ))
            .await
            .expect("refresh replay");
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

        // The descendant is now revoked too.
        let after = app
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": new_refresh }),
            ))
            .await
            .expect("refresh after theft");
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_with_unknown_token_returns_401() {
        let app = build_router(test_state());
        // Synthesize a wire-shaped value that won't match anything.
        let resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
            ))
            .await
            .expect("refresh");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_with_empty_token_returns_401() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": "" }),
            ))
            .await
            .expect("refresh");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_invalidates_session_and_cascades_to_refresh_family() {
        let app = build_router(test_state());
        let (_id, _t, refresh_token, cookie) = enroll_then_login(&app, "vivo").await;

        // Logout — 204, clears cookie.
        let resp = app
            .clone()
            .oneshot(post_with_cookie("/dev/logout", &cookie))
            .await
            .expect("logout");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let clear = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("Set-Cookie present")
            .to_str()
            .expect("ascii");
        assert!(clear.contains("Max-Age=0"));

        // Same cookie now rejected.
        let me = app
            .clone()
            .oneshot(get_with_cookie("/dev/me", &cookie))
            .await
            .expect("me");
        assert_eq!(me.status(), StatusCode::UNAUTHORIZED);

        // Refresh family is revoked.
        let refresh_resp = app
            .oneshot(json_request(
                Method::POST,
                "/dev/refresh",
                &json!({ "refresh_token": refresh_token }),
            ))
            .await
            .expect("refresh after logout");
        assert_eq!(refresh_resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_is_idempotent_and_does_not_leak_session_existence() {
        let app = build_router(test_state());

        // No cookie at all — still 204.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/dev/logout")
                    .body(Body::empty())
                    .expect("build"),
            )
            .await
            .expect("logout");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Forged cookie value — also 204.
        let resp = app
            .oneshot(post_with_cookie(
                "/dev/logout",
                "konekto_session=never-was-a-session",
            ))
            .await
            .expect("logout forged");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
