//! Trimero Konekto — HTTP API.
//!
//! This crate exposes the dev-mode identity flow over HTTP:
//!
//! - `POST /dev/enroll` — provision a new identity from a passphrase.
//! - `POST /dev/login`  — authenticate and derive a context key.
//!
//! The router is generic over any [`ApiStore`]. In production the
//! binary wires up [`konekto_db::pg::PgIdentityStore`]; the in-crate
//! tests wire up an in-memory adapter via `SharedInMemoryStore`.

pub mod error;
pub mod handlers;
pub mod state;

pub use error::ApiError;
pub use state::{ApiStore, AppState};

use axum::routing::post;
use axum::Router;

/// Build the top-level axum router wired against `state`.
///
/// Wire-level invariants:
/// - Bodies are JSON; malformed JSON yields axum's default 400.
/// - Semantic errors flow through [`ApiError`] and are serialized
///   as `{"error": "<code>"}` with a stable snake-case code set.
/// - No endpoint ever leaks a context key or wrapped-root blob.
pub fn build_router<S: ApiStore>(state: AppState<S>) -> Router {
    Router::new()
        .route("/dev/enroll", post(handlers::enroll::<S>))
        .route("/dev/login", post(handlers::login::<S>))
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
    //! The tests pin down:
    //! - the happy path (enroll → login → 200),
    //! - that a wrong passphrase and an unknown identity both return
    //!   401 with the same body — no identity-enumeration oracle,
    //! - that a too-short passphrase surfaces as 400 `invalid_request`,
    //! - that the three context selectors each succeed with 200.

    use super::{build_router, AppState};
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use konekto_core::{AuditId, AuditLog, AuditWriteError, GrantRecord, PassphraseParams};
    use konekto_db::identity::{IdentityStore, InMemoryStore};
    use konekto_db::records::{
        AuditRecord, CredentialRecord, IdentityRecord, WrapKind, WrappedRootRecord,
    };
    use konekto_db::DbError;
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tower::ServiceExt;
    use uuid::Uuid;

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

    fn test_state() -> AppState<SharedInMemoryStore> {
        AppState::new(SharedInMemoryStore::new()).with_passphrase_params(fast_params())
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
        // Must parse as a UUID — fail loudly if the shape drifts.
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
}
