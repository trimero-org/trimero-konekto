//! HTTP handlers for the dev-mode identity flow.
//!
//! Endpoints:
//!
//! - `POST /dev/enroll`   — provision a new identity from a passphrase.
//! - `POST /dev/login`    — authenticate, derive a `ContextKey<C>`,
//!   issue a hybrid JWS access token, mint a single-use refresh token,
//!   and bind a first-party session cookie.
//! - `POST /dev/refresh`  — rotate a refresh token, mint a new access
//!   token. Single-use, with theft detection.
//! - `GET  /dev/me`       — echo the first-party session.
//! - `POST /dev/logout`   — drop the first-party session and revoke
//!   any linked refresh family.
//! - `GET  /vivo/whoami`  — return the authenticated Vivo identity.
//! - `GET  /laboro/whoami`— return the authenticated Laboro identity.
//! - `GET  /socio/whoami` — return the authenticated Socio identity.
//!
//! The handlers are thin adapters: they parse the JSON body, clone the
//! store out of [`AppState`] (cheap — see `state`), delegate to
//! [`konekto_db::identity`] for the crypto and persistence, and mint
//! the access token via the shared [`konekto_core::token::TokenIssuer`].
//!
//! The `/dev/login` response deliberately does NOT carry the derived
//! context key. Context keys are non-serializable by design
//! (ADR-0002, ADR-0003); the access token and refresh token are the
//! only artefacts that cross the wire, both scoped to one context.

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use konekto_core::token::{
    Clock, ContextLabel, RefreshTokenSecret, SessionId, REFRESH_ABSOLUTE_TTL_SECS,
    REFRESH_IDLE_TTL_SECS, SESSION_ABSOLUTE_TTL_SECS, SESSION_IDLE_TTL_SECS,
};
use konekto_core::{Context, Laboro, Socio, Vivo};
use konekto_db::identity::{enroll_dev_password, login_dev_password};
use konekto_db::session::{
    RefreshOutcome, RefreshStatus, RefreshTokenRecord, SessionRecord, SessionStore,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AuthedContext, AuthedSession, SESSION_COOKIE_NAME};
use crate::error::ApiError;
use crate::state::{ApiStore, AppState, CookieConfig};

/// Context selector accepted on `/dev/login`.
///
/// The HTTP surface sees contexts as runtime strings. Each handler
/// branch dispatches to `login_dev_password::<C, _>` with the
/// appropriate compile-time type so the ADR-0002 context-isolation
/// guarantees apply end-to-end.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextSelector {
    /// Personal / civic context.
    Vivo,
    /// Professional / work context.
    Laboro,
    /// Social / community context.
    Socio,
}

impl ContextSelector {
    fn as_str(self) -> &'static str {
        match self {
            Self::Vivo => "vivo",
            Self::Laboro => "laboro",
            Self::Socio => "socio",
        }
    }

    fn as_label(self) -> ContextLabel {
        match self {
            Self::Vivo => Vivo::CONTEXT_LABEL,
            Self::Laboro => Laboro::CONTEXT_LABEL,
            Self::Socio => Socio::CONTEXT_LABEL,
        }
    }
}

fn context_label_str(label: ContextLabel) -> &'static str {
    match label {
        ContextLabel::Vivo => "vivo",
        ContextLabel::Laboro => "laboro",
        ContextLabel::Socio => "socio",
    }
}

/// Request body for `POST /dev/enroll`.
#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// Caller-supplied passphrase. Length is enforced downstream by
    /// `PassphraseParams::derive_wrapping_key`; a too-short value
    /// surfaces as [`ApiError::InvalidRequest`].
    pub passphrase: String,
}

/// Response body for `POST /dev/enroll`.
#[derive(Debug, Serialize)]
pub struct EnrollResponse {
    /// UUID of the newly-provisioned identity.
    pub identity_id: Uuid,
}

/// Request body for `POST /dev/login`.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Identity to authenticate.
    pub identity_id: Uuid,
    /// Passphrase provided by the caller.
    pub passphrase: String,
    /// Which context's key to derive.
    pub context: ContextSelector,
}

/// Response body for `POST /dev/login`.
///
/// `identity_id` and `context` are preserved from the pre-token
/// response shape so existing consumers keep working; `access_token`,
/// `token_type`, `expires_in`, and `refresh_token` conform to the
/// OAuth 2 token response convention (RFC 6749 §5.1).
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Echo of the authenticated identity.
    pub identity_id: Uuid,
    /// Echo of the derived context.
    pub context: &'static str,
    /// Hybrid JWS access token (JWS JSON General Serialization).
    pub access_token: String,
    /// Always `"Bearer"` per RFC 6750.
    pub token_type: &'static str,
    /// Access-token lifetime, in seconds.
    pub expires_in: i64,
    /// Single-use refresh token (opaque, base64url).
    pub refresh_token: String,
}

/// Request body for `POST /dev/refresh`.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// Refresh token previously emitted by `/dev/login` or a prior
    /// `/dev/refresh`. Single-use: rotation invalidates this exact
    /// value, and presenting it again triggers theft detection.
    pub refresh_token: String,
}

/// Response body for `POST /dev/refresh`. Same shape as
/// [`LoginResponse`] minus the `identity_id`/`context` echoes —
/// callers already know both because they hold the prior session.
#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    /// Newly minted access token, scoped to the same context as the
    /// rotated family.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: &'static str,
    /// Access-token lifetime, in seconds.
    pub expires_in: i64,
    /// New refresh token. The presented one is now invalid.
    pub refresh_token: String,
}

/// Response body for `GET /{ctx}/whoami`.
#[derive(Debug, Serialize)]
pub struct WhoamiResponse {
    /// Authenticated identity subject (= `sub` claim).
    pub identity_id: String,
    /// Echo of the matched context.
    pub context: &'static str,
    /// Unix seconds at which the access token expires.
    pub expires_at: i64,
}

/// Response body for `GET /dev/me`.
#[derive(Debug, Serialize)]
pub struct MeResponse {
    /// Identity bound to the first-party session.
    pub identity_id: Uuid,
    /// Context the session is scoped to.
    pub context: &'static str,
    /// Sliding idle expiry (Unix seconds), after the touch performed
    /// by this very request.
    pub idle_expires_at: i64,
    /// Hard absolute expiry (Unix seconds).
    pub absolute_expires_at: i64,
}

/// Handler for `POST /dev/enroll`.
pub async fn enroll<S: ApiStore, Sess: SessionStore, K: Clock>(
    State(state): State<AppState<S, Sess, K>>,
    Json(body): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let mut store = state.store.clone();
    let outcome = enroll_dev_password(
        body.passphrase.as_bytes(),
        state.passphrase_params,
        &mut store,
    )
    .await?;
    Ok(Json(EnrollResponse {
        identity_id: outcome.identity_id,
    }))
}

/// Handler for `POST /dev/login`.
pub async fn login<S: ApiStore, Sess: SessionStore, K: Clock>(
    State(state): State<AppState<S, Sess, K>>,
    Json(body): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let mut store = state.store.clone();
    let passphrase = body.passphrase.as_bytes();

    // Runtime selector → compile-time `ContextKey<C>` dispatch. The
    // key is derived inside each arm and dropped (zeroized) before
    // the arm returns; only the success signal reaches the client.
    match body.context {
        ContextSelector::Vivo => {
            let _k =
                login_dev_password::<Vivo, _>(body.identity_id, passphrase, &mut store).await?;
        }
        ContextSelector::Laboro => {
            let _k =
                login_dev_password::<Laboro, _>(body.identity_id, passphrase, &mut store).await?;
        }
        ContextSelector::Socio => {
            let _k =
                login_dev_password::<Socio, _>(body.identity_id, passphrase, &mut store).await?;
        }
    }

    let sub = body.identity_id.to_string();
    let ctx_label = body.context.as_label();
    let token = state
        .issuer
        .issue(&sub, ctx_label, vec!["pwd".to_string()])?;

    let now = state.verifier.clock().now_unix_secs();

    // Mint refresh token + register record. Family ID == first
    // member's family (ADR-0003 §2). The hash is what the store sees;
    // the raw secret only ever flows back to the client in this
    // response.
    let refresh = RefreshTokenSecret::generate();
    let family_id = Uuid::new_v4();
    let refresh_absolute = now.saturating_add(REFRESH_ABSOLUTE_TTL_SECS);
    let refresh_idle = now
        .saturating_add(REFRESH_IDLE_TTL_SECS)
        .min(refresh_absolute);
    state
        .sessions
        .create_refresh(
            refresh.hash(),
            RefreshTokenRecord {
                family_id,
                identity_id: body.identity_id,
                ctx: ctx_label,
                status: RefreshStatus::Active,
                created_at: now,
                idle_expires_at: refresh_idle,
                absolute_expires_at: refresh_absolute,
            },
        )
        .await?;

    // Mint first-party session cookie. The session is linked to the
    // refresh family so logout cascades both surfaces atomically.
    let session_id = SessionId::generate();
    let session_absolute = now.saturating_add(SESSION_ABSOLUTE_TTL_SECS);
    let session_idle = now
        .saturating_add(SESSION_IDLE_TTL_SECS)
        .min(session_absolute);
    state
        .sessions
        .create_session(
            session_id.hash(),
            SessionRecord {
                identity_id: body.identity_id,
                ctx: ctx_label,
                created_at: now,
                last_seen_at: now,
                idle_expires_at: session_idle,
                absolute_expires_at: session_absolute,
                amr: vec!["pwd".to_string()],
                linked_refresh_family: Some(family_id),
            },
        )
        .await?;

    let body = Json(LoginResponse {
        identity_id: body.identity_id,
        context: body.context.as_str(),
        access_token: token.into_inner(),
        token_type: "Bearer",
        expires_in: i64::try_from(konekto_core::token::DEFAULT_ACCESS_TTL.as_secs())
            .unwrap_or(i64::MAX),
        refresh_token: refresh.into_inner(),
    });

    let cookie = build_session_cookie(
        session_id.as_str(),
        SESSION_ABSOLUTE_TTL_SECS,
        state.cookie_config,
    );
    let mut response = body.into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

/// Handler for `POST /dev/refresh`.
pub async fn refresh<S: ApiStore, Sess: SessionStore, K: Clock>(
    State(state): State<AppState<S, Sess, K>>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, ApiError> {
    let presented =
        RefreshTokenSecret::from_wire(body.refresh_token).ok_or(ApiError::Unauthorized)?;
    let new_secret = RefreshTokenSecret::generate();
    let now = state.verifier.clock().now_unix_secs();
    let new_idle = now.saturating_add(REFRESH_IDLE_TTL_SECS);

    let outcome = state
        .sessions
        .rotate_refresh(presented.hash(), new_secret.hash(), new_idle, now)
        .await?;

    let rotation = match outcome {
        RefreshOutcome::Rotated(r) => r,
        RefreshOutcome::Theft => {
            tracing::warn!("refresh token theft detected — family revoked");
            return Err(ApiError::Unauthorized);
        }
        RefreshOutcome::Expired => {
            tracing::warn!("refresh token expired");
            return Err(ApiError::Unauthorized);
        }
        RefreshOutcome::Revoked => {
            tracing::warn!("refresh token revoked");
            return Err(ApiError::Unauthorized);
        }
        RefreshOutcome::Unknown => {
            tracing::warn!("refresh token unknown");
            return Err(ApiError::Unauthorized);
        }
    };

    let sub = rotation.identity_id.to_string();
    let token = state
        .issuer
        .issue(&sub, rotation.ctx, vec!["pwd".to_string()])?;

    Ok(Json(RefreshResponse {
        access_token: token.into_inner(),
        token_type: "Bearer",
        expires_in: i64::try_from(konekto_core::token::DEFAULT_ACCESS_TTL.as_secs())
            .unwrap_or(i64::MAX),
        refresh_token: new_secret.into_inner(),
    }))
}

/// Handler for `GET /dev/me`. Reads the first-party session — this
/// extractor side-effects the sliding idle window forward via
/// `touch_session` before reaching the handler body.
pub async fn me(session: AuthedSession) -> Json<MeResponse> {
    Json(MeResponse {
        identity_id: session.identity_id,
        context: context_label_str(session.ctx),
        idle_expires_at: session.idle_expires_at,
        absolute_expires_at: session.absolute_expires_at,
    })
}

/// Handler for `POST /dev/logout`. Idempotent on the wire: even an
/// unknown or already-expired session yields 204, so a logout
/// confirmation is never an oracle for "this cookie was real".
pub async fn logout<S: ApiStore, Sess: SessionStore, K: Clock>(
    State(state): State<AppState<S, Sess, K>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(raw) = crate::auth::extract_session_cookie(&headers) {
        if let Some(session_id) = SessionId::from_wire(raw) {
            state.sessions.logout(session_id.hash()).await?;
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    let clear = clear_session_cookie(state.cookie_config);
    response.headers_mut().insert(header::SET_COOKIE, clear);
    Ok(response)
}

fn whoami_response<C: Context>(ctx: AuthedContext<C>, context_str: &'static str) -> WhoamiResponse {
    WhoamiResponse {
        identity_id: ctx.claims.sub,
        context: context_str,
        expires_at: ctx.claims.exp,
    }
}

/// Handler for `GET /vivo/whoami`.
pub async fn whoami_vivo(ctx: AuthedContext<Vivo>) -> Json<WhoamiResponse> {
    Json(whoami_response(ctx, "vivo"))
}

/// Handler for `GET /laboro/whoami`.
pub async fn whoami_laboro(ctx: AuthedContext<Laboro>) -> Json<WhoamiResponse> {
    Json(whoami_response(ctx, "laboro"))
}

/// Handler for `GET /socio/whoami`.
pub async fn whoami_socio(ctx: AuthedContext<Socio>) -> Json<WhoamiResponse> {
    Json(whoami_response(ctx, "socio"))
}

/// Compose the `Set-Cookie` header value for the first-party session.
/// Attributes per ADR-0003 §1: `HttpOnly; SameSite=Strict; Path=/`,
/// `Max-Age` = absolute TTL, `Secure` per `CookieConfig`.
fn build_session_cookie(value: &str, max_age_secs: i64, cfg: CookieConfig) -> HeaderValue {
    let secure = if cfg.secure { "; Secure" } else { "" };
    let s = format!(
        "{SESSION_COOKIE_NAME}={value}; HttpOnly; SameSite=Strict; Path=/; \
         Max-Age={max_age_secs}{secure}",
    );
    HeaderValue::from_str(&s).expect("session cookie ascii")
}

/// Compose a `Set-Cookie` header value that clears the first-party
/// session cookie (empty value, `Max-Age=0`).
fn clear_session_cookie(cfg: CookieConfig) -> HeaderValue {
    let secure = if cfg.secure { "; Secure" } else { "" };
    let s = format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}");
    HeaderValue::from_str(&s).expect("clear cookie ascii")
}
