//! HTTP handlers for the dev-mode identity flow.
//!
//! Endpoints:
//!
//! - `POST /dev/enroll`   — provision a new identity from a passphrase.
//! - `POST /dev/login`    — authenticate, derive a `ContextKey<C>`, and
//!   return a hybrid JWS access token bound to that context.
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
//! (ADR-0002, ADR-0003); the access token is the only artefact that
//! crosses the wire, and it is scoped to one context.

use axum::extract::State;
use axum::Json;
use konekto_core::token::{Clock, ContextLabel};
use konekto_core::{Context, Laboro, Socio, Vivo};
use konekto_db::identity::{enroll_dev_password, login_dev_password};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthedContext;
use crate::error::ApiError;
use crate::state::{ApiStore, AppState};

/// Context selector accepted on `/dev/login`.
///
/// The HTTP surface sees contexts as runtime strings. Each handler
/// branch dispatches to `login_dev_password::<C, _>` with the
/// appropriate compile-time type so the ADR-0002 context-isolation
/// guarantees apply end-to-end.
#[derive(Debug, Clone, Copy, Deserialize)]
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
/// `token_type`, and `expires_in` are additive and conform to the
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

/// Handler for `POST /dev/enroll`.
pub async fn enroll<S: ApiStore, K: Clock>(
    State(state): State<AppState<S, K>>,
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
pub async fn login<S: ApiStore, K: Clock>(
    State(state): State<AppState<S, K>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
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
    let token = state
        .issuer
        .issue(&sub, body.context.as_label(), vec!["pwd".to_string()])?;

    Ok(Json(LoginResponse {
        identity_id: body.identity_id,
        context: body.context.as_str(),
        access_token: token.into_inner(),
        token_type: "Bearer",
        expires_in: i64::try_from(konekto_core::token::DEFAULT_ACCESS_TTL.as_secs())
            .unwrap_or(i64::MAX),
    }))
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
