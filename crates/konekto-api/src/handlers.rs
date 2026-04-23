//! HTTP handlers for the dev-mode identity flow.
//!
//! Two endpoints are exposed:
//!
//! - `POST /dev/enroll` — provision a new identity from a passphrase.
//! - `POST /dev/login`  — authenticate a known identity and derive a
//!   `ContextKey<C>` for the requested context.
//!
//! The handlers are thin adapters: they parse + validate the JSON
//! body, clone the store out of [`AppState`] (cheap — see `state`),
//! delegate to [`konekto_db::identity`] for the actual crypto and
//! persistence, and map errors through [`ApiError`] so nothing
//! leaks over the wire.
//!
//! The response for `/dev/login` deliberately does NOT carry the
//! derived context key. Context keys are non-serializable by design
//! (ADR-0002, ADR-0003) — a successful 200 is the proof that the
//! passphrase was correct and the key was derived, together with the
//! audit event the flow writes server-side. A future increment will
//! mint a session token bound to a context; this increment keeps the
//! dev-mode surface minimal.

use axum::extract::State;
use axum::Json;
use konekto_core::{Laboro, Socio, Vivo};
use konekto_db::identity::{enroll_dev_password, login_dev_password};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}

/// Request body for `POST /dev/enroll`.
#[derive(Debug, Deserialize)]
pub struct EnrollRequest {
    /// Caller-supplied passphrase. Length is enforced downstream by
    /// [`PassphraseParams::derive_wrapping_key`]; a too-short value
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
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Echo of the authenticated identity.
    pub identity_id: Uuid,
    /// Echo of the derived context.
    pub context: &'static str,
}

/// Handler for `POST /dev/enroll`.
pub async fn enroll<S: ApiStore>(
    State(state): State<AppState<S>>,
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
pub async fn login<S: ApiStore>(
    State(state): State<AppState<S>>,
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

    Ok(Json(LoginResponse {
        identity_id: body.identity_id,
        context: body.context.as_str(),
    }))
}
