//! Binary entry point for `konekto-api`.
//!
//! Boot sequence:
//!
//! 1. Initialise `tracing` with an env-configurable filter.
//! 2. Open a Postgres pool from `DATABASE_URL`.
//! 3. Run embedded SQL migrations idempotently.
//! 4. Load hybrid-JWS signing keys (env vars, or ephemeral + warning).
//! 5. Build the router on top of [`konekto_api::AppState`] with an
//!    in-memory session store (Redis impl deferred — ADR-0007).
//! 6. Bind `BIND_ADDR` (default `127.0.0.1:8080`) and serve with
//!    graceful shutdown on Ctrl-C / SIGTERM.
//!
//! # Environment
//!
//! - `DATABASE_URL` — required. Standard Postgres connection string.
//! - `BIND_ADDR`    — optional. `host:port` to bind. Default
//!   `127.0.0.1:8080`.
//! - `RUST_LOG`     — optional. `tracing-subscriber::EnvFilter`
//!   directives. Default `konekto_api=info,tower_http=info`.
//! - `TOKEN_SIGNING_ED25519_SK` / `TOKEN_SIGNING_MLDSA_SK` — optional
//!   base64url-encoded seeds. Supply both for deterministic keys
//!   across restarts (so existing tokens keep verifying); omit both
//!   and a fresh keypair is drawn at boot with a loud warning.
//!   Mixing one present and one missing is treated as "both missing".
//! - `TOKEN_RETIRED_VERIFIERS` — optional. Comma-separated list of
//!   `<ed25519_pk_b64>:<mldsa_pk_b64>` pairs (each base64url-encoded,
//!   no padding). Bundles in this list keep verifying access tokens
//!   minted by a previous primary signer, but never sign new tokens.
//!   See ADR-0009 §4 for the rotation playbook.
//! - `KONEKTO_ISSUER` — optional. String used as the `iss` claim.
//!   Default `konekto-dev`.
//! - `KONEKTO_COOKIE_SECURE` — optional. `"true"` (default) emits the
//!   `Secure` attribute on the session cookie; `"false"` clears it
//!   for HTTP localhost development. Any other value is rejected at
//!   boot.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use konekto_api::{build_router, AppState, CookieConfig};
use konekto_core::token::{
    Keyring, SigningKeys, SystemClock, TokenIssuer, TokenVerifier, VerifyingKeys,
    DEFAULT_ACCESS_TTL, ENV_ED25519_SK, ENV_MLDSA_SK, ENV_RETIRED_VERIFIERS,
};
use konekto_db::pg::PgIdentityStore;
use konekto_db::session::InMemorySessionStore;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

const ENV_COOKIE_SECURE: &str = "KONEKTO_COOKIE_SECURE";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
    let issuer_claim = env::var("KONEKTO_ISSUER").unwrap_or_else(|_| "konekto-dev".to_string());
    let cookie_config = load_cookie_config()?;

    tracing::info!(%bind_addr, "starting konekto-api");

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await?;

    let store = PgIdentityStore::new(pool);
    store.migrate().await?;
    tracing::info!("migrations applied");

    let signing_keys = Arc::new(load_signing_keys()?);
    let primary_verifier = signing_keys.verifying_keys();
    tracing::info!(kid = %signing_keys.kid().as_str(), "token signing keys loaded");

    let retired = load_retired_verifiers()?;
    let retired_count = retired.len();
    let keyring = Keyring::new(primary_verifier).with_retired(retired)?;
    if retired_count > 0 {
        tracing::info!(
            retired_count,
            "retired verifier bundles loaded (verify-only)"
        );
    }

    let issuer = Arc::new(TokenIssuer::new(
        Arc::clone(&signing_keys),
        SystemClock,
        issuer_claim.clone(),
        DEFAULT_ACCESS_TTL,
    ));
    let verifier = Arc::new(TokenVerifier::new(keyring, SystemClock, issuer_claim));

    let sessions = InMemorySessionStore::new();
    tracing::warn!(
        "session and refresh storage is process-local; tokens are \
         invalidated on restart (ADR-0007 follow-up: Redis backend)"
    );

    let app = build_router(
        AppState::new(store, sessions, issuer, verifier).with_cookie_config(cookie_config),
    );

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn load_cookie_config() -> Result<CookieConfig, Box<dyn std::error::Error>> {
    match env::var(ENV_COOKIE_SECURE).as_deref() {
        Ok("true") | Err(_) => Ok(CookieConfig::production()),
        Ok("false") => {
            tracing::warn!(
                "KONEKTO_COOKIE_SECURE=false — session cookie emitted without `Secure`; \
                 HTTP localhost development only"
            );
            Ok(CookieConfig::insecure_dev())
        }
        Ok(other) => {
            Err(format!("{ENV_COOKIE_SECURE} must be `true` or `false`, got {other:?}").into())
        }
    }
}

fn load_retired_verifiers() -> Result<Vec<VerifyingKeys>, Box<dyn std::error::Error>> {
    let Ok(raw) = env::var(ENV_RETIRED_VERIFIERS) else {
        return Ok(Vec::new());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut bundles = Vec::new();
    for (idx, entry) in trimmed.split(',').enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(
                format!("{ENV_RETIRED_VERIFIERS} entry {idx} is empty (stray comma?)").into(),
            );
        }
        let (ed_b64, ml_b64) = entry.split_once(':').ok_or_else(|| {
            format!("{ENV_RETIRED_VERIFIERS} entry {idx} must be `<ed25519_pk_b64>:<mldsa_pk_b64>`")
        })?;
        let ed_bytes = B64.decode(ed_b64.trim()).map_err(|e| {
            format!("{ENV_RETIRED_VERIFIERS} entry {idx} ed25519 not base64url: {e}")
        })?;
        let ml_bytes = B64.decode(ml_b64.trim()).map_err(|e| {
            format!("{ENV_RETIRED_VERIFIERS} entry {idx} ml-dsa not base64url: {e}")
        })?;
        bundles.push(VerifyingKeys::from_public_bytes(&ed_bytes, &ml_bytes)?);
    }
    Ok(bundles)
}

fn load_signing_keys() -> Result<SigningKeys, Box<dyn std::error::Error>> {
    let ed = env::var(ENV_ED25519_SK).ok();
    let ml = env::var(ENV_MLDSA_SK).ok();
    match (ed, ml) {
        (Some(ed), Some(ml)) => {
            tracing::info!("reusing signing keys from environment");
            Ok(SigningKeys::from_encoded(&ed, &ml)?)
        }
        (None, None) => {
            tracing::warn!(
                "no signing keys in environment — generating ephemeral keypair; \
                 tokens will be invalidated on restart"
            );
            Ok(SigningKeys::generate_ephemeral()?)
        }
        _ => Err("both TOKEN_SIGNING_ED25519_SK and TOKEN_SIGNING_MLDSA_SK \
                  must be set, or neither"
            .into()),
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("konekto_api=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received");
}
