//! Binary entry point for `konekto-api`.
//!
//! Boot sequence:
//!
//! 1. Initialise `tracing` with an env-configurable filter.
//! 2. Open a Postgres pool from `DATABASE_URL`.
//! 3. Run embedded SQL migrations idempotently.
//! 4. Load hybrid-JWS signing keys (env vars, or ephemeral + warning).
//! 5. Build the router on top of [`konekto_api::AppState`].
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
//! - `KONEKTO_ISSUER` — optional. String used as the `iss` claim.
//!   Default `konekto-dev`.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use konekto_api::{build_router, AppState};
use konekto_core::token::{
    SigningKeys, SystemClock, TokenIssuer, TokenVerifier, DEFAULT_ACCESS_TTL, ENV_ED25519_SK,
    ENV_MLDSA_SK,
};
use konekto_db::pg::PgIdentityStore;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()?;
    let issuer_claim = env::var("KONEKTO_ISSUER").unwrap_or_else(|_| "konekto-dev".to_string());

    tracing::info!(%bind_addr, "starting konekto-api");

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await?;

    let store = PgIdentityStore::new(pool);
    store.migrate().await?;
    tracing::info!("migrations applied");

    let signing_keys = Arc::new(load_signing_keys()?);
    let verifying_keys = signing_keys.verifying_keys();
    tracing::info!(kid = %signing_keys.kid().as_str(), "token signing keys loaded");

    let issuer = Arc::new(TokenIssuer::new(
        Arc::clone(&signing_keys),
        SystemClock,
        issuer_claim.clone(),
        DEFAULT_ACCESS_TTL,
    ));
    let verifier = Arc::new(TokenVerifier::new(
        verifying_keys,
        SystemClock,
        issuer_claim,
    ));

    let app = build_router(AppState::new(store, issuer, verifier));

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
