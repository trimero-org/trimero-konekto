//! Binary entry point for `konekto-api`.
//!
//! Boot sequence:
//!
//! 1. Initialise `tracing` with an env-configurable filter.
//! 2. Open a Postgres pool from `DATABASE_URL`.
//! 3. Run embedded SQL migrations idempotently.
//! 4. Build the router on top of [`konekto_api::AppState`].
//! 5. Bind `BIND_ADDR` (default `127.0.0.1:8080`) and serve with
//!    graceful shutdown on Ctrl-C / SIGTERM.
//!
//! # Environment
//!
//! - `DATABASE_URL` — required. Standard Postgres connection string.
//! - `BIND_ADDR`    — optional. `host:port` to bind. Default
//!   `127.0.0.1:8080`.
//! - `RUST_LOG`     — optional. `tracing-subscriber::EnvFilter`
//!   directives. Default `konekto_api=info,tower_http=info`.

use std::env;
use std::net::SocketAddr;

use konekto_api::{build_router, AppState};
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

    tracing::info!(%bind_addr, "starting konekto-api");

    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await?;

    let store = PgIdentityStore::new(pool);
    store.migrate().await?;
    tracing::info!("migrations applied");

    let app = build_router(AppState::new(store));

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
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
