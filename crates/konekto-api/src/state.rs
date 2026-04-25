//! Application state and the store-capability traits.
//!
//! [`AppState`] is parameterised over three independent backends:
//!
//! - `S: ApiStore` — the identity / audit surface (Postgres in prod,
//!   in-memory in tests).
//! - `Sess: SessionStore` — the first-party session and OAuth refresh
//!   surface (in-memory in V1; Redis tracked under ADR-0007).
//! - `K: Clock` — `SystemClock` in prod, `FixedClock` in expiration
//!   tests.
//!
//! The three are kept as distinct generics rather than bundled into
//! one trait because their canonical production backends diverge —
//! Postgres for identity, Redis for sessions — and bundling them
//! would force every test or future deployment to carry both.

use std::sync::Arc;

use konekto_core::token::{Clock, SystemClock, TokenIssuer, TokenVerifier};
use konekto_core::{AuditLog, PassphraseParams};
use konekto_db::identity::IdentityStore;
use konekto_db::session::SessionStore;

/// Capability blanket: a store usable as the identity backing of the
/// HTTP API must expose the identity surface, the audit log, and be
/// safely cloneable across request tasks.
///
/// `axum::extract::State` requires `Clone + Send + Sync + 'static`.
/// Production [`konekto_db::pg::PgIdentityStore`] is internally
/// reference-counted, so clone is cheap; in-memory tests use a
/// `SharedInMemoryStore` adapter that wraps the raw store in
/// `Arc<Mutex<_>>`.
pub trait ApiStore: IdentityStore + AuditLog + Clone + Send + Sync + 'static {}

impl<T> ApiStore for T where T: IdentityStore + AuditLog + Clone + Send + Sync + 'static {}

/// Cookie attributes applied to the first-party session
/// (`konekto_session`).
///
/// `secure` is the only knob exposed at runtime; everything else is
/// fixed by ADR-0003 §1 (`HttpOnly`, `SameSite=Strict`, `Path=/`). Setting
/// `secure = false` is intended for HTTP localhost development only;
/// production must set it true so the cookie never crosses an
/// untrusted transport.
#[derive(Debug, Clone, Copy)]
pub struct CookieConfig {
    /// Emit the `Secure` attribute on the session cookie.
    pub secure: bool,
}

impl CookieConfig {
    /// Production-safe defaults: `Secure` set.
    #[must_use]
    pub const fn production() -> Self {
        Self { secure: true }
    }

    /// Development-only defaults: `Secure` cleared. Logged with a
    /// warning at boot whenever this is selected.
    #[must_use]
    pub const fn insecure_dev() -> Self {
        Self { secure: false }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// Shared application state handed to every request via
/// `axum::extract::State`.
///
/// Carries the Argon2id parameters for fresh enrollments, the
/// hybrid-JWS issuer/verifier, the session/refresh-token store, and
/// the cookie attribute set. All non-`Copy` fields are wrapped in
/// [`Arc`] so cloning across request tasks is cheap.
pub struct AppState<S: ApiStore, Sess: SessionStore, K: Clock = SystemClock> {
    /// The underlying identity persistence + audit backend.
    pub store: S,
    /// The session / refresh-token storage backend.
    pub sessions: Sess,
    /// Argon2id parameters used when enrolling new identities.
    pub passphrase_params: PassphraseParams,
    /// Token issuer used by `/dev/login` and `/dev/refresh`.
    pub issuer: Arc<TokenIssuer<K>>,
    /// Token verifier consulted by the [`crate::auth::AuthedContext`]
    /// extractor.
    pub verifier: Arc<TokenVerifier<K>>,
    /// Cookie attributes for the first-party session cookie.
    pub cookie_config: CookieConfig,
}

// Manual `Clone` so we do NOT require `K: Clone` — the `Arc<_>` fields
// are cheap-cloneable regardless of `K`, and the derive macro would
// add unnecessary bounds.
impl<S: ApiStore, Sess: SessionStore, K: Clock> Clone for AppState<S, Sess, K> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            sessions: self.sessions.clone(),
            passphrase_params: self.passphrase_params,
            issuer: Arc::clone(&self.issuer),
            verifier: Arc::clone(&self.verifier),
            cookie_config: self.cookie_config,
        }
    }
}

impl<S: ApiStore, Sess: SessionStore, K: Clock> AppState<S, Sess, K> {
    /// Wrap a store + session store + token issuer/verifier as
    /// application state with production Argon2id parameters
    /// ([`PassphraseParams::DEFAULT`]) and production cookie
    /// attributes ([`CookieConfig::production`]).
    #[must_use]
    pub fn new(
        store: S,
        sessions: Sess,
        issuer: Arc<TokenIssuer<K>>,
        verifier: Arc<TokenVerifier<K>>,
    ) -> Self {
        Self {
            store,
            sessions,
            passphrase_params: PassphraseParams::DEFAULT,
            issuer,
            verifier,
            cookie_config: CookieConfig::production(),
        }
    }

    /// Override the Argon2id parameters applied to new enrollments.
    /// Intended for tests; production bootstrap should not call this.
    #[must_use]
    pub fn with_passphrase_params(mut self, params: PassphraseParams) -> Self {
        self.passphrase_params = params;
        self
    }

    /// Override cookie attributes (e.g., relax `Secure` for HTTP
    /// localhost dev). Production bootstrap should not call this.
    #[must_use]
    pub fn with_cookie_config(mut self, config: CookieConfig) -> Self {
        self.cookie_config = config;
        self
    }
}
