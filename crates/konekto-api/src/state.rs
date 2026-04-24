//! Application state and the store-capability trait.
//!
//! [`AppState`] is parameterised over `S: ApiStore`, so the same
//! router wires up cleanly against either the in-memory store used
//! in tests or the Postgres-backed store used in production.
//!
//! It is also parameterised over a [`Clock`] (default [`SystemClock`])
//! so integration tests can substitute [`konekto_core::token::FixedClock`]
//! to drive `iat` / `exp` / `nbf` deterministically.

use std::sync::Arc;

use konekto_core::token::{Clock, SystemClock, TokenIssuer, TokenVerifier};
use konekto_core::{AuditLog, PassphraseParams};
use konekto_db::identity::IdentityStore;

/// Capability blanket: a store usable as the backing state of the
/// HTTP API must expose the identity surface, the audit log, and
/// be safely cloneable across request tasks.
///
/// `axum::extract::State` requires `Clone + Send + Sync + 'static`.
/// `Clone` is cheap for the canonical backends:
///
/// - [`konekto_db::pg::PgIdentityStore`] — the pool is internally
///   reference-counted, so clone is cheap and the underlying
///   connection pool is shared across all cloned handles.
/// - [`konekto_db::identity::InMemoryStore`] is not directly
///   `Clone`, but a test-side adapter (`SharedInMemoryStore`)
///   wraps it in `Arc<Mutex<_>>` and satisfies the bound.
pub trait ApiStore: IdentityStore + AuditLog + Clone + Send + Sync + 'static {}

impl<T> ApiStore for T where T: IdentityStore + AuditLog + Clone + Send + Sync + 'static {}

/// Shared application state handed to every request via
/// `axum::extract::State`.
///
/// Carries the Argon2id parameters the enrollment flow applies to
/// fresh identities. Production bootstrap uses
/// [`PassphraseParams::DEFAULT`]; tests substitute cheaper values so
/// they don't pay the full 19 MiB / 2-iter cost per request.
///
/// Also carries the [`TokenIssuer`] / [`TokenVerifier`] pair used by
/// `/dev/login` to mint access tokens and by the `AuthedContext<C>`
/// extractor to check them. Both are wrapped in [`Arc`] so that
/// cloning the state across request tasks does not duplicate the
/// signing-key bundle.
pub struct AppState<S: ApiStore, K: Clock = SystemClock> {
    /// The underlying persistence + audit backend.
    pub store: S,
    /// Argon2id parameters used when enrolling new identities.
    pub passphrase_params: PassphraseParams,
    /// Token issuer used by `/dev/login`.
    pub issuer: Arc<TokenIssuer<K>>,
    /// Token verifier consulted by the `AuthedContext<C>` extractor.
    pub verifier: Arc<TokenVerifier<K>>,
}

// Manual `Clone` so we do NOT require `K: Clone` — the `Arc<_>` fields
// are cheap-cloneable regardless of `K`, and the derive macro would add
// an unnecessary bound that `SystemClock` / `FixedClock` do not both
// satisfy without Clone being expressible on every `Clock` impl.
impl<S: ApiStore, K: Clock> Clone for AppState<S, K> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            passphrase_params: self.passphrase_params,
            issuer: Arc::clone(&self.issuer),
            verifier: Arc::clone(&self.verifier),
        }
    }
}

impl<S: ApiStore, K: Clock> AppState<S, K> {
    /// Wrap an existing store + token issuer/verifier pair as
    /// application state with production Argon2id parameters
    /// ([`PassphraseParams::DEFAULT`]).
    #[must_use]
    pub fn new(store: S, issuer: Arc<TokenIssuer<K>>, verifier: Arc<TokenVerifier<K>>) -> Self {
        Self {
            store,
            passphrase_params: PassphraseParams::DEFAULT,
            issuer,
            verifier,
        }
    }

    /// Override the Argon2id parameters applied to new enrollments.
    /// Intended for tests; production bootstrap should not call this.
    #[must_use]
    pub fn with_passphrase_params(mut self, params: PassphraseParams) -> Self {
        self.passphrase_params = params;
        self
    }
}
