//! Trimero Konekto — core domain logic and cryptographic types.
//!
//! This crate contains the foundational type-system scaffolding that
//! enforces Konekto's security invariants at compile time:
//!
//! - Three cryptographically isolated contexts — [`Vivo`], [`Laboro`],
//!   [`Socio`] — encoded as sealed-trait markers so no fourth context
//!   can be added without an explicit edit to this crate.
//! - A [`ContextKey<C>`] type whose `C` parameter makes context mix-ups
//!   a compile error rather than a runtime check.
//! - A [`RootKey`] type that exists only during bounded lifecycle
//!   scopes (enrollment, login, multi-device binding, cross-context
//!   operations) and is zeroized on drop.
//! - Deterministic derivation of a [`ContextKey<C>`] from a
//!   [`RootKey`] via HKDF-SHA256 (`aws-lc-rs`), with domain
//!   separation provided by the versioned per-context label.
//!
//! Persistence (per-credential wrapping of the root key), enrollment
//! orchestration, login, and cross-context grants are layered on top
//! of these primitives in later crates and later increments.
//!
//! See the project's ADRs in `docs/adr/` for the full rationale.

mod context;
mod error;
mod grant;
mod kdf;
mod key;
mod random;
pub mod token;
mod wrap;

pub use context::{Context, Laboro, Socio, Vivo};
pub use error::Error;
pub use grant::{
    AuditId, AuditLog, AuditWriteError, CrossContextGrant, GrantError, GrantRecord, GrantScope,
};
pub use kdf::{PassphraseParams, MIN_PASSPHRASE_LEN, MIN_SALT_LEN};
pub use key::{ContextKey, RootKey, KEY_SIZE};
pub use random::{fill_random, random_bytes};
pub use token::{
    Claims, Clock, ContextLabel, FixedClock, Jwt, Kid, RefreshTokenSecret, SessionId, SigningKeys,
    SystemClock, TokenError, TokenIssuer, TokenVerifier, VerifyingKeys, DEFAULT_ACCESS_TTL,
    DEFAULT_CLOCK_LEEWAY, ENV_ED25519_SK, ENV_MLDSA_SK, REFRESH_ABSOLUTE_TTL_SECS,
    REFRESH_IDLE_TTL_SECS, SESSION_ABSOLUTE_TTL_SECS, SESSION_HASH_LEN, SESSION_IDLE_TTL_SECS,
    SESSION_SECRET_LEN, TOKEN_VERSION,
};
pub use wrap::{WrappedRootKey, WrappingKey};
