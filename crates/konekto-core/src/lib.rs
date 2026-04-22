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
mod key;

pub use context::{Context, Laboro, Socio, Vivo};
pub use error::Error;
pub use grant::{
    AuditId, AuditLog, AuditWriteError, CrossContextGrant, GrantError, GrantRecord, GrantScope,
};
pub use key::{ContextKey, RootKey, KEY_SIZE};
