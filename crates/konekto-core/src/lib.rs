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
//!
//! This is the first increment: types and their invariants. Real
//! cryptographic derivation (HKDF-SHA256 via `aws-lc-rs`) lands in a
//! follow-up once the crypto stack is wired.
//!
//! See the project's ADRs in `docs/adr/` for the full rationale.

mod context;
mod error;
mod key;

pub use context::{Context, Laboro, Socio, Vivo};
pub use error::Error;
pub use key::{ContextKey, RootKey, KEY_SIZE};
