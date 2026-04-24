//! Hybrid JWS session-token primitive (ADR-0003 / ADR-0006).
//!
//! This module provides:
//!
//! - [`Claims`] — the V1 payload shape: `iss`, `sub`, `ctx`, `iat`,
//!   `exp`, `nbf`, `jti`, `amr`, `ver` (and optional `aud` / `acr` /
//!   `cnf`).
//! - [`ContextLabel`] — wire label tying a token to exactly one of
//!   `Vivo`, `Laboro`, `Socio`.
//! - [`SigningKeys`] / [`VerifyingKeys`] — Ed25519 + ML-DSA-65 key
//!   bundles with a shared, deterministic [`Kid`].
//! - [`TokenIssuer`] / [`TokenVerifier`] — parameterized over a
//!   [`Clock`], so tests inject [`FixedClock`] and production uses
//!   [`SystemClock`].
//!
//! The wire format is JWS JSON *General* Serialization (RFC 7515
//! §7.2.1) with exactly two signatures — one per algorithm. Both
//! signatures MUST verify for the token to be accepted; there is no
//! single-algo fallback. See ADR-0006 for the design rationale.

pub mod claims;
pub mod clock;
pub mod error;
pub mod jws;
pub mod keys;
pub mod sign_ed25519;
pub mod sign_mldsa;

pub use claims::{Claims, ContextLabel, TOKEN_VERSION};
pub use clock::{Clock, FixedClock, SystemClock};
pub use error::TokenError;
pub use jws::{Jwt, TokenIssuer, TokenVerifier, DEFAULT_ACCESS_TTL, DEFAULT_CLOCK_LEEWAY};
pub use keys::{Kid, SigningKeys, VerifyingKeys, ENV_ED25519_SK, ENV_MLDSA_SK};
