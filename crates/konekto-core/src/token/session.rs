//! Opaque session and refresh-token primitives (ADR-0003 §1, §2 / ADR-0007).
//!
//! These are the bearer secrets exchanged between Konekto and a client
//! over the wire: the cookie value carrying a first-party session ID,
//! and the body value carrying an OAuth refresh token. Both are 32
//! bytes drawn from the system CSPRNG, base64url-encoded.
//!
//! The store sees only **hashes**, never the raw secret. On lookup,
//! the server hashes the presented token and searches by hash; this
//! limits the blast radius of a storage leak (raw tokens cannot be
//! reconstructed from the database).
//!
//! # Why two newtypes
//!
//! [`SessionId`] and [`RefreshTokenSecret`] are structurally identical
//! — both wrap a base64url string of 32 random bytes — but they live
//! on disjoint surfaces (first-party cookie vs. OAuth body) with
//! different TTL policies. Distinct types make accidental cross-use
//! a compile error rather than a runtime confusion.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use blake2::{Blake2s256, Digest};

use crate::random::random_bytes;

/// Length of the underlying random secret, in bytes. 32 bytes (256
/// bits) of CSPRNG output gives an upper bound on guessing attacks
/// well above any reasonable session lifetime.
pub const SESSION_SECRET_LEN: usize = 32;

/// Length of the BLAKE2s-256 digest stored in place of the raw token.
pub const SESSION_HASH_LEN: usize = 32;

/// Sliding idle TTL for a first-party session, in seconds (30 minutes
/// per ADR-0003 §5). Each authenticated request that reaches the
/// session store resets this window.
pub const SESSION_IDLE_TTL_SECS: i64 = 30 * 60;

/// Hard absolute TTL for a first-party session, in seconds (12 hours
/// per ADR-0003 §5). Cannot be extended; expiring requires a fresh
/// login.
pub const SESSION_ABSOLUTE_TTL_SECS: i64 = 12 * 60 * 60;

/// Sliding idle TTL for an OAuth refresh token, in seconds (30 days
/// per ADR-0003 §2). Each successful rotation resets this window.
pub const REFRESH_IDLE_TTL_SECS: i64 = 30 * 24 * 60 * 60;

/// Hard absolute TTL for an OAuth refresh-token *family*, in seconds
/// (90 days per ADR-0003 §2). Rotation does not extend this; an
/// expired family forces a full re-authentication.
pub const REFRESH_ABSOLUTE_TTL_SECS: i64 = 90 * 24 * 60 * 60;

/// Opaque first-party session identifier carried in the
/// `konekto_session` cookie.
///
/// Construction is gated through [`SessionId::generate`] so callers
/// cannot accidentally bake a non-CSPRNG value into a session.
#[derive(Clone)]
pub struct SessionId(String);

impl SessionId {
    /// Draw a fresh session ID from the system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let bytes = random_bytes(SESSION_SECRET_LEN);
        Self(B64.encode(bytes))
    }

    /// Re-wrap a base64url-encoded secret received from a client
    /// cookie. No validation beyond non-empty: the verifier hashes
    /// and looks the value up; a forged or truncated string simply
    /// fails to match any stored hash.
    #[must_use]
    pub fn from_wire(value: String) -> Option<Self> {
        if value.is_empty() {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Borrow the wire representation (base64url, no padding).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// BLAKE2s-256 digest of the wire representation, suitable as the
    /// storage key in [`crate::SessionStore`](../../konekto_db).
    #[must_use]
    pub fn hash(&self) -> [u8; SESSION_HASH_LEN] {
        hash_secret(self.0.as_bytes())
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionId")
            .field("hash", &"<redacted>")
            .finish()
    }
}

/// Opaque OAuth refresh-token secret returned in the `/dev/login` and
/// `/dev/refresh` JSON bodies.
///
/// Construction is gated through [`RefreshTokenSecret::generate`].
/// The corresponding hash is what the server persists.
#[derive(Clone)]
pub struct RefreshTokenSecret(String);

impl RefreshTokenSecret {
    /// Draw a fresh refresh secret from the system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let bytes = random_bytes(SESSION_SECRET_LEN);
        Self(B64.encode(bytes))
    }

    /// Re-wrap a base64url-encoded refresh token presented by a
    /// caller. Empty values are rejected.
    #[must_use]
    pub fn from_wire(value: String) -> Option<Self> {
        if value.is_empty() {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Borrow the wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// BLAKE2s-256 digest of the wire representation.
    #[must_use]
    pub fn hash(&self) -> [u8; SESSION_HASH_LEN] {
        hash_secret(self.0.as_bytes())
    }
}

impl fmt::Debug for RefreshTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshTokenSecret")
            .field("hash", &"<redacted>")
            .finish()
    }
}

fn hash_secret(input: &[u8]) -> [u8; SESSION_HASH_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0u8; SESSION_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        hash_secret, RefreshTokenSecret, SessionId, REFRESH_ABSOLUTE_TTL_SECS,
        REFRESH_IDLE_TTL_SECS, SESSION_ABSOLUTE_TTL_SECS, SESSION_HASH_LEN, SESSION_IDLE_TTL_SECS,
        SESSION_SECRET_LEN,
    };

    #[test]
    fn ttl_constants_match_adr_0003() {
        assert_eq!(SESSION_IDLE_TTL_SECS, 30 * 60);
        assert_eq!(SESSION_ABSOLUTE_TTL_SECS, 12 * 60 * 60);
        assert_eq!(REFRESH_IDLE_TTL_SECS, 30 * 86_400);
        assert_eq!(REFRESH_ABSOLUTE_TTL_SECS, 90 * 86_400);
    }

    #[test]
    fn session_id_generate_is_unique_and_well_formed() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a.as_str(), b.as_str());
        // 32 bytes base64url-encoded with no padding == 43 chars.
        assert_eq!(a.as_str().len(), 43);
        assert!(!a.as_str().contains('='));
    }

    #[test]
    fn refresh_token_generate_is_unique_and_well_formed() {
        let a = RefreshTokenSecret::generate();
        let b = RefreshTokenSecret::generate();
        assert_ne!(a.as_str(), b.as_str());
        assert_eq!(a.as_str().len(), 43);
    }

    #[test]
    fn hash_is_deterministic_and_32_bytes() {
        let s = SessionId::generate();
        let h1 = s.hash();
        let h2 = s.hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), SESSION_HASH_LEN);
    }

    #[test]
    fn distinct_secrets_hash_distinctly() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn from_wire_rejects_empty() {
        assert!(SessionId::from_wire(String::new()).is_none());
        assert!(RefreshTokenSecret::from_wire(String::new()).is_none());
    }

    #[test]
    fn from_wire_preserves_value() {
        let s = SessionId::from_wire("abc".to_owned()).expect("non-empty");
        assert_eq!(s.as_str(), "abc");
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let s = SessionId::generate();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains(s.as_str()));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn hash_secret_is_a_blake2s256_digest() {
        // Smoke: same input -> same output, length is fixed.
        let a = hash_secret(b"hello");
        let b = hash_secret(b"hello");
        let c = hash_secret(b"world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), SESSION_HASH_LEN);
    }

    #[test]
    fn secret_len_is_32_bytes() {
        assert_eq!(SESSION_SECRET_LEN, 32);
    }
}
