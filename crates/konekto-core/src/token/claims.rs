//! Claim types for Konekto session tokens (ADR-0003 §3).
//!
//! The [`Claims`] struct is the plaintext payload of every access
//! token issued by `konekto-api`. It carries:
//!
//! - the standard JWT identity claims (`iss`, `sub`, `jti`, `iat`,
//!   `exp`, `nbf`),
//! - the Konekto-specific context tag (`ctx`) projecting onto the
//!   ADR-0002 context isolation boundary,
//! - the authentication-method reference list (`amr`), and
//! - the schema version (`ver`) — bumped on any breaking change to
//!   the claim set.
//!
//! Optional claims (`aud`, `acr`, `cnf`) are omitted from the wire
//! form when absent, not serialized as `null`.

use serde::{Deserialize, Serialize};

/// Current schema version of the claims set.
///
/// Bumping this constant is a breaking change. A verifier rejects
/// tokens whose `ver` does not match, with [`super::TokenError::UnsupportedVersion`].
pub const TOKEN_VERSION: u32 = 1;

/// Wire-form label for the three isolated contexts.
///
/// Serialized lowercase (`"vivo"` / `"laboro"` / `"socio"`) so that
/// the `ctx` claim uses a canonical, human-readable token form.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContextLabel {
    /// Personal / civic context (maps to `konekto_core::Vivo`).
    Vivo,
    /// Professional context (maps to `konekto_core::Laboro`).
    Laboro,
    /// Social / community context (maps to `konekto_core::Socio`).
    Socio,
}

impl ContextLabel {
    /// Canonical lowercase string representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vivo => "vivo",
            Self::Laboro => "laboro",
            Self::Socio => "socio",
        }
    }
}

/// JWS payload claim set.
///
/// Constructed by [`super::TokenIssuer::issue`] and returned by
/// [`super::TokenVerifier::verify`]. `Serialize` / `Deserialize` are
/// used by the token primitive itself; higher layers should treat a
/// `Claims` value as the server-trusted output of a verified token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer — matched against the verifier's expected issuer.
    pub iss: String,
    /// Subject — the identity id as stable opaque string (V1: UUID).
    pub sub: String,
    /// Context tag binding the token to exactly one of the three
    /// isolated contexts.
    pub ctx: ContextLabel,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiration (Unix seconds).
    pub exp: i64,
    /// Not-before (Unix seconds).
    pub nbf: i64,
    /// Unique token id — 128 bits of randomness, base64url-encoded.
    pub jti: String,
    /// Authentication-method references — e.g. `["pwd"]` or `["webauthn"]`.
    pub amr: Vec<String>,
    /// Schema version. V1 clients MUST produce and accept
    /// [`TOKEN_VERSION`].
    pub ver: u32,
    /// Audience (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aud: Option<String>,
    /// Authentication context class reference (optional).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub acr: Option<String>,
    /// Proof-of-possession confirmation claim (optional, reserved for
    /// dPoP in later ADR-0003 phases).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cnf: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::{Claims, ContextLabel, TOKEN_VERSION};

    #[test]
    fn context_label_serializes_lowercase() {
        let vivo = serde_json::to_string(&ContextLabel::Vivo).expect("serialize");
        let laboro = serde_json::to_string(&ContextLabel::Laboro).expect("serialize");
        let socio = serde_json::to_string(&ContextLabel::Socio).expect("serialize");
        assert_eq!(vivo, "\"vivo\"");
        assert_eq!(laboro, "\"laboro\"");
        assert_eq!(socio, "\"socio\"");
    }

    #[test]
    fn claims_omit_none_optionals_in_json() {
        let claims = Claims {
            iss: "konekto".into(),
            sub: "sub-1".into(),
            ctx: ContextLabel::Vivo,
            iat: 0,
            exp: 300,
            nbf: 0,
            jti: "jti".into(),
            amr: vec!["pwd".into()],
            ver: TOKEN_VERSION,
            aud: None,
            acr: None,
            cnf: None,
        };
        let text = serde_json::to_string(&claims).expect("serialize");
        assert!(!text.contains("\"aud\""));
        assert!(!text.contains("\"acr\""));
        assert!(!text.contains("\"cnf\""));
    }
}
