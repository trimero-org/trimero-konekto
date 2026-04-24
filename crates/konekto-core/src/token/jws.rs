//! JWS General-Serialization issuance and verification.
//!
//! See ADR-0003 §3 / ADR-0006 §2 for the full rationale and wire
//! shape.
//!
//! A Konekto token is a JSON document with two signatures produced
//! over the same unprotected payload:
//!
//! ```json
//! {
//!   "payload": "<b64url(claims)>",
//!   "signatures": [
//!     { "protected": "<b64url(header_ed)>", "signature": "<b64url(sig_ed)>" },
//!     { "protected": "<b64url(header_ml)>", "signature": "<b64url(sig_ml)>" }
//!   ]
//! }
//! ```
//!
//! Each protected header carries `{"alg": "<EdDSA|ML-DSA-65>", "typ": "JWT", "kid": "<kid>"}`.
//! Both signatures MUST verify for the token to be accepted — no
//! short-circuit, no "first match wins".

use std::marker::PhantomData;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::json;

use super::claims::{Claims, ContextLabel, TOKEN_VERSION};
use super::clock::Clock;
use super::error::TokenError;
use super::keys::{SigningKeys, VerifyingKeys};

/// Default access-token lifetime (5 minutes, per ADR-0003 §3).
pub const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(5 * 60);

/// Default clock leeway applied to `nbf` and `exp` comparisons.
pub const DEFAULT_CLOCK_LEEWAY: Duration = Duration::from_secs(30);

/// Opaque serialized token string (JWS JSON General Serialization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jwt(pub String);

impl Jwt {
    /// Borrow the token's wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned wire string.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Issues access tokens by signing a [`Claims`] payload under both
/// Ed25519 and ML-DSA-65 with a shared [`super::keys::Kid`].
pub struct TokenIssuer<C: Clock> {
    keys: std::sync::Arc<SigningKeys>,
    clock: C,
    issuer: String,
    access_ttl: Duration,
}

impl<C: Clock> TokenIssuer<C> {
    /// Build an issuer from signing keys, clock, expected issuer
    /// string (the `iss` claim), and access-token TTL.
    #[must_use]
    pub fn new(
        keys: std::sync::Arc<SigningKeys>,
        clock: C,
        issuer: impl Into<String>,
        access_ttl: Duration,
    ) -> Self {
        Self {
            keys,
            clock,
            issuer: issuer.into(),
            access_ttl,
        }
    }

    /// Issue an access token.
    ///
    /// `sub` is copied into the `sub` claim. `ctx` is copied into the
    /// `ctx` claim. `amr` is copied into the `amr` list unchanged.
    /// `iat` = `nbf` = the clock's current time; `exp` = `iat + access_ttl`.
    /// A fresh `jti` (128 bits, base64url) is drawn per call.
    pub fn issue(&self, sub: &str, ctx: ContextLabel, amr: Vec<String>) -> Result<Jwt, TokenError> {
        let now = self.clock.now_unix_secs();
        let ttl_secs = i64::try_from(self.access_ttl.as_secs()).unwrap_or(i64::MAX);
        let exp = now.saturating_add(ttl_secs);
        let jti_bytes = crate::random_bytes(16);
        let jti = B64.encode(&jti_bytes);
        let claims = Claims {
            iss: self.issuer.clone(),
            sub: sub.to_owned(),
            ctx,
            iat: now,
            nbf: now,
            exp,
            jti,
            amr,
            ver: TOKEN_VERSION,
            aud: None,
            acr: None,
            cnf: None,
        };

        let payload_json = serde_json::to_vec(&claims).map_err(|_| TokenError::PayloadEncoding)?;
        let payload_b64 = B64.encode(&payload_json);

        let kid = self.keys.kid().as_str();

        let (ed_protected_b64, ed_sig_b64) = sign_block(kid, "EdDSA", &payload_b64, |input| {
            Ok(self.keys.ed25519().sign(input))
        })?;
        let (ml_protected_b64, ml_sig_b64) = sign_block(kid, "ML-DSA-65", &payload_b64, |input| {
            self.keys.mldsa().sign(input)
        })?;

        let body = json!({
            "payload": payload_b64,
            "signatures": [
                { "protected": ed_protected_b64, "signature": ed_sig_b64 },
                { "protected": ml_protected_b64, "signature": ml_sig_b64 },
            ],
        });

        let s = serde_json::to_string(&body).map_err(|_| TokenError::PayloadEncoding)?;
        Ok(Jwt(s))
    }
}

/// Verifies access tokens against a fixed [`VerifyingKeys`] bundle,
/// issuer string, and clock leeway.
pub struct TokenVerifier<C: Clock> {
    keys: VerifyingKeys,
    clock: C,
    issuer: String,
    leeway: Duration,
    _c: PhantomData<C>,
}

impl<C: Clock> TokenVerifier<C> {
    /// Build a verifier with the default clock leeway
    /// ([`DEFAULT_CLOCK_LEEWAY`]).
    #[must_use]
    pub fn new(keys: VerifyingKeys, clock: C, issuer: impl Into<String>) -> Self {
        Self::with_leeway(keys, clock, issuer, DEFAULT_CLOCK_LEEWAY)
    }

    /// Build a verifier with an explicit clock leeway.
    #[must_use]
    pub fn with_leeway(
        keys: VerifyingKeys,
        clock: C,
        issuer: impl Into<String>,
        leeway: Duration,
    ) -> Self {
        Self {
            keys,
            clock,
            issuer: issuer.into(),
            leeway,
            _c: PhantomData,
        }
    }

    /// Verify a serialized JWS.
    ///
    /// On success, returns the decoded [`Claims`]. On failure, returns
    /// a [`TokenError`] variant — note that `konekto-api` collapses
    /// every variant to an opaque 401 at the HTTP boundary.
    pub fn verify(&self, token: &[u8]) -> Result<Claims, TokenError> {
        let doc: serde_json::Value =
            serde_json::from_slice(token).map_err(|_| TokenError::InvalidFormat)?;
        let obj = doc.as_object().ok_or(TokenError::InvalidFormat)?;

        let payload_b64 = obj
            .get("payload")
            .and_then(serde_json::Value::as_str)
            .ok_or(TokenError::InvalidFormat)?;
        let sigs = obj
            .get("signatures")
            .and_then(serde_json::Value::as_array)
            .ok_or(TokenError::InvalidFormat)?;
        if sigs.len() != 2 {
            return Err(TokenError::InvalidFormat);
        }

        // Enforce {EdDSA, ML-DSA-65} as a set — each alg seen at most once.
        let mut seen_ed = false;
        let mut seen_ml = false;
        let mut ed_ok = false;
        let mut ml_ok = false;

        for sig_obj in sigs {
            let (alg, signing_input, sig_bytes) = self.parse_sig_block(sig_obj, payload_b64)?;
            match alg.as_str() {
                "EdDSA" => {
                    if seen_ed {
                        return Err(TokenError::AlgMismatch);
                    }
                    seen_ed = true;
                    ed_ok = self
                        .keys
                        .ed25519()
                        .verify(signing_input.as_bytes(), &sig_bytes)
                        .is_ok();
                }
                "ML-DSA-65" => {
                    if seen_ml {
                        return Err(TokenError::AlgMismatch);
                    }
                    seen_ml = true;
                    ml_ok = self
                        .keys
                        .mldsa()
                        .verify(signing_input.as_bytes(), &sig_bytes)
                        .is_ok();
                }
                _ => return Err(TokenError::AlgMismatch),
            }
        }

        if !(seen_ed && seen_ml) {
            return Err(TokenError::AlgMismatch);
        }
        if !(ed_ok && ml_ok) {
            return Err(TokenError::InvalidSignature);
        }

        let payload_bytes = B64.decode(payload_b64).map_err(|_| TokenError::Base64)?;
        let claims: Claims =
            serde_json::from_slice(&payload_bytes).map_err(|_| TokenError::PayloadEncoding)?;

        if claims.ver != TOKEN_VERSION {
            return Err(TokenError::UnsupportedVersion);
        }
        if claims.iss != self.issuer {
            return Err(TokenError::IssuerMismatch);
        }

        let now = self.clock.now_unix_secs();
        let leeway = i64::try_from(self.leeway.as_secs()).unwrap_or(30);
        if now + leeway < claims.nbf {
            return Err(TokenError::NotYetValid);
        }
        if now.saturating_sub(leeway) >= claims.exp {
            return Err(TokenError::Expired);
        }

        Ok(claims)
    }

    fn parse_sig_block(
        &self,
        sig_obj: &serde_json::Value,
        payload_b64: &str,
    ) -> Result<(String, String, Vec<u8>), TokenError> {
        let sig_map = sig_obj.as_object().ok_or(TokenError::InvalidFormat)?;
        let protected_b64 = sig_map
            .get("protected")
            .and_then(serde_json::Value::as_str)
            .ok_or(TokenError::InvalidFormat)?;
        let signature_b64 = sig_map
            .get("signature")
            .and_then(serde_json::Value::as_str)
            .ok_or(TokenError::InvalidFormat)?;

        let header_bytes = B64.decode(protected_b64).map_err(|_| TokenError::Base64)?;
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| TokenError::InvalidFormat)?;
        let header_map = header.as_object().ok_or(TokenError::InvalidFormat)?;

        let alg = header_map
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .ok_or(TokenError::InvalidFormat)?;
        let typ = header_map
            .get("typ")
            .and_then(serde_json::Value::as_str)
            .ok_or(TokenError::InvalidFormat)?;
        let kid = header_map
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .ok_or(TokenError::InvalidFormat)?;

        if typ != "JWT" {
            return Err(TokenError::InvalidFormat);
        }
        if kid != self.keys.kid().as_str() {
            return Err(TokenError::KidMismatch);
        }

        let signing_input = format!("{protected_b64}.{payload_b64}");
        let sig_bytes = B64.decode(signature_b64).map_err(|_| TokenError::Base64)?;

        Ok((alg.to_string(), signing_input, sig_bytes))
    }
}

fn sign_block(
    kid: &str,
    alg: &str,
    payload_b64: &str,
    signer: impl FnOnce(&[u8]) -> Result<Vec<u8>, TokenError>,
) -> Result<(String, String), TokenError> {
    let header = json!({ "alg": alg, "typ": "JWT", "kid": kid });
    let header_bytes = serde_json::to_vec(&header).map_err(|_| TokenError::PayloadEncoding)?;
    let header_b64 = B64.encode(&header_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = signer(signing_input.as_bytes())?;
    let sig_b64 = B64.encode(&sig);
    Ok((header_b64, sig_b64))
}

#[cfg(test)]
mod tests {
    use super::{Jwt, TokenIssuer, TokenVerifier, DEFAULT_ACCESS_TTL};
    use crate::token::claims::{ContextLabel, TOKEN_VERSION};
    use crate::token::clock::FixedClock;
    use crate::token::error::TokenError;
    use crate::token::keys::SigningKeys;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;
    use std::sync::Arc;
    use std::time::Duration;

    const ISS: &str = "konekto-test";
    const FIXED_NOW: i64 = 1_750_000_000;

    fn build_pair() -> (
        TokenIssuer<FixedClock>,
        TokenVerifier<FixedClock>,
        Arc<SigningKeys>,
    ) {
        let keys = Arc::new(SigningKeys::generate_ephemeral().expect("generate keys"));
        let verifying = keys.verifying_keys();
        let issuer = TokenIssuer::new(
            Arc::clone(&keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            DEFAULT_ACCESS_TTL,
        );
        let verifier = TokenVerifier::new(verifying, FixedClock::new(FIXED_NOW), ISS);
        (issuer, verifier, keys)
    }

    fn issue(issuer: &TokenIssuer<FixedClock>, ctx: ContextLabel) -> Jwt {
        issuer
            .issue("sub-1234", ctx, vec!["pwd".to_owned()])
            .expect("issue token")
    }

    fn mutate_signature(token: &Jwt, alg: &str) -> Jwt {
        let mut v: serde_json::Value = serde_json::from_str(token.as_str()).expect("parse");
        let sigs = v["signatures"].as_array_mut().expect("sigs");
        for sig in sigs.iter_mut() {
            let header_b64 = sig["protected"].as_str().expect("protected").to_string();
            let header_bytes = B64.decode(&header_b64).expect("b64 header");
            let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("parse");
            if header["alg"] == alg {
                let sig_b64 = sig["signature"].as_str().expect("sig b64");
                let mut sig_bytes = B64.decode(sig_b64).expect("b64 sig");
                // flip a bit in the middle of the signature
                let mid = sig_bytes.len() / 2;
                sig_bytes[mid] ^= 0x01;
                sig["signature"] = serde_json::Value::String(B64.encode(&sig_bytes));
                break;
            }
        }
        Jwt(serde_json::to_string(&v).expect("serialize"))
    }

    #[test]
    fn issue_then_verify_roundtrip_per_context_succeeds() {
        for ctx in [
            ContextLabel::Vivo,
            ContextLabel::Laboro,
            ContextLabel::Socio,
        ] {
            let (issuer, verifier, _keys) = build_pair();
            let token = issue(&issuer, ctx);
            let claims = verifier.verify(token.as_str().as_bytes()).expect("verify");
            assert_eq!(claims.ctx, ctx);
            assert_eq!(claims.iss, ISS);
            assert_eq!(claims.sub, "sub-1234");
            assert_eq!(claims.ver, TOKEN_VERSION);
            assert_eq!(claims.iat, FIXED_NOW);
            assert_eq!(
                claims.exp,
                FIXED_NOW + i64::try_from(DEFAULT_ACCESS_TTL.as_secs()).expect("ttl fits in i64")
            );
        }
    }

    #[test]
    fn issued_token_has_exactly_two_signatures_with_distinct_algs() {
        let (issuer, _v, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        let v: serde_json::Value = serde_json::from_str(token.as_str()).expect("parse");
        let sigs = v["signatures"].as_array().expect("sigs");
        assert_eq!(sigs.len(), 2);
        let mut algs: Vec<String> = Vec::new();
        for sig in sigs {
            let header_bytes = B64
                .decode(sig["protected"].as_str().expect("protected"))
                .expect("b64");
            let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("parse");
            algs.push(header["alg"].as_str().expect("alg").to_string());
        }
        algs.sort();
        assert_eq!(algs, vec!["EdDSA".to_string(), "ML-DSA-65".to_string()]);
    }

    #[test]
    fn verify_rejects_when_ed25519_signature_bit_flipped() {
        let (issuer, verifier, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        let tampered = mutate_signature(&token, "EdDSA");
        let err = verifier
            .verify(tampered.as_str().as_bytes())
            .expect_err("tampered ed25519 must fail");
        assert!(matches!(err, TokenError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_when_mldsa_signature_bit_flipped() {
        let (issuer, verifier, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Laboro);
        let tampered = mutate_signature(&token, "ML-DSA-65");
        let err = verifier
            .verify(tampered.as_str().as_bytes())
            .expect_err("tampered ml-dsa must fail");
        assert!(matches!(err, TokenError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_when_payload_b64_altered() {
        let (issuer, verifier, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        let mut v: serde_json::Value = serde_json::from_str(token.as_str()).expect("parse");
        let orig = v["payload"].as_str().expect("payload").to_owned();
        let bytes = B64.decode(&orig).expect("b64");
        let mut decoded: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        decoded["sub"] = serde_json::Value::String("attacker".to_string());
        let new_payload = B64.encode(serde_json::to_vec(&decoded).expect("ser"));
        v["payload"] = serde_json::Value::String(new_payload);
        let forged = Jwt(serde_json::to_string(&v).expect("serialize"));
        let err = verifier
            .verify(forged.as_str().as_bytes())
            .expect_err("altered payload must fail");
        assert!(matches!(err, TokenError::InvalidSignature));
    }

    #[test]
    fn verify_rejects_when_protected_header_altered() {
        let (issuer, verifier, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Socio);
        let mut v: serde_json::Value = serde_json::from_str(token.as_str()).expect("parse");
        let sigs = v["signatures"].as_array_mut().expect("sigs");
        // Pick the first block, decode, alter typ, re-encode.
        let header_b64 = sigs[0]["protected"].as_str().expect("p").to_owned();
        let header_bytes = B64.decode(&header_b64).expect("b64");
        let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("parse");
        header["typ"] = serde_json::Value::String("JWS".to_string());
        let new_header = B64.encode(serde_json::to_vec(&header).expect("ser"));
        sigs[0]["protected"] = serde_json::Value::String(new_header);
        let forged = Jwt(serde_json::to_string(&v).expect("serialize"));
        let err = verifier
            .verify(forged.as_str().as_bytes())
            .expect_err("altered protected must fail");
        // Either InvalidFormat (typ!=JWT) or InvalidSignature (sig over original header);
        // both are acceptable opaque-rejection paths.
        assert!(matches!(
            err,
            TokenError::InvalidFormat | TokenError::InvalidSignature
        ));
    }

    #[test]
    fn verify_rejects_when_kid_mismatches() {
        let (issuer, _v, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        // Build a verifier with a *different* key set.
        let other_keys = Arc::new(SigningKeys::generate_ephemeral().expect("other"));
        let other_verifier =
            TokenVerifier::new(other_keys.verifying_keys(), FixedClock::new(FIXED_NOW), ISS);
        let err = other_verifier
            .verify(token.as_str().as_bytes())
            .expect_err("different kid must fail");
        assert!(matches!(err, TokenError::KidMismatch));
    }

    #[test]
    fn verify_rejects_when_only_one_signature_block_present() {
        let (issuer, verifier, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        let mut v: serde_json::Value = serde_json::from_str(token.as_str()).expect("parse");
        let sigs = v["signatures"].as_array_mut().expect("sigs");
        sigs.truncate(1);
        let forged = Jwt(serde_json::to_string(&v).expect("serialize"));
        let err = verifier
            .verify(forged.as_str().as_bytes())
            .expect_err("one-sig must fail");
        assert!(matches!(err, TokenError::InvalidFormat));
    }

    #[test]
    fn verify_rejects_when_both_signatures_use_same_alg() {
        let (issuer, verifier, _k) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        // Duplicate the Ed25519 block so we have [ed, ed].
        let mut v: serde_json::Value = serde_json::from_str(token.as_str()).expect("parse");
        let sigs = v["signatures"].as_array_mut().expect("sigs");
        // Find the Ed25519 block.
        let ed_idx = sigs
            .iter()
            .position(|s| {
                let h = B64
                    .decode(s["protected"].as_str().expect("p"))
                    .expect("b64");
                let hj: serde_json::Value = serde_json::from_slice(&h).expect("parse");
                hj["alg"] == "EdDSA"
            })
            .expect("ed block");
        let ed_block = sigs[ed_idx].clone();
        sigs[0] = ed_block.clone();
        sigs[1] = ed_block;
        let forged = Jwt(serde_json::to_string(&v).expect("serialize"));
        let err = verifier
            .verify(forged.as_str().as_bytes())
            .expect_err("dup alg must fail");
        assert!(matches!(err, TokenError::AlgMismatch));
    }

    #[test]
    fn verify_rejects_when_issuer_mismatches() {
        let (issuer, _v, keys) = build_pair();
        let token = issue(&issuer, ContextLabel::Vivo);
        let wrong = TokenVerifier::new(
            keys.verifying_keys(),
            FixedClock::new(FIXED_NOW),
            "other-issuer",
        );
        let err = wrong
            .verify(token.as_str().as_bytes())
            .expect_err("wrong iss must fail");
        assert!(matches!(err, TokenError::IssuerMismatch));
    }

    #[test]
    fn verify_rejects_when_version_unsupported() {
        // Forge a JWS with ver=99 by signing the claims manually using the
        // same signing keys, then verify via a freshly-built verifier.
        use crate::token::claims::Claims;
        use serde_json::json;
        let (_, _, keys) = build_pair();
        let verifier = TokenVerifier::new(keys.verifying_keys(), FixedClock::new(FIXED_NOW), ISS);
        let claims = Claims {
            iss: ISS.to_string(),
            sub: "x".to_string(),
            ctx: ContextLabel::Vivo,
            iat: FIXED_NOW,
            nbf: FIXED_NOW,
            exp: FIXED_NOW + 300,
            jti: "j".to_string(),
            amr: vec![],
            ver: 99,
            aud: None,
            acr: None,
            cnf: None,
        };
        let payload_b64 = B64.encode(serde_json::to_vec(&claims).expect("ser"));
        let kid = keys.kid().as_str();
        let forge_block = |alg: &str, sign: &dyn Fn(&[u8]) -> Vec<u8>| {
            let header = json!({ "alg": alg, "typ": "JWT", "kid": kid });
            let hb = B64.encode(serde_json::to_vec(&header).expect("ser"));
            let input = format!("{hb}.{payload_b64}");
            let sig = sign(input.as_bytes());
            (hb, B64.encode(sig))
        };
        let (ed_h, ed_s) = forge_block("EdDSA", &|m| keys.ed25519().sign(m));
        let (ml_h, ml_s) = forge_block("ML-DSA-65", &|m| keys.mldsa().sign(m).expect("ml"));
        let body = json!({
            "payload": payload_b64,
            "signatures": [
                { "protected": ed_h, "signature": ed_s },
                { "protected": ml_h, "signature": ml_s },
            ],
        });
        let wire = serde_json::to_string(&body).expect("ser");
        let err = verifier
            .verify(wire.as_bytes())
            .expect_err("ver=99 must fail");
        assert!(matches!(err, TokenError::UnsupportedVersion));
    }

    #[test]
    fn verify_rejects_expired_token_via_fixed_clock() {
        let keys = Arc::new(SigningKeys::generate_ephemeral().expect("keys"));
        let issue_clock = FixedClock::new(FIXED_NOW);
        let issuer = TokenIssuer::new(Arc::clone(&keys), issue_clock, ISS, Duration::from_secs(60));
        let token = issue(&issuer, ContextLabel::Vivo);
        // Verifier running 10 minutes later — well past exp + 30s leeway.
        let late = FixedClock::new(FIXED_NOW + 600);
        let verifier = TokenVerifier::new(keys.verifying_keys(), late, ISS);
        let err = verifier
            .verify(token.as_str().as_bytes())
            .expect_err("expired must fail");
        assert!(matches!(err, TokenError::Expired));
    }

    #[test]
    fn verify_rejects_not_yet_valid_token_via_fixed_clock() {
        let keys = Arc::new(SigningKeys::generate_ephemeral().expect("keys"));
        let issuer = TokenIssuer::new(
            Arc::clone(&keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            DEFAULT_ACCESS_TTL,
        );
        let token = issue(&issuer, ContextLabel::Vivo);
        // Verifier running 10 minutes *before* issuance — nbf-leeway blocks it.
        let early = FixedClock::new(FIXED_NOW - 600);
        let verifier = TokenVerifier::new(keys.verifying_keys(), early, ISS);
        let err = verifier
            .verify(token.as_str().as_bytes())
            .expect_err("nbf must fail");
        assert!(matches!(err, TokenError::NotYetValid));
    }

    #[test]
    fn verify_accepts_token_within_leeway() {
        let keys = Arc::new(SigningKeys::generate_ephemeral().expect("keys"));
        let issuer = TokenIssuer::new(
            Arc::clone(&keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            Duration::from_secs(60),
        );
        let token = issue(&issuer, ContextLabel::Vivo);
        // Verifier running 10s past exp, but leeway is 30s.
        let slightly_late = FixedClock::new(FIXED_NOW + 60 + 10);
        let verifier = TokenVerifier::new(keys.verifying_keys(), slightly_late, ISS);
        let claims = verifier
            .verify(token.as_str().as_bytes())
            .expect("within leeway must succeed");
        assert_eq!(claims.iss, ISS);
    }
}
