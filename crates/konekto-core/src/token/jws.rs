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
use super::keys::{Keyring, SigningKeys};

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

/// Verifies access tokens against a [`Keyring`] (one primary verifying
/// bundle plus zero or more retired bundles), an issuer string, and a
/// clock leeway.
///
/// On each call, [`Self::verify`] parses the `kid` from each signature
/// block, requires both blocks to carry the same `kid`, and looks up
/// the matching bundle in the keyring. Tokens whose `kid` belongs to a
/// retired bundle still verify — that is the rotation invariant from
/// ADR-0009 §2.
pub struct TokenVerifier<C: Clock> {
    keys: Keyring,
    clock: C,
    issuer: String,
    leeway: Duration,
    _c: PhantomData<C>,
}

impl<C: Clock> TokenVerifier<C> {
    /// Build a verifier with the default clock leeway
    /// ([`DEFAULT_CLOCK_LEEWAY`]).
    ///
    /// `keys` accepts either a [`Keyring`] or any single
    /// [`super::keys::VerifyingKeys`] bundle (the bundle becomes the
    /// keyring's primary, with no retired entries).
    #[must_use]
    pub fn new(keys: impl Into<Keyring>, clock: C, issuer: impl Into<String>) -> Self {
        Self::with_leeway(keys, clock, issuer, DEFAULT_CLOCK_LEEWAY)
    }

    /// Build a verifier with an explicit clock leeway.
    ///
    /// `keys` accepts either a [`Keyring`] or any single
    /// [`super::keys::VerifyingKeys`] bundle.
    #[must_use]
    pub fn with_leeway(
        keys: impl Into<Keyring>,
        clock: C,
        issuer: impl Into<String>,
        leeway: Duration,
    ) -> Self {
        Self {
            keys: keys.into(),
            clock,
            issuer: issuer.into(),
            leeway,
            _c: PhantomData,
        }
    }

    /// Borrow the verifier's clock. Exposed so adjacent extractors
    /// (notably `AuthedSession` in `konekto-api`) read the same time
    /// source as the JWS verifier — substituting a `FixedClock` in
    /// tests then drives both the token-expiry path and the
    /// session-expiry path off one synthetic clock.
    pub fn clock(&self) -> &C {
        &self.clock
    }

    /// Borrow the verifier's [`Keyring`].
    ///
    /// Exposed so the JWKS publication path can iterate every bundle
    /// (primary + retired) without re-routing them through `AppState`.
    /// Verifying keys carry no secret material — only public bytes and
    /// the shared [`super::keys::Kid`].
    pub fn keyring(&self) -> &Keyring {
        &self.keys
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

        let block_a = parse_sig_block(&sigs[0], payload_b64)?;
        let block_b = parse_sig_block(&sigs[1], payload_b64)?;

        // Both signature blocks must reference the same kid — they
        // sign the same token, and a Konekto kid identifies the hybrid
        // bundle (ADR-0008 §1).
        if block_a.kid != block_b.kid {
            return Err(TokenError::KidMismatch);
        }

        // Look up the bundle by the shared kid; an unknown kid is not
        // a bundle this verifier can accept.
        let bundle = self
            .keys
            .find(&block_a.kid)
            .ok_or(TokenError::KidMismatch)?;

        // Enforce {EdDSA, ML-DSA-65} as a set — both algs present, no
        // duplicate.
        let mut seen_ed = false;
        let mut seen_ml = false;
        let mut ed_ok = false;
        let mut ml_ok = false;

        for block in [&block_a, &block_b] {
            match block.alg.as_str() {
                "EdDSA" => {
                    if seen_ed {
                        return Err(TokenError::AlgMismatch);
                    }
                    seen_ed = true;
                    ed_ok = bundle
                        .ed25519()
                        .verify(block.signing_input.as_bytes(), &block.sig_bytes)
                        .is_ok();
                }
                "ML-DSA-65" => {
                    if seen_ml {
                        return Err(TokenError::AlgMismatch);
                    }
                    seen_ml = true;
                    ml_ok = bundle
                        .mldsa()
                        .verify(block.signing_input.as_bytes(), &block.sig_bytes)
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
}

struct ParsedBlock {
    alg: String,
    kid: String,
    signing_input: String,
    sig_bytes: Vec<u8>,
}

fn parse_sig_block(
    sig_obj: &serde_json::Value,
    payload_b64: &str,
) -> Result<ParsedBlock, TokenError> {
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

    let signing_input = format!("{protected_b64}.{payload_b64}");
    let sig_bytes = B64.decode(signature_b64).map_err(|_| TokenError::Base64)?;

    Ok(ParsedBlock {
        alg: alg.to_string(),
        kid: kid.to_string(),
        signing_input,
        sig_bytes,
    })
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
    use crate::token::keys::{Keyring, SigningKeys};
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
    fn verify_accepts_token_signed_by_a_retired_bundle() {
        // The retired keys minted the token; the primary signs new
        // tokens. A keyring containing both must accept the retired
        // token by looking it up via its kid.
        let retired_keys = Arc::new(SigningKeys::generate_ephemeral().expect("retired"));
        let primary_keys = Arc::new(SigningKeys::generate_ephemeral().expect("primary"));
        let retired_issuer = TokenIssuer::new(
            Arc::clone(&retired_keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            DEFAULT_ACCESS_TTL,
        );
        let token = issue(&retired_issuer, ContextLabel::Vivo);
        let ring = Keyring::new(primary_keys.verifying_keys())
            .with_retired(vec![retired_keys.verifying_keys()])
            .expect("distinct kids");
        let verifier = TokenVerifier::new(ring, FixedClock::new(FIXED_NOW), ISS);
        let claims = verifier
            .verify(token.as_str().as_bytes())
            .expect("retired-kid token must verify");
        assert_eq!(claims.iss, ISS);
    }

    #[test]
    fn verify_rejects_token_whose_kid_is_outside_the_keyring() {
        // Token minted by an entirely separate signer. Even though the
        // signatures themselves are valid, the kid is unknown to this
        // keyring, so the verifier rejects it as KidMismatch.
        let stranger_keys = Arc::new(SigningKeys::generate_ephemeral().expect("stranger"));
        let primary_keys = Arc::new(SigningKeys::generate_ephemeral().expect("primary"));
        let stranger_issuer = TokenIssuer::new(
            Arc::clone(&stranger_keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            DEFAULT_ACCESS_TTL,
        );
        let token = issue(&stranger_issuer, ContextLabel::Vivo);
        let verifier = TokenVerifier::new(
            primary_keys.verifying_keys(),
            FixedClock::new(FIXED_NOW),
            ISS,
        );
        let err = verifier
            .verify(token.as_str().as_bytes())
            .expect_err("unknown kid must fail");
        assert!(matches!(err, TokenError::KidMismatch));
    }

    #[test]
    fn verify_rejects_token_whose_two_signatures_carry_different_kids() {
        // Forge a token where the EdDSA block's protected header carries
        // a kid from the primary bundle while the ML-DSA-65 block's
        // header is from the retired bundle. The verifier must refuse
        // to accept "split" tokens — the kid identifies the hybrid
        // pair, both halves must agree.
        let primary_keys = Arc::new(SigningKeys::generate_ephemeral().expect("primary"));
        let retired_keys = Arc::new(SigningKeys::generate_ephemeral().expect("retired"));

        let primary_issuer = TokenIssuer::new(
            Arc::clone(&primary_keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            DEFAULT_ACCESS_TTL,
        );
        let retired_issuer = TokenIssuer::new(
            Arc::clone(&retired_keys),
            FixedClock::new(FIXED_NOW),
            ISS,
            DEFAULT_ACCESS_TTL,
        );

        // Issue two tokens with the same payload by giving them the
        // same fixed clock + issuer so iat/nbf/exp coincide. jti will
        // differ — that's fine, we only need the protected headers to
        // come from different kids while the wire shape is otherwise
        // valid.
        let primary_tok = issue(&primary_issuer, ContextLabel::Vivo);
        let retired_tok = issue(&retired_issuer, ContextLabel::Vivo);

        let mut primary_doc: serde_json::Value =
            serde_json::from_str(primary_tok.as_str()).expect("parse");
        let retired_doc: serde_json::Value =
            serde_json::from_str(retired_tok.as_str()).expect("parse");

        // Splice the retired token's ML-DSA-65 block into the primary
        // token. The result has two valid-looking signature blocks
        // with mismatched kids, signing different signing inputs.
        let retired_sigs = retired_doc["signatures"].as_array().expect("sigs");
        let retired_ml = retired_sigs
            .iter()
            .find(|s| {
                let h = B64
                    .decode(s["protected"].as_str().expect("p"))
                    .expect("b64");
                let hj: serde_json::Value = serde_json::from_slice(&h).expect("parse");
                hj["alg"] == "ML-DSA-65"
            })
            .expect("ml block")
            .clone();
        let primary_sigs = primary_doc["signatures"].as_array_mut().expect("sigs");
        let ml_idx = primary_sigs
            .iter()
            .position(|s| {
                let h = B64
                    .decode(s["protected"].as_str().expect("p"))
                    .expect("b64");
                let hj: serde_json::Value = serde_json::from_slice(&h).expect("parse");
                hj["alg"] == "ML-DSA-65"
            })
            .expect("primary ml idx");
        primary_sigs[ml_idx] = retired_ml;
        let forged = Jwt(serde_json::to_string(&primary_doc).expect("serialize"));

        let ring = Keyring::new(primary_keys.verifying_keys())
            .with_retired(vec![retired_keys.verifying_keys()])
            .expect("distinct");
        let verifier = TokenVerifier::new(ring, FixedClock::new(FIXED_NOW), ISS);
        let err = verifier
            .verify(forged.as_str().as_bytes())
            .expect_err("split-kid token must fail");
        assert!(matches!(err, TokenError::KidMismatch));
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
