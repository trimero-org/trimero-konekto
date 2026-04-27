//! JWK Set publication for the hybrid Ed25519 + ML-DSA-65 verifier
//! bundle (ADR-0008).
//!
//! [`to_jwk_set`] turns a [`VerifyingKeys`] into a JWK Set
//! ([RFC 7517 §5]) ready to serve at `/.well-known/jwks.json`. The
//! set always contains exactly two entries — one per signature
//! algorithm — and both entries carry the same [`super::keys::Kid`],
//! reflecting that a Konekto access token is the *pair*: an RP that
//! understands only one alg cannot independently accept a token, but
//! the JWK shape lets the RP locate its half of the pair by `kid`.
//!
//! ## JWK shapes
//!
//! - **Ed25519** — [RFC 8037 §2]. `kty=OKP`, `crv=Ed25519`,
//!   `alg=EdDSA`, `use=sig`, `x` is the 32-byte public key
//!   base64url-encoded without padding.
//! - **ML-DSA-65** — IANA registration is still in flight; we publish
//!   under the in-flight `kty=AKP` ("Algorithm Key Pair") shape with
//!   the variant pinned via `alg=ML-DSA-65` and the public key in the
//!   `pub` field. ADR-0008 §3 tracks the literal as a deferred
//!   follow-up: when the working group lands the final shape, the
//!   field names here change in lockstep with the alg literal in
//!   [`super::jws`].
//!
//! [RFC 7517 §5]: https://datatracker.ietf.org/doc/html/rfc7517#section-5
//! [RFC 8037 §2]: https://datatracker.ietf.org/doc/html/rfc8037#section-2

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::{json, Value};

use super::keys::VerifyingKeys;

/// Build a JWK Set document from a [`VerifyingKeys`] bundle.
///
/// The returned [`Value`] is a JSON object of the form
/// `{ "keys": [<ed25519_jwk>, <mldsa_jwk>] }`, ready to be wrapped in
/// `axum::Json` or any other `serde_json`-compatible response. The
/// caller is responsible for setting the `Content-Type` and
/// `Cache-Control` headers (see ADR-0008 §4).
#[must_use]
pub fn to_jwk_set(keys: &VerifyingKeys) -> Value {
    let kid = keys.kid().as_str();
    json!({
        "keys": [
            ed25519_jwk(kid, keys.ed25519_public_key()),
            mldsa_jwk(kid, &keys.mldsa_public_key()),
        ],
    })
}

fn ed25519_jwk(kid: &str, public_key: &[u8]) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "kid": kid,
        "x": B64.encode(public_key),
    })
}

fn mldsa_jwk(kid: &str, public_key: &[u8]) -> Value {
    json!({
        "kty": "AKP",
        "alg": "ML-DSA-65",
        "use": "sig",
        "kid": kid,
        "pub": B64.encode(public_key),
    })
}

#[cfg(test)]
mod tests {
    use super::to_jwk_set;
    use crate::token::keys::SigningKeys;
    use crate::token::sign_ed25519::ED25519_PUBKEY_LEN;
    use crate::token::sign_mldsa::MLDSA_PUBKEY_LEN;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;

    fn build() -> SigningKeys {
        SigningKeys::generate_ephemeral().expect("generate keys")
    }

    #[test]
    fn jwk_set_contains_exactly_two_keys() {
        let keys = build();
        let set = to_jwk_set(&keys.verifying_keys());
        let arr = set["keys"].as_array().expect("keys is an array");
        assert_eq!(arr.len(), 2, "hybrid JWK set must have exactly two entries");
    }

    #[test]
    fn both_jwks_share_the_verifier_kid() {
        let keys = build();
        let verifying = keys.verifying_keys();
        let set = to_jwk_set(&verifying);
        let expected = verifying.kid().as_str();
        for jwk in set["keys"].as_array().expect("keys") {
            assert_eq!(
                jwk["kid"].as_str().expect("kid"),
                expected,
                "every JWK in the hybrid set must carry the shared kid",
            );
        }
    }

    #[test]
    fn ed25519_jwk_has_rfc_8037_shape() {
        let keys = build();
        let verifying = keys.verifying_keys();
        let set = to_jwk_set(&verifying);
        let jwk = &set["keys"][0];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "EdDSA");
        let x = jwk["x"].as_str().expect("x is a string");
        let decoded = B64.decode(x).expect("x is base64url");
        assert_eq!(
            decoded.len(),
            ED25519_PUBKEY_LEN,
            "Ed25519 x must decode to 32 bytes",
        );
        assert_eq!(
            decoded.as_slice(),
            verifying.ed25519_public_key().as_slice()
        );
    }

    #[test]
    fn mldsa_jwk_has_in_flight_akp_shape() {
        let keys = build();
        let verifying = keys.verifying_keys();
        let set = to_jwk_set(&verifying);
        let jwk = &set["keys"][1];
        assert_eq!(jwk["kty"], "AKP");
        assert_eq!(jwk["alg"], "ML-DSA-65");
        assert_eq!(jwk["use"], "sig");
        let pubk = jwk["pub"].as_str().expect("pub is a string");
        let decoded = B64.decode(pubk).expect("pub is base64url");
        assert_eq!(
            decoded.len(),
            MLDSA_PUBKEY_LEN,
            "ML-DSA-65 pub must decode to 1952 bytes",
        );
        assert_eq!(decoded, verifying.mldsa_public_key());
    }

    #[test]
    fn jwk_set_is_deterministic_for_a_fixed_key_bundle() {
        let keys = build();
        let v = keys.verifying_keys();
        let a = to_jwk_set(&v);
        let b = to_jwk_set(&v);
        assert_eq!(a, b, "JWK set is a pure function of the verifying bundle");
    }
}
