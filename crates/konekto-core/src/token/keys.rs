//! Signing and verifying key bundles for hybrid JWS tokens.
//!
//! A Konekto token carries two signatures — Ed25519 (classical) and
//! ML-DSA-65 (post-quantum) — over the same signing input. The
//! issuer holds a [`SigningKeys`] bundle; verifiers hold the
//! corresponding [`VerifyingKeys`]. Both share a single [`Kid`]
//! derived deterministically from the two public keys.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2sVar;

use super::error::TokenError;
use super::sign_ed25519::{Ed25519Signer, Ed25519Verifier, ED25519_PUBKEY_LEN};
use super::sign_mldsa::{MlDsaSigner, MlDsaVerifier};

/// Environment variable holding the base64url-encoded Ed25519 seed
/// (32 bytes) used to sign access tokens.
pub const ENV_ED25519_SK: &str = "TOKEN_SIGNING_ED25519_SK";

/// Environment variable holding the base64url-encoded ML-DSA-65
/// encoded signing key used to sign access tokens.
pub const ENV_MLDSA_SK: &str = "TOKEN_SIGNING_MLDSA_SK";

/// Key identifier — a 128-bit BLAKE2s digest of the concatenated
/// public keys, base64url-encoded (no padding).
///
/// The `kid` is deterministic: reconstructing a [`SigningKeys`] from
/// the same seed + ML-DSA-65 secret yields a byte-identical `kid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kid(String);

impl Kid {
    pub(crate) fn compute(ed25519_pk: &[u8], mldsa_pk: &[u8]) -> Self {
        let mut hasher = Blake2sVar::new(16).expect("128-bit digest length accepted");
        hasher.update(ed25519_pk);
        hasher.update(mldsa_pk);
        let mut digest = [0u8; 16];
        hasher
            .finalize_variable(&mut digest)
            .expect("output buffer length matches digest size");
        Self(B64.encode(digest))
    }

    /// Borrow the canonical base64url string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bundle of the issuer's Ed25519 and ML-DSA-65 signing keys.
///
/// Holds a cached [`Kid`] so every issued token can stamp the same
/// value into each signature's protected header.
pub struct SigningKeys {
    ed25519: Ed25519Signer,
    mldsa: MlDsaSigner,
    kid: Kid,
}

impl SigningKeys {
    /// Draw a fresh Ed25519 seed and a fresh ML-DSA-65 keypair from
    /// the system CSPRNG. Intended for dev / test bootstrap — production
    /// uses [`SigningKeys::from_env`] so the `kid` stays stable across
    /// restarts.
    pub fn generate_ephemeral() -> Result<Self, TokenError> {
        let (ed25519, _seed) = Ed25519Signer::generate()?;
        let (mldsa, _sk) = MlDsaSigner::generate()?;
        let kid = Kid::compute(ed25519.public_key(), &mldsa.verifying_key_bytes());
        Ok(Self {
            ed25519,
            mldsa,
            kid,
        })
    }

    /// Reconstruct signing keys from base64url-encoded environment
    /// variables [`ENV_ED25519_SK`] and [`ENV_MLDSA_SK`].
    ///
    /// # Errors
    ///
    /// - [`TokenError::EnvConfig`] if either variable is missing or a
    ///   decoded byte length is not accepted by the backend.
    /// - [`TokenError::Base64`] if either variable is not valid
    ///   base64url.
    pub fn from_env() -> Result<Self, TokenError> {
        let ed_str = std::env::var(ENV_ED25519_SK).map_err(|_| TokenError::EnvConfig)?;
        let ml_str = std::env::var(ENV_MLDSA_SK).map_err(|_| TokenError::EnvConfig)?;
        Self::from_encoded(&ed_str, &ml_str)
    }

    /// Reconstruct signing keys from caller-supplied base64url strings.
    ///
    /// Used by [`SigningKeys::from_env`] and by tests that want to
    /// exercise the env-var round-trip without touching the real
    /// environment. Both strings are the 32-byte seeds (Ed25519 seed
    /// and ML-DSA-65 seed) base64url-encoded without padding.
    pub fn from_encoded(ed25519_sk_b64: &str, mldsa_sk_b64: &str) -> Result<Self, TokenError> {
        let ed_bytes = B64.decode(ed25519_sk_b64).map_err(|_| TokenError::Base64)?;
        let ml_bytes = B64.decode(mldsa_sk_b64).map_err(|_| TokenError::Base64)?;
        let ed25519 = Ed25519Signer::from_seed(&ed_bytes)?;
        let mldsa = MlDsaSigner::from_seed_bytes(&ml_bytes)?;
        let kid = Kid::compute(ed25519.public_key(), &mldsa.verifying_key_bytes());
        Ok(Self {
            ed25519,
            mldsa,
            kid,
        })
    }

    /// The shared `kid` these keys emit into every protected header.
    #[must_use]
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    /// Derive the matching verifying-key bundle.
    #[must_use]
    pub fn verifying_keys(&self) -> VerifyingKeys {
        let mut ed_pk = [0u8; ED25519_PUBKEY_LEN];
        ed_pk.copy_from_slice(self.ed25519.public_key());
        VerifyingKeys {
            ed25519: Ed25519Verifier::from_public_key(ed_pk),
            mldsa: self.mldsa.verifier(),
            kid: self.kid.clone(),
        }
    }

    pub(crate) fn ed25519(&self) -> &Ed25519Signer {
        &self.ed25519
    }

    pub(crate) fn mldsa(&self) -> &MlDsaSigner {
        &self.mldsa
    }
}

/// Bundle of the verifying keys matching a [`SigningKeys`] bundle.
#[derive(Clone)]
pub struct VerifyingKeys {
    ed25519: Ed25519Verifier,
    mldsa: MlDsaVerifier,
    kid: Kid,
}

impl VerifyingKeys {
    /// Build a verifier bundle from already-constructed ed25519 +
    /// ml-dsa verifiers. The `kid` is recomputed deterministically.
    #[must_use]
    pub fn new(ed25519: Ed25519Verifier, mldsa: MlDsaVerifier) -> Self {
        let kid = Kid::compute(ed25519.public_key(), &mldsa.verifying_key_bytes());
        Self {
            ed25519,
            mldsa,
            kid,
        }
    }

    /// The `kid` these verifiers will accept in a token header.
    #[must_use]
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    pub(crate) fn ed25519(&self) -> &Ed25519Verifier {
        &self.ed25519
    }

    pub(crate) fn mldsa(&self) -> &MlDsaVerifier {
        &self.mldsa
    }
}

#[cfg(test)]
mod tests {
    use super::{Kid, SigningKeys};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;

    #[test]
    fn kid_is_deterministic_for_same_public_keys() {
        let a = Kid::compute(&[1u8; 32], &[2u8; 64]);
        let b = Kid::compute(&[1u8; 32], &[2u8; 64]);
        assert_eq!(a.as_str(), b.as_str());
    }

    #[test]
    fn kid_differs_for_different_public_keys() {
        let a = Kid::compute(&[1u8; 32], &[2u8; 64]);
        let b = Kid::compute(&[1u8; 32], &[3u8; 64]);
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn kid_differs_across_independent_key_generations() {
        let a = SigningKeys::generate_ephemeral().expect("keys a");
        let b = SigningKeys::generate_ephemeral().expect("keys b");
        assert_ne!(a.kid().as_str(), b.kid().as_str());
    }

    #[test]
    fn from_encoded_roundtrips_generated_keys() {
        let ed_seed = [0x11u8; 32];
        let (_, ml_seed) = super::super::sign_mldsa::MlDsaSigner::generate().expect("mldsa");
        let ed_b64 = B64.encode(ed_seed);
        let ml_b64 = B64.encode(ml_seed);
        let once = SigningKeys::from_encoded(&ed_b64, &ml_b64).expect("once");
        let twice = SigningKeys::from_encoded(&ed_b64, &ml_b64).expect("twice");
        // Same seeds MUST yield the same kid (deterministic bootstrap).
        assert_eq!(once.kid().as_str(), twice.kid().as_str());
    }

    #[test]
    fn from_encoded_rejects_bad_base64() {
        let result = SigningKeys::from_encoded("not base64!!!", "also not base64!!!");
        assert!(result.is_err(), "bad base64 must fail");
        let err = result.err().expect("err branch");
        assert!(matches!(err, super::super::error::TokenError::Base64));
    }
}
