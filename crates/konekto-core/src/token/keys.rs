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

/// Environment variable holding zero or more retired hybrid verifier
/// bundles, each `<ed25519_pk_b64>:<mldsa_pk_b64>`, comma-separated.
///
/// Retired bundles verify access tokens minted by a previous primary
/// signer; they never sign new tokens. Only public keys are carried —
/// even a leak of this env var cannot forge new tokens.
///
/// See ADR-0009 §4 for the operator rotation playbook.
pub const ENV_RETIRED_VERIFIERS: &str = "TOKEN_RETIRED_VERIFIERS";

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

    /// Reconstruct a verifier bundle from raw public-key bytes.
    ///
    /// Used to load retired bundles whose secrets the operator has
    /// purposely dropped (ADR-0009 §3): only the public bytes are
    /// needed to keep verifying old tokens, and shipping just the
    /// public bytes minimises secret-material exposure.
    ///
    /// # Errors
    ///
    /// - [`TokenError::EnvConfig`] if `ed25519_pk` is not 32 bytes.
    /// - [`TokenError::EnvConfig`] (via the underlying ML-DSA verifier
    ///   constructor) if `mldsa_pk` is not 1952 bytes.
    pub fn from_public_bytes(ed25519_pk: &[u8], mldsa_pk: &[u8]) -> Result<Self, TokenError> {
        if ed25519_pk.len() != ED25519_PUBKEY_LEN {
            return Err(TokenError::EnvConfig);
        }
        let mut ed_pk = [0u8; ED25519_PUBKEY_LEN];
        ed_pk.copy_from_slice(ed25519_pk);
        let ed = Ed25519Verifier::from_public_key(ed_pk);
        let ml = MlDsaVerifier::from_public_bytes(mldsa_pk)?;
        Ok(Self::new(ed, ml))
    }

    /// The `kid` these verifiers will accept in a token header.
    #[must_use]
    pub fn kid(&self) -> &Kid {
        &self.kid
    }

    /// Borrow the raw Ed25519 public-key bytes (32 bytes).
    ///
    /// Exposed so the JWKS publication path
    /// ([`crate::token::jwks::to_jwk_set`]) can encode the `x` field of
    /// the JWK without leaking the rest of the verifier surface.
    #[must_use]
    pub fn ed25519_public_key(&self) -> &[u8; ED25519_PUBKEY_LEN] {
        self.ed25519.public_key()
    }

    /// Encoded ML-DSA-65 verifying key (1952 bytes).
    ///
    /// Exposed for the same JWKS publication reason as
    /// [`Self::ed25519_public_key`]. Returns an owned `Vec<u8>` because
    /// the underlying crate stores the verifying key in its native
    /// algebraic form, not as a contiguous byte slice.
    #[must_use]
    pub fn mldsa_public_key(&self) -> Vec<u8> {
        self.mldsa.verifying_key_bytes()
    }

    pub(crate) fn ed25519(&self) -> &Ed25519Verifier {
        &self.ed25519
    }

    pub(crate) fn mldsa(&self) -> &MlDsaVerifier {
        &self.mldsa
    }
}

/// A primary verifying bundle plus zero or more retired bundles.
///
/// Retired bundles verify tokens minted by a previous primary; the
/// signer never uses them. The keyring is constructed at boot from
/// env vars (ADR-0006 §3 + ADR-0009 §4) and held by [`super::jws::TokenVerifier`].
///
/// All bundles in the keyring must carry distinct `kid`s — collisions
/// are an operator misconfiguration and are rejected at construction.
#[derive(Clone)]
pub struct Keyring {
    primary: VerifyingKeys,
    retired: Vec<VerifyingKeys>,
}

impl Keyring {
    /// Build a keyring with `primary` as the only entry. Retired
    /// bundles are added with [`Self::with_retired`].
    #[must_use]
    pub fn new(primary: VerifyingKeys) -> Self {
        Self {
            primary,
            retired: Vec::new(),
        }
    }

    /// Attach retired verifying bundles. Returns `EnvConfig` if any
    /// `kid` collides — primary vs retired, or retired vs retired —
    /// since two distinct bundles cannot share a `kid` (the `kid` is
    /// a deterministic digest of the two public keys, so a collision
    /// would mean the bundles aren't distinct after all).
    ///
    /// # Errors
    ///
    /// - [`TokenError::EnvConfig`] on any `kid` collision.
    pub fn with_retired(mut self, retired: Vec<VerifyingKeys>) -> Result<Self, TokenError> {
        let mut seen: Vec<&str> = Vec::with_capacity(1 + retired.len());
        seen.push(self.primary.kid().as_str());
        for r in &retired {
            let k = r.kid().as_str();
            if seen.contains(&k) {
                return Err(TokenError::EnvConfig);
            }
            seen.push(k);
        }
        self.retired = retired;
        Ok(self)
    }

    /// The primary verifying bundle. Only this bundle's `kid` is
    /// stamped into freshly issued tokens.
    #[must_use]
    pub fn primary(&self) -> &VerifyingKeys {
        &self.primary
    }

    /// The retired verifying bundles, in insertion order.
    #[must_use]
    pub fn retired(&self) -> &[VerifyingKeys] {
        &self.retired
    }

    /// Iterate over every bundle in the keyring, primary first.
    pub fn all(&self) -> impl Iterator<Item = &VerifyingKeys> {
        std::iter::once(&self.primary).chain(self.retired.iter())
    }

    /// Look up a bundle by its `kid`. Returns `None` if no bundle in
    /// the keyring carries that `kid`.
    #[must_use]
    pub fn find(&self, kid: &str) -> Option<&VerifyingKeys> {
        self.all().find(|b| b.kid().as_str() == kid)
    }
}

impl From<VerifyingKeys> for Keyring {
    fn from(primary: VerifyingKeys) -> Self {
        Self::new(primary)
    }
}

#[cfg(test)]
mod tests {
    use super::{Keyring, Kid, SigningKeys};
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

    #[test]
    fn keyring_with_only_primary_finds_primary_kid_and_misses_others() {
        let keys = SigningKeys::generate_ephemeral().expect("keys");
        let primary = keys.verifying_keys();
        let primary_kid = primary.kid().as_str().to_string();
        let ring = Keyring::new(primary);
        assert!(ring.find(&primary_kid).is_some());
        assert!(ring.find("nonexistent-kid").is_none());
        assert_eq!(ring.retired().len(), 0);
        assert_eq!(ring.all().count(), 1);
    }

    #[test]
    fn keyring_with_retired_finds_both_primary_and_retired_kids() {
        let primary_keys = SigningKeys::generate_ephemeral().expect("primary");
        let retired_keys = SigningKeys::generate_ephemeral().expect("retired");
        let primary = primary_keys.verifying_keys();
        let retired = retired_keys.verifying_keys();
        let primary_kid = primary.kid().as_str().to_string();
        let retired_kid = retired.kid().as_str().to_string();
        let ring = Keyring::new(primary)
            .with_retired(vec![retired])
            .expect("distinct kids accepted");
        assert!(ring.find(&primary_kid).is_some());
        assert!(ring.find(&retired_kid).is_some());
        assert_eq!(ring.all().count(), 2);
    }

    #[test]
    fn keyring_iteration_yields_primary_first() {
        let primary_keys = SigningKeys::generate_ephemeral().expect("primary");
        let retired_keys = SigningKeys::generate_ephemeral().expect("retired");
        let primary_kid = primary_keys.verifying_keys().kid().as_str().to_string();
        let ring = Keyring::new(primary_keys.verifying_keys())
            .with_retired(vec![retired_keys.verifying_keys()])
            .expect("distinct");
        let kids: Vec<String> = ring.all().map(|b| b.kid().as_str().to_string()).collect();
        assert_eq!(
            kids[0], primary_kid,
            "primary must be first in iteration order",
        );
    }

    #[test]
    fn keyring_rejects_kid_collision_between_primary_and_retired() {
        // Same SigningKeys → same VerifyingKeys → same kid.
        let keys = SigningKeys::generate_ephemeral().expect("keys");
        let primary = keys.verifying_keys();
        let retired_dup = keys.verifying_keys();
        let result = Keyring::new(primary).with_retired(vec![retired_dup]);
        assert!(
            result.is_err(),
            "primary kid must not collide with a retired bundle's kid",
        );
    }

    #[test]
    fn keyring_rejects_kid_collision_among_retired_entries() {
        let primary_keys = SigningKeys::generate_ephemeral().expect("primary");
        let dup_keys = SigningKeys::generate_ephemeral().expect("dup");
        let retired_a = dup_keys.verifying_keys();
        let retired_b = dup_keys.verifying_keys();
        let result =
            Keyring::new(primary_keys.verifying_keys()).with_retired(vec![retired_a, retired_b]);
        assert!(result.is_err(), "two retired bundles must not share a kid");
    }

    #[test]
    fn from_public_bytes_round_trips_a_generated_bundle() {
        let keys = SigningKeys::generate_ephemeral().expect("keys");
        let v = keys.verifying_keys();
        let ed_pk = *v.ed25519_public_key();
        let ml_pk = v.mldsa_public_key();
        let reconstructed =
            super::VerifyingKeys::from_public_bytes(&ed_pk, &ml_pk).expect("reconstruct");
        assert_eq!(reconstructed.kid().as_str(), v.kid().as_str());
    }

    #[test]
    fn from_public_bytes_rejects_wrong_length_ed25519() {
        let keys = SigningKeys::generate_ephemeral().expect("keys");
        let ml_pk = keys.verifying_keys().mldsa_public_key();
        let result = super::VerifyingKeys::from_public_bytes(&[0u8; 31], &ml_pk);
        assert!(result.is_err());
    }

    #[test]
    fn verifying_keys_implements_into_keyring() {
        let keys = SigningKeys::generate_ephemeral().expect("keys");
        let v = keys.verifying_keys();
        let kid = v.kid().as_str().to_string();
        let ring: Keyring = v.into();
        assert!(ring.find(&kid).is_some());
        assert_eq!(ring.retired().len(), 0);
    }
}
