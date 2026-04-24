//! Ed25519 signer / verifier wrapping `aws-lc-rs` (ADR-0001).
//!
//! Kept thin so the surface of the signature stack this crate
//! exposes is stable even if the backend crate changes.

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use super::error::TokenError;

/// Length of an Ed25519 public key, in bytes.
pub const ED25519_PUBKEY_LEN: usize = 32;

/// Length of an Ed25519 seed, in bytes.
pub const ED25519_SEED_LEN: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Ed25519 signer, reconstructed from a 32-byte seed.
pub struct Ed25519Signer {
    keypair: Ed25519KeyPair,
    public_key: [u8; ED25519_PUBKEY_LEN],
}

impl Ed25519Signer {
    /// Rebuild a signer from its 32-byte seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self, TokenError> {
        if seed.len() != ED25519_SEED_LEN {
            return Err(TokenError::EnvConfig);
        }
        let keypair =
            Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| TokenError::EnvConfig)?;
        let mut public_key = [0u8; ED25519_PUBKEY_LEN];
        public_key.copy_from_slice(keypair.public_key().as_ref());
        Ok(Self {
            keypair,
            public_key,
        })
    }

    /// Draw a fresh seed from the system CSPRNG and return both the
    /// resulting signer and the seed bytes.
    ///
    /// The seed is returned so callers that want to persist or log
    /// ephemeral secrets (for warning banners in dev mode) can do so.
    /// Callers are responsible for zeroizing the seed copy when they
    /// no longer need it.
    pub fn generate() -> Result<(Self, [u8; ED25519_SEED_LEN]), TokenError> {
        let bytes = crate::random_bytes(ED25519_SEED_LEN);
        let mut seed = [0u8; ED25519_SEED_LEN];
        seed.copy_from_slice(&bytes);
        let signer = Self::from_seed(&seed)?;
        Ok((signer, seed))
    }

    /// Borrow the Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; ED25519_PUBKEY_LEN] {
        &self.public_key
    }

    /// Produce an Ed25519 signature over `msg`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.keypair.sign(msg).as_ref().to_vec()
    }
}

/// Ed25519 verifier with a 32-byte public key.
#[derive(Clone)]
pub struct Ed25519Verifier {
    public_key: [u8; ED25519_PUBKEY_LEN],
}

impl Ed25519Verifier {
    /// Wrap a caller-supplied public key.
    #[must_use]
    pub fn from_public_key(pk: [u8; ED25519_PUBKEY_LEN]) -> Self {
        Self { public_key: pk }
    }

    /// Borrow the raw public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; ED25519_PUBKEY_LEN] {
        &self.public_key
    }

    /// Verify `sig` against `msg` under this public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), TokenError> {
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(msg, sig)
            .map_err(|_| TokenError::InvalidSignature)
    }
}
