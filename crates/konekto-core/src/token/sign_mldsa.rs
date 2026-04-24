//! ML-DSA-65 signer / verifier wrapping the `ml-dsa` crate (ADR-0001).
//!
//! Kept isolated so the eventual bump from `0.1.0-rc.x` → `1.0` only
//! needs to touch this module.
//!
//! ML-DSA-65 signing keys are stored as their 32-byte seed (ADR-0006
//! §6): this is the canonical FIPS 204 representation, is what
//! round-trips through env-var bootstrap, and is what
//! [`ml_dsa::SigningKey::to_seed`] returns.

use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyGen, MlDsa65, Signature as MlDsaSig, SigningKey,
    VerifyingKey, B32,
};

use super::error::TokenError;
use crate::random::fill_random;

/// Length of an ML-DSA-65 canonical seed (= signing-key wire form), in bytes.
pub const MLDSA_SEED_LEN: usize = 32;

/// Length of an ML-DSA-65 encoded verifying key, in bytes.
pub const MLDSA_PUBKEY_LEN: usize = 1952;

/// ML-DSA-65 signer: the seed-backed canonical signing key plus its
/// derived verifying key.
pub struct MlDsaSigner {
    signing_key: SigningKey<MlDsa65>,
    verifying_key: VerifyingKey<MlDsa65>,
    seed: [u8; MLDSA_SEED_LEN],
}

impl MlDsaSigner {
    /// Rebuild a signer from its 32-byte seed.
    pub fn from_seed_bytes(seed_bytes: &[u8]) -> Result<Self, TokenError> {
        if seed_bytes.len() != MLDSA_SEED_LEN {
            return Err(TokenError::EnvConfig);
        }
        let mut seed = [0u8; MLDSA_SEED_LEN];
        seed.copy_from_slice(seed_bytes);
        let seed_b32: B32 = seed.into();
        let signing_key = MlDsa65::from_seed(&seed_b32);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
            seed,
        })
    }

    /// Draw a fresh ML-DSA-65 seed from the system CSPRNG and return
    /// both the signer and the seed bytes (so an ephemeral signer can
    /// log a warning + optionally persist it).
    pub fn generate() -> Result<(Self, [u8; MLDSA_SEED_LEN]), TokenError> {
        let mut seed = [0u8; MLDSA_SEED_LEN];
        fill_random(&mut seed);
        let signer = Self::from_seed_bytes(&seed)?;
        Ok((signer, seed))
    }

    /// The 32-byte seed (canonical signing-key wire form).
    #[must_use]
    pub fn seed(&self) -> &[u8; MLDSA_SEED_LEN] {
        &self.seed
    }

    /// Return a fresh verifier holding this signer's public key.
    #[must_use]
    pub fn verifier(&self) -> MlDsaVerifier {
        MlDsaVerifier {
            verifying_key: self.verifying_key.clone(),
        }
    }

    /// Encoded verifying-key bytes.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        let encoded: EncodedVerifyingKey<MlDsa65> = self.verifying_key.encode();
        encoded.as_slice().to_vec()
    }

    /// Produce an ML-DSA-65 signature over `msg`.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, TokenError> {
        let sig: MlDsaSig<MlDsa65> = self
            .signing_key
            .try_sign(msg)
            .map_err(|_| TokenError::SigningFailed)?;
        let encoded: EncodedSignature<MlDsa65> = sig.encode();
        Ok(encoded.as_slice().to_vec())
    }
}

/// ML-DSA-65 verifier: wraps a [`VerifyingKey<MlDsa65>`] (the crate's
/// canonical public-key form).
#[derive(Clone)]
pub struct MlDsaVerifier {
    verifying_key: VerifyingKey<MlDsa65>,
}

impl MlDsaVerifier {
    /// Reconstruct a verifier from encoded verifying-key bytes.
    pub fn from_public_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        let encoded: &EncodedVerifyingKey<MlDsa65> =
            bytes.try_into().map_err(|_| TokenError::EnvConfig)?;
        let verifying_key = VerifyingKey::<MlDsa65>::decode(encoded);
        Ok(Self { verifying_key })
    }

    /// Encoded verifying-key bytes.
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.encode().as_slice().to_vec()
    }

    /// Verify an ML-DSA-65 signature.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), TokenError> {
        let encoded: &EncodedSignature<MlDsa65> =
            sig.try_into().map_err(|_| TokenError::InvalidSignature)?;
        let sig_decoded =
            MlDsaSig::<MlDsa65>::decode(encoded).ok_or(TokenError::InvalidSignature)?;
        self.verifying_key
            .verify(msg, &sig_decoded)
            .map_err(|_| TokenError::InvalidSignature)
    }
}
