//! Password-based key derivation for wrapping keys.
//!
//! Implements the KDF side of ADR-0004 §4: a user-memorable secret
//! (the BIP-39 recovery passphrase, or in dev-mode a plain password)
//! is stretched into a 256-bit [`WrappingKey`] via Argon2id. The
//! resulting wrapping key then feeds the AEAD primitive in
//! [`crate::wrap`].
//!
//! # Parameter choice
//!
//! [`PassphraseParams::DEFAULT`] tracks the OWASP 2024 minimum for
//! Argon2id on server-class hardware: 19 MiB memory, 2 iterations,
//! parallelism 1. Deployments with harder security requirements
//! (Socio / sovereign mode) are expected to raise these at the call
//! site.
//!
//! # Salt handling
//!
//! Salts are caller-provided. This crate does not decide where to
//! store them — that is a job for `konekto-db`. The minimum salt
//! length enforced here is 16 bytes (Argon2 accepts as low as 8,
//! but 16 is the threshold below which a dedicated-per-user salt
//! no longer meaningfully resists rainbow-table precomputation).

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::error::Error;
use crate::key::KEY_SIZE;
use crate::wrap::WrappingKey;

/// Minimum accepted salt length, in bytes.
///
/// Argon2id itself accepts 8 bytes; this crate enforces 16 to bind
/// the wrapping key firmly to a per-user salt and to match the
/// size of the salts the `konekto-db` layer will store.
pub const MIN_SALT_LEN: usize = 16;

/// Minimum accepted passphrase length, in bytes.
///
/// Argon2 has no intrinsic minimum, so this is an application-level
/// sanity floor that rejects empty or one-byte inputs at the
/// boundary.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Argon2id tuning parameters.
///
/// Fields are private so every `PassphraseParams` carrying a value
/// has been validated via [`Self::new`] or is the immutable
/// [`Self::DEFAULT`].
#[derive(Clone, Copy, Debug)]
pub struct PassphraseParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl PassphraseParams {
    /// OWASP 2024 minimum for Argon2id on server-class hardware:
    /// 19 MiB memory, 2 iterations, parallelism 1.
    pub const DEFAULT: Self = Self {
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    };

    /// Build a parameter set and validate it against Argon2's
    /// accepted ranges.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdfInput`] if Argon2 rejects the
    /// combination (e.g., memory below `8 * parallelism`).
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, Error> {
        Params::new(memory_kib, iterations, parallelism, Some(KEY_SIZE))
            .map_err(|_| Error::InvalidKdfInput)?;
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Memory cost, in KiB.
    #[must_use]
    pub fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Number of passes over memory.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Parallelism (number of lanes).
    #[must_use]
    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    /// Derive a 256-bit [`WrappingKey`] from `passphrase` + `salt`.
    ///
    /// Uses Argon2id with the parameters carried by `self`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKdfInput`] if the passphrase is shorter
    ///   than [`MIN_PASSPHRASE_LEN`] or the salt is shorter than
    ///   [`MIN_SALT_LEN`].
    /// - [`Error::KdfFailed`] if the underlying Argon2
    ///   implementation fails (allocation or environment error).
    pub fn derive_wrapping_key(
        &self,
        passphrase: &[u8],
        salt: &[u8],
    ) -> Result<WrappingKey, Error> {
        if passphrase.len() < MIN_PASSPHRASE_LEN {
            return Err(Error::InvalidKdfInput);
        }
        if salt.len() < MIN_SALT_LEN {
            return Err(Error::InvalidKdfInput);
        }

        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEY_SIZE),
        )
        .map_err(|_| Error::InvalidKdfInput)?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; KEY_SIZE];
        let result = argon.hash_password_into(passphrase, salt, &mut out);
        if result.is_err() {
            out.zeroize();
            return Err(Error::KdfFailed);
        }

        let key = WrappingKey::from_bytes(out);
        out.zeroize();
        Ok(key)
    }
}

impl Default for PassphraseParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::{PassphraseParams, MIN_PASSPHRASE_LEN, MIN_SALT_LEN};
    use crate::error::Error;
    use crate::key::RootKey;

    // Cheap params for fast tests — NOT for production. Argon2 at
    // DEFAULT costs ~50 ms per derivation, which makes a test suite
    // unreasonably slow. These parameters satisfy Argon2's minimum
    // acceptance ranges and exercise the same code paths.
    fn fast_params() -> PassphraseParams {
        PassphraseParams::new(8, 1, 1).expect("fast params accepted by argon2")
    }

    #[test]
    fn default_params_match_owasp_2024_minimum() {
        let p = PassphraseParams::DEFAULT;
        assert_eq!(p.memory_kib(), 19_456);
        assert_eq!(p.iterations(), 2);
        assert_eq!(p.parallelism(), 1);
    }

    #[test]
    fn new_rejects_parameters_argon2_refuses() {
        // memory must be at least 8 * parallelism, so memory=1,
        // parallelism=4 should fail.
        let r = PassphraseParams::new(1, 1, 4);
        assert!(matches!(r, Err(Error::InvalidKdfInput)));
    }

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let params = fast_params();
        let passphrase = b"correct horse battery staple";
        let salt = b"konekto-test-salt-0001";
        let a = params
            .derive_wrapping_key(passphrase, salt)
            .expect("derive a");
        let b = params
            .derive_wrapping_key(passphrase, salt)
            .expect("derive b");
        // WrappingKey isn't directly comparable; use it to wrap and
        // unwrap a RootKey via the other key — if the keys differ,
        // unwrap will fail with auth error.
        let root = RootKey::from_bytes_for_test([0x42; 32]);
        let wrapped = root.wrap(&a);
        let restored = RootKey::unwrap(&wrapped, &b).expect("same-key unwrap");
        let k_a = root.derive::<crate::context::Vivo>();
        let k_b = restored.derive::<crate::context::Vivo>();
        assert_eq!(k_a.as_bytes(), k_b.as_bytes());
    }

    #[test]
    fn derive_separates_by_salt() {
        let params = fast_params();
        let passphrase = b"correct horse battery staple";
        let a = params
            .derive_wrapping_key(passphrase, b"konekto-test-salt-aaaa")
            .expect("derive a");
        let b = params
            .derive_wrapping_key(passphrase, b"konekto-test-salt-bbbb")
            .expect("derive b");
        // Different salts must produce different wrapping keys.
        // Confirm by checking a wrap-under-a does not unwrap under-b.
        let root = RootKey::from_bytes_for_test([0x55; 32]);
        let wrapped = root.wrap(&a);
        let res = RootKey::unwrap(&wrapped, &b);
        assert!(matches!(res, Err(Error::UnwrapAuthFailed)));
    }

    #[test]
    fn derive_separates_by_passphrase() {
        let params = fast_params();
        let salt = b"konekto-test-salt-0001";
        let a = params
            .derive_wrapping_key(b"passphrase-one!!", salt)
            .expect("derive a");
        let b = params
            .derive_wrapping_key(b"passphrase-two!!", salt)
            .expect("derive b");
        let root = RootKey::from_bytes_for_test([0x77; 32]);
        let wrapped = root.wrap(&a);
        let res = RootKey::unwrap(&wrapped, &b);
        assert!(matches!(res, Err(Error::UnwrapAuthFailed)));
    }

    #[test]
    fn derive_rejects_short_passphrase() {
        let params = fast_params();
        let short = vec![b'x'; MIN_PASSPHRASE_LEN - 1];
        let salt = b"konekto-test-salt-0001";
        let r = params.derive_wrapping_key(&short, salt);
        assert!(matches!(r, Err(Error::InvalidKdfInput)));
    }

    #[test]
    fn derive_rejects_short_salt() {
        let params = fast_params();
        let passphrase = b"long-enough-passphrase";
        let short_salt = vec![b's'; MIN_SALT_LEN - 1];
        let r = params.derive_wrapping_key(passphrase, &short_salt);
        assert!(matches!(r, Err(Error::InvalidKdfInput)));
    }

    #[test]
    fn default_trait_yields_default_const() {
        let a = PassphraseParams::default();
        let b = PassphraseParams::DEFAULT;
        assert_eq!(a.memory_kib(), b.memory_kib());
        assert_eq!(a.iterations(), b.iterations());
        assert_eq!(a.parallelism(), b.parallelism());
    }
}
