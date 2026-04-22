//! AEAD wrapping of the [`crate::RootKey`].
//!
//! This module provides the primitive on top of which every
//! credential-bound storage path is built: `WebAuthn` PRF wrapping
//! per authenticator (ADR-0004 §3), Argon2id wrapping for the BIP-39
//! recovery code (ADR-0004 §4), and any future opt-in wrappers (HSM,
//! KMS, password-backed for development).
//!
//! # Construction
//!
//! A [`WrappingKey`] is a 256-bit opaque secret. Callers obtain one
//! by passing 32 bytes produced by an upstream KDF / PRF
//! ([`WrappingKey::from_bytes`]) or by drawing one from the system
//! CSPRNG ([`WrappingKey::generate`]). The type is move-only,
//! `Debug`-redacted, and zeroized on drop.
//!
//! # Wire format (v1)
//!
//! A [`WrappedRootKey`] serializes to a single byte string with a
//! fixed 61-byte layout:
//!
//! ```text
//! byte 0        : version tag (0x01 = AES-256-GCM v1)
//! bytes 1..13   : 96-bit GCM nonce (random per wrap)
//! bytes 13..61  : AES-256-GCM ciphertext (32 B) || tag (16 B)
//! ```
//!
//! AAD is the fixed ASCII string `konekto.rootkey.wrap.v1`. It binds
//! the ciphertext to this primitive and this version so that a
//! future wire format cannot be confused for a v1 blob and vice
//! versa (a v2 implementation MUST choose a different AAD and
//! version byte).

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

use crate::error::Error;
use crate::key::{RootKey, KEY_SIZE};

/// Version byte for the current wrapped-root-key wire format.
///
/// Bumping this constant is a breaking change: a different version
/// MUST also use a different [`WRAP_AAD`] so AEAD authentication
/// rejects cross-version ciphertext reinterpretation.
const WRAP_VERSION: u8 = 0x01;

/// AEAD associated data for the v1 wrapped-root-key format.
///
/// Binds the ciphertext to the primitive (root-key wrapping), the
/// algorithm family, and the version. Any future variant MUST choose
/// a distinct AAD.
const WRAP_AAD: &[u8] = b"konekto.rootkey.wrap.v1";

/// AES-256-GCM authentication tag length.
const TAG_LEN: usize = 16;

/// Offset of the nonce in the serialized wire form.
const NONCE_OFFSET: usize = 1;
/// First byte after the nonce (also the ciphertext-plus-tag start).
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

/// Total serialized length of a v1 wrapped root key.
const WRAPPED_LEN: usize = CIPHERTEXT_OFFSET + KEY_SIZE + TAG_LEN;

/// A 256-bit symmetric key used to wrap a [`RootKey`] at rest.
///
/// In production, a `WrappingKey` is derived from a credential-bound
/// secret (`WebAuthn` PRF output, Argon2id of a recovery code, an
/// HSM handle). This module is agnostic to the source: it accepts
/// any 32-byte secret via [`WrappingKey::from_bytes`].
///
/// Like [`RootKey`], the type is:
/// - move-only (no `Clone`, no `Copy`),
/// - non-serializable,
/// - `Debug`-redacted,
/// - zeroized on drop.
pub struct WrappingKey {
    material: [u8; KEY_SIZE],
}

impl WrappingKey {
    /// Wrap existing 32-byte key material.
    ///
    /// Takes ownership of the caller's buffer to encourage the
    /// caller to `zeroize` any intermediate copies. The provided
    /// array is copied into the `WrappingKey`'s own buffer; the
    /// caller's copy is not zeroized by this constructor.
    #[must_use]
    pub fn from_bytes(material: [u8; KEY_SIZE]) -> Self {
        Self { material }
    }

    /// Draw a fresh wrapping key from the system CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics if the system CSPRNG is unavailable. Unrecoverable.
    #[must_use]
    pub fn generate() -> Self {
        let mut material = [0u8; KEY_SIZE];
        SystemRandom::new()
            .fill(&mut material)
            .expect("system CSPRNG failed");
        Self { material }
    }
}

impl core::fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WrappingKey")
            .field("material", &"<redacted>")
            .finish()
    }
}

impl Drop for WrappingKey {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

/// An opaque, serializable blob carrying a `RootKey` encrypted under
/// a [`WrappingKey`].
///
/// Callers treat this as an opaque byte string suitable for
/// persistence. Only the originating pair
/// `(root_key, wrapping_key)` can produce a blob that
/// [`RootKey::unwrap`] will accept; any tampering or wrong wrapping
/// key causes [`Error::UnwrapAuthFailed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedRootKey {
    bytes: [u8; WRAPPED_LEN],
}

impl WrappedRootKey {
    /// Borrow the serialized wire representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parse a serialized wrapped-root-key blob.
    ///
    /// Validates the total length and the version byte. AEAD
    /// authentication happens later, inside [`RootKey::unwrap`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidWrappedFormat`] if the buffer is the
    /// wrong length or carries an unknown version byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != WRAPPED_LEN {
            return Err(Error::InvalidWrappedFormat);
        }
        if bytes[0] != WRAP_VERSION {
            return Err(Error::InvalidWrappedFormat);
        }
        let mut buf = [0u8; WRAPPED_LEN];
        buf.copy_from_slice(bytes);
        Ok(Self { bytes: buf })
    }
}

impl RootKey {
    /// Encrypt this `RootKey` under `wrapping_key`.
    ///
    /// A fresh 96-bit nonce is drawn from the system CSPRNG for each
    /// call, so wrapping the same `(root, wrapping_key)` twice
    /// produces two distinct ciphertexts.
    ///
    /// # Panics
    ///
    /// Panics if the system CSPRNG fails or if `aws-lc-rs`'s AEAD
    /// seal returns an error. Both conditions indicate a
    /// catastrophic environment failure that must abort the calling
    /// flow.
    #[must_use]
    pub fn wrap(&self, wrapping_key: &WrappingKey) -> WrappedRootKey {
        let unbound = UnboundKey::new(&AES_256_GCM, &wrapping_key.material)
            .expect("AES-256-GCM accepts any 32-byte key");
        let sealing = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .expect("system CSPRNG failed");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = Vec::with_capacity(KEY_SIZE + TAG_LEN);
        in_out.extend_from_slice(self.material_for_wrap());
        sealing
            .seal_in_place_append_tag(nonce, Aad::from(WRAP_AAD), &mut in_out)
            .expect("AES-256-GCM seal cannot fail for well-formed inputs");
        debug_assert_eq!(in_out.len(), KEY_SIZE + TAG_LEN);

        let mut bytes = [0u8; WRAPPED_LEN];
        bytes[0] = WRAP_VERSION;
        bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET].copy_from_slice(&nonce_bytes);
        bytes[CIPHERTEXT_OFFSET..].copy_from_slice(&in_out);
        // Scrub the heap copy of the plaintext-turned-ciphertext buffer
        // (ciphertext itself is not sensitive, but the buffer briefly
        // held plaintext).
        in_out.zeroize();

        WrappedRootKey { bytes }
    }

    /// Decrypt and authenticate a `WrappedRootKey`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidWrappedFormat`] if the blob's version byte
    ///   does not match this implementation.
    /// - [`Error::UnwrapAuthFailed`] if AEAD authentication fails
    ///   (wrong wrapping key, tampered ciphertext, wrong AAD).
    pub fn unwrap(wrapped: &WrappedRootKey, wrapping_key: &WrappingKey) -> Result<RootKey, Error> {
        if wrapped.bytes[0] != WRAP_VERSION {
            return Err(Error::InvalidWrappedFormat);
        }

        let unbound = UnboundKey::new(&AES_256_GCM, &wrapping_key.material)
            .expect("AES-256-GCM accepts any 32-byte key");
        let opening = LessSafeKey::new(unbound);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&wrapped.bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET]);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = wrapped.bytes[CIPHERTEXT_OFFSET..].to_vec();
        let plaintext = opening
            .open_in_place(nonce, Aad::from(WRAP_AAD), &mut in_out)
            .map_err(|_| Error::UnwrapAuthFailed)?;

        if plaintext.len() != KEY_SIZE {
            // Should be impossible: AES-256-GCM on a 48-byte input
            // produces exactly 32 bytes of plaintext. Defend anyway.
            in_out.zeroize();
            return Err(Error::InvalidWrappedFormat);
        }
        let mut material = [0u8; KEY_SIZE];
        material.copy_from_slice(plaintext);
        in_out.zeroize();

        Ok(RootKey::from_material(material))
    }
}

#[cfg(test)]
mod tests {
    use super::{WrappedRootKey, WrappingKey, WRAPPED_LEN, WRAP_VERSION};
    use crate::error::Error;
    use crate::key::{RootKey, KEY_SIZE};

    fn fixed_wrapping_key(byte: u8) -> WrappingKey {
        WrappingKey::from_bytes([byte; KEY_SIZE])
    }

    #[test]
    fn round_trip_restores_material() {
        let root = RootKey::from_bytes_for_test([0x5A; KEY_SIZE]);
        let wk = fixed_wrapping_key(0xA5);
        let wrapped = root.wrap(&wk);

        let restored = RootKey::unwrap(&wrapped, &wk).expect("unwrap");
        // RootKey does not expose material publicly; derive a context
        // key from both and assert derivations agree.
        let k_a = root.derive::<crate::context::Vivo>();
        let k_b = restored.derive::<crate::context::Vivo>();
        assert_eq!(k_a.as_bytes(), k_b.as_bytes());
    }

    #[test]
    fn wrap_is_fresh_each_call() {
        let root = RootKey::from_bytes_for_test([0x11; KEY_SIZE]);
        let wk = fixed_wrapping_key(0x22);
        let a = root.wrap(&wk);
        let b = root.wrap(&wk);
        assert_ne!(a.as_bytes(), b.as_bytes(), "nonce must be fresh per wrap");
    }

    #[test]
    fn wrapped_blob_has_expected_length_and_version() {
        let root = RootKey::from_bytes_for_test([0x33; KEY_SIZE]);
        let wk = fixed_wrapping_key(0x44);
        let wrapped = root.wrap(&wk);
        assert_eq!(wrapped.as_bytes().len(), WRAPPED_LEN);
        assert_eq!(wrapped.as_bytes()[0], WRAP_VERSION);
    }

    #[test]
    fn unwrap_with_wrong_key_fails_with_auth_error() {
        let root = RootKey::from_bytes_for_test([0x77; KEY_SIZE]);
        let wk = fixed_wrapping_key(0x11);
        let wrong = fixed_wrapping_key(0x22);
        let wrapped = root.wrap(&wk);
        let res = RootKey::unwrap(&wrapped, &wrong);
        assert!(matches!(res, Err(Error::UnwrapAuthFailed)));
    }

    #[test]
    fn unwrap_of_tampered_ciphertext_fails() {
        let root = RootKey::from_bytes_for_test([0x99; KEY_SIZE]);
        let wk = fixed_wrapping_key(0x88);
        let mut wrapped = root.wrap(&wk);
        // Flip one bit inside the ciphertext/tag region.
        wrapped.bytes[WRAPPED_LEN - 5] ^= 0x01;
        let res = RootKey::unwrap(&wrapped, &wk);
        assert!(matches!(res, Err(Error::UnwrapAuthFailed)));
    }

    #[test]
    fn unwrap_of_tampered_nonce_fails() {
        let root = RootKey::from_bytes_for_test([0x66; KEY_SIZE]);
        let wk = fixed_wrapping_key(0x55);
        let mut wrapped = root.wrap(&wk);
        wrapped.bytes[1] ^= 0x01;
        let res = RootKey::unwrap(&wrapped, &wk);
        assert!(matches!(res, Err(Error::UnwrapAuthFailed)));
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(matches!(
            WrappedRootKey::from_bytes(&[WRAP_VERSION; WRAPPED_LEN - 1]),
            Err(Error::InvalidWrappedFormat)
        ));
        assert!(matches!(
            WrappedRootKey::from_bytes(&[WRAP_VERSION; WRAPPED_LEN + 1]),
            Err(Error::InvalidWrappedFormat)
        ));
    }

    #[test]
    fn from_bytes_rejects_unknown_version() {
        let mut buf = [0u8; WRAPPED_LEN];
        buf[0] = 0xFF; // not WRAP_VERSION
        assert!(matches!(
            WrappedRootKey::from_bytes(&buf),
            Err(Error::InvalidWrappedFormat)
        ));
    }

    #[test]
    fn from_bytes_round_trip_preserves_wire_form() {
        let root = RootKey::from_bytes_for_test([0xAB; KEY_SIZE]);
        let wk = fixed_wrapping_key(0xCD);
        let wrapped = root.wrap(&wk);
        let reparsed =
            WrappedRootKey::from_bytes(wrapped.as_bytes()).expect("valid wire form round-trips");
        assert_eq!(reparsed, wrapped);

        let restored = RootKey::unwrap(&reparsed, &wk).expect("unwrap after round-trip");
        let k_a = root.derive::<crate::context::Laboro>();
        let k_b = restored.derive::<crate::context::Laboro>();
        assert_eq!(k_a.as_bytes(), k_b.as_bytes());
    }

    #[test]
    fn wrapping_key_generate_is_fresh() {
        let a = WrappingKey::generate();
        let b = WrappingKey::generate();
        assert_ne!(a.material, b.material);
    }

    #[test]
    fn wrapping_key_debug_redacts_material() {
        let wk = fixed_wrapping_key(0xEE);
        let rendered = format!("{wk:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.to_lowercase().contains("ee"));
    }
}
