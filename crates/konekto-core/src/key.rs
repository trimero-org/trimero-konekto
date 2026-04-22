//! Root and context keys.
//!
//! See ADR-0002 (type-system encoding) and ADR-0004 (root-key
//! lifecycle) for the full design.
//!
//! [`RootKey`] and [`ContextKey<C>`] are move-only, zeroized on drop,
//! and expose no serialization or cloning. Context keys are derived
//! from the root via HKDF-SHA256 (FIPS-validated primitive from
//! `aws-lc-rs`), with domain separation carried by each context's
//! versioned [`Context::LABEL`] used as the HKDF `info` parameter.

use aws_lc_rs::hkdf::{Salt, HKDF_SHA256};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use core::marker::PhantomData;
use zeroize::Zeroize;

use crate::context::Context;

/// Size in bytes of a [`RootKey`] and of every [`ContextKey`].
///
/// 32 bytes = 256 bits — the output size of SHA-256 / HKDF-SHA256
/// and the key size of AES-256-GCM and ChaCha20-Poly1305.
pub const KEY_SIZE: usize = 32;

/// A user's root identity key material.
///
/// Per ADR-0004 §1, a `RootKey` exists in plaintext only during four
/// bounded request scopes: enrollment, login, multi-device binding,
/// and cross-context operations that require a `CrossContextGrant`
/// (ADR-0002 / ADR-0003 §6). Outside these scopes it exists only as
/// per-credential wrapped blobs at rest.
///
/// The type is intentionally:
/// - move-only (no [`Clone`], no [`Copy`]),
/// - non-serializable (no `Serialize` / `Deserialize`),
/// - `Debug`-redacted (never prints key material),
/// - zeroized on drop.
pub struct RootKey {
    material: [u8; KEY_SIZE],
}

impl RootKey {
    /// Generate a fresh root key from the system CSPRNG.
    ///
    /// Per ADR-0004 §2, a user's root key is a 256-bit value drawn
    /// from the operating-system CSPRNG at enrollment. This is the
    /// single production entry point for minting new root keys.
    ///
    /// # Panics
    ///
    /// Panics if the system CSPRNG is unavailable or returns an
    /// error. This condition is unrecoverable (entropy exhaustion
    /// or kernel malfunction) and must abort the enrollment flow.
    #[must_use]
    pub fn generate() -> Self {
        let mut material = [0u8; KEY_SIZE];
        SystemRandom::new()
            .fill(&mut material)
            .expect("system CSPRNG failed");
        Self { material }
    }

    /// Derive a context-specific key via HKDF-SHA256.
    ///
    /// Domain separation is provided by the caller-selected context
    /// `C`: the HKDF `info` parameter is [`Context::LABEL`], a
    /// versioned, namespaced byte string unique to each context (see
    /// [`crate::context`]). HKDF is run with an empty salt because
    /// the input keying material is already a uniformly random
    /// 256-bit secret drawn from the CSPRNG.
    ///
    /// The derivation is deterministic: calling `derive` twice on
    /// the same [`RootKey`] with the same `C` produces byte-equal
    /// key material. Different contexts — or different root keys —
    /// produce cryptographically independent outputs.
    #[must_use]
    pub fn derive<C: Context>(&self) -> ContextKey<C> {
        let prk = Salt::new(HKDF_SHA256, &[]).extract(&self.material);
        let okm = prk
            .expand(&[C::LABEL], HKDF_SHA256)
            .expect("HKDF-SHA256 expand with 32-byte output cannot fail");
        let mut material = [0u8; KEY_SIZE];
        okm.fill(&mut material)
            .expect("HKDF-SHA256 fill with 32-byte output cannot fail");
        ContextKey {
            material,
            _context: PhantomData,
        }
    }

    /// Test-only constructor with caller-supplied material.
    ///
    /// Only compiled under `cfg(test)`. Production `RootKey`
    /// instances are produced by [`RootKey::generate`] at enrollment
    /// or by unwrapping a per-credential wrapped blob at login
    /// (login flow not yet implemented).
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(material: [u8; KEY_SIZE]) -> Self {
        Self { material }
    }
}

impl core::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RootKey")
            .field("material", &"<redacted>")
            .finish()
    }
}

impl Drop for RootKey {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

/// A context-bound key for context `C`.
///
/// `ContextKey<Vivo>`, `ContextKey<Laboro>`, and `ContextKey<Socio>`
/// are **distinct, non-coercible types at compile time**. A function
/// signed as `fn f(k: &ContextKey<Vivo>)` cannot be called with a
/// `ContextKey<Laboro>` — the confusion is caught by the compiler,
/// not by a runtime check.
///
/// Like [`RootKey`], `ContextKey<C>` is move-only, non-serializable,
/// `Debug`-redacted, and zeroized on drop.
pub struct ContextKey<C: Context> {
    material: [u8; KEY_SIZE],
    _context: PhantomData<C>,
}

impl<C: Context> ContextKey<C> {
    /// Expose the key material as a read-only byte slice.
    ///
    /// Callers MUST treat the returned slice as sensitive and must
    /// not copy it outside the scope that holds the [`ContextKey`].
    /// Downstream AEAD / KDF operations should consume the slice
    /// directly rather than copying into another buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.material
    }

    /// Test-only constructor with caller-supplied material.
    #[cfg(test)]
    pub(crate) fn from_bytes_for_test(material: [u8; KEY_SIZE]) -> Self {
        Self {
            material,
            _context: PhantomData,
        }
    }
}

impl<C: Context> core::fmt::Debug for ContextKey<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let label = core::str::from_utf8(C::LABEL).unwrap_or("<invalid-utf8>");
        f.debug_struct("ContextKey")
            .field("context", &label)
            .field("material", &"<redacted>")
            .finish()
    }
}

impl<C: Context> Drop for ContextKey<C> {
    fn drop(&mut self) {
        self.material.zeroize();
    }
}

// ContextKey<C> intentionally does not implement Clone, Copy,
// Serialize, or Deserialize. Key material is move-only.

#[cfg(test)]
mod tests {
    use super::{ContextKey, RootKey, KEY_SIZE};
    use crate::context::{Laboro, Socio, Vivo};

    #[test]
    fn context_keys_have_distinct_types() {
        // This test exists to document and exercise that ContextKey<C>
        // is generic in C. Attempting to assign a ContextKey<Laboro>
        // into a binding typed ContextKey<Vivo> is a compile error
        // (E0308). A trybuild-based compile_fail harness is tracked
        // as a follow-up once the crate grows a wider test surface.
        let v: ContextKey<Vivo> = ContextKey::from_bytes_for_test([0xAA; KEY_SIZE]);
        let l: ContextKey<Laboro> = ContextKey::from_bytes_for_test([0xBB; KEY_SIZE]);
        let s: ContextKey<Socio> = ContextKey::from_bytes_for_test([0xCC; KEY_SIZE]);
        assert_ne!(v.as_bytes(), l.as_bytes());
        assert_ne!(l.as_bytes(), s.as_bytes());
        assert_ne!(v.as_bytes(), s.as_bytes());
    }

    #[test]
    fn context_key_debug_redacts_material() {
        // Use 0xDD — its hex form "dd" does not occur in any of the three
        // context labels ("konekto.context.vivo|laboro|socio.v1"), so a
        // false positive from the label alone is ruled out.
        let k = ContextKey::<Laboro>::from_bytes_for_test([0xDD; KEY_SIZE]);
        let rendered = format!("{k:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("konekto.context.laboro.v1"));
        assert!(
            !rendered.to_lowercase().contains("dd"),
            "key material must not leak into Debug output"
        );
    }

    #[test]
    fn root_key_debug_redacts_material() {
        let k = RootKey::from_bytes_for_test([0xCD; KEY_SIZE]);
        let rendered = format!("{k:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.to_lowercase().contains("cd"));
    }

    #[test]
    fn key_size_matches_expected_constant() {
        assert_eq!(KEY_SIZE, 32);
    }

    #[test]
    fn generate_produces_distinct_keys() {
        // Two CSPRNG draws colliding on 256 bits has probability
        // 2^-256; treat a collision as a test failure.
        let a = RootKey::generate();
        let b = RootKey::generate();
        assert_ne!(a.material, b.material);
    }

    #[test]
    fn derive_is_deterministic() {
        let material = [0x42; KEY_SIZE];
        let root_a = RootKey::from_bytes_for_test(material);
        let root_b = RootKey::from_bytes_for_test(material);
        let k_a = root_a.derive::<Vivo>();
        let k_b = root_b.derive::<Vivo>();
        assert_eq!(k_a.as_bytes(), k_b.as_bytes());
    }

    #[test]
    fn derive_separates_contexts() {
        let root = RootKey::from_bytes_for_test([0x11; KEY_SIZE]);
        let v = root.derive::<Vivo>();
        let l = root.derive::<Laboro>();
        let s = root.derive::<Socio>();
        assert_ne!(v.as_bytes(), l.as_bytes());
        assert_ne!(l.as_bytes(), s.as_bytes());
        assert_ne!(v.as_bytes(), s.as_bytes());
    }

    #[test]
    fn derive_separates_roots() {
        let root_a = RootKey::from_bytes_for_test([0x01; KEY_SIZE]);
        let root_b = RootKey::from_bytes_for_test([0x02; KEY_SIZE]);
        let k_a = root_a.derive::<Vivo>();
        let k_b = root_b.derive::<Vivo>();
        assert_ne!(k_a.as_bytes(), k_b.as_bytes());
    }

    #[test]
    fn derived_key_does_not_equal_root_material() {
        // Sanity: HKDF must transform the input, not pass it through.
        let material = [0x77; KEY_SIZE];
        let root = RootKey::from_bytes_for_test(material);
        let k = root.derive::<Laboro>();
        assert_ne!(k.as_bytes(), &material);
    }
}
