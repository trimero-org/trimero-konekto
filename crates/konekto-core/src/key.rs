//! Root and context keys.
//!
//! See ADR-0002 (type-system encoding) and ADR-0004 (root-key
//! lifecycle) for the full design.
//!
//! This module establishes the type skeleton: [`RootKey`] and
//! [`ContextKey<C>`] are move-only, zeroized on drop, and expose no
//! serialization or cloning. Cryptographic derivation
//! (HKDF-SHA256 via `aws-lc-rs`) lands in a follow-up increment;
//! this version intentionally does not expose a public
//! `RootKey::derive` so that no accidental "fake crypto" slips
//! through.

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
    /// Test-only constructor with caller-supplied material.
    ///
    /// Only compiled under `cfg(test)`. Production `RootKey`
    /// instances are produced by enrollment and login flows (not yet
    /// implemented in this increment).
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
}
