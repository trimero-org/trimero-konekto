//! Context markers and the sealed [`Context`] trait.
//!
//! See ADR-0002 for the full design. A Konekto identity has three
//! cryptographically isolated contexts: `Vivo` (personal / B2C),
//! `Laboro` (professional / B2B including legal persons), and
//! `Socio` (civic / B2G). Each context maps one-to-one to a Trimero
//! filiale.
//!
//! The contexts are encoded as zero-sized marker types behind a
//! sealed trait so that the three listed here are the complete,
//! closed universe. Introducing a fourth context requires editing
//! this module and is caught by code review.

/// Marker trait for identity contexts.
///
/// Sealed: cannot be implemented outside this module. Implementers
/// are the zero-sized types [`Vivo`], [`Laboro`], and [`Socio`].
///
/// The associated [`Self::LABEL`] constant is the domain-separation
/// string used as the HKDF `info` parameter when deriving the
/// context-specific key from a [`crate::RootKey`]. Labels are
/// versioned (`.v1` suffix) so the derivation scheme can evolve
/// without re-using the same label for a different algorithm.
pub trait Context: private::Sealed + Copy + Clone + core::fmt::Debug + 'static {
    /// HKDF `info` parameter — versioned and domain-separated.
    const LABEL: &'static [u8];
}

mod private {
    /// Sealing marker. Not publicly re-exported.
    pub trait Sealed {}
}

/// Personal-life context. Maps to the Vivo filiale (B2C individuals).
#[derive(Copy, Clone, Debug)]
pub struct Vivo;

/// Professional context. Maps to the Laboro filiale (B2B + B2C-pro),
/// which includes both natural persons acting professionally and
/// legal persons (organizations). See ADR-0005.
#[derive(Copy, Clone, Debug)]
pub struct Laboro;

/// Civic context. Maps to the Socio filiale (B2G / institutional).
#[derive(Copy, Clone, Debug)]
pub struct Socio;

impl private::Sealed for Vivo {}
impl Context for Vivo {
    const LABEL: &'static [u8] = b"konekto.context.vivo.v1";
}

impl private::Sealed for Laboro {}
impl Context for Laboro {
    const LABEL: &'static [u8] = b"konekto.context.laboro.v1";
}

impl private::Sealed for Socio {}
impl Context for Socio {
    const LABEL: &'static [u8] = b"konekto.context.socio.v1";
}

#[cfg(test)]
mod tests {
    use super::{Context, Laboro, Socio, Vivo};

    #[test]
    fn labels_are_pairwise_distinct() {
        let labels = [Vivo::LABEL, Laboro::LABEL, Socio::LABEL];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a, b, "context labels must be pairwise distinct");
            }
        }
    }

    #[test]
    fn labels_are_versioned() {
        for label in [Vivo::LABEL, Laboro::LABEL, Socio::LABEL] {
            assert!(
                label.ends_with(b".v1"),
                "label `{:?}` must carry a .v1 version suffix",
                core::str::from_utf8(label).unwrap_or("<invalid>"),
            );
        }
    }

    #[test]
    fn labels_are_prefix_namespaced() {
        for label in [Vivo::LABEL, Laboro::LABEL, Socio::LABEL] {
            assert!(
                label.starts_with(b"konekto.context."),
                "label `{:?}` must be namespaced under konekto.context.",
                core::str::from_utf8(label).unwrap_or("<invalid>"),
            );
        }
    }
}
