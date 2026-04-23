//! CSPRNG helpers.
//!
//! A thin wrapper over `aws-lc-rs`'s [`SystemRandom`] so callers
//! elsewhere in the workspace (notably `konekto-db`, which generates
//! salts) do not need to depend on `aws-lc-rs` directly. Cryptographic
//! entropy is owned by `konekto-core`.

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

/// Fill `buf` with bytes from the system CSPRNG.
///
/// # Panics
///
/// Panics if the CSPRNG returns an error. This indicates kernel-level
/// entropy exhaustion or a broken environment — callers cannot
/// meaningfully recover, and continuing with non-random bytes would
/// be catastrophic.
pub fn fill_random(buf: &mut [u8]) {
    SystemRandom::new().fill(buf).expect("system CSPRNG failed");
}

/// Allocate a `Vec<u8>` of the given length filled with CSPRNG bytes.
///
/// Convenience over [`fill_random`] for call sites that need owned
/// salt or nonce material. Length 0 returns an empty vector without
/// touching the CSPRNG.
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if len > 0 {
        fill_random(&mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{fill_random, random_bytes};

    #[test]
    fn fill_random_produces_different_bytes_across_calls() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a);
        fill_random(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn random_bytes_respects_length() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(16).len(), 16);
        assert_eq!(random_bytes(64).len(), 64);
    }

    #[test]
    fn random_bytes_is_not_all_zero_for_nonzero_length() {
        let b = random_bytes(32);
        assert!(b.iter().any(|&x| x != 0));
    }
}
