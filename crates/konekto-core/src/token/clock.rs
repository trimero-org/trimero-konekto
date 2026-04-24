//! Clock abstraction used by the token issuance and verification path.
//!
//! Production uses [`SystemClock`], which reads the wall clock via
//! [`std::time::SystemTime`]. Tests can substitute [`FixedClock`] to
//! produce deterministic `iat` / `exp` / `nbf` timestamps and to
//! advance synthetic time without racing the real wall clock.
//!
//! The [`Clock`] trait is taken by generic parameter (not by
//! `dyn`-object) everywhere in the token primitive, so the chosen
//! implementation is monomorphized into the issuer / verifier with
//! zero runtime overhead.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of the current Unix timestamp, in seconds.
pub trait Clock: Send + Sync + 'static {
    /// Current wall-clock time, expressed as Unix seconds.
    fn now_unix_secs(&self) -> i64;
}

/// Wall-clock implementation of [`Clock`] backed by [`SystemTime`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> i64 {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before UNIX_EPOCH");
        i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
    }
}

/// Test-only [`Clock`] whose current time can be set explicitly.
///
/// Exposed outside `#[cfg(test)]` so that `konekto-api`'s integration
/// tests can drive expiration and not-yet-valid paths without having
/// to fake `SystemTime`.
#[derive(Debug)]
pub struct FixedClock {
    now: AtomicI64,
}

impl FixedClock {
    /// Construct a clock pinned at `unix_secs`.
    #[must_use]
    pub fn new(unix_secs: i64) -> Self {
        Self {
            now: AtomicI64::new(unix_secs),
        }
    }

    /// Move the clock to `unix_secs`.
    pub fn set(&self, unix_secs: i64) {
        self.now.store(unix_secs, Ordering::SeqCst);
    }

    /// Advance the clock by `delta_secs`.
    pub fn advance(&self, delta_secs: i64) {
        self.now.fetch_add(delta_secs, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, FixedClock, SystemClock};

    #[test]
    fn system_clock_returns_positive_timestamp() {
        let c = SystemClock;
        assert!(c.now_unix_secs() > 0);
    }

    #[test]
    fn fixed_clock_set_and_advance() {
        let c = FixedClock::new(1_000);
        assert_eq!(c.now_unix_secs(), 1_000);
        c.advance(25);
        assert_eq!(c.now_unix_secs(), 1_025);
        c.set(50);
        assert_eq!(c.now_unix_secs(), 50);
    }
}
