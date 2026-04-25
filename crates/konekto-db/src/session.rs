//! Session and refresh-token storage (ADR-0003 §1, §2 / ADR-0007).
//!
//! Two surfaces share this module:
//!
//! - **First-party sessions** are opaque, cookie-bound, and live as
//!   long as the user keeps interacting with Konekto's own management
//!   plane (passkeys, audit log, …). Sliding 30-minute idle TTL,
//!   hard 12-hour absolute TTL.
//! - **OAuth refresh tokens** are opaque body values exchanged for a
//!   new access+refresh pair. Single-use rotation with theft
//!   detection: presenting an already-rotated token revokes the
//!   entire family.
//!
//! Both secrets are stored only as BLAKE2s-256 digests
//! ([`konekto_core::SESSION_HASH_LEN`]); the wire-side raw value is
//! the bearer of authority and never re-emitted by the store.
//!
//! The trait is parameterized on neither a clock nor a backend, only
//! on `&self` (clonable, cheap) — production Redis impls naturally
//! borrow shared state through a connection pool, and the in-memory
//! impl uses an `Arc<Mutex<_>>` to match that signature.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use konekto_core::token::ContextLabel;
use konekto_core::SESSION_HASH_LEN;
use uuid::Uuid;

use crate::error::DbError;

/// Lifecycle state of a refresh token within its family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshStatus {
    /// Issued and not yet rotated. The next rotation request that
    /// presents this hash will succeed and move it to [`Self::Rotated`].
    Active,
    /// Already rotated. A second presentation triggers theft
    /// detection — the entire family is moved to [`Self::Revoked`].
    Rotated,
    /// Explicitly revoked (logout, theft detection). Any presentation
    /// is rejected.
    Revoked,
}

/// Durable shape of a first-party session as held in the store.
///
/// `linked_refresh_family` carries the binding established at
/// `/dev/login`: deleting the session via `/dev/logout` also revokes
/// the refresh family so both surfaces tear down atomically (ADR-0003
/// §8 — "user logs out (first-party)" cascades).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    /// Identity bound to this session.
    pub identity_id: Uuid,
    /// Single context the session is scoped to (ADR-0003 §6 — one
    /// active context per session).
    pub ctx: ContextLabel,
    /// Unix-seconds of session creation.
    pub created_at: i64,
    /// Unix-seconds of the last request that authenticated against
    /// this session.
    pub last_seen_at: i64,
    /// Sliding idle expiry (Unix-seconds). Reset on every successful
    /// `touch_session`; a request observed past this point fails
    /// closed.
    pub idle_expires_at: i64,
    /// Hard absolute expiry (Unix-seconds). Cannot be extended.
    pub absolute_expires_at: i64,
    /// Authentication-method references (OIDC `amr`). `["pwd"]` in V1.
    pub amr: Vec<String>,
    /// Refresh-token family minted alongside this session, if any.
    pub linked_refresh_family: Option<Uuid>,
}

/// Durable shape of an OAuth refresh token as held in the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    /// All members of a single login share a `family_id`. Theft
    /// detection revokes the family, not just the rotated entry.
    pub family_id: Uuid,
    /// Identity bound to this refresh token.
    pub identity_id: Uuid,
    /// Context the refresh token mints access tokens for.
    pub ctx: ContextLabel,
    /// Lifecycle state — see [`RefreshStatus`].
    pub status: RefreshStatus,
    /// Unix-seconds of issuance (or rotation, for non-original
    /// members of the family).
    pub created_at: i64,
    /// Sliding idle expiry; reset on each successful rotation.
    pub idle_expires_at: i64,
    /// Hard absolute expiry; carried across the family unchanged.
    pub absolute_expires_at: i64,
}

/// Outcome of a successful session lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionLookup {
    /// Session present, within both idle and absolute windows.
    Active(SessionRecord),
    /// Session present but past one of its expiry bounds. The store
    /// has already evicted the record.
    Expired,
    /// No session matches the presented hash.
    Unknown,
}

/// Outcome of a refresh-token rotation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Rotation applied. The caller mints new access + refresh
    /// tokens against the returned binding.
    Rotated(RefreshRotation),
    /// Presented hash never existed in the store.
    Unknown,
    /// Presented hash had already been rotated. The store has
    /// revoked the entire family — every other member is now
    /// [`RefreshStatus::Revoked`].
    Theft,
    /// Presented hash is in [`RefreshStatus::Revoked`] (logout or
    /// prior theft detection).
    Revoked,
    /// Presented hash is past idle or absolute expiry.
    Expired,
}

/// Identity + context binding returned on a successful rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshRotation {
    /// Identity to encode in the new access token's `sub`.
    pub identity_id: Uuid,
    /// Context to encode in the new access token's `ctx`.
    pub ctx: ContextLabel,
    /// Family the new refresh token must inherit so subsequent
    /// rotations stay correlated.
    pub family_id: Uuid,
    /// Absolute expiry carried over from the old member, so the
    /// caller can apply the ADR-0003 §2 rule that rotation does not
    /// extend the family's hard ceiling.
    pub absolute_expires_at: i64,
}

/// Storage surface for first-party sessions and OAuth refresh
/// tokens.
///
/// Production implementations use Redis (single-region, replicated);
/// the in-memory implementation is exercised by tests and the
/// pre-alpha binary. The trait takes `&self` everywhere because both
/// canonical backends are internally synchronized — Redis through
/// its connection pool, [`InMemorySessionStore`] through an
/// `Arc<Mutex<_>>`.
#[async_trait]
pub trait SessionStore: Clone + Send + Sync + 'static {
    /// Insert a fresh session record keyed by the hash of its opaque
    /// ID. Returns [`DbError::Conflict`] if the hash collides — a
    /// non-event in practice but checked nonetheless.
    async fn create_session(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        record: SessionRecord,
    ) -> Result<(), DbError>;

    /// Look up a session without mutating it. Returns
    /// [`SessionLookup::Expired`] if the record exists but is past
    /// either expiry bound; the entry is removed as a side effect so
    /// the next lookup sees [`SessionLookup::Unknown`].
    async fn get_session(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        now: i64,
    ) -> Result<SessionLookup, DbError>;

    /// Look up a session and, on success, slide its idle window
    /// forward. Returns the post-touch record. The absolute window
    /// is never extended.
    async fn touch_session(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        now: i64,
        new_idle_expires_at: i64,
    ) -> Result<SessionLookup, DbError>;

    /// Atomically delete the session and revoke its linked refresh
    /// family (if any). Idempotent — calling twice is not an error.
    async fn logout(&self, hash: [u8; SESSION_HASH_LEN]) -> Result<(), DbError>;

    /// Insert a fresh refresh-token record. The family must already
    /// be known to the caller (the first member's `family_id` is the
    /// family's identifier).
    async fn create_refresh(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        record: RefreshTokenRecord,
    ) -> Result<(), DbError>;

    /// Atomically rotate a refresh token. The presented hash must
    /// reference an [`RefreshStatus::Active`] entry within both
    /// expiry windows; on success it is moved to
    /// [`RefreshStatus::Rotated`] and the new hash is inserted in
    /// the same family with `now` as its `created_at` and
    /// `new_idle_expires_at` as its sliding bound. The absolute
    /// expiry is carried unchanged. All other outcomes are reported
    /// via the returned [`RefreshOutcome`] without surfacing as
    /// [`DbError`].
    async fn rotate_refresh(
        &self,
        old_hash: [u8; SESSION_HASH_LEN],
        new_hash: [u8; SESSION_HASH_LEN],
        new_idle_expires_at: i64,
        now: i64,
    ) -> Result<RefreshOutcome, DbError>;

    /// Move every member of the named family to
    /// [`RefreshStatus::Revoked`]. Idempotent.
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), DbError>;
}

/// Process-local [`SessionStore`] backed by `HashMap`s under an
/// `Arc<Mutex<_>>`. Loses all state on process restart — adequate
/// for the pre-alpha binary and for unit tests; production deployments
/// substitute the Redis-backed implementation tracked under ADR-0007
/// follow-ups.
#[derive(Clone, Default)]
pub struct InMemorySessionStore {
    inner: Arc<Mutex<SessionStoreState>>,
}

#[derive(Default)]
struct SessionStoreState {
    sessions: HashMap<[u8; SESSION_HASH_LEN], SessionRecord>,
    refresh: HashMap<[u8; SESSION_HASH_LEN], RefreshTokenRecord>,
}

impl InMemorySessionStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SessionStoreState> {
        // The mutex is only poisoned if a thread panicked while
        // holding it. We have no recovery story for that beyond
        // failing closed; propagate as a storage write failure.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create_session(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        record: SessionRecord,
    ) -> Result<(), DbError> {
        let mut state = self.lock();
        if state.sessions.contains_key(&hash) {
            return Err(DbError::Conflict);
        }
        state.sessions.insert(hash, record);
        Ok(())
    }

    async fn get_session(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        now: i64,
    ) -> Result<SessionLookup, DbError> {
        let mut state = self.lock();
        let Some(record) = state.sessions.get(&hash).cloned() else {
            return Ok(SessionLookup::Unknown);
        };
        if now >= record.idle_expires_at || now >= record.absolute_expires_at {
            state.sessions.remove(&hash);
            return Ok(SessionLookup::Expired);
        }
        Ok(SessionLookup::Active(record))
    }

    async fn touch_session(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        now: i64,
        new_idle_expires_at: i64,
    ) -> Result<SessionLookup, DbError> {
        let mut state = self.lock();
        let Some(record) = state.sessions.get_mut(&hash) else {
            return Ok(SessionLookup::Unknown);
        };
        if now >= record.idle_expires_at || now >= record.absolute_expires_at {
            state.sessions.remove(&hash);
            return Ok(SessionLookup::Expired);
        }
        record.last_seen_at = now;
        // The sliding window cannot extend past the absolute bound.
        record.idle_expires_at = new_idle_expires_at.min(record.absolute_expires_at);
        Ok(SessionLookup::Active(record.clone()))
    }

    async fn logout(&self, hash: [u8; SESSION_HASH_LEN]) -> Result<(), DbError> {
        let mut state = self.lock();
        let family = state
            .sessions
            .remove(&hash)
            .and_then(|r| r.linked_refresh_family);
        if let Some(family_id) = family {
            for entry in state.refresh.values_mut() {
                if entry.family_id == family_id {
                    entry.status = RefreshStatus::Revoked;
                }
            }
        }
        Ok(())
    }

    async fn create_refresh(
        &self,
        hash: [u8; SESSION_HASH_LEN],
        record: RefreshTokenRecord,
    ) -> Result<(), DbError> {
        let mut state = self.lock();
        if state.refresh.contains_key(&hash) {
            return Err(DbError::Conflict);
        }
        state.refresh.insert(hash, record);
        Ok(())
    }

    async fn rotate_refresh(
        &self,
        old_hash: [u8; SESSION_HASH_LEN],
        new_hash: [u8; SESSION_HASH_LEN],
        new_idle_expires_at: i64,
        now: i64,
    ) -> Result<RefreshOutcome, DbError> {
        let mut state = self.lock();
        let Some(old) = state.refresh.get(&old_hash).cloned() else {
            return Ok(RefreshOutcome::Unknown);
        };
        match old.status {
            RefreshStatus::Rotated => {
                let family_id = old.family_id;
                for entry in state.refresh.values_mut() {
                    if entry.family_id == family_id {
                        entry.status = RefreshStatus::Revoked;
                    }
                }
                return Ok(RefreshOutcome::Theft);
            }
            RefreshStatus::Revoked => return Ok(RefreshOutcome::Revoked),
            RefreshStatus::Active => {}
        }
        if now >= old.idle_expires_at || now >= old.absolute_expires_at {
            return Ok(RefreshOutcome::Expired);
        }
        if state.refresh.contains_key(&new_hash) {
            return Err(DbError::Conflict);
        }
        if let Some(entry) = state.refresh.get_mut(&old_hash) {
            entry.status = RefreshStatus::Rotated;
        }
        let new_record = RefreshTokenRecord {
            family_id: old.family_id,
            identity_id: old.identity_id,
            ctx: old.ctx,
            status: RefreshStatus::Active,
            created_at: now,
            idle_expires_at: new_idle_expires_at.min(old.absolute_expires_at),
            absolute_expires_at: old.absolute_expires_at,
        };
        state.refresh.insert(new_hash, new_record);
        Ok(RefreshOutcome::Rotated(RefreshRotation {
            identity_id: old.identity_id,
            ctx: old.ctx,
            family_id: old.family_id,
            absolute_expires_at: old.absolute_expires_at,
        }))
    }

    async fn revoke_family(&self, family_id: Uuid) -> Result<(), DbError> {
        let mut state = self.lock();
        for entry in state.refresh.values_mut() {
            if entry.family_id == family_id {
                entry.status = RefreshStatus::Revoked;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InMemorySessionStore, RefreshOutcome, RefreshStatus, RefreshTokenRecord, SessionLookup,
        SessionRecord, SessionStore,
    };
    use konekto_core::token::ContextLabel;
    use konekto_core::SESSION_HASH_LEN;
    use uuid::Uuid;

    const T0: i64 = 1_800_000_000;

    fn h(byte: u8) -> [u8; SESSION_HASH_LEN] {
        [byte; SESSION_HASH_LEN]
    }

    fn session_record(now: i64, family: Option<Uuid>) -> SessionRecord {
        SessionRecord {
            identity_id: Uuid::new_v4(),
            ctx: ContextLabel::Vivo,
            created_at: now,
            last_seen_at: now,
            idle_expires_at: now + 1800,       // +30 min
            absolute_expires_at: now + 43_200, // +12 h
            amr: vec!["pwd".to_owned()],
            linked_refresh_family: family,
        }
    }

    fn refresh_record(now: i64, family: Uuid) -> RefreshTokenRecord {
        RefreshTokenRecord {
            family_id: family,
            identity_id: Uuid::new_v4(),
            ctx: ContextLabel::Vivo,
            status: RefreshStatus::Active,
            created_at: now,
            idle_expires_at: now + 2_592_000,     // +30 days
            absolute_expires_at: now + 7_776_000, // +90 days
        }
    }

    #[tokio::test]
    async fn create_then_get_session_roundtrips() {
        let store = InMemorySessionStore::new();
        let rec = session_record(T0, None);
        store
            .create_session(h(1), rec.clone())
            .await
            .expect("create");
        let got = store.get_session(h(1), T0).await.expect("get");
        assert_eq!(got, SessionLookup::Active(rec));
    }

    #[tokio::test]
    async fn expired_idle_session_is_rejected_on_get() {
        let store = InMemorySessionStore::new();
        store
            .create_session(h(2), session_record(T0, None))
            .await
            .expect("create");
        // Past idle expiry but still within absolute.
        let got = store.get_session(h(2), T0 + 1801).await.expect("get");
        assert_eq!(got, SessionLookup::Expired);
        // The store evicted it.
        let again = store.get_session(h(2), T0).await.expect("get again");
        assert_eq!(again, SessionLookup::Unknown);
    }

    #[tokio::test]
    async fn expired_absolute_session_is_rejected_even_within_idle() {
        let store = InMemorySessionStore::new();
        let mut rec = session_record(T0, None);
        // Force a tight absolute, generous idle.
        rec.absolute_expires_at = T0 + 100;
        rec.idle_expires_at = T0 + 100_000;
        store.create_session(h(3), rec).await.expect("create");
        let got = store.get_session(h(3), T0 + 200).await.expect("get");
        assert_eq!(got, SessionLookup::Expired);
    }

    #[tokio::test]
    async fn touch_session_extends_idle_but_not_absolute() {
        let store = InMemorySessionStore::new();
        let rec = session_record(T0, None);
        let abs = rec.absolute_expires_at;
        store.create_session(h(4), rec).await.expect("create");

        // Slide the idle bound to T0 + 5h. Capped at absolute (T0 + 12h),
        // so the new value should land at T0 + 5h.
        let touched = store
            .touch_session(h(4), T0 + 60, T0 + 18_000)
            .await
            .expect("touch");
        let SessionLookup::Active(r) = touched else {
            panic!("expected active");
        };
        assert_eq!(r.last_seen_at, T0 + 60);
        assert_eq!(r.idle_expires_at, T0 + 18_000);
        assert_eq!(r.absolute_expires_at, abs);

        // Try to slide past the absolute — must cap.
        let capped = store
            .touch_session(h(4), T0 + 120, T0 + 100_000)
            .await
            .expect("touch capped");
        let SessionLookup::Active(r2) = capped else {
            panic!("expected active");
        };
        assert_eq!(r2.idle_expires_at, abs);
    }

    #[tokio::test]
    async fn delete_session_removes_it() {
        let store = InMemorySessionStore::new();
        store
            .create_session(h(5), session_record(T0, None))
            .await
            .expect("create");
        store.logout(h(5)).await.expect("logout");
        let got = store.get_session(h(5), T0).await.expect("get");
        assert_eq!(got, SessionLookup::Unknown);
        // Idempotent.
        store.logout(h(5)).await.expect("logout again");
    }

    #[tokio::test]
    async fn create_then_consume_refresh_rotates_atomically() {
        let store = InMemorySessionStore::new();
        let family = Uuid::new_v4();
        let rec = refresh_record(T0, family);
        store
            .create_refresh(h(10), rec.clone())
            .await
            .expect("create");

        let outcome = store
            .rotate_refresh(h(10), h(11), T0 + 2_592_000, T0 + 60)
            .await
            .expect("rotate");
        let RefreshOutcome::Rotated(rot) = outcome else {
            panic!("expected rotated, got {outcome:?}");
        };
        assert_eq!(rot.family_id, family);
        assert_eq!(rot.identity_id, rec.identity_id);
        assert_eq!(rot.ctx, ContextLabel::Vivo);
        assert_eq!(rot.absolute_expires_at, rec.absolute_expires_at);

        // The new entry is Active; the old is Rotated.
        let next = store
            .rotate_refresh(h(11), h(12), T0 + 2_592_000, T0 + 120)
            .await
            .expect("rotate again");
        assert!(matches!(next, RefreshOutcome::Rotated(_)));
    }

    #[tokio::test]
    async fn presenting_rotated_refresh_revokes_family() {
        let store = InMemorySessionStore::new();
        let family = Uuid::new_v4();
        store
            .create_refresh(h(20), refresh_record(T0, family))
            .await
            .expect("create");
        // Rotate once: h(20) -> h(21).
        store
            .rotate_refresh(h(20), h(21), T0 + 2_592_000, T0 + 1)
            .await
            .expect("first rotate");

        // Present h(20) again — theft detection.
        let theft = store
            .rotate_refresh(h(20), h(99), T0 + 2_592_000, T0 + 2)
            .await
            .expect("rotate replayed");
        assert_eq!(theft, RefreshOutcome::Theft);

        // h(21) is now revoked too.
        let after = store
            .rotate_refresh(h(21), h(22), T0 + 2_592_000, T0 + 3)
            .await
            .expect("rotate post-theft");
        assert_eq!(after, RefreshOutcome::Revoked);
    }

    #[tokio::test]
    async fn presenting_revoked_refresh_returns_revoked() {
        let store = InMemorySessionStore::new();
        let family = Uuid::new_v4();
        store
            .create_refresh(h(30), refresh_record(T0, family))
            .await
            .expect("create");
        store.revoke_family(family).await.expect("revoke");

        let outcome = store
            .rotate_refresh(h(30), h(31), T0 + 2_592_000, T0 + 1)
            .await
            .expect("rotate");
        assert_eq!(outcome, RefreshOutcome::Revoked);
    }

    #[tokio::test]
    async fn expired_refresh_idle_returns_expired() {
        let store = InMemorySessionStore::new();
        let family = Uuid::new_v4();
        let mut rec = refresh_record(T0, family);
        rec.idle_expires_at = T0 + 100;
        rec.absolute_expires_at = T0 + 100_000;
        store.create_refresh(h(40), rec).await.expect("create");

        let outcome = store
            .rotate_refresh(h(40), h(41), T0 + 2_592_000, T0 + 200)
            .await
            .expect("rotate");
        assert_eq!(outcome, RefreshOutcome::Expired);
    }

    #[tokio::test]
    async fn revoke_family_invalidates_all_members_atomically() {
        let store = InMemorySessionStore::new();
        let family = Uuid::new_v4();
        store
            .create_refresh(h(50), refresh_record(T0, family))
            .await
            .expect("create a");
        store
            .create_refresh(h(51), refresh_record(T0, family))
            .await
            .expect("create b");
        store.revoke_family(family).await.expect("revoke");

        for hh in [h(50), h(51)] {
            let outcome = store
                .rotate_refresh(hh, h(99), T0 + 2_592_000, T0 + 1)
                .await
                .expect("rotate");
            assert_eq!(outcome, RefreshOutcome::Revoked);
        }
    }

    #[tokio::test]
    async fn independent_families_dont_interfere() {
        let store = InMemorySessionStore::new();
        let fam_a = Uuid::new_v4();
        let fam_b = Uuid::new_v4();
        store
            .create_refresh(h(60), refresh_record(T0, fam_a))
            .await
            .expect("a");
        store
            .create_refresh(h(70), refresh_record(T0, fam_b))
            .await
            .expect("b");

        store.revoke_family(fam_a).await.expect("revoke a");

        // Family A is gone; family B is fine.
        let a = store
            .rotate_refresh(h(60), h(61), T0 + 2_592_000, T0 + 1)
            .await
            .expect("rotate a");
        assert_eq!(a, RefreshOutcome::Revoked);

        let b = store
            .rotate_refresh(h(70), h(71), T0 + 2_592_000, T0 + 1)
            .await
            .expect("rotate b");
        assert!(matches!(b, RefreshOutcome::Rotated(_)));
    }

    #[tokio::test]
    async fn unknown_refresh_returns_unknown() {
        let store = InMemorySessionStore::new();
        let outcome = store
            .rotate_refresh(h(80), h(81), T0 + 2_592_000, T0 + 1)
            .await
            .expect("rotate");
        assert_eq!(outcome, RefreshOutcome::Unknown);
    }

    #[tokio::test]
    async fn logout_cascades_to_linked_refresh_family() {
        let store = InMemorySessionStore::new();
        let family = Uuid::new_v4();
        store
            .create_session(h(90), session_record(T0, Some(family)))
            .await
            .expect("create session");
        store
            .create_refresh(h(91), refresh_record(T0, family))
            .await
            .expect("create refresh");

        store.logout(h(90)).await.expect("logout");

        let outcome = store
            .rotate_refresh(h(91), h(92), T0 + 2_592_000, T0 + 1)
            .await
            .expect("rotate after logout");
        assert_eq!(outcome, RefreshOutcome::Revoked);
    }
}
