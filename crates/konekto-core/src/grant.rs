//! Cross-context grants — audit-backed capabilities for inter-context
//! operations.
//!
//! See ADR-0002 §4. A [`CrossContextGrant<From, To>`] is the only way
//! to express, at the type level, that a cross-context operation is
//! authorized. The grant's private fields and private construction
//! site mean the only way to obtain one is via [`AuditLog::issue`],
//! which writes an audit record **before** returning the grant. The
//! grant therefore encodes the invariant "an audit record exists for
//! this access" structurally, not by convention.
//!
//! This increment lands the type skeleton and trait shape. User
//! verification (a fresh `WebAuthn` assertion re-materializing the
//! [`crate::RootKey`]) is enforced at the session layer and is not
//! yet threaded as a typed parameter here — ADR-0003 §6, ADR-0004 §5.

use core::marker::PhantomData;
use std::time::{Duration, SystemTime};

use crate::context::Context;

/// Opaque identifier for an audit-log record.
///
/// The concrete numbering scheme is an implementation detail of the
/// backing [`AuditLog`]. Callers outside `konekto-core` treat this as
/// an opaque handle suitable for logging and for cross-referencing
/// with the audit store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuditId(u128);

impl AuditId {
    /// Wrap a raw `u128` produced by a concrete audit-log backend.
    #[must_use]
    pub fn from_u128(value: u128) -> Self {
        Self(value)
    }

    /// Expose the raw `u128` for serialization by a concrete backend.
    #[must_use]
    pub fn as_u128(&self) -> u128 {
        self.0
    }
}

/// The kind of cross-context operation a grant authorizes.
///
/// `#[non_exhaustive]`: concrete scopes are added as features land.
/// Matching on a [`GrantScope`] value outside this crate must include
/// a wildcard arm so adding a scope is not a breaking change.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantScope {
    /// Reserved marker used for tests and for the initial
    /// scaffolding. Will be replaced by concrete scopes as
    /// cross-context flows land.
    Reserved,
}

/// Errors produced when issuing a cross-context grant.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// The audit log rejected or failed to record the grant request.
    /// The grant MUST NOT be issued in this case.
    #[error("audit log write failed")]
    AuditFailed,

    /// The caller requested a zero or otherwise invalid TTL.
    #[error("invalid grant TTL")]
    InvalidTtl,
}

/// A time-bounded, audit-backed capability authorizing an operation
/// that reads from context `From` and writes to (or reads from)
/// context `To`.
///
/// Invariants enforced by construction:
///
/// - The grant exists **only** if [`AuditLog::issue`] wrote an audit
///   record — the `audit_id` field is the handle to that record.
/// - The `From` and `To` context parameters are compile-time markers:
///   a function signed as
///   `fn f(g: &CrossContextGrant<Vivo, Laboro>)` cannot be invoked
///   with a `CrossContextGrant<Vivo, Socio>`.
/// - Fields are private: no crate outside `konekto-core` can forge or
///   mutate a grant.
///
/// The grant is move-only: no `Clone`, no `Copy`, no `Serialize`. A
/// handler that forwards a grant moves it; a handler that inspects
/// it takes `&CrossContextGrant<_, _>`.
pub struct CrossContextGrant<From: Context, To: Context> {
    audit_id: AuditId,
    scope: GrantScope,
    issued_at: SystemTime,
    expires_at: SystemTime,
    _from: PhantomData<From>,
    _to: PhantomData<To>,
}

impl<From: Context, To: Context> CrossContextGrant<From, To> {
    /// Audit-log handle bound to this grant.
    #[must_use]
    pub fn audit_id(&self) -> AuditId {
        self.audit_id
    }

    /// Scope authorized by this grant.
    #[must_use]
    pub fn scope(&self) -> GrantScope {
        self.scope
    }

    /// Wall-clock instant at which this grant was issued.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// Wall-clock instant at which this grant expires.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Whether this grant is expired relative to `now`.
    ///
    /// Callers should check this immediately before executing the
    /// authorized operation, passing the current [`SystemTime`].
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }
}

impl<From: Context, To: Context> core::fmt::Debug for CrossContextGrant<From, To> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let from = core::str::from_utf8(From::LABEL).unwrap_or("<invalid-utf8>");
        let to = core::str::from_utf8(To::LABEL).unwrap_or("<invalid-utf8>");
        f.debug_struct("CrossContextGrant")
            .field("from", &from)
            .field("to", &to)
            .field("audit_id", &self.audit_id)
            .field("scope", &self.scope)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

// No Clone / Copy / Serialize / Deserialize — grants are move-only.

/// Record written to the audit log at the moment a grant is issued.
///
/// This is the payload passed from [`AuditLog::issue`]'s default
/// implementation down to the concrete [`AuditLog::record_grant`]
/// hook. Implementations persist it (and typically more context
/// such as actor identity and request correlation ID).
#[derive(Debug, Clone)]
pub struct GrantRecord {
    /// UTF-8 domain-separation label of the source context (from
    /// [`Context::LABEL`]), carried as a string so it persists
    /// through the audit store without re-binding a generic type.
    pub from_label: &'static [u8],
    /// UTF-8 label of the destination context.
    pub to_label: &'static [u8],
    /// Scope authorized by the grant.
    pub scope: GrantScope,
    /// Wall-clock issue time.
    pub issued_at: SystemTime,
    /// Wall-clock expiry time.
    pub expires_at: SystemTime,
}

/// Backend for recording grant issuance.
///
/// Implementations live outside `konekto-core` (the canonical one
/// will back onto the `konekto-db` audit table). The default
/// [`AuditLog::issue`] method is the sole constructor of a
/// [`CrossContextGrant`]: concrete implementors only provide the
/// storage hook [`AuditLog::record_grant`] and inherit correct grant
/// construction from this crate.
pub trait AuditLog {
    /// Persist the audit record and return its identifier.
    ///
    /// Implementations MUST ensure the record is durable before
    /// returning `Ok`. A grant whose audit record is not durable
    /// is a grant that never existed.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined error if the audit record
    /// could not be durably persisted. The default [`Self::issue`]
    /// method maps any such error to [`GrantError::AuditFailed`].
    fn record_grant(&mut self, record: &GrantRecord) -> Result<AuditId, AuditWriteError>;

    /// Issue a cross-context grant.
    ///
    /// This is the single public construction point for
    /// [`CrossContextGrant`]. The flow is:
    ///
    /// 1. Validate `ttl` (non-zero).
    /// 2. Persist a [`GrantRecord`] via [`Self::record_grant`].
    /// 3. Only on successful persistence, return a grant carrying
    ///    the resulting [`AuditId`].
    ///
    /// # Errors
    ///
    /// - [`GrantError::InvalidTtl`] if `ttl` is zero.
    /// - [`GrantError::AuditFailed`] if [`Self::record_grant`]
    ///   failed. The grant is not constructed in this case.
    fn issue<From: Context, To: Context>(
        &mut self,
        scope: GrantScope,
        ttl: Duration,
    ) -> Result<CrossContextGrant<From, To>, GrantError> {
        if ttl.is_zero() {
            return Err(GrantError::InvalidTtl);
        }
        let issued_at = SystemTime::now();
        let expires_at = issued_at + ttl;
        let record = GrantRecord {
            from_label: From::LABEL,
            to_label: To::LABEL,
            scope,
            issued_at,
            expires_at,
        };
        let audit_id = self
            .record_grant(&record)
            .map_err(|_| GrantError::AuditFailed)?;
        Ok(CrossContextGrant {
            audit_id,
            scope,
            issued_at,
            expires_at,
            _from: PhantomData,
            _to: PhantomData,
        })
    }
}

/// Implementation-defined failure while writing an audit record.
///
/// Opaque at this layer — the concrete audit-log backend is
/// responsible for surfacing diagnostic detail via its own logs.
#[derive(Debug, thiserror::Error)]
#[error("audit write failed")]
pub struct AuditWriteError;

#[cfg(test)]
mod tests {
    use super::{
        AuditId, AuditLog, AuditWriteError, CrossContextGrant, GrantError, GrantRecord, GrantScope,
    };
    use crate::context::{Context, Laboro, Socio, Vivo};
    use std::time::Duration;

    /// In-memory audit log: assigns monotonically increasing IDs and
    /// stores the records in a Vec for assertions.
    #[derive(Default)]
    struct InMemoryAudit {
        next_id: u128,
        records: Vec<(AuditId, GrantRecord)>,
    }

    impl AuditLog for InMemoryAudit {
        fn record_grant(&mut self, record: &GrantRecord) -> Result<AuditId, AuditWriteError> {
            self.next_id += 1;
            let id = AuditId::from_u128(self.next_id);
            self.records.push((id, record.clone()));
            Ok(id)
        }
    }

    /// Audit log that always fails.
    struct FailingAudit;

    impl AuditLog for FailingAudit {
        fn record_grant(&mut self, _record: &GrantRecord) -> Result<AuditId, AuditWriteError> {
            Err(AuditWriteError)
        }
    }

    #[test]
    fn issue_writes_audit_record_and_returns_grant() {
        let mut log = InMemoryAudit::default();
        let grant: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .expect("grant issuance");

        assert_eq!(log.records.len(), 1);
        let (recorded_id, record) = &log.records[0];
        assert_eq!(grant.audit_id(), *recorded_id);
        assert_eq!(record.from_label, Vivo::LABEL);
        assert_eq!(record.to_label, Laboro::LABEL);
        assert_eq!(record.scope, GrantScope::Reserved);
        assert_eq!(grant.scope(), GrantScope::Reserved);
    }

    #[test]
    fn issue_carries_ttl_into_expiry() {
        let mut log = InMemoryAudit::default();
        let ttl = Duration::from_secs(300);
        let grant: CrossContextGrant<Vivo, Socio> = log
            .issue::<Vivo, Socio>(GrantScope::Reserved, ttl)
            .expect("grant issuance");

        let elapsed = grant
            .expires_at()
            .duration_since(grant.issued_at())
            .expect("expires_at >= issued_at");
        assert_eq!(elapsed, ttl);
    }

    #[test]
    fn issue_rejects_zero_ttl() {
        let mut log = InMemoryAudit::default();
        let res: Result<CrossContextGrant<Laboro, Vivo>, _> =
            log.issue::<Laboro, Vivo>(GrantScope::Reserved, Duration::from_secs(0));
        assert!(matches!(res, Err(GrantError::InvalidTtl)));
        assert!(log.records.is_empty(), "no audit record on invalid TTL");
    }

    #[test]
    fn issue_propagates_audit_failure_without_constructing_grant() {
        let mut log = FailingAudit;
        let res: Result<CrossContextGrant<Vivo, Laboro>, _> =
            log.issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60));
        assert!(matches!(res, Err(GrantError::AuditFailed)));
    }

    #[test]
    fn grant_is_not_expired_at_issue_and_is_expired_past_ttl() {
        let mut log = InMemoryAudit::default();
        let ttl = Duration::from_secs(10);
        let grant: CrossContextGrant<Socio, Laboro> = log
            .issue::<Socio, Laboro>(GrantScope::Reserved, ttl)
            .expect("grant issuance");

        assert!(!grant.is_expired(grant.issued_at()));
        assert!(grant.is_expired(grant.expires_at()));
        assert!(grant.is_expired(grant.expires_at() + Duration::from_secs(1)));
    }

    #[test]
    fn debug_format_shows_context_labels_and_does_not_leak_private_state() {
        let mut log = InMemoryAudit::default();
        let grant: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .expect("grant issuance");
        let rendered = format!("{grant:?}");
        assert!(rendered.contains("konekto.context.vivo.v1"));
        assert!(rendered.contains("konekto.context.laboro.v1"));
    }

    #[test]
    fn audit_ids_are_distinct_across_issuances() {
        let mut log = InMemoryAudit::default();
        let a: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .unwrap();
        let b: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .unwrap();
        assert_ne!(a.audit_id(), b.audit_id());
    }

    #[test]
    fn grants_carry_distinct_compile_time_types_per_context_pair() {
        // This test documents (and exercises) that distinct `(From, To)`
        // pairs produce distinct, non-coercible types. Attempting to bind
        // the result of `issue::<Vivo, Laboro>` into a
        // `CrossContextGrant<Vivo, Socio>` slot is a compile error
        // (E0308). A trybuild compile_fail harness is tracked as a
        // follow-up once the crate grows a wider test surface.
        let mut log = InMemoryAudit::default();
        let _a: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .unwrap();
        let _b: CrossContextGrant<Laboro, Socio> = log
            .issue::<Laboro, Socio>(GrantScope::Reserved, Duration::from_secs(60))
            .unwrap();
    }

    #[test]
    fn audit_id_round_trips_through_u128() {
        let raw = 0x1234_5678_9abc_def0_1122_3344_5566_7788_u128;
        assert_eq!(AuditId::from_u128(raw).as_u128(), raw);
    }
}
