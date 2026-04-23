//! Backends for [`konekto_core::AuditLog`].
//!
//! The in-memory implementation ([`InMemoryAuditLog`]) is suitable
//! for unit tests, integration tests in downstream crates, and
//! dev-mode deployments that do not need durable audit records.
//! The Postgres-backed implementation lands in the next increment.

use std::sync::atomic::{AtomicU64, Ordering};

use konekto_core::{AuditId, AuditLog, AuditWriteError, GrantRecord};

/// In-memory [`AuditLog`] that assigns monotonically increasing ids
/// and keeps every recorded grant in a `Vec` for inspection.
///
/// This type is not a database: records live only for the process
/// lifetime. Do not use it in production unless the deployment is
/// explicitly configured for volatile, non-durable operation.
#[derive(Debug, Default)]
pub struct InMemoryAuditLog {
    next_id: AtomicU64,
    records: Vec<(AuditId, GrantRecord)>,
}

impl InMemoryAuditLog {
    /// Construct an empty in-memory audit log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the recorded grants in insertion order.
    #[must_use]
    pub fn records(&self) -> &[(AuditId, GrantRecord)] {
        &self.records
    }

    /// Number of grant records currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no grants have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl AuditLog for InMemoryAuditLog {
    fn record_grant(&mut self, record: &GrantRecord) -> Result<AuditId, AuditWriteError> {
        // `fetch_add` returns the previous value; +1 so the first id
        // is 1 (matches the expectation that 0 is never a live id).
        let id_value = u128::from(self.next_id.fetch_add(1, Ordering::SeqCst) + 1);
        let id = AuditId::from_u128(id_value);
        self.records.push((id, record.clone()));
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::InMemoryAuditLog;
    use konekto_core::{AuditLog, CrossContextGrant, GrantScope, Laboro, Vivo};
    use std::time::Duration;

    #[test]
    fn issues_grant_and_records_in_order() {
        let mut log = InMemoryAuditLog::new();
        assert!(log.is_empty());
        let _g1: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .expect("first grant");
        let _g2: CrossContextGrant<Vivo, Laboro> = log
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .expect("second grant");
        assert_eq!(log.len(), 2);
        let ids: Vec<_> = log.records().iter().map(|(id, _)| id.as_u128()).collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn new_and_default_match() {
        let a = InMemoryAuditLog::new();
        let b = InMemoryAuditLog::default();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.is_empty(), b.is_empty());
    }
}
