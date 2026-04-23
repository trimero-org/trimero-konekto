//! Identity storage and the dev-mode enrollment / login flow.
//!
//! This module demonstrates that the primitives in `konekto-core`
//! compose into a working identity lifecycle end-to-end:
//!
//! ```text
//! enroll                          login
//! ──────                          ─────
//!   generate RootKey                fetch WrappedRootRecord
//!   generate salt                   Argon2id(passphrase, stored salt) -> WrappingKey
//!   Argon2id(passphrase, salt)      RootKey::unwrap(blob, WrappingKey) -> RootKey
//!       -> WrappingKey              RootKey::derive::<C>() -> ContextKey<C>
//!   RootKey::wrap(WrappingKey)
//!       -> WrappedRootKey
//!   persist Identity + wrap
//!   RootKey drops (zeroized)
//! ```
//!
//! The dev-mode path wraps the root key under `Argon2id(password)`.
//! Production flows (`WebAuthn` PRF per credential, BIP-39 recovery
//! passphrase) reuse the same primitives and persistence types —
//! they differ only in where the `WrappingKey` comes from.

use konekto_core::{
    random_bytes, AuditId, AuditLog, AuditWriteError, Context, ContextKey, Error as CryptoError,
    GrantRecord, PassphraseParams, RootKey, WrappedRootKey, MIN_SALT_LEN,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::DbError;
use crate::records::{
    AuditEventKind, AuditRecord, CredentialRecord, IdentityRecord, IdentityStatus, KdfParamsRecord,
    WrapKind, WrappedRootRecord,
};

/// Storage surface required by the identity flows.
///
/// A single implementor owns identities, their credentials, the
/// wrapped root-key blobs bound to them, and the audit trail. This
/// bundles concerns that a mature deployment will split across
/// multiple backends (Postgres tables, a KMS, a dedicated audit
/// store); the dev-mode flow treats them as one unit for
/// testability.
pub trait IdentityStore {
    /// Insert a new identity. Fails with [`DbError::Conflict`] if an
    /// identity with the same id already exists.
    fn create_identity(&mut self, record: &IdentityRecord) -> Result<(), DbError>;

    /// Load an identity by id.
    fn get_identity(&self, id: Uuid) -> Result<IdentityRecord, DbError>;

    /// Insert a new credential for an identity.
    fn save_credential(&mut self, record: &CredentialRecord) -> Result<(), DbError>;

    /// Insert a wrapped root-key record.
    fn save_wrapped_root(&mut self, record: &WrappedRootRecord) -> Result<(), DbError>;

    /// Find the first wrapped-root record for `identity_id` matching
    /// `wrap_kind`. The dev-password and recovery-passphrase paths
    /// have at most one row per identity (enforced by the schema),
    /// so a single-result lookup is sufficient.
    fn find_wrapped_root(
        &self,
        identity_id: Uuid,
        wrap_kind: WrapKind,
    ) -> Result<WrappedRootRecord, DbError>;

    /// Append an audit event.
    fn record_audit_event(&mut self, record: &AuditRecord) -> Result<(), DbError>;
}

/// Process-local store combining identities, credentials, wrapped
/// roots, and the audit log. Suitable for tests and dev deployments.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    identities: HashMap<Uuid, IdentityRecord>,
    credentials: HashMap<Uuid, CredentialRecord>,
    wrapped_roots: Vec<WrappedRootRecord>,
    audit_events: Vec<AuditRecord>,
    grant_records: Vec<(AuditId, GrantRecord)>,
    next_audit_id: AtomicU64,
}

impl InMemoryStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// All audit events recorded so far, in insertion order.
    #[must_use]
    pub fn audit_events(&self) -> &[AuditRecord] {
        &self.audit_events
    }

    /// All cross-context grant records recorded so far, in
    /// insertion order.
    #[must_use]
    pub fn grant_records(&self) -> &[(AuditId, GrantRecord)] {
        &self.grant_records
    }

    /// All wrapped-root records currently held.
    #[must_use]
    pub fn wrapped_roots(&self) -> &[WrappedRootRecord] {
        &self.wrapped_roots
    }

    fn next_id(&self) -> u128 {
        u128::from(self.next_audit_id.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

impl IdentityStore for InMemoryStore {
    fn create_identity(&mut self, record: &IdentityRecord) -> Result<(), DbError> {
        if self.identities.contains_key(&record.id) {
            return Err(DbError::Conflict);
        }
        self.identities.insert(record.id, record.clone());
        Ok(())
    }

    fn get_identity(&self, id: Uuid) -> Result<IdentityRecord, DbError> {
        self.identities.get(&id).cloned().ok_or(DbError::NotFound)
    }

    fn save_credential(&mut self, record: &CredentialRecord) -> Result<(), DbError> {
        if self.credentials.contains_key(&record.id) {
            return Err(DbError::Conflict);
        }
        if self
            .credentials
            .values()
            .any(|c| c.credential_id == record.credential_id)
        {
            return Err(DbError::Conflict);
        }
        self.credentials.insert(record.id, record.clone());
        Ok(())
    }

    fn save_wrapped_root(&mut self, record: &WrappedRootRecord) -> Result<(), DbError> {
        self.wrapped_roots.push(record.clone());
        Ok(())
    }

    fn find_wrapped_root(
        &self,
        identity_id: Uuid,
        wrap_kind: WrapKind,
    ) -> Result<WrappedRootRecord, DbError> {
        self.wrapped_roots
            .iter()
            .find(|r| r.identity_id == identity_id && r.wrap_kind == wrap_kind)
            .cloned()
            .ok_or(DbError::NotFound)
    }

    fn record_audit_event(&mut self, record: &AuditRecord) -> Result<(), DbError> {
        self.audit_events.push(record.clone());
        Ok(())
    }
}

impl AuditLog for InMemoryStore {
    fn record_grant(&mut self, record: &GrantRecord) -> Result<AuditId, AuditWriteError> {
        let id = AuditId::from_u128(self.next_id());
        self.grant_records.push((id, record.clone()));
        Ok(id)
    }
}

/// Errors produced by the dev-mode enrollment flow.
#[derive(Debug, Error)]
pub enum EnrollmentError {
    /// A cryptographic step (KDF, wrap, derive) failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// Persistence failed.
    #[error("storage error: {0}")]
    Storage(#[from] DbError),
}

/// Errors produced by the dev-mode login flow.
#[derive(Debug, Error)]
pub enum LoginError {
    /// Identity or wrapped-root record not found.
    #[error("identity not found")]
    NotFound,
    /// The wrapped-root record carries a wrap kind other than
    /// [`WrapKind::DevPassword`], indicating a state corruption or
    /// that the caller reached this flow with an identity provisioned
    /// via a different path.
    #[error("identity is not provisioned for dev-password login")]
    WrongWrapKind,
    /// The stored wrap is missing the salt or KDF parameters the
    /// dev-password flow requires — a state invariant violation.
    #[error("stored wrap is missing dev-password metadata")]
    MissingDevMetadata,
    /// Passphrase derivation failed a boundary check.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// The wrapped blob failed AEAD authentication: wrong passphrase,
    /// or tampered storage.
    #[error("bad passphrase or tampered storage")]
    BadPassphrase,
    /// Persistence failed.
    #[error("storage error: {0}")]
    Storage(#[from] DbError),
}

/// Outcome of a successful [`enroll_dev_password`] call.
#[derive(Debug)]
pub struct EnrollmentOutcome {
    /// Newly-created identity id.
    pub identity_id: Uuid,
}

/// Create a brand-new identity wrapped under a dev-mode passphrase.
///
/// - Generates a 256-bit [`RootKey`] from the system CSPRNG.
/// - Generates a fresh [`MIN_SALT_LEN`]-byte salt.
/// - Derives a [`konekto_core::WrappingKey`] via Argon2id with the
///   provided [`PassphraseParams`].
/// - Wraps the root key and persists the blob plus the salt and
///   parameters needed to re-derive at login.
/// - Records an [`AuditEventKind::Enrollment`] event.
///
/// The [`RootKey`] is dropped (zeroized) before the function
/// returns. Callers get an identity id; they then call
/// [`login_dev_password`] to establish a context-bound session.
pub fn enroll_dev_password<S>(
    passphrase: &[u8],
    params: PassphraseParams,
    store: &mut S,
) -> Result<EnrollmentOutcome, EnrollmentError>
where
    S: IdentityStore,
{
    let root = RootKey::generate();
    let salt = random_bytes(MIN_SALT_LEN);

    let wrapping_key = params.derive_wrapping_key(passphrase, &salt)?;
    let wrapped = root.wrap(&wrapping_key);

    let now = OffsetDateTime::now_utc();
    let identity_id = Uuid::new_v4();

    store.create_identity(&IdentityRecord {
        id: identity_id,
        status: IdentityStatus::Active,
        created_at: now,
        updated_at: now,
    })?;

    store.save_wrapped_root(&WrappedRootRecord {
        id: Uuid::new_v4(),
        identity_id,
        credential_id: None,
        wrap_kind: WrapKind::DevPassword,
        salt: Some(salt),
        kdf_params: Some(KdfParamsRecord {
            memory_kib: params.memory_kib(),
            iterations: params.iterations(),
            parallelism: params.parallelism(),
        }),
        wrapped_blob: wrapped.as_bytes().to_vec(),
        created_at: now,
    })?;

    let audit_id = Uuid::new_v4().as_u128();
    store.record_audit_event(&AuditRecord {
        id: audit_id,
        identity_id: Some(identity_id),
        kind: AuditEventKind::Enrollment,
        grant_scope: None,
        payload: b"{\"flow\":\"dev_password\"}".to_vec(),
        recorded_at: now,
    })?;

    Ok(EnrollmentOutcome { identity_id })
}

/// Establish a context-bound session for an existing dev-password
/// identity and return its [`ContextKey<C>`].
///
/// The `C` type parameter selects the context: `login_dev_password::<Vivo, _>(...)`
/// returns a `ContextKey<Vivo>` that is a distinct, non-coercible
/// compile-time type from the Laboro and Socio variants.
///
/// - Loads the stored wrap + salt + KDF params.
/// - Re-derives the wrapping key via Argon2id.
/// - Unwraps the root key (AEAD-authenticated — a wrong passphrase
///   surfaces as [`LoginError::BadPassphrase`]).
/// - Derives the context key for `C` and drops the root.
/// - Records an [`AuditEventKind::Login`] event.
pub fn login_dev_password<C, S>(
    identity_id: Uuid,
    passphrase: &[u8],
    store: &mut S,
) -> Result<ContextKey<C>, LoginError>
where
    C: Context,
    S: IdentityStore,
{
    let wrap_record = match store.find_wrapped_root(identity_id, WrapKind::DevPassword) {
        Ok(r) => r,
        Err(DbError::NotFound) => return Err(LoginError::NotFound),
        Err(e) => return Err(e.into()),
    };

    if wrap_record.wrap_kind != WrapKind::DevPassword {
        return Err(LoginError::WrongWrapKind);
    }

    let (Some(salt), Some(kdf_params)) = (&wrap_record.salt, wrap_record.kdf_params) else {
        return Err(LoginError::MissingDevMetadata);
    };

    let params = PassphraseParams::new(
        kdf_params.memory_kib,
        kdf_params.iterations,
        kdf_params.parallelism,
    )?;
    let wrapping_key = params.derive_wrapping_key(passphrase, salt)?;

    let wrapped = WrappedRootKey::from_bytes(&wrap_record.wrapped_blob)?;

    let root = match RootKey::unwrap(&wrapped, &wrapping_key) {
        Ok(r) => r,
        Err(CryptoError::UnwrapAuthFailed) => return Err(LoginError::BadPassphrase),
        Err(e) => return Err(LoginError::Crypto(e)),
    };

    let context_key = root.derive::<C>();

    let now = OffsetDateTime::now_utc();
    let audit_id = Uuid::new_v4().as_u128();
    store.record_audit_event(&AuditRecord {
        id: audit_id,
        identity_id: Some(identity_id),
        kind: AuditEventKind::Login,
        grant_scope: None,
        payload: b"{\"flow\":\"dev_password\"}".to_vec(),
        recorded_at: now,
    })?;

    Ok(context_key)
}

#[cfg(test)]
mod tests {
    use super::{
        enroll_dev_password, login_dev_password, EnrollmentError, InMemoryStore, LoginError,
    };
    use crate::records::{AuditEventKind, WrapKind};
    use konekto_core::{Laboro, PassphraseParams, Socio, Vivo};

    // Cheap params — same rationale as the kdf test module.
    fn fast_params() -> PassphraseParams {
        PassphraseParams::new(8, 1, 1).expect("fast argon2 params")
    }

    #[test]
    fn enroll_then_login_yields_identical_context_keys() {
        let mut store = InMemoryStore::new();
        let passphrase = b"correct-horse-battery-staple";
        let params = fast_params();

        let outcome = enroll_dev_password(passphrase, params, &mut store).expect("enroll");

        let k1 = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .expect("login 1");
        let k2 = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .expect("login 2");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn login_with_wrong_passphrase_fails_with_bad_passphrase() {
        let mut store = InMemoryStore::new();
        let params = fast_params();
        let outcome =
            enroll_dev_password(b"correct-passphrase", params, &mut store).expect("enroll");

        let res =
            login_dev_password::<Vivo, _>(outcome.identity_id, b"incorrect-passphrase", &mut store);
        assert!(matches!(res, Err(LoginError::BadPassphrase)));
    }

    #[test]
    fn login_for_unknown_identity_fails_with_not_found() {
        let mut store = InMemoryStore::new();
        let res = login_dev_password::<Vivo, _>(uuid::Uuid::new_v4(), b"anything12", &mut store);
        assert!(matches!(res, Err(LoginError::NotFound)));
    }

    #[test]
    fn login_derives_distinct_context_keys_per_context() {
        let mut store = InMemoryStore::new();
        let passphrase = b"passphrase-context-isolation";
        let params = fast_params();
        let outcome = enroll_dev_password(passphrase, params, &mut store).expect("enroll");

        let kv = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .expect("vivo");
        let kl = login_dev_password::<Laboro, _>(outcome.identity_id, passphrase, &mut store)
            .expect("laboro");
        let ks = login_dev_password::<Socio, _>(outcome.identity_id, passphrase, &mut store)
            .expect("socio");

        assert_ne!(kv.as_bytes(), kl.as_bytes());
        assert_ne!(kl.as_bytes(), ks.as_bytes());
        assert_ne!(kv.as_bytes(), ks.as_bytes());
    }

    #[test]
    fn two_enrollments_produce_independent_identities_and_keys() {
        let mut store = InMemoryStore::new();
        let params = fast_params();

        let a = enroll_dev_password(b"passphrase-alpha", params, &mut store).expect("enroll a");
        let b = enroll_dev_password(b"passphrase-bravo", params, &mut store).expect("enroll b");
        assert_ne!(a.identity_id, b.identity_id);

        let ka = login_dev_password::<Vivo, _>(a.identity_id, b"passphrase-alpha", &mut store)
            .expect("login a");
        let kb = login_dev_password::<Vivo, _>(b.identity_id, b"passphrase-bravo", &mut store)
            .expect("login b");
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn enroll_rejects_short_passphrase_via_kdf_boundary() {
        let mut store = InMemoryStore::new();
        let params = fast_params();
        let res = enroll_dev_password(b"short", params, &mut store);
        assert!(matches!(res, Err(EnrollmentError::Crypto(_))));
        // Must not leave partial state behind.
        assert!(store.wrapped_roots().is_empty());
    }

    #[test]
    fn enroll_writes_audit_event_of_expected_kind() {
        let mut store = InMemoryStore::new();
        let params = fast_params();
        let outcome =
            enroll_dev_password(b"correct-horse-battery", params, &mut store).expect("enroll");
        let events = store.audit_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::Enrollment);
        assert_eq!(events[0].identity_id, Some(outcome.identity_id));
    }

    #[test]
    fn login_writes_audit_event_of_expected_kind() {
        let mut store = InMemoryStore::new();
        let params = fast_params();
        let passphrase = b"correct-horse-battery";
        let outcome = enroll_dev_password(passphrase, params, &mut store).expect("enroll");
        let _k = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .expect("login");

        let events = store.audit_events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].kind, AuditEventKind::Login);
        assert_eq!(events[1].identity_id, Some(outcome.identity_id));
    }

    #[test]
    fn wrapped_root_record_carries_dev_password_kind_and_salt() {
        let mut store = InMemoryStore::new();
        let params = fast_params();
        let outcome =
            enroll_dev_password(b"correct-horse-battery", params, &mut store).expect("enroll");

        let roots = store.wrapped_roots();
        assert_eq!(roots.len(), 1);
        let r = &roots[0];
        assert_eq!(r.identity_id, outcome.identity_id);
        assert_eq!(r.wrap_kind, WrapKind::DevPassword);
        assert!(r.credential_id.is_none());
        assert!(r.salt.is_some());
        assert!(r.kdf_params.is_some());
        let stored_params = r.kdf_params.unwrap();
        assert_eq!(stored_params.memory_kib, params.memory_kib());
        assert_eq!(stored_params.iterations, params.iterations());
        assert_eq!(stored_params.parallelism, params.parallelism());
    }
}
