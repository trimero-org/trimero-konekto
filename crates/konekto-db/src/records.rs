//! Rust record types that pair with the durable schema.
//!
//! One struct per persisted table. Fields mirror column names and
//! carry the primitive Rust types that the Postgres driver will
//! serialize in a follow-up increment.
//!
//! These types are intentionally plain data — no behaviour, no
//! serialization impls, no derived `serde::Serialize`. That keeps
//! the boundary crisp: callers construct records, storage moves
//! bytes, and no one accidentally ships a record over a public API.

use konekto_core::GrantScope;
use time::OffsetDateTime;
use uuid::Uuid;

/// Lifecycle state of an identity. Mirrors ADR-0005's organisational
/// lifecycle for consistency; natural-person identities only use
/// the subset `{Active, Frozen, Archived}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityStatus {
    /// Normal, usable identity.
    Active,
    /// Suspended: authentication attempts fail but records remain.
    Frozen,
    /// Deletion target: wrapped-root records are crypto-shredded
    /// (per ADR-0004 §5). Retained for audit-period only.
    Archived,
}

/// The identity anchor. No PII, no per-context data — that lives in
/// the filiale-specific databases.
#[derive(Clone, Debug)]
pub struct IdentityRecord {
    /// Opaque identity id (UUID v4). Stable for the lifetime of the
    /// identity, including through context-specific changes.
    pub id: Uuid,
    /// Current lifecycle state.
    pub status: IdentityStatus,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last state change.
    pub updated_at: OffsetDateTime,
}

/// Metadata for one authenticator registered to an identity.
///
/// Actual credential bytes follow the `WebAuthn` Level 3 / CTAP 2.1
/// conventions. The wrapped-root-key material for this credential
/// is stored separately in [`WrappedRootRecord`] to keep wrap
/// rotation (ADR-0004 §3) a targeted operation.
#[derive(Clone, Debug)]
pub struct CredentialRecord {
    /// Local primary key (UUID v4). Distinct from `credential_id`
    /// so the `WebAuthn` id is never used as a foreign-key value.
    pub id: Uuid,
    /// Identity this credential belongs to.
    pub identity_id: Uuid,
    /// `WebAuthn` credential id, as issued by the authenticator.
    /// Unique across the whole table.
    pub credential_id: Vec<u8>,
    /// COSE-encoded public key for signature verification.
    pub public_key: Vec<u8>,
    /// Authenticator signature counter at last assertion. Used for
    /// cloned-authenticator detection (`WebAuthn` §6.1.3 step 17).
    pub sign_count: u32,
    /// Transports reported by the authenticator (e.g. "usb", "nfc",
    /// "ble", "internal", "hybrid"). Stored as a text array.
    pub transports: Vec<String>,
    /// Registration timestamp.
    pub created_at: OffsetDateTime,
    /// Timestamp of the most recent successful assertion, if any.
    pub last_used_at: Option<OffsetDateTime>,
}

/// Which wrapping mechanism produced this `WrappedRootKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapKind {
    /// Wrapped under a `WebAuthn` PRF (`hmac-secret`) output.
    /// No KDF params; no salt (the authenticator provides the
    /// secret and the salt as part of the assertion).
    WebauthnPrf,
    /// Wrapped under Argon2id of a BIP-39 recovery passphrase
    /// combined with a server-stored per-identity salt.
    RecoveryPassphrase,
    /// Dev-mode password wrap. Compiled into dev/test paths only
    /// and rejected by production config.
    DevPassword,
}

/// Serialized Argon2id parameters stored alongside a KDF-based
/// wrapped root. Maps 1-1 with [`konekto_core::PassphraseParams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParamsRecord {
    /// Argon2 memory cost, in KiB.
    pub memory_kib: u32,
    /// Argon2 iteration count.
    pub iterations: u32,
    /// Argon2 parallelism.
    pub parallelism: u32,
}

/// A single wrapped root-key blob attached to an identity.
///
/// Multi-device (ADR-0004 §3) means a single identity holds
/// multiple `WrappedRootRecord`s — one per registered authenticator
/// plus one for the recovery-passphrase path. Deletion (ADR-0004
/// §5) zeroes the `wrapped_blob` column, rendering every wrapped
/// root cryptographically unrecoverable.
#[derive(Clone, Debug)]
pub struct WrappedRootRecord {
    /// Local primary key.
    pub id: Uuid,
    /// Identity this wrap belongs to.
    pub identity_id: Uuid,
    /// Credential whose secret produced the wrapping key. `None`
    /// for recovery-passphrase and dev-password wraps.
    pub credential_id: Option<Uuid>,
    /// Which wrapping mechanism this blob was produced by.
    pub wrap_kind: WrapKind,
    /// Per-wrap salt, for KDF-based mechanisms. `None` for
    /// [`WrapKind::WebauthnPrf`].
    pub salt: Option<Vec<u8>>,
    /// KDF tuning parameters, if the wrap came from a KDF.
    pub kdf_params: Option<KdfParamsRecord>,
    /// Serialized [`konekto_core::WrappedRootKey`] bytes
    /// (61 bytes for v1).
    pub wrapped_blob: Vec<u8>,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
}

/// Audit event kind. Free-form tag persisted as text in the audit
/// table so new kinds can be added without a migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditEventKind {
    /// A [`konekto_core::CrossContextGrant`] was issued.
    CrossContextGrant,
    /// A successful login (first-party or OAuth).
    Login,
    /// An enrollment completed — new identity + first credential.
    Enrollment,
    /// A new credential was bound to an existing identity.
    CredentialBinding,
    /// A credential was revoked.
    CredentialRevocation,
    /// An identity transitioned to `Archived`.
    IdentityDeletion,
}

/// Inserted into the audit log for every security-relevant event.
///
/// The polymorphic `payload` field is represented as an owned
/// byte vector here; the Postgres backend stores it as JSONB.
/// `konekto-db` does not parse this vector — it is produced and
/// consumed by the layer that issues the event.
#[derive(Clone, Debug)]
pub struct AuditRecord {
    /// Audit entry id. Matches [`konekto_core::AuditId`].
    pub id: u128,
    /// Identity the event pertains to, if any. `None` for global
    /// or pre-authentication events.
    pub identity_id: Option<Uuid>,
    /// Kind of event.
    pub kind: AuditEventKind,
    /// Scope of a cross-context grant, if the event is one.
    pub grant_scope: Option<GrantScope>,
    /// JSON-encoded payload describing the event in detail.
    pub payload: Vec<u8>,
    /// Event time.
    pub recorded_at: OffsetDateTime,
}
