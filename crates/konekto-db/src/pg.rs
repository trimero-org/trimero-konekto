//! Postgres-backed [`IdentityStore`] and [`konekto_core::AuditLog`].
//!
//! Gated by the `postgres` Cargo feature. Uses `sqlx` with the
//! `runtime-tokio-rustls` runtime against a [`sqlx::PgPool`] the
//! caller constructs and owns.
//!
//! # Composition
//!
//! [`PgIdentityStore`] implements both [`IdentityStore`] and
//! [`konekto_core::AuditLog`] against the same pool. This mirrors the
//! shape of [`crate::identity::InMemoryStore`]: one handle that the
//! dev-mode enrollment and login flows can take `&mut` of, regardless
//! of which backing store is wired in.
//!
//! The handle is cheap to [`Clone`] (the pool is internally
//! reference-counted), so HTTP handlers typically clone a shared
//! store out of application state per-request to satisfy the
//! `&mut self` contract of the trait methods.
//!
//! # Schema
//!
//! The schema is defined by the SQL migrations under
//! `konekto-db/migrations/`. Call [`PgIdentityStore::migrate`] once
//! at application startup (or out-of-band via `sqlx migrate run`)
//! before using any other method.
//!
//! # Encoding
//!
//! - Enum-typed columns (`status`, `wrap_kind`, `kind`, `grant_scope`)
//!   are persisted as their canonical lower-snake-case text forms.
//!   The helpers in this module are the single source of truth for
//!   the Rust ↔ text mapping.
//! - [`konekto_core::AuditId`] is persisted as a 16-byte big-endian
//!   `BYTEA` so numeric order matches lexicographic byte order.
//! - `kdf_params` is persisted as `JSONB` carrying the three fields
//!   of [`KdfParamsRecord`] as plain integers.

use async_trait::async_trait;
use konekto_core::{AuditId, AuditLog, AuditWriteError, GrantRecord, GrantScope};
use serde_json::{json, Value as JsonValue};
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::DbError;
use crate::identity::IdentityStore;
use crate::records::{
    AuditEventKind, AuditRecord, CredentialRecord, IdentityRecord, IdentityStatus, KdfParamsRecord,
    WrapKind, WrappedRootRecord,
};

/// Embedded SQL migrations. Applied by [`PgIdentityStore::migrate`].
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Postgres-backed persistence for identities, credentials, wrapped
/// root-keys, and the audit log.
///
/// Implements both [`IdentityStore`] and [`konekto_core::AuditLog`]
/// against a single [`sqlx::PgPool`]. Cloning the store is cheap —
/// the pool is internally `Arc`-shared.
#[derive(Clone)]
pub struct PgIdentityStore {
    pool: PgPool,
}

impl PgIdentityStore {
    /// Wrap an existing [`PgPool`].
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Apply the embedded migrations against the pool.
    ///
    /// Idempotent — sqlx's migration tracking skips applied versions.
    ///
    /// # Errors
    ///
    /// Returns the underlying `sqlx` migration error if a migration
    /// script fails to apply.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    /// Borrow the underlying pool — useful for ad-hoc queries, tests,
    /// or upstream code that wants to share the pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// --- error helpers -----------------------------------------------------

// Both helpers take the error by value to compose nicely with
// `.map_err(write_err)` / `.map_err(read_err)`. Silencing
// `needless_pass_by_value` is the right call here: the alternative
// (`|e| write_err(&e)` at every call site) pays a readability cost
// for no real benefit.
#[allow(clippy::needless_pass_by_value)]
fn write_err(err: sqlx::Error) -> DbError {
    match err {
        sqlx::Error::Database(db) if db.is_unique_violation() => DbError::Conflict,
        _ => DbError::StorageWriteFailed,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn read_err(err: sqlx::Error) -> DbError {
    match err {
        sqlx::Error::RowNotFound => DbError::NotFound,
        _ => DbError::StorageReadFailed,
    }
}

// --- enum <-> text mappings --------------------------------------------

fn status_to_text(s: IdentityStatus) -> &'static str {
    match s {
        IdentityStatus::Active => "active",
        IdentityStatus::Frozen => "frozen",
        IdentityStatus::Archived => "archived",
    }
}

fn status_from_text(s: &str) -> Result<IdentityStatus, DbError> {
    match s {
        "active" => Ok(IdentityStatus::Active),
        "frozen" => Ok(IdentityStatus::Frozen),
        "archived" => Ok(IdentityStatus::Archived),
        _ => Err(DbError::StorageReadFailed),
    }
}

fn wrap_kind_to_text(k: WrapKind) -> &'static str {
    match k {
        WrapKind::WebauthnPrf => "webauthn_prf",
        WrapKind::RecoveryPassphrase => "recovery_passphrase",
        WrapKind::DevPassword => "dev_password",
    }
}

fn wrap_kind_from_text(s: &str) -> Result<WrapKind, DbError> {
    match s {
        "webauthn_prf" => Ok(WrapKind::WebauthnPrf),
        "recovery_passphrase" => Ok(WrapKind::RecoveryPassphrase),
        "dev_password" => Ok(WrapKind::DevPassword),
        _ => Err(DbError::StorageReadFailed),
    }
}

fn audit_kind_to_text(k: AuditEventKind) -> &'static str {
    match k {
        AuditEventKind::CrossContextGrant => "cross_context_grant",
        AuditEventKind::Login => "login",
        AuditEventKind::Enrollment => "enrollment",
        AuditEventKind::CredentialBinding => "credential_binding",
        AuditEventKind::CredentialRevocation => "credential_revocation",
        AuditEventKind::IdentityDeletion => "identity_deletion",
    }
}

// `GrantScope` is `#[non_exhaustive]` — the wildcard arm is required
// and intentional. Any future variant must be added here with an
// explicit text form before it is persisted.
fn scope_to_text(s: GrantScope) -> &'static str {
    match s {
        GrantScope::Reserved => "reserved",
        _ => "unknown",
    }
}

// --- KDF params JSON encoding ------------------------------------------

fn kdf_to_json(p: &KdfParamsRecord) -> JsonValue {
    json!({
        "memory_kib": p.memory_kib,
        "iterations": p.iterations,
        "parallelism": p.parallelism,
    })
}

fn kdf_from_json(v: &JsonValue) -> Result<KdfParamsRecord, DbError> {
    let field = |name: &str| -> Result<u32, DbError> {
        v.get(name)
            .and_then(JsonValue::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(DbError::StorageReadFailed)
    };
    Ok(KdfParamsRecord {
        memory_kib: field("memory_kib")?,
        iterations: field("iterations")?,
        parallelism: field("parallelism")?,
    })
}

// --- IdentityStore -----------------------------------------------------

#[async_trait]
impl IdentityStore for PgIdentityStore {
    async fn create_identity(&mut self, record: &IdentityRecord) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO identities (id, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(record.id)
        .bind(status_to_text(record.status))
        .bind(record.created_at)
        .bind(record.updated_at)
        .execute(&self.pool)
        .await
        .map_err(write_err)?;
        Ok(())
    }

    async fn get_identity(&self, id: Uuid) -> Result<IdentityRecord, DbError> {
        let row = sqlx::query(
            "SELECT id, status, created_at, updated_at
             FROM identities WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(read_err)?;

        let status: String = row.try_get("status").map_err(read_err)?;
        Ok(IdentityRecord {
            id: row.try_get("id").map_err(read_err)?,
            status: status_from_text(&status)?,
            created_at: row.try_get("created_at").map_err(read_err)?,
            updated_at: row.try_get("updated_at").map_err(read_err)?,
        })
    }

    async fn save_credential(&mut self, record: &CredentialRecord) -> Result<(), DbError> {
        let sign_count =
            i32::try_from(record.sign_count).map_err(|_| DbError::StorageWriteFailed)?;
        sqlx::query(
            "INSERT INTO credentials
                (id, identity_id, credential_id, public_key, sign_count,
                 transports, created_at, last_used_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(record.id)
        .bind(record.identity_id)
        .bind(&record.credential_id)
        .bind(&record.public_key)
        .bind(sign_count)
        .bind(&record.transports)
        .bind(record.created_at)
        .bind(record.last_used_at)
        .execute(&self.pool)
        .await
        .map_err(write_err)?;
        Ok(())
    }

    async fn save_wrapped_root(&mut self, record: &WrappedRootRecord) -> Result<(), DbError> {
        let kdf_json = record.kdf_params.as_ref().map(kdf_to_json).map(Json);
        sqlx::query(
            "INSERT INTO wrapped_roots
                (id, identity_id, credential_id, wrap_kind, salt,
                 kdf_params, wrapped_blob, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(record.id)
        .bind(record.identity_id)
        .bind(record.credential_id)
        .bind(wrap_kind_to_text(record.wrap_kind))
        .bind(record.salt.as_deref())
        .bind(kdf_json)
        .bind(&record.wrapped_blob)
        .bind(record.created_at)
        .execute(&self.pool)
        .await
        .map_err(write_err)?;
        Ok(())
    }

    async fn find_wrapped_root(
        &self,
        identity_id: Uuid,
        wrap_kind: WrapKind,
    ) -> Result<WrappedRootRecord, DbError> {
        let row = sqlx::query(
            "SELECT id, identity_id, credential_id, wrap_kind,
                    salt, kdf_params, wrapped_blob, created_at
             FROM wrapped_roots
             WHERE identity_id = $1 AND wrap_kind = $2
             LIMIT 1",
        )
        .bind(identity_id)
        .bind(wrap_kind_to_text(wrap_kind))
        .fetch_one(&self.pool)
        .await
        .map_err(read_err)?;

        let wrap_kind_text: String = row.try_get("wrap_kind").map_err(read_err)?;
        let kdf_params: Option<Json<JsonValue>> = row.try_get("kdf_params").map_err(read_err)?;
        let kdf_params = kdf_params.map(|j| kdf_from_json(&j.0)).transpose()?;

        Ok(WrappedRootRecord {
            id: row.try_get("id").map_err(read_err)?,
            identity_id: row.try_get("identity_id").map_err(read_err)?,
            credential_id: row.try_get("credential_id").map_err(read_err)?,
            wrap_kind: wrap_kind_from_text(&wrap_kind_text)?,
            salt: row.try_get("salt").map_err(read_err)?,
            kdf_params,
            wrapped_blob: row.try_get("wrapped_blob").map_err(read_err)?,
            created_at: row.try_get("created_at").map_err(read_err)?,
        })
    }

    async fn record_audit_event(&mut self, record: &AuditRecord) -> Result<(), DbError> {
        let id_bytes = record.id.to_be_bytes();
        let payload: JsonValue =
            serde_json::from_slice(&record.payload).map_err(|_| DbError::StorageWriteFailed)?;
        let scope_text = record.grant_scope.map(scope_to_text);

        sqlx::query(
            "INSERT INTO audit_log
                (id, identity_id, kind, grant_scope, payload, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&id_bytes[..])
        .bind(record.identity_id)
        .bind(audit_kind_to_text(record.kind))
        .bind(scope_text)
        .bind(Json(payload))
        .bind(record.recorded_at)
        .execute(&self.pool)
        .await
        .map_err(write_err)?;
        Ok(())
    }
}

// --- AuditLog (cross-context grants) -----------------------------------

#[async_trait]
impl AuditLog for PgIdentityStore {
    async fn record_grant(&mut self, record: &GrantRecord) -> Result<AuditId, AuditWriteError> {
        let id_u128 = Uuid::new_v4().as_u128();
        let id_bytes = id_u128.to_be_bytes();

        let issued_ms = record
            .issued_at
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let expires_ms = record
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let from_label = core::str::from_utf8(record.from_label).unwrap_or("<invalid-utf8>");
        let to_label = core::str::from_utf8(record.to_label).unwrap_or("<invalid-utf8>");

        let payload = json!({
            "from": from_label,
            "to": to_label,
            "issued_at_ms": issued_ms,
            "expires_at_ms": expires_ms,
        });

        let now = OffsetDateTime::now_utc();

        sqlx::query(
            "INSERT INTO audit_log
                (id, identity_id, kind, grant_scope, payload, recorded_at)
             VALUES ($1, NULL, 'cross_context_grant', $2, $3, $4)",
        )
        .bind(&id_bytes[..])
        .bind(scope_to_text(record.scope))
        .bind(Json(payload))
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|_| AuditWriteError)?;

        Ok(AuditId::from_u128(id_u128))
    }
}

// --- integration tests -------------------------------------------------
//
// All `#[ignore]` because they need a live Docker daemon. Run with:
//
//     cargo test -p konekto-db --features postgres -- --ignored
//
// Each test brings up a fresh Postgres container, applies migrations,
// and exercises the flow end-to-end against that container. Containers
// are torn down when the test function returns (testcontainers drops
// the handle, which stops and removes the container).

#[cfg(test)]
mod tests {
    use super::PgIdentityStore;
    use crate::identity::{enroll_dev_password, login_dev_password, IdentityStore};
    use crate::records::{AuditEventKind, WrapKind};
    use konekto_core::{AuditLog, GrantScope, Laboro, PassphraseParams, Socio, Vivo};
    use sqlx::PgPool;
    use std::time::Duration;
    use testcontainers::runners::AsyncRunner;
    use testcontainers::ContainerAsync;
    use testcontainers_modules::postgres::Postgres;

    // Cheap Argon2 params — same rationale as the other test modules.
    fn fast_params() -> PassphraseParams {
        PassphraseParams::new(8, 1, 1).expect("fast argon2 params")
    }

    /// Spin up a fresh Postgres container, connect, and return the
    /// pool plus the container guard. Dropping the guard tears the
    /// container down.
    async fn fresh_postgres() -> (PgPool, ContainerAsync<Postgres>) {
        let container = Postgres::default()
            .start()
            .await
            .expect("start postgres container");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("resolve mapped port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        let pool = PgPool::connect(&url).await.expect("connect to postgres");
        (pool, container)
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn migrate_is_idempotent() {
        let (pool, _guard) = fresh_postgres().await;
        let store = PgIdentityStore::new(pool);
        store.migrate().await.expect("first migrate");
        store.migrate().await.expect("second migrate");
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn enroll_then_login_roundtrip_against_postgres() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool);
        store.migrate().await.expect("migrate");

        let passphrase = b"correct-horse-battery-staple";
        let params = fast_params();

        let outcome = enroll_dev_password(passphrase, params, &mut store)
            .await
            .expect("enroll");

        let k1 = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .await
            .expect("login 1");
        let k2 = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .await
            .expect("login 2");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn login_with_wrong_passphrase_fails_against_postgres() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool);
        store.migrate().await.expect("migrate");

        let outcome = enroll_dev_password(b"correct-passphrase", fast_params(), &mut store)
            .await
            .expect("enroll");

        let res =
            login_dev_password::<Vivo, _>(outcome.identity_id, b"incorrect-passphrase", &mut store)
                .await;
        assert!(matches!(
            res,
            Err(crate::identity::LoginError::BadPassphrase)
        ));
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn distinct_context_keys_against_postgres() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool);
        store.migrate().await.expect("migrate");

        let passphrase = b"passphrase-context-isolation";
        let outcome = enroll_dev_password(passphrase, fast_params(), &mut store)
            .await
            .expect("enroll");

        let kv = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .await
            .expect("vivo");
        let kl = login_dev_password::<Laboro, _>(outcome.identity_id, passphrase, &mut store)
            .await
            .expect("laboro");
        let ks = login_dev_password::<Socio, _>(outcome.identity_id, passphrase, &mut store)
            .await
            .expect("socio");

        assert_ne!(kv.as_bytes(), kl.as_bytes());
        assert_ne!(kl.as_bytes(), ks.as_bytes());
        assert_ne!(kv.as_bytes(), ks.as_bytes());
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn identity_round_trip_preserves_fields() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool);
        store.migrate().await.expect("migrate");

        let outcome = enroll_dev_password(b"round-trip-identity", fast_params(), &mut store)
            .await
            .expect("enroll");

        let fetched = store
            .get_identity(outcome.identity_id)
            .await
            .expect("fetch");
        assert_eq!(fetched.id, outcome.identity_id);
        assert_eq!(fetched.status, crate::records::IdentityStatus::Active);
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn wrapped_root_round_trip_preserves_kdf_params() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool);
        store.migrate().await.expect("migrate");

        let params = PassphraseParams::new(16, 2, 1).expect("custom params");
        let outcome = enroll_dev_password(b"custom-params-check", params, &mut store)
            .await
            .expect("enroll");

        let fetched = store
            .find_wrapped_root(outcome.identity_id, WrapKind::DevPassword)
            .await
            .expect("fetch wrap");
        assert_eq!(fetched.identity_id, outcome.identity_id);
        assert_eq!(fetched.wrap_kind, WrapKind::DevPassword);
        assert!(fetched.credential_id.is_none());
        let kdf = fetched.kdf_params.expect("kdf params present");
        assert_eq!(kdf.memory_kib, 16);
        assert_eq!(kdf.iterations, 2);
        assert_eq!(kdf.parallelism, 1);
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn audit_events_are_persisted_across_enroll_and_login() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool.clone());
        store.migrate().await.expect("migrate");

        let passphrase = b"audit-events-check";
        let outcome = enroll_dev_password(passphrase, fast_params(), &mut store)
            .await
            .expect("enroll");
        let _k = login_dev_password::<Vivo, _>(outcome.identity_id, passphrase, &mut store)
            .await
            .expect("login");

        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT kind FROM audit_log ORDER BY recorded_at ASC")
                .fetch_all(&pool)
                .await
                .expect("query audit");
        let kinds: Vec<&str> = rows.iter().map(|(k,)| k.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                audit_kind_str(AuditEventKind::Enrollment),
                audit_kind_str(AuditEventKind::Login),
            ]
        );
    }

    fn audit_kind_str(k: AuditEventKind) -> &'static str {
        match k {
            AuditEventKind::CrossContextGrant => "cross_context_grant",
            AuditEventKind::Login => "login",
            AuditEventKind::Enrollment => "enrollment",
            AuditEventKind::CredentialBinding => "credential_binding",
            AuditEventKind::CredentialRevocation => "credential_revocation",
            AuditEventKind::IdentityDeletion => "identity_deletion",
        }
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn cross_context_grant_writes_audit_row() {
        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool.clone());
        store.migrate().await.expect("migrate");

        let grant = store
            .issue::<Vivo, Laboro>(GrantScope::Reserved, Duration::from_secs(60))
            .await
            .expect("issue grant");

        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_log
             WHERE kind = 'cross_context_grant' AND grant_scope = 'reserved'",
        )
        .fetch_one(&pool)
        .await
        .expect("count grants");
        assert_eq!(count, 1);
        // Grant carries the audit id so downstream can cross-reference.
        assert_ne!(grant.audit_id().as_u128(), 0);
    }

    #[tokio::test]
    #[ignore = "requires docker"]
    async fn duplicate_identity_id_raises_conflict() {
        use crate::records::{IdentityRecord, IdentityStatus};
        use time::OffsetDateTime;
        use uuid::Uuid;

        let (pool, _guard) = fresh_postgres().await;
        let mut store = PgIdentityStore::new(pool);
        store.migrate().await.expect("migrate");

        let id = Uuid::new_v4();
        let rec = IdentityRecord {
            id,
            status: IdentityStatus::Active,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        store.create_identity(&rec).await.expect("first insert");
        let second = store.create_identity(&rec).await;
        assert!(matches!(second, Err(crate::DbError::Conflict)));
    }
}
