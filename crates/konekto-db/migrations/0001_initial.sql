-- Konekto initial schema.
--
-- Scope: V1 primitives — identities, credentials, wrapped root
-- keys, audit log. Organisational identity (ADR-0005) is handled
-- by a subsequent migration once the natural-person side stabilises.
--
-- Conventions:
--   - UUID v4 primary keys everywhere except the audit log, whose
--     id is a 128-bit integer mirroring `konekto_core::AuditId`.
--   - TIMESTAMPTZ with second precision sufficient for audit;
--     application code uses UTC exclusively.
--   - Enumerated lifecycle states live as TEXT with CHECK
--     constraints rather than Postgres ENUM types: adding a
--     variant in the future is an ALTER TABLE, not a pg_enum
--     mutation, and keeps migrations reviewable.

CREATE TABLE identities (
    id           UUID PRIMARY KEY,
    status       TEXT NOT NULL CHECK (status IN ('active', 'frozen', 'archived')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WebAuthn authenticators bound to an identity.
CREATE TABLE credentials (
    id              UUID PRIMARY KEY,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_id   BYTEA NOT NULL UNIQUE,
    public_key      BYTEA NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports      TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX credentials_by_identity ON credentials (identity_id);

-- Per-credential wrapped root keys (ADR-0004 §3).
-- Multiple rows per identity: one per authenticator plus the
-- recovery-passphrase wrap.
--
-- `credential_id` is nullable because recovery-passphrase and
-- dev-password wraps are not bound to a WebAuthn credential.
-- A partial unique index enforces at-most-one
-- wrap per (identity, credential) pair.
CREATE TABLE wrapped_roots (
    id              UUID PRIMARY KEY,
    identity_id     UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_id   UUID REFERENCES credentials(id) ON DELETE CASCADE,
    wrap_kind       TEXT NOT NULL CHECK (wrap_kind IN (
        'webauthn_prf', 'recovery_passphrase', 'dev_password'
    )),
    salt            BYTEA,
    kdf_params      JSONB,
    wrapped_blob    BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- KDF-based wraps carry a salt + kdf_params; PRF wraps do not.
    CHECK (
        (wrap_kind = 'webauthn_prf'  AND salt IS NULL AND kdf_params IS NULL)
        OR
        (wrap_kind IN ('recovery_passphrase', 'dev_password')
         AND salt IS NOT NULL AND kdf_params IS NOT NULL)
    )
);

CREATE UNIQUE INDEX wrapped_roots_one_per_credential
    ON wrapped_roots (identity_id, credential_id)
    WHERE credential_id IS NOT NULL;

CREATE UNIQUE INDEX wrapped_roots_one_recovery_per_identity
    ON wrapped_roots (identity_id)
    WHERE wrap_kind = 'recovery_passphrase';

-- Audit log.
--
-- `id` is a 16-byte BYTEA holding a u128 in big-endian form so
-- every record has the same identifier on the Rust side
-- (`konekto_core::AuditId`) as in the database. Big-endian
-- encoding preserves numeric order under BYTEA's lexicographic
-- comparator, so ORDER BY id is a monotonic sort.
-- A CHECK constraint enforces the 16-byte width.
--
-- `payload` is JSONB so the serialization format of individual
-- event kinds can evolve without a migration.
CREATE TABLE audit_log (
    id              BYTEA PRIMARY KEY CHECK (octet_length(id) = 16),
    identity_id     UUID REFERENCES identities(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL CHECK (kind IN (
        'cross_context_grant',
        'login',
        'enrollment',
        'credential_binding',
        'credential_revocation',
        'identity_deletion'
    )),
    grant_scope     TEXT,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_by_identity ON audit_log (identity_id, recorded_at DESC);
CREATE INDEX audit_log_by_kind     ON audit_log (kind, recorded_at DESC);
