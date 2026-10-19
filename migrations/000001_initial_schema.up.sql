-- Polyglot Postgres Migrations: 000001_initial_schema.up.sql
-- Compatible with golang-migrate
-- Creates schemas 'app' and 'signer', roles 'api_role' and 'signer_role',
-- tables, indexes, immutability triggers, and enforces strict role separation.

-- 1. Create Roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_role') THEN
        CREATE ROLE api_role WITH LOGIN PASSWORD 'api_pass';
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'signer_role') THEN
        CREATE ROLE signer_role WITH LOGIN PASSWORD 'signer_pass';
    END IF;
END
$$;

-- 2. Create Schemas
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS signer;

-- 3. Create Tables in 'app' Schema

-- app.api_keys
CREATE TABLE IF NOT EXISTS app.api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_lookup ON app.api_keys (key_hash) WHERE revoked_at IS NULL;

-- app.wallets
CREATE TABLE IF NOT EXISTS app.wallets (
    wallet_id TEXT PRIMARY KEY,
    label TEXT NOT NULL DEFAULT '',
    scheme TEXT NOT NULL,
    curve TEXT NOT NULL,
    seed_version INTEGER NOT NULL DEFAULT 1,
    kek_label TEXT NOT NULL,
    wrapped_seed BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_wallets_created_at ON app.wallets (created_at DESC);

-- app.requests
CREATE TABLE IF NOT EXISTS app.requests (
    request_id UUID PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    type TEXT NOT NULL,
    wallet_id TEXT NOT NULL,
    body_canonical BYTEA NOT NULL,
    "authorization" JSONB NOT NULL,
    body_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ready',
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_until TIMESTAMPTZ,
    result JSONB,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_requests_ready_queue ON app.requests (created_at) WHERE status = 'ready';
CREATE INDEX IF NOT EXISTS idx_requests_claimed_lease ON app.requests (claimed_until) WHERE status = 'claimed';
CREATE INDEX IF NOT EXISTS idx_requests_expiry ON app.requests (expires_at) WHERE status IN ('ready', 'claimed');
CREATE INDEX IF NOT EXISTS idx_requests_wallet_id ON app.requests (wallet_id);

-- app.audit_log (hash-chained immutable audit log)
CREATE TABLE IF NOT EXISTS app.audit_log (
    seq BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    request_id UUID,
    decision_id TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_app_audit_seq ON app.audit_log (seq ASC);
CREATE INDEX IF NOT EXISTS idx_app_audit_request_id ON app.audit_log (request_id) WHERE request_id IS NOT NULL;

-- 4. Create Tables in 'signer' Schema

-- signer.replay
CREATE TABLE IF NOT EXISTS signer.replay (
    request_id UUID PRIMARY KEY,
    nonce TEXT UNIQUE NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- signer.results
CREATE TABLE IF NOT EXISTS signer.results (
    request_id UUID PRIMARY KEY,
    response JSONB NOT NULL,
    response_sig TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- signer.signer_audit (hash-chained immutable audit log)
CREATE TABLE IF NOT EXISTS signer.signer_audit (
    seq BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    request_id UUID,
    decision_id TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signer_audit_seq ON signer.signer_audit (seq ASC);
CREATE INDEX IF NOT EXISTS idx_signer_audit_request_id ON signer.signer_audit (request_id) WHERE request_id IS NOT NULL;

-- 5. Audit Immutability Triggers (Reject UPDATE and DELETE)
CREATE OR REPLACE FUNCTION app.prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log entries are immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_no_modify_app_audit'
    ) THEN
        CREATE TRIGGER trg_no_modify_app_audit
        BEFORE UPDATE OR DELETE ON app.audit_log
        FOR EACH ROW EXECUTE FUNCTION app.prevent_audit_modification();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_no_modify_signer_audit'
    ) THEN
        CREATE TRIGGER trg_no_modify_signer_audit
        BEFORE UPDATE OR DELETE ON signer.signer_audit
        FOR EACH ROW EXECUTE FUNCTION app.prevent_audit_modification();
    END IF;
END
$$;

-- 6. Role Isolation and Grants

-- Revoke default public schema privileges
REVOKE ALL ON SCHEMA signer FROM PUBLIC;
REVOKE ALL ON SCHEMA app FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA signer FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA app FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA signer FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA app FROM PUBLIC;

-- api_role isolation & privileges
-- Zero privileges on signer schema
REVOKE ALL ON SCHEMA signer FROM api_role;
REVOKE ALL ON ALL TABLES IN SCHEMA signer FROM api_role;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA signer FROM api_role;
REVOKE ALL ON ALL ROUTINES IN SCHEMA signer FROM api_role;

-- Privileges on app schema
GRANT USAGE ON SCHEMA app TO api_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.api_keys TO api_role;
GRANT SELECT, INSERT, UPDATE ON app.wallets TO api_role;
GRANT SELECT, INSERT, UPDATE ON app.requests TO api_role;

-- app.audit_log: SELECT and INSERT only; no UPDATE or DELETE
GRANT SELECT, INSERT ON app.audit_log TO api_role;
GRANT USAGE, SELECT ON SEQUENCE app.audit_log_seq_seq TO api_role;
REVOKE UPDATE, DELETE, TRUNCATE ON app.audit_log FROM api_role;

-- signer_role isolation & privileges
-- Privileges on signer schema
GRANT USAGE ON SCHEMA signer TO signer_role;
GRANT SELECT, INSERT ON signer.replay TO signer_role;
GRANT SELECT, INSERT ON signer.results TO signer_role;
GRANT SELECT, INSERT ON signer.signer_audit TO signer_role;
GRANT USAGE, SELECT ON SEQUENCE signer.signer_audit_seq_seq TO signer_role;
REVOKE UPDATE, DELETE, TRUNCATE ON signer.signer_audit FROM signer_role;

-- signer_role privileges on app schema (read-only on app.wallets, zero access on others)
GRANT USAGE ON SCHEMA app TO signer_role;
GRANT SELECT ON app.wallets TO signer_role;
REVOKE ALL ON app.api_keys FROM signer_role;
REVOKE ALL ON app.requests FROM signer_role;
REVOKE ALL ON app.audit_log FROM signer_role;
