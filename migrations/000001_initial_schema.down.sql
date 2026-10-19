-- Polyglot Postgres Migrations: 000001_initial_schema.down.sql
-- Compatible with golang-migrate
-- Reverts initial schema: drops triggers, tables, schemas, and roles.

-- 1. Drop Audit Triggers & Function
DROP TRIGGER IF EXISTS trg_no_modify_signer_audit ON signer.signer_audit;
DROP TRIGGER IF EXISTS trg_no_modify_app_audit ON app.audit_log;
DROP FUNCTION IF EXISTS app.prevent_audit_modification();

-- 2. Drop Tables in 'signer' Schema
DROP TABLE IF EXISTS signer.signer_audit CASCADE;
DROP TABLE IF EXISTS signer.results CASCADE;
DROP TABLE IF EXISTS signer.replay CASCADE;

-- 3. Drop Tables in 'app' Schema
DROP TABLE IF EXISTS app.audit_log CASCADE;
DROP TABLE IF EXISTS app.requests CASCADE;
DROP TABLE IF EXISTS app.wallets CASCADE;
DROP TABLE IF EXISTS app.api_keys CASCADE;

-- 4. Drop Schemas
DROP SCHEMA IF EXISTS signer CASCADE;
DROP SCHEMA IF EXISTS app CASCADE;

-- 5. Drop Roles
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_role') THEN
        DROP OWNED BY api_role;
        DROP ROLE api_role;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'signer_role') THEN
        DROP OWNED BY signer_role;
        DROP ROLE signer_role;
    END IF;
END
$$;
