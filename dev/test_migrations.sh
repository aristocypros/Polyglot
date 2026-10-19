#!/usr/bin/env bash
# dev/test_migrations.sh - Automated SQL migration & permission check validation
set -euo pipefail

CONTAINER_NAME="${PG_CONTAINER:-pg-test-task22}"
MIGRATIONS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../migrations" && pwd)"
SPAWNED_CONTAINER=0

cleanup() {
    if [ "${SPAWNED_CONTAINER}" -eq 1 ]; then
        echo "Cleaning up temporary container ${CONTAINER_NAME}..."
        docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Starting temporary PostgreSQL 16 container ${CONTAINER_NAME}..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker run -d --name "${CONTAINER_NAME}" -e POSTGRES_PASSWORD=postgres postgres:16 >/dev/null
    SPAWNED_CONTAINER=1
    echo "Waiting for postgres to become ready..."
    until docker exec "${CONTAINER_NAME}" pg_isready -U postgres >/dev/null 2>&1; do
        sleep 0.5
    done
fi

echo "=== Running Polyglot Postgres Migrations Validation ==="
echo "Container: ${CONTAINER_NAME}"
echo "Migrations: ${MIGRATIONS_DIR}"

run_sql() {
    local sql="$1"
    docker exec -i "${CONTAINER_NAME}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c "${sql}"
}

run_sql_file() {
    local file="$1"
    docker exec -i "${CONTAINER_NAME}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 < "${file}"
}

run_expect_error() {
    local desc="$1"
    local sql="$2"
    local expected_pattern="$3"

    echo -n "  Testing: ${desc}... "
    local out
    if out=$(docker exec -i "${CONTAINER_NAME}" psql -U postgres -d postgres -c "${sql}" 2>&1); then
        echo "FAILED (command unexpectedly succeeded)"
        echo "${out}"
        exit 1
    else
        if echo "${out}" | grep -qE "${expected_pattern}"; then
            echo "PASSED (expected error received: ${expected_pattern})"
        else
            echo "FAILED (unexpected error output: ${out})"
            exit 1
        fi
    fi
}

run_expect_success() {
    local desc="$1"
    local sql="$2"

    echo -n "  Testing: ${desc}... "
    local out
    if out=$(docker exec -i "${CONTAINER_NAME}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c "${sql}" 2>&1); then
        echo "PASSED"
    else
        echo "FAILED"
        echo "${out}"
        exit 1
    fi
}

echo "1. Applying Down Migration (clean state)..."
run_sql_file "${MIGRATIONS_DIR}/000001_initial_schema.down.sql" > /dev/null

echo "2. Applying Up Migration..."
run_sql_file "${MIGRATIONS_DIR}/000001_initial_schema.up.sql" > /dev/null
echo "   Migration 000001 applied successfully."

echo "3. Verifying api_role isolation on signer schema..."
run_expect_error "api_role cannot SELECT signer.replay" \
    "SET ROLE api_role; SELECT * FROM signer.replay;" \
    "permission denied for schema signer"

run_expect_error "api_role cannot INSERT signer.replay" \
    "SET ROLE api_role; INSERT INTO signer.replay (request_id, nonce, seen_at) VALUES ('11111111-1111-1111-1111-111111111111', 'n1', now());" \
    "permission denied for schema signer"

run_expect_error "api_role cannot SELECT signer.results" \
    "SET ROLE api_role; SELECT * FROM signer.results;" \
    "permission denied for schema signer"

run_expect_error "api_role cannot INSERT signer.results" \
    "SET ROLE api_role; INSERT INTO signer.results (request_id, response, response_sig) VALUES ('11111111-1111-1111-1111-111111111111', '{}', 's');" \
    "permission denied for schema signer"

run_expect_error "api_role cannot SELECT signer.signer_audit" \
    "SET ROLE api_role; SELECT * FROM signer.signer_audit;" \
    "permission denied for schema signer"

run_expect_error "api_role cannot INSERT signer.signer_audit" \
    "SET ROLE api_role; INSERT INTO signer.signer_audit (actor, event, prev_hash, hash) VALUES ('a', 'e', '0', '1');" \
    "permission denied for schema signer"

echo "4. Verifying api_role privileges on app schema..."
run_expect_success "api_role can INSERT into app.api_keys" \
    "SET ROLE api_role; INSERT INTO app.api_keys (name, role, key_hash) VALUES ('test-key', 'client', 'hash123');"

run_expect_success "api_role can SELECT app.api_keys" \
    "SET ROLE api_role; SELECT * FROM app.api_keys WHERE key_hash = 'hash123';"

run_expect_success "api_role can INSERT into app.wallets" \
    "SET ROLE api_role; INSERT INTO app.wallets (wallet_id, scheme, curve, seed_version, kek_label, wrapped_seed) VALUES ('w_perm_01', 'bip32', 'secp256k1', 1, 'kek-v1', '\x010203');"

run_expect_success "api_role can SELECT app.wallets" \
    "SET ROLE api_role; SELECT * FROM app.wallets WHERE wallet_id = 'w_perm_01';"

run_expect_success "api_role can INSERT into app.requests" \
    "SET ROLE api_role; INSERT INTO app.requests (request_id, type, wallet_id, body_canonical, \"authorization\", body_hash, status, expires_at) VALUES ('44444444-4444-4444-4444-444444444444', 'create_wallet', 'w_perm_01', '\x7b7d', '{}', 'h', 'ready', now() + interval '5m');"

run_expect_success "api_role can SELECT and UPDATE app.requests" \
    "SET ROLE api_role; UPDATE app.requests SET status = 'claimed', claimed_until = now() + interval '60s' WHERE request_id = '44444444-4444-4444-4444-444444444444';"

run_expect_success "api_role can INSERT into app.audit_log" \
    "SET ROLE api_role; INSERT INTO app.audit_log (actor, event, prev_hash, hash) VALUES ('api', 'req_created', '00', '11');"

run_expect_success "api_role can SELECT app.audit_log" \
    "SET ROLE api_role; SELECT seq, actor, hash FROM app.audit_log;"

run_expect_error "api_role CANNOT UPDATE app.audit_log" \
    "SET ROLE api_role; UPDATE app.audit_log SET event = 'hacked' WHERE seq = 1;" \
    "permission denied for table audit_log"

run_expect_error "api_role CANNOT DELETE app.audit_log" \
    "SET ROLE api_role; DELETE FROM app.audit_log WHERE seq = 1;" \
    "permission denied for table audit_log"

echo "5. Verifying signer_role privileges on signer schema..."
run_expect_success "signer_role can INSERT into signer.replay" \
    "SET ROLE signer_role; INSERT INTO signer.replay (request_id, nonce, seen_at) VALUES ('55555555-5555-5555-5555-555555555555', 'nonce_valid', now());"

run_expect_success "signer_role can SELECT signer.replay" \
    "SET ROLE signer_role; SELECT * FROM signer.replay WHERE nonce = 'nonce_valid';"

run_expect_success "signer_role can INSERT into signer.results" \
    "SET ROLE signer_role; INSERT INTO signer.results (request_id, response, response_sig) VALUES ('55555555-5555-5555-5555-555555555555', '{\"ok\":true}'::jsonb, 'sig_abc');"

run_expect_success "signer_role can SELECT signer.results" \
    "SET ROLE signer_role; SELECT * FROM signer.results WHERE request_id = '55555555-5555-5555-5555-555555555555';"

run_expect_success "signer_role can INSERT into signer.signer_audit" \
    "SET ROLE signer_role; INSERT INTO signer.signer_audit (actor, event, prev_hash, hash) VALUES ('signer', 'signed', '00', '22');"

run_expect_success "signer_role can SELECT signer.signer_audit" \
    "SET ROLE signer_role; SELECT seq, actor, hash FROM signer.signer_audit;"

run_expect_error "signer_role CANNOT UPDATE signer.signer_audit" \
    "SET ROLE signer_role; UPDATE signer.signer_audit SET event = 'tampered' WHERE seq = 1;" \
    "permission denied for table signer_audit"

run_expect_error "signer_role CANNOT DELETE signer.signer_audit" \
    "SET ROLE signer_role; DELETE FROM signer.signer_audit WHERE seq = 1;" \
    "permission denied for table signer_audit"

echo "6. Verifying signer_role isolation on app schema..."
run_expect_success "signer_role can SELECT app.wallets (read-only)" \
    "SET ROLE signer_role; SELECT wallet_id, scheme FROM app.wallets;"

run_expect_error "signer_role CANNOT INSERT app.wallets" \
    "SET ROLE signer_role; INSERT INTO app.wallets (wallet_id, scheme, curve, seed_version, kek_label, wrapped_seed) VALUES ('w_fail', 'bip32', 'secp256k1', 1, 'k', '\x00');" \
    "permission denied for table wallets"

run_expect_error "signer_role CANNOT SELECT app.requests" \
    "SET ROLE signer_role; SELECT * FROM app.requests;" \
    "permission denied for table requests"

run_expect_error "signer_role CANNOT SELECT app.api_keys" \
    "SET ROLE signer_role; SELECT * FROM app.api_keys;" \
    "permission denied for table api_keys"

run_expect_error "signer_role CANNOT SELECT app.audit_log" \
    "SET ROLE signer_role; SELECT * FROM app.audit_log;" \
    "permission denied for table audit_log"

echo "7. Verifying audit immutability triggers (even for superuser)..."
run_expect_error "Superuser CANNOT UPDATE app.audit_log" \
    "RESET ROLE; UPDATE app.audit_log SET event = 'tampered';" \
    "Audit log entries are immutable and cannot be updated or deleted"

run_expect_error "Superuser CANNOT DELETE app.audit_log" \
    "RESET ROLE; DELETE FROM app.audit_log;" \
    "Audit log entries are immutable and cannot be updated or deleted"

run_expect_error "Superuser CANNOT UPDATE signer.signer_audit" \
    "RESET ROLE; UPDATE signer.signer_audit SET event = 'tampered';" \
    "Audit log entries are immutable and cannot be updated or deleted"

run_expect_error "Superuser CANNOT DELETE signer.signer_audit" \
    "RESET ROLE; DELETE FROM signer.signer_audit;" \
    "Audit log entries are immutable and cannot be updated or deleted"

echo "8. Verifying down migration rollback..."
run_sql_file "${MIGRATIONS_DIR}/000001_initial_schema.down.sql" > /dev/null
run_expect_error "app schema is dropped" \
    "SELECT * FROM app.wallets;" \
    "does not exist"
run_expect_error "signer schema is dropped" \
    "SELECT * FROM signer.replay;" \
    "does not exist"

echo "9. Re-applying Up Migration for final clean state..."
run_sql_file "${MIGRATIONS_DIR}/000001_initial_schema.up.sql" > /dev/null

echo "=== ALL POSTGRES MIGRATION & ROLE SEPARATION TESTS PASSED ==="
