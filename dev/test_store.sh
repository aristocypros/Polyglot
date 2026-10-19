#!/usr/bin/env bash
# dev/test_store.sh - Run SignerStore integration tests against PostgreSQL
set -euo pipefail

CONTAINER_NAME="${PG_CONTAINER:-pg-test-task23}"
TEST_PG_PORT="${TEST_PG_PORT:-5433}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATIONS_DIR="${ROOT_DIR}/migrations"
SPAWNED_CONTAINER=0

cleanup() {
    if [ "${SPAWNED_CONTAINER}" -eq 1 ]; then
        echo "Cleaning up temporary container ${CONTAINER_NAME}..."
        docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "Starting temporary PostgreSQL 16 container ${CONTAINER_NAME} on port ${TEST_PG_PORT}..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker run -d --name "${CONTAINER_NAME}" -p "${TEST_PG_PORT}:5432" -e POSTGRES_PASSWORD=postgres postgres:16 >/dev/null
    SPAWNED_CONTAINER=1
    echo "Waiting for postgres to become ready..."
    until docker exec "${CONTAINER_NAME}" pg_isready -U postgres >/dev/null 2>&1; do
        sleep 0.5
    done
fi

echo "Applying migrations to ${CONTAINER_NAME}..."
docker exec -i "${CONTAINER_NAME}" psql -U postgres -d postgres -v ON_ERROR_STOP=1 < "${MIGRATIONS_DIR}/000001_initial_schema.up.sql" > /dev/null

echo "Running SignerStore test suite against PostgreSQL on port ${TEST_PG_PORT}..."
DATABASE_URL="postgres://signer_role:signer_pass@127.0.0.1:${TEST_PG_PORT}/postgres" \
    cargo test --manifest-path "${ROOT_DIR}/signer/Cargo.toml" store -- --nocapture

echo "=== ALL SIGNER STORE TESTS PASSED SUCCESSFULLY ==="
