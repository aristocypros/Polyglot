#!/usr/bin/env bash
# dev/bootstrap.sh - Bootstrap environment, secrets, and SoftHSM token for Polyglot
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${REPO_ROOT}/secrets"
DEPLOY_DIR="${REPO_ROOT}/deploy"

echo "=== Polyglot Bootstrap: Initializing Secrets & Environment ==="

# 1. Create secrets directory with restricted permissions
mkdir -p "${SECRETS_DIR}"
chmod 0700 "${SECRETS_DIR}"

# Helper to generate secret if missing
generate_secret_if_missing() {
    local file="$1"
    local gen_cmd="$2"
    if [ ! -s "${file}" ]; then
        eval "${gen_cmd}" > "${file}"
        chmod 0600 "${file}"
        echo "  [+] Generated $(basename "${file}")"
    else
        echo "  [.] $(basename "${file}") already exists"
    fi
}

# Writes a SoftHSM PIN from an environment variable, or a random one when the variable is unset.
# An existing PIN file is kept: the token in the hsm-tokens volume was initialized with it.
write_pin() {
    local file="$1"
    local var_name="$2"
    local value="${!var_name:-}"
    if [ -s "${file}" ]; then
        if [ -n "${value}" ] && [ "${value}" != "$(cat "${file}")" ]; then
            echo "Error: ${var_name} differs from the existing $(basename "${file}")." >&2
            echo "The HSM token was initialized with the existing PIN. To change it, delete" >&2
            echo "${file} and reset the token (docker compose -f deploy/compose.yaml down -v)." >&2
            exit 1
        fi
        echo "  [.] $(basename "${file}") already exists"
        return
    fi
    if [ -n "${value}" ]; then
        if [ "${#value}" -lt 4 ] || [ "${#value}" -gt 255 ] || [[ "${value}" =~ [[:space:]] ]]; then
            echo "Error: ${var_name} must be 4 to 255 characters with no whitespace." >&2
            exit 1
        fi
        printf '%s' "${value}" > "${file}"
        echo "  [+] Wrote $(basename "${file}") from ${var_name}"
    else
        openssl rand -hex 16 | tr -d '\n' > "${file}"
        echo "  [+] Generated random $(basename "${file}")"
    fi
    chmod 0600 "${file}"
}

# 2. Generate secrets if missing
write_pin "${SECRETS_DIR}/softhsm_user_pin" SOFTHSM_USER_PIN
write_pin "${SECRETS_DIR}/softhsm_so_pin" SOFTHSM_SO_PIN
generate_secret_if_missing "${SECRETS_DIR}/db_admin_password" "openssl rand -hex 16 | tr -d '\n'"
generate_secret_if_missing "${SECRETS_DIR}/db_api_password" "openssl rand -hex 16 | tr -d '\n'"
generate_secret_if_missing "${SECRETS_DIR}/db_signer_password" "openssl rand -hex 16 | tr -d '\n'"
generate_secret_if_missing "${SECRETS_DIR}/client_api_key" "echo -n 'client_sec_'$(openssl rand -hex 24)"
generate_secret_if_missing "${SECRETS_DIR}/signer_token" "echo -n 'signer_sec_'$(openssl rand -hex 24)"

# Set restrictive permissions on all secret files
chmod 0600 "${SECRETS_DIR}"/*

# 3. Generate dev Policy Engine key pairs if missing (for pe-sim)
mkdir -p "${SECRETS_DIR}/pe"
chmod 0700 "${SECRETS_DIR}/pe"

if [ -f "${REPO_ROOT}/tools/pe-sim/pe-sim" ]; then
    if [ ! -f "${SECRETS_DIR}/pe/pe-dev-1.key" ]; then
        echo "  [+] Generating pe-dev-1 Ed25519 dev policy key..."
        "${REPO_ROOT}/tools/pe-sim/pe-sim" keygen --alg ed25519 --kid pe-dev-1 --out "${SECRETS_DIR}/pe" >/dev/null || true
    fi
    if [ ! -f "${SECRETS_DIR}/pe/pe-dev-2.key" ]; then
        echo "  [+] Generating pe-dev-2 ES256 dev policy key..."
        "${REPO_ROOT}/tools/pe-sim/pe-sim" keygen --alg es256 --kid pe-dev-2 --out "${SECRETS_DIR}/pe" >/dev/null || true
    fi
fi

# 4. Build Docker images and run bootstrap job
echo "=== Building Docker Images & Executing SoftHSM Bootstrap Job ==="
docker compose -f "${DEPLOY_DIR}/compose.yaml" build
docker compose -f "${DEPLOY_DIR}/compose.yaml" run --rm bootstrap

echo "=== Polyglot Bootstrap Completed Successfully ==="
