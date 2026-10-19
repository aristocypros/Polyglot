#!/usr/bin/env bash
# dev/demo.sh - Polyglot End-to-End Demo Across All 5 Chains (Milestone 6 Gate)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PE_SIM="${REPO_ROOT}/tools/pe-sim/pe-sim"
API_URL="${API_URL:-http://127.0.0.1:8080}"
CLIENT_KEY_FILE="${REPO_ROOT}/secrets/client_api_key"
PE_DIR="${REPO_ROOT}/secrets/pe"

# 1. Verify pe-sim launcher exists and is executable
if [ ! -f "${PE_SIM}" ]; then
    echo "Error: pe-sim launcher not found at ${PE_SIM}" >&2
    exit 1
fi
chmod +x "${PE_SIM}"

# 2. Check stack availability
echo "=== Pre-flight Check: Verifying Polyglot Stack at ${API_URL} ==="
if ! curl -sf "${API_URL}/healthz" >/dev/null 2>&1; then
    echo "Error: Polyglot API is not responding at ${API_URL}/healthz" >&2
    echo "Please ensure the stack is running: run 'make bootstrap && make up' first." >&2
    exit 1
fi
echo "Stack is healthy and operational."
echo ""

# 3. Execute End-to-End Demo Runner
exec "${PE_SIM}" demo \
    --api "${API_URL}" \
    --client-key "${CLIENT_KEY_FILE}" \
    --pe-dir "${PE_DIR}" \
    "$@"
