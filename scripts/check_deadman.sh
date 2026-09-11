#!/usr/bin/env bash
# path-xyzt: Dead-Man Switch Sentinel
# Enforces a physical lease timeout (default: 48 hours).
# Probes automatically self-terminate across all vantages if the lease is not renewed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HEARTBEAT_FILE="${BASE_DIR}/DEADMAN_HEARTBEAT"

if [[ ! -f "${HEARTBEAT_FILE}" ]]; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DEADMAN] FATAL: ${HEARTBEAT_FILE} does not exist. Halting execution." >&2
    exit 1
fi

EXPIRY_EPOCH=$(tr -d '[:space:]' < "${HEARTBEAT_FILE}")
CURRENT_EPOCH=$(date +%s)

if ! [[ "${EXPIRY_EPOCH}" =~ ^[0-9]+$ ]]; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DEADMAN] FATAL: Invalid epoch in ${HEARTBEAT_FILE}: '${EXPIRY_EPOCH}'." >&2
    exit 1
fi

if (( CURRENT_EPOCH >= EXPIRY_EPOCH )); then
    EXPIRY_HUMAN=$(date -u -d "@${EXPIRY_EPOCH}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "${EXPIRY_EPOCH}")
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DEADMAN] EXPIRED: Lease expired at ${EXPIRY_HUMAN} (now: $(date -u +"%Y-%m-%dT%H:%M:%SZ"))." >&2
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DEADMAN] Probes halted. Run './scripts/rearm_deadman.sh 48h' to re-arm." >&2
    exit 2
fi

REMAINING_SECS=$(( EXPIRY_EPOCH - CURRENT_EPOCH ))
REMAINING_HOURS=$(( REMAINING_SECS / 3600 ))
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DEADMAN] OK: Lease valid for ${REMAINING_HOURS}h ($(( (REMAINING_SECS % 3600) / 60 ))m remaining)."
exit 0
