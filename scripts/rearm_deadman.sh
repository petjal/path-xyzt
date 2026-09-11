#!/usr/bin/env bash
# path-xyzt: Re-arm Dead-Man Switch
# Usage: ./scripts/rearm_deadman.sh [24h|48h|72h] (default: 48h)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
HEARTBEAT_FILE="${BASE_DIR}/DEADMAN_HEARTBEAT"

DURATION="${1:-48h}"

case "${DURATION}" in
    24h) SECONDS_ADD=$(( 24 * 3600 )) ;;
    48h) SECONDS_ADD=$(( 48 * 3600 )) ;;
    72h) SECONDS_ADD=$(( 72 * 3600 )) ;;
    *)
        echo "Error: Invalid duration '${DURATION}'. Use 24h, 48h, or 72h." >&2
        exit 1
        ;;
esac

NEW_EXPIRY=$(( $(date +%s) + SECONDS_ADD ))
echo "${NEW_EXPIRY}" > "${HEARTBEAT_FILE}"

EXPIRY_HUMAN=$(date -u -d "@${NEW_EXPIRY}" +"%Y-%m-%dT%H:%M:%SZ")
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [DEADMAN] RE-ARMED: Set to ${DURATION} lease (Expires: ${EXPIRY_HUMAN})."
