#!/usr/bin/env bash
set -eo pipefail

PYTHON_BIN="$(command -v python3 || command -v python || echo "/usr/local/bin/python")"
NODE_ID="${PROBE_NODE_ID:-vantage-gcp-generic}"
VANTAGE_TYPE="${PROBE_VANTAGE_TYPE:-hyperscaler_serverless}"
TARGETS_FILE="${TARGETS_FILE:-/app/targets.txt}"

echo "[*] Initializing path-xyzt probe container on ${NODE_ID} (${VANTAGE_TYPE})..." >&2
echo "[*] Python binary: ${PYTHON_BIN}" >&2
echo "[*] Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2

mkdir -p /dev/shm/batch

while IFS= read -r target || [[ -n "${target}" ]]; do
    [[ "${target}" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${target// }" ]] && continue

    echo "[*] Probing target: ${target}" >&2
    
    if PROBE_NODE_ID="${NODE_ID}" PROBE_VANTAGE_TYPE="${VANTAGE_TYPE}" "${PYTHON_BIN}" /app/collector.py "${target}" > "/dev/shm/batch/${target}.json"; then
        if [ -s "/dev/shm/batch/${target}.json" ]; then
            # Prefix with XYZT_DATA_ROW: for unambiguous parsing from Cloud Logging
            echo -n "XYZT_DATA_ROW:"
            jq -c . "/dev/shm/batch/${target}.json"
        fi
    else
        echo "[-] Non-zero exit on target: ${target}" >&2
    fi

    rm -f "/dev/shm/batch/${target}.json"
    sleep 1
done < "${TARGETS_FILE}"

echo "[*] Probe sweep finished on ${NODE_ID}." >&2
