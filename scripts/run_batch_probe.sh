#!/usr/bin/env bash
# path-xyzt: Continuous Automated Probe Runner
set -euo pipefail

BASE_DIR="/home/petjal/dev/path-xyzt"
TARGETS_FILE="${BASE_DIR}/targets.txt"
DATA_DIR="${BASE_DIR}/data"
OUTPUT_FILE="${DATA_DIR}/telemetry_stream.ndjson"
LOG_FILE="${DATA_DIR}/probe_runner.log"

mkdir -p "${DATA_DIR}"

if ! "${BASE_DIR}/scripts/check_deadman.sh" >> "${LOG_FILE}" 2>&1; then
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Dead-man switch check failed or expired. Halting probe run." >> "${LOG_FILE}"
    exit 0
fi

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Starting path-xyzt probe batch (Dead-man switch verified)" >> "${LOG_FILE}"

while IFS= read -r target || [[ -n "${target}" ]]; do
    # Skip comments and empty lines
    [[ "${target}" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${target// }" ]] && continue

    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Probing target: ${target}" >> "${LOG_FILE}"
    
    # Run collector with global generous timeout (50s wrapper allowing internal 45s alarm to handle fallback)
    if timeout 50s "${BASE_DIR}/scripts/strawman_collector.py" "${target}" > "/dev/shm/tmp_probe_${target}.json" 2>> "${LOG_FILE}"; then
        # Compact single-line NDJSON append
        jq -c . "/dev/shm/tmp_probe_${target}.json" >> "${OUTPUT_FILE}"
        rm -f "/dev/shm/tmp_probe_${target}.json"
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Successfully recorded: ${target}" >> "${LOG_FILE}"
    else
        echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] ERROR/TIMEOUT probing: ${target}" >> "${LOG_FILE}"
    fi

    
    # Polite inter-target spacing (1-2s)
    sleep 1.5
done < "${TARGETS_FILE}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Batch run complete." >> "${LOG_FILE}"
