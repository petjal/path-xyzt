#!/usr/bin/env bash
# path-xyzt: Master 6-Way Multi-Vantage Hourly Orchestrator
# Coordinates concurrent telemetry sampling across:
# 0. Local Eyeball Control (ThinkPad T14 Comcast residential)
# 1. GCP Compute Engine Always-On VM (free-tier-hdd static anchor)
# 2. GCP Cloud Run Jobs (Serverless Anycast/gVisor Netstack)
# 3. GCP Cloud Batch Spot Sweep (Ephemeral KVM raw kernel)
# 4. GCP Cloud Build Runner (Free-tier worker container)
# 5. GCP Ephemeral Spot VM (On-demand KVM instance)
# + Deep-Dive Policy & Canary Tree Audit
set -euo pipefail

BASE_DIR="/home/petjal/dev/path-xyzt"
LOG_DIR="${BASE_DIR}/data"
mkdir -p "${LOG_DIR}"
ORCH_LOG="${LOG_DIR}/orchestrator.log"
VM_SSH="ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no pjalajas_gmail_com@100.68.160.4"

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [ORCH] $*" | tee -a "${ORCH_LOG}"
}

# 1. Verify Dead-Man Switch Lease
if ! "${BASE_DIR}/scripts/check_deadman.sh" >> "${ORCH_LOG}" 2>&1; then
    log "FATAL: Dead-man switch check failed or lease expired. Halting hourly orchestration."
    exit 0
fi

log "=== Starting Complete 6-Way Multi-Vantage Telemetry Cycle ==="

# Vantage 0: Local T14 Residential Eyeball Control
log "[0/5] Triggering Local Eyeball Vantage sweep (T14 residential Comcast)..."
"${BASE_DIR}/scripts/run_batch_probe.sh" >> "${LOG_DIR}/eyeball_runner.log" 2>&1 &
PID_EYEBALL=$!

# Vantage 1: GCP Compute Engine Always-On VM (Static Anchor 146.148.40.72)
log "[1/5] Triggering GCP Static Anchor VM probe (free-tier-hdd)..."
${VM_SSH} "python3 ~/dev/path-xyzt/scripts/strawman_collector.py dtcc.com > /dev/null 2>&1" &

# Vantage 2: GCP Cloud Run Jobs (Serverless gVisor Netstack)
log "[2/5] Triggering GCP Cloud Run Job 'xyzt-probe-cloudrun' (us-central1)..."
${VM_SSH} "gcloud run jobs execute xyzt-probe-cloudrun --region=us-central1" >> "${ORCH_LOG}" 2>&1 || {
    log "[-] Warning: Cloud Run trigger returned non-zero."
}

# Vantage 3: GCP Cloud Batch Spot Sweep (Native KVM raw kernel)
log "[3/5] Triggering GCP Cloud Batch Spot Job..."
${VM_SSH} "JOB_ID=\"xyzt-batch-\$(date +%s)\" && gcloud batch jobs submit \"\${JOB_ID}\" --location=us-central1 --config=- << 'EOF'
{
  \"taskGroups\": [{
    \"taskSpec\": {
      \"runnables\": [{
        \"container\": {
          \"imageUri\": \"gcr.io/pjgeneral-projects/path-xyzt-probe:latest\",
          \"entrypoint\": \"/app/entrypoint.sh\",
          \"options\": \"--env PROBE_NODE_ID=vantage-gcp-batch-us-central1 --env PROBE_VANTAGE_TYPE=hyperscaler_batch\"
        }
      }],
      \"computeResource\": {\"cpuMilli\": 1000, \"memoryMib\": 1024}
    },
    \"taskCount\": 1
  }],
  \"allocationPolicy\": {
    \"instances\": [{
      \"policy\": {
        \"provisioningModel\": \"SPOT\",
        \"machineType\": \"e2-micro\"
      }
    }]
  },
  \"logsPolicy\": {\"destination\": \"CLOUD_LOGGING\"}
}
EOF" >> "${ORCH_LOG}" 2>&1 || log "[-] Warning: Cloud Batch submit returned non-zero."

# Vantage 4: GCP Cloud Build Runner (Free-tier worker)
log "[4/5] Triggering GCP Cloud Build Runner step..."
${VM_SSH} "gcloud builds submit --config=~/dev/path-xyzt/cloudbuild-probe.yaml --no-source" >> "${ORCH_LOG}" 2>&1 || {
    log "[-] Warning: Cloud Build step returned non-zero."
}

# Vantage 5: Deep-Dive Policy & Warrant Canary Audit
log "[5/5] Triggering Deep-Dive Policy & Canary Tree Audit on critical targets..."
for target in dtcc.com hongkongpost.gov.hk; do
    "${BASE_DIR}/scripts/deep_dive_collector.py" "${target}" >> "${LOG_DIR}/deep_dive_stream.ndjson" 2>> "${ORCH_LOG}" || {
        log "[-] Warning: Deep-dive audit failed on ${target}."
    }
done

# Wait for local eyeball probe to finalize
wait "${PID_EYEBALL}" || log "[-] Local eyeball batch finished with warnings."

log "=== Complete 6-Way Multi-Vantage Cycle Dispatched & Recorded ==="
