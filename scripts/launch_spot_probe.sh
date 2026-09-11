#!/usr/bin/env bash
set -eo pipefail

ZONE="us-central1-a"
INSTANCE_NAME="xyzt-probe-spot-$(date +%s)"
PROJECT_ID="pjgeneral-projects"

echo "[*] Provisioning ephemeral Spot VM: ${INSTANCE_NAME} in ${ZONE}..."

STARTUP_SCRIPT=$(cat << 'INNER_EOF'
#!/bin/bash
set -x
echo "[*] Ephemeral Spot VM initialized at $(date -u)"
apt-get update -y && apt-get install -y docker.io jq

docker run --rm \
  -e PROBE_NODE_ID="vantage-gcp-spotvm-us-central1" \
  -e PROBE_VANTAGE_TYPE="hyperscaler_spot_vm" \
  gcr.io/pjgeneral-projects/path-xyzt-probe:latest

echo "[*] Spot probe finished. Self-destructing..."
# Terminate instance immediately to stop billing
ZONE_LOC=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone | awk -F/ '{print $4}')
VM_NAME=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/name)
gcloud compute instances delete "${VM_NAME}" --zone="${ZONE_LOC}" --quiet || sudo poweroff
INNER_EOF
)

gcloud compute instances create "${INSTANCE_NAME}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --machine-type="e2-micro" \
  --preemptible \
  --provisioning-model="SPOT" \
  --scopes="cloud-platform" \
  --metadata="startup-script=${STARTUP_SCRIPT}"

echo "[*] Spot VM ${INSTANCE_NAME} launched successfully."
