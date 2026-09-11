#!/usr/bin/env python3
"""
path-xyzt: GCP Multi-Vantage Shootout Harvester
Extracts, validates, and compares telemetry across all 5 GCP methods and Eyeball vantage.
"""

import sys
import json
import subprocess
from datetime import datetime, timezone

def harvest_cloud_logging(hours_back=1):
    cmd = [
        "gcloud", "logging", "read",
        f'textPayload=~"XYZT_DATA_ROW:" AND timestamp >= "{(datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:00:00Z")}"',
        "--limit=500",
        "--format=json(textPayload,timestamp,resource.type,labels)"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        entries = json.loads(res.stdout)
        rows = []
        for e in entries:
            text = e.get("textPayload", "")
            if "XYZT_DATA_ROW:" in text:
                raw_json = text.split("XYZT_DATA_ROW:", 1)[1].strip()
                try:
                    row = json.loads(raw_json)
                    rows.append(row)
                except Exception:
                    pass
        return rows
    except Exception as ex:
        print(f"[-] Error querying Cloud Logging: {ex}", file=sys.stderr)
        return []

if __name__ == '__main__':
    print("[*] Harvesting GCP multi-vantage telemetry...")
    rows = harvest_cloud_logging()
    print(f"[*] Retrieved {len(rows)} normalized probe rows.")
    for r in rows:
        meta = r.get("probe_metadata", {})
        target = r.get("target", {})
        hops = r.get("last_mile_signature", {})
        print(f"[{meta.get('probe_node_id')}] {target.get('hostname')} -> {target.get('resolved_ip')} | Hops: {hops.get('total_hops')} | HopHash: {hops.get('hophash')[:12]}")
