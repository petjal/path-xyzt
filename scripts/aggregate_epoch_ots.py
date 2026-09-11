#!/usr/bin/env python3
"""
path-xyzt: RFC 6962 Merkle Tree Aggregator & OpenTimestamps (OTS) Client Hook
Specification v1.5.0 - Invariant 3

Pipeline:
1. Intake hourly NDJSON probe records from local/cloud streams.
2. Extract and lexicographically sort all 256-bit BundleSeal digests.
3. Compute RFC 6962 Merkle EpochRoot:
   - Leaf: SHA256(0x00 || BundleSeal_bytes)
   - Internal: SHA256(0x01 || LeftChild || RightChild)
   - Odd leaf promotion (no duplication, CVE-2012-2459 immune)
4. Submit EpochRoot to OpenTimestamps calendar servers:
   - Primary: alice.btc.calendar.opentimestamps.org
   - Secondary: bob.btc.calendar.opentimestamps.org
   - Tertiary: finney.calendar.eternitywall.com
5. Write out audit receipt (.ots commitment file) and JSON manifest.
"""

import sys
import os
import json
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone

CALENDAR_URLS = [
    "https://alice.btc.calendar.opentimestamps.org/digest",
    "https://bob.btc.calendar.opentimestamps.org/digest",
    "https://finney.calendar.eternitywall.com/digest"
]

CANONICAL_USER_AGENT = "path-xyzt/1.5.0 (+https://github.com/petjal/path-xyzt; public-telemetry-probe; contact: pjalajas@gmail.com)"

def rfc6962_leaf_hash(seal_hex: str) -> bytes:
    seal_bytes = bytes.fromhex(seal_hex)
    h = hashlib.sha256()
    h.update(b'\x00')
    h.update(seal_bytes)
    return h.digest()

def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b'\x01')
    h.update(left)
    h.update(right)
    return h.digest()

def _mth(leaves: list) -> bytes:
    n = len(leaves)
    if n == 0:
        h = hashlib.sha256()
        h.update(b"path-xyzt/v1/epoch/empty:\x00")
        return h.digest()
    if n == 1:
        return leaves[0]
    
    # RFC 6962 Section 2.1: k = largest power of 2 strictly less than n
    k = 1 << ((n - 1).bit_length() - 1)
    return rfc6962_node_hash(_mth(leaves[:k]), _mth(leaves[k:]))

def build_rfc6962_epoch_root(sorted_seals: list) -> bytes:
    if not sorted_seals:
        h = hashlib.sha256()
        h.update(b"path-xyzt/v1/epoch/empty:\x00")
        return h.digest()

    leaf_hashes = [rfc6962_leaf_hash(s) for s in sorted_seals]
    return _mth(leaf_hashes)

def submit_to_ots_calendar(digest: bytes, calendar_url: str) -> bytes:
    req = urllib.request.Request(
        calendar_url,
        data=digest,
        headers={
            "User-Agent": CANONICAL_USER_AGENT,
            "Content-Type": "application/octet-stream",
            "Accept": "application/vnd.opentimestamps.v1"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 201):
                return resp.read()
    except Exception as e:
        sys.stderr.write(f"[-] Calendar {calendar_url} error: {e}\n")
    return b""

def main():
    if len(sys.argv) < 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} <telemetry_stream.ndjson> [output_epoch_manifest.json]\n")
        sys.exit(2)

    ndjson_path = sys.argv[1]
    if not os.path.exists(ndjson_path):
        sys.stderr.write(f"Error: file not found: {ndjson_path}\n")
        sys.exit(1)

    output_manifest_path = sys.argv[2] if len(sys.argv) > 2 else None

    seals = set()
    records_parsed = 0
    with open(ndjson_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                seal = row.get("merkle_seals", {}).get("bundle_seal")
                if seal and len(seal) == 64:
                    seals.add(seal)
                    records_parsed += 1
            except json.JSONDecodeError:
                continue

    sorted_seals = sorted(list(seals))
    epoch_root_bytes = build_rfc6962_epoch_root(sorted_seals)
    epoch_root_hex = epoch_root_bytes.hex()

    now_iso = datetime.now(timezone.utc).isoformat()

    print(f"[*] Parsed {records_parsed} probe records, found {len(sorted_seals)} unique BundleSeals.")
    print(f"[*] RFC 6962 EpochRoot: {epoch_root_hex}")

    calendar_results = {}
    for cal in CALENDAR_URLS:
        cal_resp = submit_to_ots_calendar(epoch_root_bytes, cal)
        calendar_results[cal] = {
            "status": "SUBMITTED" if cal_resp else "FAILED",
            "response_bytes_len": len(cal_resp)
        }
        if cal_resp and output_manifest_path:
            cal_slug = cal.split("//")[1].split("/")[0]
            ots_out_file = f"{output_manifest_path}.{cal_slug}.ots"
            with open(ots_out_file, "wb") as bf:
                bf.write(cal_resp)

    manifest = {
        "schema_version": "1.5.0",
        "protocol": "path-xyzt/v1/epoch",
        "timestamp_iso8601": now_iso,
        "input_stream": ndjson_path,
        "records_parsed": records_parsed,
        "unique_bundle_seals_count": len(sorted_seals),
        "bundle_seals": sorted_seals,
        "rfc6962_epoch_root_sha256": epoch_root_hex,
        "ots_submission": {
            "lifecycle_state": "PENDING_CALENDAR" if any(c["status"] == "SUBMITTED" for c in calendar_results.values()) else "CALENDAR_FAILED",
            "calendars": calendar_results
        }
    }

    if output_manifest_path:
        with open(output_manifest_path, "w", encoding="utf-8") as out_f:
            json.dump(manifest, out_f, indent=2)
        print(f"[+] Wrote Epoch manifest to: {output_manifest_path}")
    else:
        print(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
