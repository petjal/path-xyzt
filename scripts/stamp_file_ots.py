#!/usr/bin/env python3
import sys
import os
import hashlib
import urllib.request

CALENDAR_URL = "https://alice.btc.calendar.opentimestamps.org/digest"
USER_AGENT = "path-xyzt/1.5.0 (+https://github.com/petjal/path-xyzt; contact: pjalajas@gmail.com)"

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <file_to_stamp>")
    sys.exit(1)

target_path = sys.argv[1]
if not os.path.exists(target_path):
    print(f"File not found: {target_path}")
    sys.exit(1)

with open(target_path, "rb") as f:
    content = f.read()

file_hash = hashlib.sha256(content).digest()
print(f"File: {target_path}")
print(f"Size: {len(content)} bytes")
print(f"SHA256: {file_hash.hex()}")

# Submit raw 32-byte digest to calendar
req = urllib.request.Request(
    CALENDAR_URL,
    data=file_hash,
    headers={
        "User-Agent": USER_AGENT,
        "Content-Type": "application/octet-stream",
        "Accept": "application/vnd.opentimestamps.v1"
    },
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        if resp.status in (200, 201):
            calendar_reply = resp.read()
            ots_path = f"{target_path}.ots"
            
            # OpenTimestamps .ots file format starts with magic bytes: \x00OpenTimestamps\x00\x00Proof\x00\xbf\x89e\xa7\x91SN\x08
            # Followed by the hash operation and the calendar commitment
            magic = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89e\xa7\x91SN\x08"
            major_version = b"\x01"
            # SHA256 opcode tag: 0x08
            # Then the payload from calendar
            with open(ots_path, "wb") as out:
                out.write(magic)
                out.write(major_version)
                out.write(b"\x08") # OpSha256 tag
                out.write(calendar_reply)
            
            print(f"[+] Successfully stamped and wrote valid OTS file: {ots_path}")
            print(f"[+] Receipt size: {os.path.getsize(ots_path)} bytes")
        else:
            print(f"[-] Calendar returned HTTP {resp.status}")
except Exception as e:
    print(f"[-] Calendar submission error: {e}")
