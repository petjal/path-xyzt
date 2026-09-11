#!/usr/bin/env python3
"""
path-xyzt: Deep Dive Policy & Warrant Canary Collector (v1.0.0)
Performs scheduled, non-intrusive structural inspections into High-Value Target
policy directories, terms of service, vulnerability disclosure rules, and warrant canaries.
"""

import sys
import os
import json
import time
import ssl
import urllib.request
import xml.etree.ElementTree as ET
import hashlib
import re
from datetime import datetime, timezone

CANONICAL_USER_AGENT = "path-xyzt/1.6.0 (+https://github.com/petjal/path-xyzt; deep-dive-probe; contact: pjalajas@gmail.com)"

HIGH_INTEREST_KEYWORDS = [
    "legal", "terms", "privacy", "security", "disclosure",
    "vulnerability", "canary", "compliance", "subprocessor",
    "transparency", "arbitration", "disclaimer", "cybersecurity"
]

def get_normalized_prose(html_content: str) -> str:
    """Strips scripts, styles, dynamic nonce attributes, and whitespace."""
    clean = re.sub(r"<script[^>]*>.*?</script>", "", html_content, flags=re.I | re.S)
    clean = re.sub(r"<style[^>]*>.*?</style>", "", clean, flags=re.I | re.S)
    clean = re.sub(r"<[^>]+>", " ", clean)
    return " ".join(clean.split())

def discover_policy_urls_from_sitemap(domain: str, max_urls=30):
    sitemap_url = f"https://{domain}/sitemap.xml"
    req = urllib.request.Request(sitemap_url, headers={'User-Agent': CANONICAL_USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    urls = []
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            data = resp.read(2097152) # cap at 2 MiB
            root = ET.fromstring(data)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for url_elem in root.findall("sm:url", ns):
                loc = url_elem.find("sm:loc", ns)
                lastmod = url_elem.find("sm:lastmod", ns)
                if loc is not None and loc.text:
                    u = loc.text.strip()
                    lm = lastmod.text.strip() if (lastmod is not None and lastmod.text) else None
                    if any(k in u.lower() for k in HIGH_INTEREST_KEYWORDS):
                        urls.append((u, lm))
                        if len(urls) >= max_urls:
                            break
    except Exception:
        pass
    return urls

def discover_policy_urls_from_root(domain: str, max_urls=30):
    root_url = f"https://{domain}/"
    req = urllib.request.Request(root_url, headers={'User-Agent': CANONICAL_USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    urls = []
    seen = set()
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            html = resp.read(262144).decode('utf-8', errors='ignore')
            raw_anchors = re.findall(r"<a\s+(?:[^>]*?\s+)?href=[\x22\x27]([^\x22\x27]+)[\x22\x27][^>]*>(.*?)</a>", html, re.I | re.S)
            for href, text in raw_anchors:
                clean_href = href.strip()
                clean_text = re.sub(r"<[^>]+>", "", text).strip()
                href_l = clean_href.lower()
                text_l = clean_text.lower()
                if any(k in href_l or k in text_l for k in HIGH_INTEREST_KEYWORDS):
                    full_url = clean_href if clean_href.startswith("http") else ("https://" + domain + ("/" if not clean_href.startswith("/") else "") + clean_href)
                    if full_url not in seen:
                        seen.add(full_url)
                        urls.append((full_url, None))
                        if len(urls) >= max_urls:
                            break
    except Exception:
        pass
    return urls

def inspect_policy_target(url: str):
    req = urllib.request.Request(url, headers={'User-Agent': CANONICAL_USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    res = {
        "url": url,
        "status": None,
        "content_length": 0,
        "etag": None,
        "last_modified": None,
        "h_raw": "00"*32,
        "h_prose": "00"*32,
        "is_pgp_signed": False
    }

    try:
        with urllib.request.urlopen(req, timeout=4, context=ctx) as resp:
            res["status"] = resp.status
            res["etag"] = resp.headers.get("ETag")
            res["last_modified"] = resp.headers.get("Last-Modified")
            body = resp.read(131072) # cap at 128 KiB
            res["content_length"] = len(body)
            res["h_raw"] = hashlib.sha256(body).hexdigest()
            text = body.decode('utf-8', errors='ignore')
            res["is_pgp_signed"] = ("-----BEGIN PGP SIGNED MESSAGE-----" in text)
            prose = get_normalized_prose(text)
            res["h_prose"] = hashlib.sha256(prose.encode('utf-8')).hexdigest()
    except Exception as e:
        res["status"] = f"ERR: {e}"

    return res

def run_deep_dive_audit(target_domain: str, max_pages=25):
    t0 = time.time()
    discovered = discover_policy_urls_from_sitemap(target_domain, max_urls=max_pages)
    source = "SITEMAP_XML"
    if not discovered:
        discovered = discover_policy_urls_from_root(target_domain, max_urls=max_pages)
        source = "ROOT_PAGE_FALLBACK"

    inspected_pages = []
    leaves = []
    for u, declared_lm in discovered:
        r = inspect_policy_target(u)
        r["declared_lastmod_sitemap"] = declared_lm
        inspected_pages.append(r)
        
        leaf_str = f"{r['url']}|{r['status']}|{r['h_prose']}"
        leaves.append(hashlib.sha256(leaf_str.encode('utf-8')).hexdigest())

    leaves.sort()
    if not leaves:
        h_tree = "00" * 32
    else:
        current = [bytes.fromhex(l) for l in leaves]
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    combined = hashlib.sha256(b"\x01" + current[i] + current[i+1]).digest()
                else:
                    combined = current[i]
                next_level.append(combined)
            current = next_level
        h_tree = current[0].hex()

    total_time_ms = round((time.time() - t0) * 1000, 2)

    return {
        "schema_version": "1.6.0",
        "probe_metadata": {
            "probe_node_id": os.environ.get("PROBE_NODE_ID", "vantage-us-east-eyeball-01"),
            "probe_type": "deep_dive_policy_audit",
            "timestamp_iso8601": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": total_time_ms
        },
        "target_domain": target_domain,
        "discovery_source": source,
        "pages_monitored_count": len(inspected_pages),
        "h_policy_tree_root": h_tree,
        "inspected_pages": inspected_pages
    }

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "dtcc.com"
    report = run_deep_dive_audit(target)
    print(json.dumps(report, indent=2))
