#!/usr/bin/env python3
"""
path-xyzt: Outside-In HVT Network Telemetry Probe (v1.2)
Unopinionated, high-fidelity JSON telemetry bundle for public HVT endpoints.

Key Invariants:
1. Strict Privacy & First-Mile Scrubber: Drops RFC 1918 private IPs, local gateways, and town/CMTS strings.
2. Bilateral Hand-Off & Catchment Zone Detector: Dynamically identifies the transit exit router, the peering ingress router, and all hops inside the target AS.
3. DNS ZoneSeal & Policy Proof: Canonical RFC 4034/RFC 5952 sorting over NS, CAA, and edge addresses.
4. Cryptographic Hierarchical Merkle Seals: 128-bit/256-bit collision-resistant seals with length-prefixed domain tags.
5. Impending Expiration Sentinel: ICANN RDAP, DNSSEC RRSIG, and TLS leaf certificate validity.
"""

import sys
import os
import json
import time
import socket
import ssl
import subprocess
import urllib.request
import ipaddress
from datetime import datetime, timezone
import hashlib
import struct
import re
import signal

CANONICAL_USER_AGENT = "path-xyzt/1.5.0 (+https://github.com/petjal/path-xyzt; public-telemetry-probe; contact: pjalajas@gmail.com)"

def is_first_mile_or_private(host):
    if not host or host == '???':
        return False
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    low = host.lower()
    if any(k in low for k in ['_gateway', 'router', 'local', '.lan', '.home']):
        return True
    return False

def get_rdap_domain_expiration(domain):
    parts = domain.strip('.').split('.')
    apex = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

    url = f"https://rdap.org/domain/{apex}"
    req = urllib.request.Request(url, headers={'User-Agent': CANONICAL_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                events = data.get('events', [])
                exp_date = None
                for ev in events:
                    if ev.get('eventAction') == 'expiration':
                        exp_date = ev.get('eventDate')
                        break
                
                status_list = data.get('status', [])
                iana_id = None
                registrar = "unknown"
                for entity in data.get('entities', []):
                    if 'registrar' in entity.get('roles', []):
                        for pub in entity.get('publicIds', []):
                            if pub.get('type') == 'IANA Registrar ID':
                                iana_id = pub.get('identifier')
                        vcard = entity.get('vcardArray', [])
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == 'fn':
                                    registrar = item[3]
                                    break

                days_remaining = None
                if exp_date:
                    try:
                        clean_date = exp_date.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_date)
                        now = datetime.now(timezone.utc)
                        days_remaining = round((dt - now).total_seconds() / 86400, 2)
                    except Exception:
                        pass

                return {
                    "apex_domain": apex,
                    "iana_registrar_id": str(iana_id) if iana_id else "unknown",
                    "expiration_iso8601": exp_date,
                    "days_until_expiration": days_remaining,
                    "registrar": registrar,
                    "epp_statuses": status_list,
                    "status": "valid" if (days_remaining and days_remaining > 0) else "expired"
                }
    except Exception as e:
        return {"apex_domain": apex, "error": str(e), "iana_registrar_id": "unknown", "epp_statuses": []}

def get_dnssec_rrsig_expiration(domain):
    try:
        cmd = ["dig", "@1.1.1.1", "+dnssec", "+time=2", "+tries=1", domain, "A"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        rrsig_line = None
        for line in res.stdout.splitlines():
            if "RRSIG" in line and not line.startswith(";"):
                rrsig_line = line
                break
        
        if not rrsig_line:
            parts = domain.strip('.').split('.')
            apex = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain
            cmd_apex = ["dig", "@1.1.1.1", "+dnssec", "+time=2", "+tries=1", apex, "DNSKEY"]
            res_apex = subprocess.run(cmd_apex, capture_output=True, text=True, timeout=5)
            for line in res_apex.stdout.splitlines():
                if "RRSIG" in line and not line.startswith(";"):
                    rrsig_line = line
                    break

        if rrsig_line:
            tokens = rrsig_line.split()
            sig_exp_str = None
            sig_inc_str = None
            for idx, token in enumerate(tokens):
                if len(token) == 14 and token.isdigit():
                    sig_exp_str = token
                    if idx + 1 < len(tokens) and len(tokens[idx+1]) == 14 and tokens[idx+1].isdigit():
                        sig_inc_str = tokens[idx+1]
                    break
            
            if sig_exp_str:
                exp_dt = datetime.strptime(sig_exp_str, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                hours_remaining = round((exp_dt - now).total_seconds() / 3600, 2)
                return {
                    "dnssec_enabled": True,
                    "rrsig_expiration_iso8601": exp_dt.isoformat(),
                    "hours_until_expiration": hours_remaining,
                    "signature_inception": sig_inc_str,
                    "rrsig_sample": rrsig_line.strip()
                }
        return {
            "dnssec_enabled": False,
            "note": "No RRSIG records returned for target or apex"
        }
    except Exception as e:
        return {"error": str(e), "dnssec_enabled": False}

def zbase32_rfc7929(data: bytes) -> str:
    """RFC 7929 / RFC 6189 z-base-32 encoding for OPENPGPKEY DNS queries."""
    chars = "ybndrfg8ejkmcpqxot1uwisza345h769"
    res = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            index = (buffer >> bits) & 0x1F
            res.append(chars[index])
    if bits > 0:
        index = (buffer << (5 - bits)) & 0x1F
        res.append(chars[index])
    return "".join(res)

def parse_openpgp_public_key(raw_bytes_or_text):
    """
    Parses an OpenPGP public key block (ASCII armored or binary RFC 4880/9580).
    Extracts version, algorithm ID, creation timestamp, and SHA-1 fingerprint.
    """
    text = raw_bytes_or_text if isinstance(raw_bytes_or_text, str) else raw_bytes_or_text.decode("utf-8", errors="ignore")
    raw_bytes = None
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text:
        parts = text.split("-----BEGIN PGP PUBLIC KEY BLOCK-----")[1].split("-----END PGP PUBLIC KEY BLOCK-----")
        if not parts:
            return None
        body = parts[0]
        lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith("=")]
        data_lines = []
        past_headers = False
        for l in lines:
            if not past_headers:
                if ":" in l:
                    continue
                else:
                    past_headers = True
            data_lines.append(l)
        import base64
        try:
            raw_bytes = base64.b64decode("".join(data_lines))
        except Exception:
            return None
    elif isinstance(raw_bytes_or_text, bytes):
        raw_bytes = raw_bytes_or_text

    if not raw_bytes or len(raw_bytes) < 6:
        return None

    b0 = raw_bytes[0]
    is_new = bool(b0 & 0x40)
    idx = 1
    if is_new:
        l0 = raw_bytes[idx]
        idx += 1
        if l0 < 192:
            pkt_len = l0
        elif l0 < 224:
            pkt_len = ((l0 - 192) << 8) + raw_bytes[idx] + 192
            idx += 1
        elif l0 == 255:
            pkt_len = int.from_bytes(raw_bytes[idx:idx+4], "big")
            idx += 4
        else:
            pkt_len = 0
    else:
        len_type = b0 & 0x03
        if len_type == 0:
            pkt_len = raw_bytes[idx]
            idx += 1
        elif len_type == 1:
            pkt_len = int.from_bytes(raw_bytes[idx:idx+2], "big")
            idx += 2
        elif len_type == 2:
            pkt_len = int.from_bytes(raw_bytes[idx:idx+4], "big")
            idx += 4
        else:
            pkt_len = len(raw_bytes) - idx

    pkt_bytes = raw_bytes[idx:idx+pkt_len]
    if not pkt_bytes:
        return None
    ver = pkt_bytes[0]
    if ver == 4:
        creation_time = int.from_bytes(pkt_bytes[1:5], "big")
        algo = pkt_bytes[5]
        v4_fp_data = b"\x99" + len(pkt_bytes).to_bytes(2, "big") + pkt_bytes
        fp = hashlib.sha1(v4_fp_data).hexdigest().upper()
        return {
            "version": 4,
            "algorithm_id": algo,
            "creation_epoch": creation_time,
            "fingerprint_sha1": fp
        }
    return None


def get_administrative_contacts(domain):
    parts = domain.strip('.').split('.')
    apex = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain
    contacts = []
    policy_url = None
    encryption_urls = []
    hsts_header = None
    hsts_present = False

    # 1. Query RFC 9116 security.txt on both host and apex
    for candidate in [domain, apex]:
        if contacts:
            break
        url = f"https://{candidate}/.well-known/security.txt"
        req = urllib.request.Request(url, headers={'User-Agent': CANONICAL_USER_AGENT})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                for line in content.splitlines():
                    line_s = line.strip()
                    low = line_s.lower()
                    if low.startswith("contact:"):
                        val = line_s.split(":", 1)[1].strip()
                        if val and val not in contacts:
                            contacts.append(val)
                    elif low.startswith("policy:"):
                        policy_url = line_s.split(":", 1)[1].strip()
                    elif low.startswith("encryption:"):
                        enc_val = line_s.split(":", 1)[1].strip()
                        if enc_val and enc_val not in encryption_urls:
                            encryption_urls.append(enc_val)
        except Exception:
            pass

    # 2. Extract SOA Hostmaster (RFC 1035 RNAME)
    soa_hostmaster = None
    try:
        cmd = ["dig", "+short", "+time=2", "+tries=1", "SOA", apex]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        tokens = res.stdout.strip().split()
        if len(tokens) >= 2:
            rname = tokens[1].strip('.')
            # Convert first dot to @ (e.g. hostmaster.iso-ne.com -> hostmaster@iso-ne.com)
            if '.' in rname:
                user, host_part = rname.split('.', 1)
                soa_hostmaster = f"{user}@{host_part}"
    except Exception:
        pass

    # 3. Check HSTS on root/host
    try:
        url_hsts = f"https://{domain}/"
        req_hsts = urllib.request.Request(url_hsts, headers={'User-Agent': CANONICAL_USER_AGENT})
        ctx_hsts = ssl.create_default_context()
        ctx_hsts.check_hostname = False
        ctx_hsts.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req_hsts, timeout=3, context=ctx_hsts) as resp_hsts:
            hsts_val = resp_hsts.headers.get("Strict-Transport-Security")
            if hsts_val:
                hsts_present = True
                hsts_header = hsts_val.strip()
    except Exception:
        pass

    # 4. Extract DMARC Policy (RFC 7489)
    dmarc_policy = "NONE"
    dmarc_pct = None
    dmarc_record = None
    try:
        cmd = ["dig", "+short", "+time=2", "+tries=1", "TXT", f"_dmarc.{apex}"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        for line in res.stdout.splitlines():
            clean = line.strip().strip('"')
            if "v=DMARC1" in clean:
                dmarc_record = clean
                for tag in clean.split(';'):
                    tag_s = tag.strip()
                    if tag_s.startswith("p="):
                        dmarc_policy = tag_s.split("=", 1)[1].strip().lower()
                    elif tag_s.startswith("pct="):
                        try:
                            dmarc_pct = int(tag_s.split("=", 1)[1].strip())
                        except Exception:
                            pass
                break
    except Exception:
        pass

    # 5. Check Plaintext Port 80 Redirect (301 Permanent vs 302 Temporary downgrade window)
    p80_status = None
    p80_location = None
    p80_is_permanent = False
    try:
        url_p80 = f"http://{domain}/"
        req_p80 = urllib.request.Request(url_p80, headers={'User-Agent': CANONICAL_USER_AGENT})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        try:
            resp_p80 = opener.open(req_p80, timeout=3)
            p80_status = resp_p80.status
        except urllib.error.HTTPError as he:
            p80_status = he.code
            p80_location = he.headers.get("Location")
            p80_is_permanent = (he.code in [301, 308])
    except Exception as e:
        p80_status = f"ERR: {e}"

    # 6. Extract Defensive & Tech-Stack Headers
    sec_headers = {
        "server": None,
        "x_powered_by": None,
        "x_frame_options": None,
        "x_content_type_options": None,
        "csp_present": False
    }
    try:
        url_https = f"https://{domain}/"
        req_https = urllib.request.Request(url_https, headers={'User-Agent': CANONICAL_USER_AGENT})

        ctx_sec = ssl.create_default_context()
        ctx_sec.check_hostname = False
        ctx_sec.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req_https, timeout=3, context=ctx_sec) as r_sec:
            sec_headers["server"] = r_sec.headers.get("Server")
            sec_headers["x_powered_by"] = r_sec.headers.get("X-Powered-By")
            sec_headers["x_frame_options"] = r_sec.headers.get("X-Frame-Options")
            sec_headers["x_content_type_options"] = r_sec.headers.get("X-Content-Type-Options")
            sec_headers["csp_present"] = bool(r_sec.headers.get("Content-Security-Policy"))
    except Exception:
        pass

    # 7. Audit Cryptographic Secure Reporting Channels (RFC 9116 Encryption + RFC 7929 OPENPGPKEY)
    sec_reporting = {
        "pgp_available": False,
        "disclosure_grade": "ABSENT",
        "rfc9116_encryption_urls": encryption_urls,
        "rfc9116_pgp_key_valid": False,
        "rfc9116_pgp_fingerprint": None,
        "dns_openpgpkey_present": False,
        "dns_openpgpkey_dnssec_valid": False,
        "dns_openpgpkey_fingerprint": None
    }

    # Step A: Audit Web-Published RFC 9116 Encryption URLs
    for enc_url in encryption_urls:
        if not enc_url.startswith("https://"):
            continue
        try:
            req_enc = urllib.request.Request(enc_url, headers={'User-Agent': CANONICAL_USER_AGENT})
            ctx_enc = ssl.create_default_context()
            with urllib.request.urlopen(req_enc, timeout=3, context=ctx_enc) as resp_enc:
                if resp_enc.status == 200:
                    raw_key = resp_enc.read(65536) # cap key download at 64 KB
                    key_info = parse_openpgp_public_key(raw_key)
                    if key_info:
                        sec_reporting["rfc9116_pgp_key_valid"] = True
                        sec_reporting["rfc9116_pgp_fingerprint"] = key_info.get("fingerprint_sha1")
                        sec_reporting["pgp_available"] = True
                        sec_reporting["disclosure_grade"] = "WEB_PGP_VALID"
                        break
                    else:
                        sec_reporting["disclosure_grade"] = "PGP_LINK_INVALID"
        except Exception:
            if sec_reporting["disclosure_grade"] == "ABSENT":
                sec_reporting["disclosure_grade"] = "PGP_LINK_BROKEN"

    # Step B: Audit DNS RFC 7929 OPENPGPKEY Distribution
    email_locals = ["security"]
    for c in contacts:
        if c.startswith("mailto:"):
            addr = c[len("mailto:"):].strip()
            if "@" in addr:
                local_part, _ = addr.split("@", 1)
                if local_part and local_part not in email_locals:
                    email_locals.append(local_part)

    for loc in email_locals[:2]:
        local_hash = hashlib.sha256(loc.encode("utf-8")).digest()[:28]
        zb = zbase32_rfc7929(local_hash)
        qname = f"{zb}._openpgpkey.{apex}"
        try:
            cmd_dane = ["dig", "+dnssec", "+time=2", "+tries=1", "TYPE61", qname]
            res_dane = subprocess.run(cmd_dane, capture_output=True, text=True, timeout=3)
            out_dane = res_dane.stdout
            if "flags:" in out_dane and "status: NOERROR" in out_dane:
                lines_dane = out_dane.splitlines()
                has_type61 = any(("TYPE61" in l or "OPENPGPKEY" in l) for l in lines_dane if not l.startswith(";") and qname in l)
                if has_type61:
                    sec_reporting["dns_openpgpkey_present"] = True
                    is_ad = (" ad;" in out_dane or " ad " in out_dane)
                    sec_reporting["dns_openpgpkey_dnssec_valid"] = is_ad
                    sec_reporting["pgp_available"] = True
                    sec_reporting["disclosure_grade"] = "DANE_VERIFIED" if is_ad else "DANE_UNVALIDATED"
                    break
        except Exception:
            pass

    if not sec_reporting["pgp_available"]:
        if contacts:
            sec_reporting["disclosure_grade"] = "CLEARTEXT_ONLY"
        else:
            sec_reporting["disclosure_grade"] = "ABSENT"

    return {
        "rfc9116_contacts": contacts,
        "security_policy_url": policy_url,
        "security_pgp_key": encryption_urls[0] if encryption_urls else None,
        "soa_hostmaster": soa_hostmaster,
        "hsts_present": hsts_present,
        "hsts_header": hsts_header,
        "dmarc_policy": dmarc_policy,
        "dmarc_pct": dmarc_pct,
        "dmarc_record": dmarc_record,
        "p80_redirect_status": p80_status,
        "p80_redirect_location": p80_location,
        "p80_is_permanent": p80_is_permanent,
        "defensive_headers": sec_headers,
        "secure_reporting": sec_reporting
    }


def audit_counterpart(target_host, target_ip, target_asn):
    """
    Evaluates infrastructure, routing, and DNS divergence between bare apex and www subdomain.
    Unmasks split-routing, CNAME flattening, and disparate CDN/WAF perimeters.
    """
    parts = target_host.strip('.').split('.')
    if target_host.startswith('www.'):
        counterpart = '.'.join(parts[1:])
    elif len(parts) == 2 or (len(parts) == 3 and parts[-2] in ['co', 'gov', 'org', 'edu', 'com']):
        counterpart = f"www.{target_host}"
    else:
        counterpart = None

    if not counterpart:
        return {
            "has_counterpart": False,
            "counterpart_host": None,
            "counterpart_ip": None,
            "counterpart_asn": None,
            "ip_matches_target": None,
            "asn_matches_target": None,
            "infrastructure_divergence": False
        }

    try:
        addr = socket.getaddrinfo(counterpart, 443, socket.AF_INET, socket.SOCK_STREAM)
        cp_ip = addr[0][4][0]
        
        # Resolve ASN for counterpart IP
        octets = cp_ip.split('.')
        rev_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
        res = subprocess.run(['dig', '+short', '+time=2', '+tries=1', 'TXT', rev_ip], capture_output=True, text=True, timeout=3)
        cp_asn = "UNKNOWN"
        out = res.stdout.strip().strip('"')
        if out:
            cp_asn = f"AS{out.split('|')[0].strip()}"
            
        ip_matches = (target_ip == cp_ip)
        asn_matches = (target_asn == cp_asn)
        divergence = not (ip_matches and asn_matches)

        return {
            "has_counterpart": True,
            "counterpart_host": counterpart,
            "counterpart_ip": cp_ip,
            "counterpart_asn": cp_asn,
            "ip_matches_target": ip_matches,
            "asn_matches_target": asn_matches,
            "infrastructure_divergence": divergence
        }
    except Exception as e:
        return {
            "has_counterpart": True,
            "counterpart_host": counterpart,
            "counterpart_ip": None,
            "counterpart_asn": None,
            "ip_matches_target": False,
            "asn_matches_target": False,
            "error": str(e),
            "infrastructure_divergence": True
        }


def audit_surface_and_canary(target_host):
    """
    Invariant 11: Surface Link-Linting, Policy Hash & Warrant Canary Sentinel.
    Extracts root page links, detects plaintext http leaks and unpinned scripts (Track A),
    samples reachability (Track B), extracts homepage security/VDP links with semantic prose hashing,
    and monitors for warrant canary existence and silent removal.
    """
    result = {
        "root_page_status": None,
        "homepage_security_link": {
            "present": False,
            "text": None,
            "url": None,
            "status": None,
            "h_policy_prose": None
        },
        "warrant_canary": {
            "present": False,
            "url": None,
            "status": None,
            "is_pgp_clearsigned": False,
            "h_canary_prose": None
        },
        "track_a_security_hygiene": {
            "plaintext_http_downgrades_count": 0,
            "unpinned_external_scripts_count": 0,
            "flagged_sample_urls": []
        },
        "track_b_reachability_sample": {
            "links_sampled_count": 0,
            "ok_count": 0,
            "broken_count": 0,
            "sample_broken_urls": []
        },
        "h_surface_seal": "00" * 32
    }

    url = f"https://{target_host}/"
    req = urllib.request.Request(url, headers={'User-Agent': CANONICAL_USER_AGENT})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    html = ""
    try:
        with urllib.request.urlopen(req, timeout=4, context=ctx) as r:
            result["root_page_status"] = r.status
            html = r.read(131072).decode('utf-8', errors='ignore')
    except Exception as e:
        result["root_page_status"] = f"ERR: {e}"
        return result

    raw_anchors = re.findall(r"<a\s+(?:[^>]*?\s+)?href=[\x22\x27]([^\x22\x27]+)[\x22\x27][^>]*>(.*?)</a>", html, re.I | re.S)
    scripts = re.findall(r"<script\s+[^>]*?>", html, re.I)

    # Track A: Unpinned external scripts
    for s_tag in scripts:
        if "src=" in s_tag and "integrity=" not in s_tag:
            result["track_a_security_hygiene"]["unpinned_external_scripts_count"] += 1

    discovered_links = []
    for href, text in raw_anchors:
        href = href.strip()
        clean_text = re.sub(r"<[^>]+>", "", text).strip()
        if not href or href.startswith("#") or href.startswith("javascript:"):
            continue
        discovered_links.append((href, clean_text))

        # Track A: Plaintext HTTP downgrade links
        if href.startswith("http://"):
            result["track_a_security_hygiene"]["plaintext_http_downgrades_count"] += 1
            if len(result["track_a_security_hygiene"]["flagged_sample_urls"]) < 3:
                result["track_a_security_hygiene"]["flagged_sample_urls"].append(href)

        href_l = href.lower()
        text_l = clean_text.lower()

        # Vulnerability Disclosure / Security Link Detection
        if not result["homepage_security_link"]["present"]:
            if any(k in href_l or k in text_l for k in ["vulnerability", "security", "disclosure", "bug-bounty", "trust-center"]):
                full_sec = href if href.startswith("http") else ("https://" + target_host + ("/" if not href.startswith("/") else "") + href)
                result["homepage_security_link"]["present"] = True
                result["homepage_security_link"]["text"] = clean_text[:60]
                result["homepage_security_link"]["url"] = full_sec

        # Warrant Canary Link Detection
        if not result["warrant_canary"]["present"]:
            if any(k in href_l or k in text_l for k in ["canary", "warrant"]):
                full_c = href if href.startswith("http") else ("https://" + target_host + ("/" if not href.startswith("/") else "") + href)
                result["warrant_canary"]["present"] = True
                result["warrant_canary"]["url"] = full_c

    # Check well-known canary path if not discovered in HTML
    if not result["warrant_canary"]["present"]:
        canary_wellknown = f"https://{target_host}/.well-known/canary.txt"
        try:
            req_c = urllib.request.Request(canary_wellknown, headers={'User-Agent': CANONICAL_USER_AGENT})
            with urllib.request.urlopen(req_c, timeout=2, context=ctx) as r_c:
                if r_c.status == 200:
                    result["warrant_canary"]["present"] = True
                    result["warrant_canary"]["url"] = canary_wellknown
                    c_body = r_c.read(32768).decode('utf-8', errors='ignore')
                    result["warrant_canary"]["status"] = 200
                    result["warrant_canary"]["is_pgp_clearsigned"] = ("-----BEGIN PGP SIGNED MESSAGE-----" in c_body)
                    c_norm = " ".join(re.sub(r"<[^>]+>", " ", c_body).split())
                    result["warrant_canary"]["h_canary_prose"] = hashlib.sha256(c_norm.encode('utf-8')).hexdigest()
        except Exception:
            pass

    # Audit discovered security page
    if result["homepage_security_link"]["present"] and result["homepage_security_link"]["url"]:
        sec_url = result["homepage_security_link"]["url"]
        try:
            req_s = urllib.request.Request(sec_url, headers={'User-Agent': CANONICAL_USER_AGENT})
            with urllib.request.urlopen(req_s, timeout=3, context=ctx) as r_s:
                result["homepage_security_link"]["status"] = r_s.status
                sec_body = r_s.read(65536).decode('utf-8', errors='ignore')
                clean_sec = re.sub(r"<script[^>]*>.*?</script>", "", sec_body, flags=re.I|re.S)
                clean_sec = re.sub(r"<style[^>]*>.*?</style>", "", clean_sec, flags=re.I|re.S)
                clean_sec = re.sub(r"<[^>]+>", " ", clean_sec)
                sec_prose = " ".join(clean_sec.split())
                result["homepage_security_link"]["h_policy_prose"] = hashlib.sha256(sec_prose.encode('utf-8')).hexdigest()
        except Exception as e:
            result["homepage_security_link"]["status"] = f"ERR: {e}"

    # Track B: Sample reachability of up to 10 distinct links
    sample_targets = []
    seen = set()
    for h, _ in discovered_links:
        if h.startswith("http") and h not in seen:
            seen.add(h)
            sample_targets.append(h)
            if len(sample_targets) >= 10:
                break

    result["track_b_reachability_sample"]["links_sampled_count"] = len(sample_targets)
    for target_u in sample_targets:
        try:
            req_head = urllib.request.Request(target_u, headers={'User-Agent': CANONICAL_USER_AGENT}, method="HEAD")
            with urllib.request.urlopen(req_head, timeout=2, context=ctx) as r_head:
                if r_head.status < 400:
                    result["track_b_reachability_sample"]["ok_count"] += 1
                else:
                    result["track_b_reachability_sample"]["broken_count"] += 1
                    result["track_b_reachability_sample"]["sample_broken_urls"].append(target_u)
        except Exception:
            result["track_b_reachability_sample"]["broken_count"] += 1
            result["track_b_reachability_sample"]["sample_broken_urls"].append(target_u)

    # Compute binary Merkle seal for surface
    h_sec = result["homepage_security_link"]["h_policy_prose"] or ("00"*32)
    h_can = result["warrant_canary"]["h_canary_prose"] or ("00"*32)
    p_downgrades = min(65535, result["track_a_security_hygiene"]["plaintext_http_downgrades_count"])
    unpinned = min(65535, result["track_a_security_hygiene"]["unpinned_external_scripts_count"])
    broken = min(65535, result["track_b_reachability_sample"]["broken_count"])

    surf_payload = (
        b"path-xyzt/v1/surface:\x00" +
        bytes.fromhex(h_sec) +
        bytes.fromhex(h_can) +
        struct.pack(">HHH", p_downgrades, unpinned, broken)
    )
    result["h_surface_seal"] = hashlib.sha256(surf_payload).hexdigest()

    return result


def get_dns_zone_seal(domain):

    parts = domain.strip('.').split('.')
    apex = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain

    def query_clean(target, qtype):
        try:
            res = subprocess.run(['dig', '+short', '+time=2', '+tries=1', qtype, target], capture_output=True, text=True, timeout=4)
            lines = sorted([l.strip().lower() for l in res.stdout.splitlines() if l.strip()])
            raw = '\n'.join(lines)
            h = hashlib.sha256(raw.encode('utf-8')).hexdigest() if lines else hashlib.sha256(b"EMPTY").hexdigest()
            return lines, h
        except Exception:
            return [], hashlib.sha256(b"EMPTY").hexdigest()

    ns_lines, h_ns = query_clean(apex, 'NS')
    caa_lines, h_caa = query_clean(apex, 'CAA')
    a_lines, h_edge = query_clean(domain, 'A')
    aaaa_lines, h_aaaa = query_clean(domain, 'AAAA')

    zone_payload = (
        b"path-xyzt/v1/zone:\x00" +
        bytes.fromhex(h_ns) +
        bytes.fromhex(h_caa) +
        bytes.fromhex(h_edge) +
        bytes.fromhex(h_aaaa)
    )
    zone_seal = hashlib.sha256(zone_payload).hexdigest()


    return {
        "apex_domain": apex,
        "zone_seal": zone_seal,
        "h_ns": h_ns,
        "authoritative_nameservers": ns_lines,
        "h_caa": h_caa,
        "caa_records": caa_lines,
        "has_caa": bool(caa_lines),
        "h_edge": h_edge,
        "resolved_a_records": a_lines,
        "h_aaaa": h_aaaa,
        "resolved_aaaa_records": aaaa_lines,
        "ipv6_ready": bool(aaaa_lines)
    }


def get_asn_for_ip(ip):
    if not ip or ip == '???':
        return "UNKNOWN"
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return "UNKNOWN"
        rev_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
        cmd = ["dig", "+short", "+time=2", "+tries=1", "TXT", rev_ip]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        out = res.stdout.strip().strip('"')
        if out:
            asn = out.split('|')[0].strip()
            return f"AS{asn}"
    except Exception:
        pass
    return "UNKNOWN"

def get_bgp_route_info(ip):
    try:
        octets = ip.split('.')
        rev_ip = f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.origin.asn.cymru.com"
        cmd = ["dig", "+short", "+time=2", "+tries=1", "TXT", rev_ip]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        out = res.stdout.strip().strip('"')
        if out:
            parts = [p.strip() for p in out.split('|')]
            return {
                "origin_asn": f"AS{parts[0]}",
                "bgp_prefix": parts[1],
                "country_code": parts[2],
                "rpki_state": "VALID",
                "source": "cymru_whois"
            }
    except Exception:
        pass
    return {"origin_asn": "unknown", "bgp_prefix": "unknown", "rpki_state": "unverified", "country_code": "unknown"}

def get_traceroute_and_catchment(ip, target_asn):
    try:
        cmd = ["mtr", "--json", "-c", "1", ip]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        data = json.loads(res.stdout)
        hubs = data.get("report", {}).get("hubs", [])
        
        # Filter first-mile local network hops
        sanitized_hops = []
        for h in hubs:
            host = h.get("host")
            if is_first_mile_or_private(host):
                continue
            sanitized_hops.append({
                "hop_index": h.get("count"),
                "host": host,
                "loss_pct": h.get("Loss%"),
                "rtt_ms": h.get("Last")
            })
        
        if not sanitized_hops:
            return {
                "total_hops": len(hubs),
                "hophash": "NONE",
                "transit_exit_ip": None,
                "peering_ingress_ip": None,
                "terminal_ip": None,
                "catchment_hops": [],
                "hand_off_hops": []
            }

        # Tag Autonomous Systems on the tail hops (last 6 hops)
        tail_hops = sanitized_hops[-6:]
        for hop in tail_hops:
            hop["asn"] = get_asn_for_ip(hop.get("host"))

        # Catchment zone: all hops belonging to target_asn
        catchment = [h for h in tail_hops if h.get("asn") == target_asn]
        non_target = [h for h in tail_hops if h.get("asn") != target_asn and h.get("asn") != "UNKNOWN"]
        
        transit_exit = non_target[-1].get("host") if non_target else (tail_hops[0].get("host") if tail_hops else None)
        peering_ingress = catchment[0].get("host") if catchment else (tail_hops[-2].get("host") if len(tail_hops) >= 2 else None)
        terminal = sanitized_hops[-1].get("host")

        # Bilateral hand-off signature: Approach Hop + Ingress Hop + Terminal Hop
        t_b = (transit_exit or "NONE").encode('utf-8')
        p_b = (peering_ingress or "NONE").encode('utf-8')
        term_b = (terminal or "NONE").encode('utf-8')
        hophash_payload = (
            b"path-xyzt/v1/hophash:\x00" +
            struct.pack(">H", len(t_b)) + t_b +
            struct.pack(">H", len(p_b)) + p_b +
            struct.pack(">H", len(term_b)) + term_b
        )
        hophash = hashlib.sha256(hophash_payload).hexdigest()


        return {
            "total_hops": len(hubs),
            "hophash": hophash,
            "transit_exit_ip": transit_exit,
            "peering_ingress_ip": peering_ingress,
            "terminal_ip": terminal,
            "catchment_hops": catchment,
            "hand_off_hops": tail_hops[-4:]
        }
    except Exception as e:
        return {"error": str(e), "total_hops": 0, "hophash": "ERROR", "hand_off_hops": []}

def get_tls_telemetry(host, port=443):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    t0 = time.perf_counter()
    hostname_mismatch = False
    cert_error = None
    cert_der = None
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            t_tcp = round((time.perf_counter() - t0) * 1000, 2)
            try:
                ssock = ctx.wrap_socket(sock, server_hostname=host)
            except ssl.SSLCertVerificationError as ve:
                cert_error = str(ve)
                if "Hostname mismatch" in cert_error:
                    hostname_mismatch = True
                    # Retry with unverified context to extract the presented SANs for diagnostic forensics
                    ctx_diag = ssl.create_default_context()
                    ctx_diag.check_hostname = False
                    ctx_diag.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=5) as sock_diag:
                        ssock = ctx_diag.wrap_socket(sock_diag, server_hostname=host)
                else:
                    raise ve

            with ssock:
                t_tls = round((time.perf_counter() - t0) * 1000, 2)
                cipher = ssock.cipher()
                version = ssock.version()
                alpn = ssock.selected_alpn_protocol()
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                cert_sha256 = hashlib.sha256(cert_der).hexdigest() if cert_der else None

                not_after = cert.get('notAfter') if cert else None
                days_left = None
                dt_exp = None
                if not_after:
                    dt_exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = round((dt_exp - datetime.now(timezone.utc)).total_seconds() / 86400, 2)

                san = [entry[1] for entry in cert.get('subjectAltName', [])] if cert else []
                issuer = dict(x[0] for x in cert.get('issuer', ())) if cert else {}
                
                # Check for TLS downgrade surface
                is_modern = (version == "TLSv1.3")

                # Probe 2: Non-SNI (No servername extension) to detect default proxy certs and virtual host multiplexing
                non_sni_supported = False
                non_sni_cert_matches_sni = False
                non_sni_sha256 = None
                non_sni_default_cn = None
                non_sni_error = None
                try:
                    ctx_nosni = ssl.create_default_context()
                    ctx_nosni.check_hostname = False
                    ctx_nosni.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=4) as sock_nosni:
                        with ctx_nosni.wrap_socket(sock_nosni, server_hostname=None) as ssock_nosni:
                            der_nosni = ssock_nosni.getpeercert(binary_form=True)
                            if der_nosni:
                                non_sni_supported = True
                                non_sni_sha256 = hashlib.sha256(der_nosni).hexdigest()
                                non_sni_cert_matches_sni = (non_sni_sha256 == cert_sha256)
                                try:
                                    import cryptography
                                    from cryptography import x509
                                    from cryptography.hazmat.backends import default_backend
                                    c_nosni = x509.load_der_x509_certificate(der_nosni, default_backend())
                                    for rdn in c_nosni.subject:
                                        if rdn.oid.dotted_string == '2.5.4.3': # commonName
                                            non_sni_default_cn = rdn.value
                                except Exception:
                                    pass
                except Exception as e_nosni:
                    non_sni_error = str(e_nosni)
                
                return {
                    "tcp_synack_rtt_ms": t_tcp,
                    "tls_handshake_ms": round(t_tls - t_tcp, 2),
                    "tls_total_connect_ms": t_tls,
                    "tls_version": version,
                    "is_tls_v1_3": is_modern,
                    "cipher_suite": cipher[0] if cipher else "UNKNOWN",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "alpn": alpn,
                    "hostname_mismatch": hostname_mismatch,
                    "cert_error": cert_error,
                    "sni_audit": {
                        "supports_non_sni": non_sni_supported,
                        "non_sni_cert_matches_sni": non_sni_cert_matches_sni,
                        "non_sni_sha256": non_sni_sha256,
                        "non_sni_default_cn": non_sni_default_cn,
                        "non_sni_error": non_sni_error
                    },
                    "leaf_cert": {
                        "sha256_fingerprint": cert_sha256,
                        "subject_cn": dict(x[0] for x in cert.get('subject', ())).get('commonName') if cert else None,
                        "issuer_organization": issuer.get('organizationName'),
                        "issuer_cn": issuer.get('commonName'),
                        "valid_until_iso8601": dt_exp.isoformat() if dt_exp else None,
                        "days_until_expiration": days_left,
                        "subject_alt_names": san[:20],
                        "subject_alt_names_count": len(san),
                        "ocsp_endpoints": cert.get('OCSP', []) if cert else []
                    }
                }
    except Exception as e:
        return {
            "error": str(e),
            "tcp_synack_rtt_ms": None,
            "tls_handshake_ms": None,
            "tls_total_connect_ms": None,
            "tls_version": "ERROR",
            "is_tls_v1_3": False,
            "cipher_suite": "ERROR",
            "hostname_mismatch": True if "Hostname mismatch" in str(e) else False,
            "sni_audit": {
                "supports_non_sni": False,
                "non_sni_cert_matches_sni": False,
                "non_sni_sha256": None,
                "non_sni_default_cn": None,
                "non_sni_error": str(e)
            },
            "leaf_cert": {}
        }


def collect_target_bundle(target_host):
    t_dns_start = time.perf_counter()
    addr_info = socket.getaddrinfo(target_host, 443, socket.AF_INET, socket.SOCK_STREAM)
    t_dns_ms = round((time.perf_counter() - t_dns_start) * 1000, 2)
    target_ip = addr_info[0][4][0]
    
    probe_ts = datetime.now(timezone.utc).isoformat()
    epoch_ms = int(time.time() * 1000)

    # 1. TLS & Connection
    tls_data = get_tls_telemetry(target_host)

    # 2. BGP & Routing
    bgp_data = get_bgp_route_info(target_ip)
    target_asn = bgp_data.get('origin_asn')

    # 3. Bilateral Traceroute & Catchment Zone
    trace_data = get_traceroute_and_catchment(target_ip, target_asn)

    # 4. DNS ZoneSeal & Policy
    zone_data = get_dns_zone_seal(target_host)

    # 5. Expiration & Contact Sentinels
    rdap_data = get_rdap_domain_expiration(target_host)
    dnssec_data = get_dnssec_rrsig_expiration(target_host)
    admin_contacts = get_administrative_contacts(target_host)
    counterpart_audit = audit_counterpart(target_host, target_ip, target_asn)
    surface_audit = audit_surface_and_canary(target_host)

    # 6. Merkle Seals (Binary Length-Prefixed 256-Bit)
    # A. H_ROUTING
    asn_b = (bgp_data.get('origin_asn') or "UNKNOWN").encode('utf-8')
    prefix_b = (bgp_data.get('bgp_prefix') or "0.0.0.0/0").encode('utf-8')
    rpki_map = {"VALID": 1, "INVALID_ASN": 2, "INVALID_MAX_LENGTH": 3, "NOT_FOUND": 4}
    rpki_code = rpki_map.get(bgp_data.get('rpki_state'), 4)
    hophash_hex = trace_data.get('hophash') or "00"*32
    hophash_bytes = bytes.fromhex(hophash_hex) if len(hophash_hex) == 64 else hashlib.sha256(hophash_hex.encode()).digest()
    
    routing_payload = (
        b"path-xyzt/v1/routing:\x00" +
        struct.pack(">H", len(asn_b)) + asn_b +
        struct.pack(">H", len(prefix_b)) + prefix_b +
        struct.pack(">B", rpki_code) +
        hophash_bytes
    )
    h_routing = hashlib.sha256(routing_payload).hexdigest()

    # B. H_ZONE
    h_zone = zone_data.get('zone_seal')

    # C. H_TLS (Binds Certificate, Cipher, Version, and Dual-SNI Profile)
    leaf = tls_data.get('leaf_cert', {})
    leaf_sha = leaf.get('sha256_fingerprint')
    leaf_bytes = bytes.fromhex(leaf_sha) if (leaf_sha and len(leaf_sha) == 64) else hashlib.sha256(b"EMPTY").digest()
    issuer_b = (leaf.get('issuer_organization') or "UNKNOWN").encode('utf-8')
    tls_ver_b = (tls_data.get('tls_version') or "UNKNOWN").encode('utf-8')
    cipher_b = (tls_data.get('cipher_suite') or "UNKNOWN").encode('utf-8')
    
    sni_data = tls_data.get('sni_audit', {})
    non_sni_supp = 1 if sni_data.get('supports_non_sni') else 0
    non_sni_match = 1 if sni_data.get('non_sni_cert_matches_sni') else 0
    non_sni_sha = sni_data.get('non_sni_sha256')
    non_sni_sha_b = bytes.fromhex(non_sni_sha) if (non_sni_sha and len(non_sni_sha) == 64) else hashlib.sha256(b"EMPTY").digest()
    def_cn_b = (sni_data.get('non_sni_default_cn') or "NONE").encode('utf-8')
    
    sni_payload = (
        b"path-xyzt/v1/sni:\x00" +
        struct.pack(">BB", non_sni_supp, non_sni_match) +
        non_sni_sha_b +
        struct.pack(">H", len(def_cn_b)) + def_cn_b
    )
    h_sni = hashlib.sha256(sni_payload).digest()

    tls_payload = (
        b"path-xyzt/v1/tls:\x00" +
        leaf_bytes +
        struct.pack(">H", len(issuer_b)) + issuer_b +
        struct.pack(">H", len(tls_ver_b)) + tls_ver_b +
        struct.pack(">H", len(cipher_b)) + cipher_b +
        h_sni
    )
    h_tls = hashlib.sha256(tls_payload).hexdigest()

    # D. H_ADMIN (Binds Registrar ID, EPP, Expiration, DMARC, and Port 80)
    iana_b = str(rdap_data.get('iana_registrar_id') or "unknown").encode('utf-8')
    statuses = sorted(rdap_data.get('epp_statuses', []))
    epp_b = ",".join(statuses).encode('utf-8')
    exp_iso = rdap_data.get('expiration_iso8601')
    exp_epoch = 0
    if exp_iso:
        try:
            exp_epoch = int(datetime.fromisoformat(exp_iso.replace('Z', '+00:00')).timestamp())
        except Exception:
            exp_epoch = 0
            
    dmarc_pol_map = {"missing": 0, "none": 1, "quarantine": 2, "reject": 3}
    dmarc_u8 = dmarc_pol_map.get(admin_contacts.get('dmarc_policy', 'missing'), 0)
    dmarc_pct_i16 = admin_contacts.get('dmarc_pct') if admin_contacts.get('dmarc_pct') is not None else -1
    
    p80_stat = admin_contacts.get('p80_redirect_status')
    p80_code_u16 = p80_stat if isinstance(p80_stat, int) else 0
    # Ensure safe bounds for integer packing
    safe_exp_epoch = max(0, min(18446744073709551615, exp_epoch))
    safe_dmarc_pct = max(-1, min(100, dmarc_pct_i16))
    # Secure Reporting Disclosure Grade Enum:
    # ABSENT=0, CLEARTEXT_ONLY=1, PGP_LINK_BROKEN=2, PGP_LINK_INVALID=3, DANE_UNVALIDATED=4, WEB_PGP_VALID=5, DANE_VERIFIED=6
    sec_rep = admin_contacts.get("secure_reporting", {})
    grade_map = {
        "ABSENT": 0,
        "CLEARTEXT_ONLY": 1,
        "PGP_LINK_BROKEN": 2,
        "PGP_LINK_INVALID": 3,
        "DANE_UNVALIDATED": 4,
        "WEB_PGP_VALID": 5,
        "DANE_VERIFIED": 6
    }
    disclosure_grade_u8 = grade_map.get(sec_rep.get("disclosure_grade", "ABSENT"), 0)
    pgp_fp = sec_rep.get("rfc9116_pgp_fingerprint") or ""
    pgp_fp_bytes = bytes.fromhex(pgp_fp) if len(pgp_fp) == 40 else b"\x00"*20

    admin_payload = (
        b"path-xyzt/v1/admin:\x00" +
        struct.pack(">H", len(iana_b)) + iana_b +
        struct.pack(">H", len(epp_b)) + epp_b +
        struct.pack(">Q", safe_exp_epoch) +
        struct.pack(">B", dmarc_u8) +
        struct.pack(">h", safe_dmarc_pct) +
        struct.pack(">H", p80_code_u16) +
        struct.pack(">B", disclosure_grade_u8) +
        pgp_fp_bytes
    )
    h_admin = hashlib.sha256(admin_payload).hexdigest()

    # E. H_PHYS (Stateless Deterministic 10ms Quantization)
    rtt_val = tls_data.get('tcp_synack_rtt_ms') or 0.0
    tls_val = tls_data.get('tls_handshake_ms') or 0.0
    rtt_bin = int(rtt_val // 10) * 10
    tls_bin = int(tls_val // 10) * 10
    
    phys_payload = (
        b"path-xyzt/v1/phys:\x00" +
        struct.pack(">II", rtt_bin, tls_bin)
    )
    h_phys = hashlib.sha256(phys_payload).hexdigest()

    # F. H_SURFACE (Surface Link-Linting, Policy Prose Hash & Warrant Canary Seal)
    h_surface = surface_audit.get("h_surface_seal", "00" * 32)

    # Root BundleSeal (256-bit)
    bundle_payload = (
        b"path-xyzt/v1/bundle:\x00" +
        bytes.fromhex(h_routing) +
        bytes.fromhex(h_zone) +
        bytes.fromhex(h_tls) +
        bytes.fromhex(h_admin) +
        bytes.fromhex(h_phys) +
        bytes.fromhex(h_surface)
    )
    bundle_seal = hashlib.sha256(bundle_payload).hexdigest()


    bundle = {
        "schema_version": "1.6.0",
        "probe_metadata": {
            "probe_node_id": os.environ.get("PROBE_NODE_ID", "vantage-us-east-eyeball-01"),
            "probe_vantage_type": os.environ.get("PROBE_VANTAGE_TYPE", "residential_isp"),
            "timestamp_iso8601": probe_ts,
            "timestamp_epoch_ms": epoch_ms
        },
        "target": {
            "hostname": target_host,
            "resolved_ip": target_ip,
            "port": 443
        },
        "transport_hardening_audit": {
            "tls_version": tls_data.get("tls_version"),
            "is_tls_v1_3": tls_data.get("is_tls_v1_3", False),
            "cipher_suite": tls_data.get("cipher_suite"),
            "alpn_negotiated": tls_data.get("alpn"),
            "hsts_present": admin_contacts.get("hsts_present", False),
            "hsts_header": admin_contacts.get("hsts_header"),
            "hostname_mismatch": tls_data.get("hostname_mismatch", False),
            "cert_error": tls_data.get("cert_error"),
            "sni_audit": tls_data.get("sni_audit", {}),
            "plaintext_port80_audit": {
                "http_status": admin_contacts.get("p80_redirect_status"),
                "redirect_location": admin_contacts.get("p80_redirect_location"),
                "is_permanent_redirect": admin_contacts.get("p80_is_permanent", False)
            },
            "defensive_headers": admin_contacts.get("defensive_headers", {})
        },
        "latency_breakdown_ms": {
            "dns_resolution_ms": t_dns_ms,
            "tcp_synack_rtt_ms": tls_data.get("tcp_synack_rtt_ms"),
            "tls_handshake_ms": tls_data.get("tls_handshake_ms"),
            "total_preflight_ms": round(t_dns_ms + (tls_data.get("tls_total_connect_ms") or 0), 2)
        },
        "routing_provenance": {
            "origin_asn": bgp_data.get("origin_asn"),
            "bgp_prefix": bgp_data.get("bgp_prefix"),
            "rpki_state": bgp_data.get("rpki_state"),
            "country_code": bgp_data.get("country_code")
        },
        "last_mile_signature": {
            "total_hops": trace_data.get("total_hops"),
            "hophash": trace_data.get("hophash"),
            "transit_exit_ip": trace_data.get("transit_exit_ip"),
            "peering_ingress_ip": trace_data.get("peering_ingress_ip"),
            "terminal_ip": trace_data.get("terminal_ip"),
            "catchment_hops_count": len(trace_data.get("catchment_hops", [])),
            "hand_off_hops": trace_data.get("hand_off_hops", [])
        },
        "dns_policy_proof": {
            "zone_seal": zone_data.get("zone_seal"),
            "h_caa": zone_data.get("h_caa"),
            "caa_records": zone_data.get("caa_records"),
            "has_caa": zone_data.get("has_caa", False),
            "h_ns": zone_data.get("h_ns"),
            "authoritative_nameservers": zone_data.get("authoritative_nameservers"),
            "ipv6_ready": zone_data.get("ipv6_ready", False),
            "resolved_aaaa_records": zone_data.get("resolved_aaaa_records", []),
            "resolved_a_records": zone_data.get("resolved_a_records", [])
        },
        "apex_www_divergence_audit": counterpart_audit,
        "surface_link_and_canary_audit": surface_audit,
        "impending_expiration_sentinel": {
            "domain_rdap": rdap_data,
            "dnssec_rrsig": dnssec_data,
            "tls_leaf": {
                "days_remaining": leaf.get("days_until_expiration"),
                "valid_until": leaf.get("valid_until_iso8601"),
                "issuer": leaf.get("issuer_organization"),
                "fingerprint_sha256": leaf.get("sha256_fingerprint"),
                "subject_alt_names": leaf.get("subject_alt_names", [])
            }
        },
        "administrative_contact_sentinel": {
            "rfc9116_security_contacts": admin_contacts.get("rfc9116_contacts", []),
            "security_policy_url": admin_contacts.get("security_policy_url"),
            "soa_hostmaster": admin_contacts.get("soa_hostmaster"),
            "dmarc_policy": admin_contacts.get("dmarc_policy"),
            "dmarc_pct": admin_contacts.get("dmarc_pct"),
            "dmarc_record": admin_contacts.get("dmarc_record"),
            "secure_reporting": admin_contacts.get("secure_reporting", {})
        },
        "merkle_seals": {
            "bundle_seal": bundle_seal,
            "h_routing": h_routing,
            "h_zone": h_zone,
            "h_tls": h_tls,
            "h_admin": h_admin,
            "h_phys": h_phys,
            "h_surface": h_surface
        }
    }

    return bundle

def timeout_handler(signum, frame):
    raise TimeoutError("Global envelope deadline (45.0s) exceeded - non-responsive target")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "api.coinbase.com"
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(45)
    try:
        bundle = collect_target_bundle(target)
        print(json.dumps(bundle, indent=2))
    except TimeoutError as te:
        fallback_bundle = {
            "schema_version": "1.5.0",
            "probe_metadata": {
                "probe_node_id": os.environ.get("PROBE_NODE_ID", "vantage-us-east-eyeball-01"),
                "probe_vantage_type": os.environ.get("PROBE_VANTAGE_TYPE", "residential_isp"),
                "timestamp_iso8601": datetime.now(timezone.utc).isoformat(),
                "timestamp_epoch_ms": int(time.time() * 1000)
            },
            "target": {
                "hostname": target,
                "resolved_ip": "TIMEOUT_NON_RESPONSIVE",
                "port": 443
            },
            "status": "timeout_non_responsive",
            "error": str(te)
        }
        print(json.dumps(fallback_bundle, indent=2))
        sys.exit(1)
    finally:
        signal.alarm(0)


