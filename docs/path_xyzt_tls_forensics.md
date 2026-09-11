# High-Value-Target TLS/Certificate Forensic Telemetry Matrix

**Author**: Pete Jalajas (`pjalajas@gmail.com`)  
**Repository**: `/home/petjal/dev/path-xyzt`  
**Date**: 2026-09-09  
**Scope**: Deep TLS & X.509 Forensic Signals for Enterprise HVT Monitoring  

---

## 1. Beyond Expiration & Fingerprinting: The 8 Critical TLS Blindspots

While leaf certificate thumbprints (SHA-256) and expiration countdowns ($T - \text{notAfter} < 30\text{d}$) are standard table stakes, enterprise high-value targets (banks, exchanges, custody APIs) routinely suffer catastrophic failures or targeted middlebox compromises in 8 deeper dimensions:

```
+-----------------------------------------------------------------------------------------+
|                               HVT TLS HANDSHAKE FORENSICS                               |
+-----------------------------------------------------------------------------------------+
|  1. CA / Issuer Mutation      -> Did the root/intermediate issuer switch unexpectedly?  |
|  2. Regional Cert Split-Brain -> Do US-East, EU, and APAC edge nodes serve identical certs? |
|  3. Incomplete Intermediate   -> Did the server omit intermediate CA (breaking mobile/curl)?|
|  4. OCSP Stapling & Freshness -> Is OCSP stapled, valid, and unexpired (RFC 6066)?      |
|  5. CT Log Auditing & SCTs    -> Are Signed Certificate Timestamps embedded and valid?  |
|  6. SAN Scoping & Wildcard Bleed -> Was tight FQDN replaced by high-risk *.wildcard?   |
|  7. Crypto Parameter Downgrade-> RSA size, ECC curve, and Post-Quantum hybrid status.  |
|  8. Future "notBefore" Traps  -> Did automated renewal push a cert before valid window? |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Detailed Dimension Breakdown

### 2.1 CA / Issuer Mutation (The Interception Sentinel)
* **The Risk**: A financial endpoint (`api.citibank.com`) normally signs under DigiCert or Sectigo. If an intermediate network middlebox (government inspection, corporate proxy, or BGP-diverted proxy) intercepts traffic, it re-signs on the fly with an enterprise or rogue root CA (e.g. Zscaler, Palo Alto, or state-controlled CAs like CNNIC/DarkMatter).
* **The Forensic Metric**: Track and alert on any change to the **Issuer Distinguished Name (DN)** and intermediate CA chain, even if the certificate is cryptographically valid.

### 2.2 Regional Cert Split-Brain (Anycast CDN Divergence)
* **The Risk**: Cloudflare, Fastly, or Akamai Anycast edge nodes in different continents may deploy different SSL certificates during rotation or regional key management. In worse scenarios, an adversary in a specific geographic jurisdiction conducts localized SSL tampering.
* **The Forensic Metric**: Multi-vantage consensus. Alert if vantage probes in US, EU, and APAC observe divergent SHA-256 cert thumbprints at the same block/time epoch.

### 2.3 The "Incomplete Intermediate Chain" Trap (The Curl/Mobile Killer)
* **The Risk**: Desktop browsers (Chrome, Edge) cache intermediate certificates or aggressively fetch them via AIA (`Authority Information Access`). However, automated API clients, Python scripts, Go binaries, curl, and mobile apps do **not** fetch AIA—they strictly require the server to send the complete bundle (`leaf + intermediate`). Misconfigured web servers frequently omit intermediate certs, causing silent B2B API outages that web devs miss because "it works in my browser."
* **The Forensic Metric**: Assert that the TLS handshake `Certificate` payload contains the complete unbroken chain up to a known trust store root.

### 2.4 OCSP Stapling & Revocation Freshness (RFC 6066)
* **The Risk**: Client-side OCSP checking leaks user browsing to CAs and adds 200ms+ latency. OCSP Stapling allows the server to present a pre-signed, timestamped validity token. If the HVT's OCSP stapling engine fails or returns stale `nextUpdate` tokens, clients either fail closed (outage) or fail open (security vulnerability).
* **The Forensic Metric**: Verify:
  1. Is OCSP Staple present in TLS handshake?
  2. Is OCSP status `good`?
  3. Freshness delta: $T_{\text{now}} < \text{nextUpdate}$.

### 2.5 Certificate Transparency (CT) & SCT Verification
* **The Risk**: Rogue certificates issued by compromised CAs.
* **The Forensic Metric**: Verify that the leaf certificate contains valid **Embedded Signed Certificate Timestamps (SCTs)** from at least 2 distinct Google/Cloudflare CT log operators (RFC 6962), confirming the cert was publicly logged before deployment.

### 2.6 SAN Scoping & Wildcard Expansion Bleed
* **The Risk**: An enterprise switches from an exact-domain certificate (`api.custody.institution.com`) to an over-scoped wildcard (`*.institution.com`) or bundles 50 unrelated subdomains onto one shared SAN list, significantly broadening the blast radius if an edge private key is compromised.
* **The Forensic Metric**: Monitor Subject Alternative Name (SAN) count, detect wildcard introductions, and flag unintended subdomain co-tenancy.

### 2.7 Cryptographic Parameter & Post-Quantum (PQ) Tracking
* **The Risk**: Silent algorithm downgrades or lingering legacy parameters.
* **The Forensic Metric**:
  1. Key type and length: RSA $\ge 2048$ / $\ge 4096$, ECC curve (P-256, P-384, Ed25519).
  2. Signature hash algorithm: Assert $\ge \text{SHA-256}$ (zero SHA-1 / MD5).
  3. Post-Quantum Readiness: Track negotiation of hybrid PQ key exchanges (e.g. `X25519Kyber768Draft00` / `ML-KEM-768`).

### 2.8 Premature "notBefore" & Clock Skew Desync
* **The Risk**: Automated ACME / Let's Encrypt bots sometimes generate and deploy certificates where `notBefore` is a few seconds/minutes in the future due to server clock drift, immediately throwing `ERR_CERT_DATE_INVALID` across strict clients.
* **The Forensic Metric**: Assert $\text{notBefore} \le T_{\text{current}} \le \text{notAfter}$.

---

## 3. Recommended Telemetry Schema for `path-xyzt` TLS Module

```json
{
  "endpoint": "api.citibank.com",
  "port": 443,
  "observed_utc": "2026-09-09T14:50:00Z",
  "tls_version": "TLSv1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "post_quantum_kx": true,
  "leaf_cert": {
    "thumbprint_sha256": "3a8f1b2c...",
    "serial_number": "12:34:56:78:...",
    "subject_cn": "api.citibank.com",
    "issuer_o": "DigiCert Inc",
    "issuer_cn": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "san_count": 4,
    "has_wildcard": false,
    "key_type": "RSA-4096",
    "sig_algo": "sha256WithRSAEncryption",
    "valid_from_utc": "2026-05-01T00:00:00Z",
    "valid_to_utc": "2027-05-01T23:59:59Z",
    "days_until_expiration": 234
  },
  "chain_integrity": {
    "chain_length": 3,
    "is_complete_bundle": true,
    "root_anchor": "DigiCert Global Root G2",
    "intermediate_expirations": [
      {"cn": "DigiCert Global G2...", "days_until_expiration": 482}
    ]
  },
  "ocsp_stapling": {
    "present": true,
    "status": "GOOD",
    "this_update_utc": "2026-09-09T12:00:00Z",
    "next_update_utc": "2026-09-16T12:00:00Z",
    "is_fresh": true
  },
  "certificate_transparency": {
    "sct_count": 3,
    "all_valid": true
  }
}
```
