# path-xyzt: Specification & Architecture Standard (v1.5.0)

## 1. System Overview & Mandate
`path-xyzt` is an unopinionated outside-in network telemetry and perimeter integrity engine designed specifically for High-Value-Target (HVT) public endpoints (crypto custody/exchanges, institutional clearing houses, regional electric power grids, and Tier-1 internet infrastructure).

Rather than delivering a complex web dashboard, `path-xyzt` executes continuous, automated probes from geographically distributed external vantages (residential eyeballs, hyperscaler VMs) and generates a canonical, high-fidelity atomic telemetry stream (NDJSON / Parquet). The output is designed for direct, seamless ingestion into enterprise SIEMs and data lakes (Splunk, Datadog, Snowflake, ClickHouse).

To guarantee cryptographic non-repudiation and prevent historical revisionism by compromised providers or upstream transit attackers, `path-xyzt` commits periodic telemetry Merkle roots directly to a public decentralized blockchain ledger via OpenTimestamps (OTS).

---

## 2. Mathematical & Cryptographic Invariants

### Invariant 1: Binary Length-Prefixed, Full 256-Bit Merkle Seals
All Merkle tree hashes MUST enforce strict domain separation tags and fixed-width binary length-prefixed framing (`uint16_be` for strings/slices, `uint8` for enums) to mathematically eliminate length-extension and boundary-shifting second-preimage attacks.

All Merkle seals MUST output a full **64-hex character (256-bit / 32-byte)** SHA-256 digest. Truncation to 128 bits (32 hex) or 64 bits (16 hex) is strictly forbidden.

The composite root seal for a single probe observation is defined as:
$$\text{BundleSeal} = \text{SHA256}(\text{"path-xyzt/v1/bundle:\x00"} \parallel H_{\text{ROUTING}} \parallel H_{\text{ZONE}} \parallel H_{\text{TLS}} \parallel H_{\text{ADMIN}} \parallel H_{\text{PHYS}} \parallel H_{\text{SURFACE}})$$
*(Where each component $H$ is a 32-byte binary digest).*

Where Tier-1 component seals are defined as:

1. **$H_{\text{ROUTING}}$ (Autonomous Routing & Peering)**:
   $$H_{\text{ROUTING}} = \text{SHA256}(\text{"path-xyzt/v1/routing:\x00"} \parallel \text{len}_2(asn) \parallel asn \parallel \text{len}_2(prefix) \parallel prefix \parallel rpki\_code \parallel HopHash_{\text{raw}})$$
   - `len_2(x)`: Big-endian unsigned 16-bit integer length (`uint16_be`).
   - `asn`: Canonical origin AS string (e.g. `AS13335`).
   - `prefix`: Canonical CIDR string (e.g. `104.18.35.0/24` or `2606:4700::/32`).
   - `rpki_code`: `uint8` enum: `VALID` (0x01), `INVALID_ASN` (0x02), `INVALID_MAX_LENGTH` (0x03), `NOT_FOUND` (0x04).
   - `HopHash_raw`: 32-byte binary digest computed per Section 2.4.

2. **$H_{\text{ZONE}}$ (DNS Resolution & Security Policy)**:
   $$H_{\text{ZONE}} = \text{SHA256}(\text{"path-xyzt/v1/zone:\x00"} \parallel H_{\text{NS}} \parallel H_{\text{CAA}} \parallel H_{\text{EDGE}} \parallel H_{\text{AAAA}})$$
   - Each sub-hash ($H_{\text{NS}}$, $H_{\text{CAA}}$, $H_{\text{EDGE}}$, $H_{\text{AAAA}}$) is computed over its respective RRSet sorted deterministically according to RFC 4034 Section 6.2 canonical wire-format ordering.
   - If an RRSet is empty (e.g., no CAA records or IPv6-blind), its sub-hash is deterministically defined as $\text{SHA256}(\text{"EMPTY"})$.

3. **$H_{\text{TLS}}$ (Cryptographic Transport Security & Dual SNI)**:
   $$H_{\text{TLS}} = \text{SHA256}(\text{"path-xyzt/v1/tls:\x00"} \parallel leaf\_der\_sha256 \parallel \text{len}_2(issuer) \parallel issuer \parallel \text{len}_2(tls\_ver) \parallel tls\_ver \parallel \text{len}_2(cipher) \parallel cipher \parallel H_{\text{SNI}})$$
   - `leaf_der_sha256`: 32-byte binary SHA-256 digest of the raw ASN.1 DER leaf certificate.
   - $H_{\text{SNI}}$ binds the result of the dual-pass SNI probe:
     $$H_{\text{SNI}} = \text{SHA256}(\text{"path-xyzt/v1/sni:\x00"} \parallel non\_sni\_supp\_u8 \parallel non\_sni\_match\_u8 \parallel non\_sni\_sha256\_raw \parallel \text{len}_2(def\_cn) \parallel def\_cn)$$

4. **$H_{\text{ADMIN}}$ (Administrative, Email, Registrar & Cryptographic Disclosure Integrity)**:
   $$H_{\text{ADMIN}} = \text{SHA256}(\text{"path-xyzt/v1/admin:\x00"} \parallel \text{len}_2(iana\_id) \parallel iana\_id \parallel \text{len}_2(epp\_csv) \parallel epp\_csv \parallel exp\_epoch\_u64 \parallel dmarc\_u8 \parallel dmarc\_pct\_i16 \parallel p80\_code\_u16 \parallel disclosure\_grade\_u8 \parallel pgp\_fingerprint\_raw)$$
   - `iana_id`: Canonical numeric IANA Registrar ID string (e.g. `292`).
   - `epp_csv`: Sorted, comma-separated EPP statuses.
   - `exp_epoch_u64`: 64-bit big-endian unsigned integer UTC timestamp.
   - `dmarc_u8`: Enum: `missing` (0x00), `none` (0x01), `quarantine` (0x02), `reject` (0x03).
   - `dmarc_pct_i16`: Signed 16-bit integer (0–100, or -1 if omitted).
   - `p80_code_u16`: Unsigned 16-bit HTTP status code (e.g. 301, 302, 308, or 0 if error).
   - `disclosure_grade_u8`: Enum: `ABSENT` (0x00), `CLEARTEXT_ONLY` (0x01), `PGP_LINK_BROKEN` (0x02), `PGP_LINK_INVALID` (0x03), `DANE_UNVALIDATED` (0x04), `WEB_PGP_VALID` (0x05), `DANE_VERIFIED` (0x06).
   - `pgp_fingerprint_raw`: 20-byte raw binary SHA-1 fingerprint of the authoritative OpenPGP public key (or 20 null bytes `0x00` if absent/unparseable).

5. **$H_{\text{PHYS}}$ (Stateless Deterministic Physical Latency Bucket)**:
   - To guarantee independent, stateless verification across arbitrary verifiers without reliance on historical node state:
   - Latency measurements are quantized into stateless $10\text{ms}$ integer buckets:
     $$\text{bucket}(x) = \lfloor x / 10.0 \rfloor \times 10$$
   - $$H_{\text{PHYS}} = \text{SHA256}(\text{"path-xyzt/v1/phys:\x00"} \parallel \text{bucket}(rtt\_ms) \parallel \text{bucket}(tls\_handshake\_ms))$$

6. **$H_{\text{SURFACE}}$ (Surface Link-Linting, Policy Prose Hash & Warrant Canary Seal)**:
   $$H_{\text{SURFACE}} = \text{SHA256}(\text{"path-xyzt/v1/surface:\x00"} \parallel H_{\text{POLICY\_PROSE}} \parallel H_{\text{CANARY\_PROSE}} \parallel p\_downgrades\_u16 \parallel unpinned\_scripts\_u16 \parallel broken\_links\_u16)$$
   - $H_{\text{POLICY\_PROSE}}$: 32-byte SHA-256 digest of normalized semantic prose of the root-discovered Vulnerability Disclosure Policy / Security page (or 32 null bytes if absent).
   - $H_{\text{CANARY\_PROSE}}$: 32-byte SHA-256 digest of normalized prose / PGP clearsigned warrant canary declaration (or 32 null bytes if absent).
   - `p_downgrades_u16`: Unsigned 16-bit count of plaintext `http://` hyperlinks discovered on HTTPS root landing page.
   - `unpinned_scripts_u16`: Unsigned 16-bit count of external `<script src="...">` tags lacking Subresource Integrity (`integrity="sha384-..."`).
   - `broken_links_u16`: Unsigned 16-bit count of non-responding or HTTP error links sampled on the root landing page.

---

### Invariant 2: Forward Path Last-Mile Hashing (`HopHash`)
- **Forward Path Invariant**: Measures forward path from probe vantage to target edge.
- **Null Hop (`* * *`) Resilience**: The traceroute window anchors strictly to terminal destination hop ($N$) and examines preceding 3 hops ($N-3, N-2, N-1$).
- Non-responding hops are encoded deterministically as `NULL_HOP_{TTL}` rather than omitted.
- $$HopHash = \text{SHA256}(\text{"path-xyzt/v1/hophash:\x00"} \parallel \text{len}_2(h_{N-3}) \parallel h_{N-3} \dots \parallel \text{len}_2(h_N) \parallel h_N)$$
- Output is a full 64-hex character (256-bit) digest.

---

### Invariant 3: Canonical RFC 6962 EpochRoot & OpenTimestamps (OTS)
To prove historical state integrity without central notary reliance:
1. **Canonical Lexicographical Leaf Sorting**:
   At the conclusion of each measurement epoch $T_E$ (hourly batch across all $K$ targets and $M$ vantages):
   All `BundleSeal` 256-bit hex strings are sorted lexicographically:
   $$\text{SortedLeaves} = \text{sort}(\text{BundleSeal}_1, \text{BundleSeal}_2, \dots, \text{BundleSeal}_N)$$
2. **RFC 6962 Tree Domain Separation**:
   - Leaf nodes: $\text{LeafHash}_i = \text{SHA256}(0x00 \parallel \text{bytes}(\text{BundleSeal}_i))$
   - Interior nodes: $\text{NodeHash} = \text{SHA256}(0x01 \parallel \text{LeftChild} \parallel \text{RightChild})$
   - Odd leaf nodes are promoted without duplicating leaves (preventing CVE-2012-2459 malleability).
3. **OpenTimestamps Attestation Lifecycle**:
   - Step 1 (`PENDING_CALENDAR`): Submit `EpochRoot` to $\ge 3$ decentralized OpenTimestamps calendar servers (`alice.btc.calendar.opentimestamps.org`, `bob.btc.calendar.opentimestamps.org`, `finney.calendar.eternitywall.com`).
   - Step 2 (`BLOCKCHAIN_MINED`): After calendar batch aggregation, run `ots upgrade` to embed the full Merkle inclusion path to the confirmed block header.
   - Step 3 (`FINALIZED`): Validated after block confirmations.

---


### Invariant 13: Passive Telemetry Stand-Off & Zero-Exploitation Perimeter Guard
`path-xyzt` is strictly an outside-in, zero-privilege, empirical telemetry recorder—**NEVER a vulnerability scanner, fuzzer, or intrusive penetration tool**.

To maintain rigorous safe-harbor protections, prevent defensive WAF/fail2ban bans, and uphold ethical telemetry integrity, all transport probing adheres strictly to the following stand-off bounds:
1. **Zero Exploitation & Zero Fuzzing**: Under no circumstances does `path-xyzt` inject malformed payloads, fuzzing buffers, shellcode, exploit sequences, path traversal strings, or non-standard control sequences.
2. **Zero Ingestion of Auth Endpoints**: For SSH (port 22), the probe connects solely to read the server's unsolicited RFC 4253 protocol identification string (`SSH-protoversion-softwareversion`). The probe NEVER sends client identification, NEVER attempts key exchange, NEVER submits usernames/passwords, and NEVER requests an authentication method. Upon receiving the initial banner (or at 1.5s timeout), the TCP socket is immediately terminated with `shutdown(SHUT_RDWR)` and `close()`.
3. **Pure Passive Observation**: The probe records solely what the public server voluntarily announces to the open network prior to any interactive session. Findings are recorded as factual telemetry observations (e.g. `raw_banner: "SSH-2.0-OpenSSH_9.6p1"`), never speculative vulnerability verdicts.

## 3. Systems, Execution & Timeout Budgets

### Invariant 4: Generous 45.0s Envelope & The "Non-Responsive Target" Invariant
1. **The Generous 45.0s Probe Envelope**:
   Total execution of a single endpoint probe is strictly bounded by an operating-system level deadline:
   $$T_{\text{envelope}} = 45.0\text{ seconds}$$
   The collector process registers an OS-level `signal.alarm(45)`.
2. **The "Zero-Retry In-Flight / Unfiltered Reality" Doctrine ("Their Problem, Not Ours")**:
   - Standard application clients and synthetic monitors (Pingdom, Datadog Synthetics) are designed with sycophantic *in-flight* retry loops, exponential backoffs, and connection smoothing to *hide* transient infrastructure defects from dashboards.
   - `path-xyzt` inverts this: **We do NOT retry in-flight. We do NOT poll. We do NOT mask the delay.**
   - In distributed systems, in-flight retrying is a distortion of reality. If an HVT endpoint drops packets, triggers a BGP route flap, or stalls for 45 seconds, an actual consumer or API client experienced that exact latency degradation or hard failure.
   - When the 45s alarm fires, the engine treats the non-response as an **actionable first-class empirical observation**: raises `TimeoutError`, halts immediately, and writes an unvarnished `status: "timeout_non_responsive"` record into the telemetry stream.
   - The failure is committed to the Merkle tree and public blockchain ledger via OpenTimestamps, establishing an immutable cryptographic record that the target failed to answer outside-in client traffic at that timestamp.
   - **Sampling Cadence vs. Fault Attribution ("We DO retry... a few times an hour")**:
     - The engine *does* retry periodically out-of-band: scheduled sweeps re-probe targets every few minutes or hourly across vantages.
     - *Exception / Self-Blame Invariant*: Periodic retrying is suspended *only* if the failure is provably our own fault (e.g. local interface down, zero default route, default gateway unresponsive, unresolvable local DNS, expired dead-man lease). If our vantage's first-mile health check fails, the run is flagged as `LOCAL_VANTAGE_FAULT` and suppressed from penalizing the target's perimeter record.
     - If our first-mile is sound and the target is non-responsive, the blame sits squarely on the target. We record the failure, seal it, and revisit them on the next scheduled run.

3. **Deterministic IP Pinning**:
   - The probe performs DNS resolution once at $T=0$.
   - All subsequent transport measurements (TCP SYN-ACK, TLS handshake, MTR forward trace) bind strictly to the exact same pinned IP address.
3. **Uniform RFC 9110 Vantage Identity**:
   - All network calls (HTTP, HTTPS, RDAP) MUST use an identical User-Agent string:
     ```http
     User-Agent: path-xyzt/1.5.0 (+https://github.com/petjal/path-xyzt; public-telemetry-probe; contact: pjalajas@gmail.com)
     ```
   - Arbitrary browser user-agents (`Mozilla/5.0`) are strictly forbidden to eliminate heuristic WAF split-brain signatures.

---

## 4. Telemetry Vectors & Wire Schema (v1.5.0)

```json
{
  "schema_version": "1.5.0",
  "probe_metadata": {
    "probe_node_id": "vantage-us-east-eyeball-01",
    "probe_vantage_type": "residential_isp",
    "timestamp_iso8601": "2026-09-10T00:55:00.000000+00:00",
    "timestamp_epoch_ms": 1789001700000
  },
  "target": {
    "hostname": "iso-ne.com",
    "resolved_ip": "18.161.34.100",
    "port": 443
  },
  "transport_hardening_audit": {
    "tls_version": "TLSv1.3",
    "is_tls_v1_3": true,
    "cipher_suite": "TLS_AES_128_GCM_SHA256",
    "alpn_negotiated": "h2",
    "hsts_present": true,
    "hsts_header": "max-age=31536000; includeSubDomains; preload",
    "hostname_mismatch": true,
    "cert_error": "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'iso-ne.com'.",
    "sni_audit": {
      "supports_non_sni": false,
      "non_sni_cert_matches_sni": false,
      "non_sni_sha256": null,
      "non_sni_default_cn": null,
      "non_sni_error": "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure"
    },
    "plaintext_port80_audit": {
      "http_status": 301,
      "redirect_location": "https://iso-ne.com/",
      "is_permanent_redirect": true
    },
    "defensive_headers": {
      "server": "ISO New England",
      "x_powered_by": "CrafterCMS",
      "x_frame_options": "SAMEORIGIN",
      "x_content_type_options": "nosniff",
      "csp_present": false
    }
  },
  "latency_breakdown_ms": {
    "dns_resolution_ms": 3.38,
    "tcp_synack_rtt_ms": 202.32,
    "tls_handshake_ms": 366.28,
    "total_preflight_ms": 571.98
  },
  "routing_provenance": {
    "origin_asn": "AS16509",
    "bgp_prefix": "18.161.32.0/21",
    "rpki_state": "VALID",
    "country_code": "US"
  },
  "last_mile_signature": {
    "total_hops": 12,
    "hophash": "6e13f0fffa10a975df0599780acc04245903b44781467406a09a5b174092b704",
    "transit_exit_ip": "be-301-arsc1.needham.ma.boston.comcast.net",
    "peering_ingress_ip": "150.222.71.142",
    "terminal_ip": "server-18-161-34-100.bos50.r.cloudfront.net",
    "catchment_hops_count": 0,
    "hand_off_hops": []
  },
  "dns_policy_proof": {
    "zone_seal": "379d42e14d9d927c39f630dc67879f9e9508bcde348821948572019485720194",
    "h_caa": "NONE",
    "caa_records": [],
    "has_caa": false,
    "h_ns": "34ad438b149d8bd8a2a634852a91599384729104857201948572019485720194",
    "authoritative_nameservers": ["ns-1199.awsdns-21.org."],
    "ipv6_ready": false,
    "resolved_aaaa_records": [],
    "resolved_a_records": ["18.161.34.100"]
  },
  "impending_expiration_sentinel": {
    "domain_rdap": {
      "apex_domain": "iso-ne.com",
      "iana_registrar_id": "9",
      "expiration_iso8601": "2027-06-19T04:00:00Z",
      "days_until_expiration": 282.14,
      "registrar": "Register.com - Network Solutions, LLC",
      "epp_statuses": ["client transfer prohibited"],
      "status": "valid"
    },
    "dnssec_rrsig": {
      "dnssec_enabled": false,
      "note": "No RRSIG records returned for target or apex"
    },
    "tls_leaf": {
      "days_remaining": 29.0,
      "valid_until": "2026-10-08T23:59:59+00:00",
      "issuer": "DigiCert Inc",
      "fingerprint_sha256": "2f482900d8d0dfabd3f05cd2f3f4c8b608890a0d5f41a4ca4c760aa844476fc0",
      "subject_alt_names": ["www.iso-ne.com"]
    }
  },
  "administrative_contact_sentinel": {
    "rfc9116_security_contacts": ["mailto:security@iso-ne.com"],
    "security_policy_url": "https://iso-ne.com/security",
    "soa_hostmaster": "awsdns-hostmaster@amazon.com",
    "dmarc_policy": "quarantine",
    "dmarc_pct": 0,
    "dmarc_record": "v=DMARC1; p=quarantine; pct=0; rua=mailto:rua@iso-ne.com;",
    "secure_reporting": {
      "pgp_available": false,
      "disclosure_grade": "CLEARTEXT_ONLY",
      "rfc9116_encryption_urls": [],
      "rfc9116_pgp_key_valid": false,
      "rfc9116_pgp_fingerprint": null,
      "dns_openpgpkey_present": false,
      "dns_openpgpkey_dnssec_valid": false,
      "dns_openpgpkey_fingerprint": null
    }
  },
  "merkle_seals": {
    "bundle_seal": "14c294a87fbd24e195bf870d4afa08a385720194857201948572019485720194",
    "h_routing": "28833f17a1497975308bfbe4125d921285720194857201948572019485720194",
    "h_zone": "379d42e14d9d927c39f630dc67879f9e85720194857201948572019485720194",
    "h_tls": "829690e0c5f8eb550b9a076737f067a585720194857201948572019485720194",
    "h_admin": "e3d86589fae2340f332f0291a0f0258485720194857201948572019485720194",
    "h_phys": "8332fde234d6a249f06f4b2f37a6b25485720194857201948572019485720194"
  }
}
```

---

## 5. Sampling Cadence & Scheduling Standards
- Probes MUST execute every **1 hour** (24 samples per day) during early shakeout, with randomized inter-probe jitter: $\delta \sim \mathcal{U}(-180, +180)\text{ seconds}$ ($\pm 3\text{ minutes}$).
- Identification headers MUST follow RFC 9110:
  ```http
  User-Agent: path-xyzt/1.5.0 (+https://github.com/petjal/path-xyzt; public-telemetry-probe; contact: pjalajas@gmail.com)
  X-Probe-Provider: path-xyzt
  X-Probe-Purpose: outside-in-network-telemetry-and-perimeter-health
  ```

---

## 6. Advanced Telemetry Vectors & Invariant Expansion (v1.6.0 Roadmap)

### Invariant 5: Outside-In Proxy & Middlebox Fingerprinting
1. **The Proxy Hand-Off Differential ($\Delta \tau_{\text{proxy}}$)**:
   - Evaluates local proxy latency vs backend origin latency:
     $$\Delta \tau_{\text{proxy}} = T_{\text{TLS}} - T_{\text{TCP}}$$
   - If $T_{\text{TCP}} \le 10\text{ms}$ but $\Delta \tau_{\text{proxy}} \ge 350\text{ms}$, the handshake completed at a local reverse proxy while the origin backend was delayed or stalled.
2. **TCP ZeroWindow & Buffer Saturation Sentinel**:
   - Detects TCP window advertisement collapse ($\text{win} = 0$) during transport handshake, proving backend application queue/thread pool exhaustion behind edge reverse proxies.
3. **Proxy Interception & Hop-by-Hop Header Unmasking**:
   - Captures `Via:`, `X-Cache:`, `X-Served-By:`, `Server-Timing:` (e.g. APM transaction tracing), and corporate MITM root substitution.

### Invariant 6: Path MTU (PMTUD) & Post-Quantum Encapsulation Diagnostics
1. **Path MTU Detour & Encapsulation Detection**:
   - Historical baseline MTU $= 1500\text{ bytes}$ (MSS $1460$).
   - Contraction to $1420\text{--}1440\text{ bytes}$ triggers an **Encapsulation / Detour Finding** (indicative of dynamic IPsec, WireGuard, or BGP traffic diversion to an off-path inspection hub).
2. **Post-Quantum Hybrid Handshake Blackhole Sentinel**:
   - Probes endpoints with padded ClientHello payloads ($> 1400\text{ bytes}$) simulating NIST PQC hybrid key exchanges (X25519 + ML-KEM-768).
   - Identifies enterprise firewalls dropping ICMP Type 3 Code 4 (fragmentation needed) packets that silently drop post-quantum connections.

### Invariant 7: Decoupled Tri-Sentinel Fault Attribution Math
To mathematically isolate target failure from intermediate or local transit:
1. Concurrently probe $K=3$ topologically disjoint Anycast sentinels: Quad9 (`9.9.9.9`), Cloudflare (`1.1.1.1`), Google (`8.8.8.8`) alongside the local gateway ($GW$).
2. Evaluate local health invariant:
   $$\text{Fault}_{\text{local}} = \left( RTT(GW) = \infty \lor \frac{1}{K}\sum_{i=1}^K \mathbb{I}(Loss(R_i) = 1.0) \ge \frac{2}{3} \right)$$
3. If $\text{Fault}_{\text{local}} = \text{true}$, emit `LOCAL_VANTAGE_FAULT` and suppress penalizing target records.
4. If local sentinels and intermediate transit hops are clean, non-response is mathematically proven to be target-side application saturation.

### Invariant 8: Exponential Retention & The Zero-Storage KB Moat
1. **Tier 1 (Days 0–3)**: Full wire capture (raw PCAP, full DER x509 chains, exact HTTP wire dumps).
2. **Tier 2 (Days 4–30)**: Structured NDJSON telemetry rows (fingerprints, RTT vectors, header keys).
3. **Tier 3 (Day 31+)**: Pure cryptographic attestation. Retain strictly the 32-byte `BundleSeal` and the RFC 6962 inclusion proof linking to the public ledger-anchored `EpochRoot`.

### Invariant 9: Automated Apex vs. WWW Perimeter Divergence Audit
1. **The RFC 1034 Zone Apex Limitation**:
   - RFC 1034 §3.6.2 prohibits `CNAME` records at the zone apex (`example.com`).
   - Consequently, enterprises frequently route `www.example.com` through managed global CDN/WAF Anycast networks (Cloudflare, Akamai, Fastly, CloudFront), while bare apex (`example.com`) points to legacy on-prem load balancers, direct IP origin servers, or bare HTTP redirect appliances.
2. **Automated Counterpart Resolution**:
   - For every probe target, if the hostname is an apex domain (`example.com`), the probe dynamically resolves and audits counterpart `www.example.com`.
   - If the hostname starts with `www.` (`www.example.com`), the probe dynamically resolves and audits counterpart apex `example.com`.
3. **Perimeter Divergence Invariant**:
   $$\text{Divergence} = \left( IP_{\text{target}} \neq IP_{\text{counterpart}} \lor ASN_{\text{target}} \neq ASN_{\text{counterpart}} \right)$$
   - When $\text{Divergence} = \text{true}$, `path-xyzt` emits an explicit `infrastructure_divergence: true` finding, exposing split-routing, CNAME flattening anomalies, disparate TLS certificate authorities, and asymmetric plaintext downgrade attack windows.

### Invariant 10: Cryptographic Vulnerability Disclosure & Key Provenance Audit
1. **The Cleartext Reporting Blindspot**:
   - High-value perimeters frequently publish administrative security contacts (`mailto:security@...`), but omit public encryption keys, forcing external vulnerability reporters to transmit sensitive zero-day observations over unencrypted cleartext email or surrender data to walled-garden commercial bug-bounty platforms.
2. **Dual-Channel Cryptographic Ingestion Audit**:
   - **Channel A (Web - RFC 9116 §2.5.3)**: Probes `/.well-known/security.txt` for `Encryption:` URI directives. Downloads the referenced key over HTTPS, parses the OpenPGP packet structure (RFC 4880 / RFC 9580), extracts the 160-bit SHA-1 key fingerprint, verifies packet integrity, and detects expired or broken key rot.
   - **Channel B (DNS - RFC 7929 / DANE OPENPGPKEY)**: Encodes target security contact local part into 28-octet SHA-256 slice formatted in z-base-32 (`<hash>._openpgpkey.<apex>`), queries RR type 61 (`OPENPGPKEY`), and validates whether the DNS zone is authenticated via DNSSEC (`AD=1`).
3. **Cryptographic Binding Invariant**:
   - The verified disclosure grade (`ABSENT`, `CLEARTEXT_ONLY`, `PGP_LINK_BROKEN`, `PGP_LINK_INVALID`, `DANE_UNVALIDATED`, `WEB_PGP_VALID`, `DANE_VERIFIED`) and authoritative OpenPGP key fingerprint are cryptographically bound directly into $H_{\text{ADMIN}}$ and anchored into the public ledger via the hourly `EpochRoot`.

### Invariant 11: Surface Link-Linting, Semantic Policy Hashing & Warrant Canary Sentinel
1. **The Dual-Track Surface Linting Invariant**:
   - Executes single-pass non-intrusive inspection of target root landing page HTML ($\le 128\text{ KiB}$), strictly bounded without recursive spidering.
   - **Track A (Security & Liability Surface)**: Detects passive downgrade vectors (`http://` hyperlinks on HTTPS landing pages), external scripts lacking Subresource Integrity (`integrity="sha384-..."`), and potential subdomain takeover opportunities.
   - **Track B (Reachability & Dead Link Audit)**: Executes concurrent HTTP `HEAD` probes ($\le 2.0\text{s}$ timeout per link) across sampled root page hyperlinks, exposing dead marketing links (`404`) and backend infrastructure stalls (`5xx`).
2. **Semantic Policy Prose Hashing**:
   - Discovers human-navigable Vulnerability Disclosure Policy (VDP), Security, or Trust Center links on the root page.
   - Normalizes HTML by stripping volatile scripts, styling tags, dynamic nonce attributes, and whitespace, computing a deterministic 256-bit hash ($H_{\text{POLICY\_PROSE}}$) to detect and mathematically date corporate policy/legal safe harbor alterations.
3. **Warrant Canary Silence Sentinel**:
   - Discovers declared transparency/canary links or probes `/.well-known/canary.txt`.
   - Normalizes and hashes canary text ($H_{\text{CANARY\_PROSE}}$) and verifies inline PGP clearsigned wrappers (`-----BEGIN PGP SIGNED MESSAGE-----`).
   - Cryptographically attests canary presence and flags silent canary disappearance or expiration cliffs directly into the public ledger-anchored Merkle tree ($H_{\text{SURFACE}}$).

### Invariant 12: Scheduled Deep-Dive Policy & Canary Tree Auditing
1. **The Progressive Cadence Lifecycle**:
   - Strictly decouples fast atomic 30s hourly probes from deep structural policy inspections:
      - **Phase 1 (Shakeout)**: Hourly execution for 24–48 hours to establish initial baselines across all target endpoints.
      - **Phase 2 (Stabilization)**: Daily execution for 7–14 days to test conditional `304 Not Modified` caching efficiency across normal enterprise release cycles.
      - **Phase 3 (Steady-State Cruise)**: Monthly (or bi-weekly) execution permanently, capturing long-term statutory, legal, and warrant canary drift with near-zero bandwidth overhead.
2. **Sitemap Fast-Track & Target Path Discovery ($\text{Depth} \le 2$)**:
   - Queries `/sitemap.xml` directly to extract authoritative legal/security/terms URLs and declared `<lastmod>` timestamps without crawling.
   - Falls back to regex-filtered anchor discovery strictly bounded to high-interest paths (`/legal`, `/terms`, `/privacy`, `/security`, `/compliance`, `/subprocessor`, `/transparency`, `/canary`). Max 25–30 pages per target.
3. **Dual-Hash Forensic Fingerprinting & Tree Seal**:
   - For every discovered page, extracts both bit-for-bit raw body hash ($H_{\text{RAW}}$) and normalized semantic prose hash ($H_{\text{PROSE}}$).
   - Aggregates all inspected page states into an RFC 6962 Merkle tree root ($H_{\text{POLICY\_TREE}}$):
     $$\text{Leaf}_i = \text{SHA256}(\text{URL}_i \parallel \text{Status}_i \parallel H_{\text{PROSE}, i})$$
     $$H_{\text{POLICY\_TREE}} = \text{RFC6962\_MerkleRoot}(\text{SortedLeaves})$$
   - Anchors the full governance state of the target perimeter into the public cryptographic ledger.
