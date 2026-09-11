# path-xyzt: Full-Stack Endpoint Hijack Surface (Electrons to Cloud)

## 1. Physical & L1/L2 Substrate (Electrons / Photons)
- **Subsea Cable & Optical Fiber Splice / Bending**:
  - Optical taps (macrobending) on unencrypted terrestrial or subsea fiber backbones.
  - Optical carrier re-routing at DWDM layer prior to IP-level routing.
  - Observable artifact: Step-function RTT jump (+15–40 ms) with zero change in IP traceroute hops.
- **IXP Cross-Connect Miswiring & Mirroring**:
  - Promiscuous taps or misdirected VLAN trunks at peering exchanges (Equinix, DE-CIX, LINX).
  - Rogue L2 MAC announcement on shared peering fabrics.
  - Observable artifact: ARP/NDP churn, asymmetric latency jitter ($r_{jitter} > 3\sigma$).

## 2. Autonomous Transit & Routing (BGP / L3)
- **BGP Origin Hijacking**:
  - Illegitimate AS announces target prefix (exact match /24).
  - Observable artifact: Sudden change in Cymru origin AS, RPKI ROA state flips from VALID to INVALID.
- **Sub-Prefix Disaggregation (Traffic Detour)**:
  - Legitimate target announces `/20`; attacker announces specific `/24` or `/25`. Longest-prefix match pulls traffic globally through attacker AS without triggering exact-match route alarms.
  - Observable artifact: Prefix length increases; transit hop count and AS-path length deviate from baseline.
- **AS-Path Poisoning / Prepending Hijack**:
  - Injecting fabricated AS-paths to bypass simple path-length filters or evade detection by tier-1 upstream up-links.
  - Observable artifact: Transit AS list changes; path hash mutates.

## 3. DNS & Resolution Infrastructure (Layer 5/7 Control Plane)
- **Nameserver (NS) Delegation Hijacking (Parent Zone Glue Injection)**:
  - Attacker breaches registrar or uses compromised EPP credentials to swap parent TLD zone delegation (e.g. changing `.com` glue records pointing `coinbase.com` from `ns1.cloudflare.com` to rogue NS).
  - Observable artifact: Mismatch between parent TLD NS records (`dig @a.gtld-servers.net <domain> NS`) and authoritative child zone NS records (`dig @ns1.cloudflare.com <domain> NS`).
- **Dangling CNAME / Subdomain Takeover**:
  - Target points CNAME to external SaaS/cloud service (e.g., AWS S3 bucket, CloudFront, Azure Traffic Manager, Zendesk) that has been decommissioned or unclaimed.
  - Attacker claims the backend resource and gains immediate TLS + control plane authority over the subdomain.
  - Observable artifact: CNAME targets responding with NXDOMAIN or provider error codes (`NoSuchBucket`, `ResourceNotFound`).
- **DNS Cache Poisoning & Kaminsky/0x20 Bypass**:
  - Injecting forged RRsets into intermediate recursive resolvers.
  - Observable artifact: Divergence in resolved IP sets across vantage resolvers (Cloudflare 1.1.1.1 vs Google 8.8.8.8 vs Quad9 9.9.9.9 vs Authoritative).
- **DNSSEC Strip / Signature Expiration (RRSIG Stall)**:
  - Withholding new RRSIG signatures or replaying expired signatures while dropping DS records.
  - Observable artifact: RRSIG expiration countdown hits 0; DS record validation status flips to INSECURE or BOGUS.

## 4. Identity, Administrative & Account Layer (The Human & Carrier Frontier)
- **Registrar Account Compromise / EPP Lock Stripping**:
  - Bypassing 2FA, session hijacking, or abusing insider access at domain registrars (MarkMonitor, CSC, GoDaddy).
  - Attacker removes `clientTransferProhibited` and `serverTransferProhibited` EPP status locks to initiate registrar transfer or update authoritative NS.
  - Observable artifact: Drop of `*Prohibited` flags in RDAP/WHOIS; registrar change event; sudden modification of contact handles.
- **SIM-Swapping & SS7/Diameter Signaling Attacks**:
  - Attacker socially engineers carrier (e.g. Verizon, AT&T, T-Mobile) or exploits SS7/Diameter roaming vulnerabilities to re-route SMS 2FA tokens.
  - Used to take over registrar accounts, Cloudflare/AWS root consoles, or DNS management portals.
  - Observable artifact: Rapid sequence: Registrar login -> EPP lock strip -> NS delegation update -> Let's Encrypt / ACME cert issuance.
- **BGP / Peering Portal Account Hijack**:
  - Takeover of PeeringDB, RADB, or RIR portals (ARIN, RIPE NCC, APNIC) to mutate IRR route objects or modify RPKI ROAs.
  - Observable artifact: Unauthorized creation or deletion of ROAs for the target's IP prefixes.

## 5. Public Key Infrastructure (PKI / TLS Layer)
- **Rogue Intermediate CA / Compromised ACME Validation**:
  - Attacker leverages transient BGP hijack or DNS takeover to satisfy ACME HTTP-01 or DNS-01 challenges and issue authentic, trusted public certificates (e.g. Let's Encrypt, ZeroSSL, DigiCert).
  - Observable artifact: New leaf certificate appears on Certificate Transparency (CT) logs with an anomalous issuer or outside normal maintenance cadence; leaf public key sha256 changes abruptly.
- **CAA Record Circumvention / Omission**:
  - Missing or hijacked CAA (Certification Authority Authorization) records allowing unauthorized CAs to issue certs.
  - Observable artifact: Mutation or absence of `issue` / `issuewild` CAA records.
- **OCSP Stapling Suppression & Revocation Tampering**:
  - MitM attacker drops OCSP responses or serves stale status to prevent clients from learning of revoked certs.
  - Observable artifact: OCSP response age exceeding `NextUpdate`; stapling missing during TLS handshake.

## 6. Edge & Cloud Infrastructure (Edge VIP / Ingress)
- **Cloudflare / CDN Edge Account Misattribution**:
  - Prior to proper custom host verification, claiming a domain in a separate CDN tenant before apex DNS is verified, or exploiting wildcard routing rules.
  - Observable artifact: `Server` or edge headers (e.g., `cf-ray`, `x-amz-cf-id`, `akamai-grn`) pointing to disparate geographic edge pops or anomalous account IDs.
- **Origin Server Bypass & Direct-to-IP Exposure**:
  - Locating real backend IP behind Cloudflare/Akamai via historical DNS records, certificate leaks, or outbound webhooks, bypassing all edge WAF/DDoS mitigations.
  - Observable artifact: Target IP answers HTTP requests on non-CDN AS.

---

## 7. path-xyzt Telemetry Matrix: Automated Outside-In Invariants

| Attack Vector | Detection Mechanism in path-xyzt | Metric / Invariant Monitored |
|---|---|---|
| **NS Delegation Hijack** | Query TLD parent NS vs Child NS | Diff of parent TLD glue vs Authoritative child NS set |
| **Registrar EPP Stripping** | RDAP polling every 30m | Absence of `clientTransferProhibited` / `serverDeleteProhibited` |
| **SIM-Swap / Portal Takeover** | Composite Sentinel Alert | Correlated EPP status flip + NS change + ACME cert issuance |
| **BGP Origin / Sub-prefix** | Team Cymru + RPKI API | ASN mismatch, `/24` prefix emergence, RPKI `INVALID` |
| **Subsea / IXP Divergence** | Polar Latency Coordinate ($r, \theta$) | TCP handshake RTT jump ($>25\%$) without hop count change |
| **Rogue Cert Issuance** | TLS Leaf Telemetry + CT logs | Leaf SHA256 change, unexpected issuer org, CAA violation |
| **DNSSEC Expiration Stall** | Authoritative RRSIG parser | RRSIG hours remaining $\le 12$ hours |
| **Last-Mile Peering Shift** | HopHash over last 4 hops | Ingress peering router IP mutation |

