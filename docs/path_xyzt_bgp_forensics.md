# High-Value-Target BGP Routing Forensic Telemetry Matrix

**Author**: Pete Jalajas (`pjalajas@gmail.com`)  
**Repository**: `/home/petjal/dev/path-xyzt`  
**Date**: 2026-09-09  
**Scope**: BGP Route Hijacking, Sub-Prefix Detours, RPKI Validation & Middlebox Trajectory Detection  

---

## 1. The Threat Model: How BGP Is Weaponized Against HVTs

Border Gateway Protocol (BGP) governs how Autonomous Systems (ASNs) route traffic across the global Internet. Because BGP was designed around unauthenticated trust, adversaries (hostile state actors, rogue telecoms, criminal syndicates) regularly exploit core protocol mechanics to intercept financial and crypto infrastructure:

```
+-----------------------------------------------------------------------------------------+
|                                    LEGITIMATE ROUTE                                     |
|  Observer (AS_Local) ---> Tier-1 Transit (AS1299/AS3356) ---> Target Bank/Exchange (AS_Target) |
+-----------------------------------------------------------------------------------------+
                                           |
                                    [BGP HIJACK EVENT]
                                           v
+-----------------------------------------------------------------------------------------+
|                                  HIJACKED DETOUR ROUTE                                  |
|  Observer ---> Tier-1 ---> Rogue AS (e.g. Foreign Telco) ---> [MITM / Snooping]         |
|                                       |                                                 |
|                                       +---> Legitimate Target (Delayed / Re-routed)     |
+-----------------------------------------------------------------------------------------+
```

---

## 2. The 4 Distinct Attack Vectors

### 2.1 The Sub-Prefix Hijack (Longest-Prefix Match Dominance)
* **Mechanism**: If Citibank or Coinbase announces `198.51.100.0/22` (1,024 IPs), an attacker announces `198.51.100.0/24` (256 IPs).
* **The Rule**: BGP routing tables universally prioritize the most specific route (`/24` over `/22`), regardless of AS-path length.
* **Impact**: 100% of global traffic destined for that `/24` automatically flows into the attacker's infrastructure.
* **Precedent**: The 2018 Amazon Route 53 / MyEtherWallet attack, where attackers announced Amazon's `/24` DNS prefix via eNet (AS10297) to steal millions in crypto.

### 2.2 The Stealth Man-in-the-Middle (Traffic Snooping Detour)
* **Mechanism**: The rogue AS announces the target's prefix with an artificially forged path. The attacker sniffs, logs, or tampers with traffic (e.g. SSL stripping, DNS spoofing), then forwards the packets onward to the legitimate target.
* **Impact**: Zero downtime. The target appears online to basic uptime monitors (Ping/HTTP 200 OK), but traffic travels thousands of miles out of its way through an adversarial nation-state wiretap.
* **Precedent**: Repeated Rostelecom (AS12389) and China Telecom (AS4134) detours routing Western banking, Google, and Cloudflare traffic through Moscow/Beijing before delivery.

### 2.3 Exact-Prefix Route Leaks & Peering Inversions
* **Mechanism**: A multihomed enterprise or intermediate ISP erroneously re-announces routes learned from one upstream provider to another, creating an unintentional transit blackhole or massive latency spike.

### 2.4 Autonomous System (AS) Path Forgery
* **Mechanism**: Attackers append the legitimate target's ASN to the end of their announcement to bypass primitive origin-ASN filters.

---

## 3. How `path-xyzt` Detects and Forensically Proves BGP Tampering

`path-xyzt` combines 5 continuous telemetry streams to detect BGP anomalies within seconds:

### 3.1 RPKI & ROA Cryptographic Validation
* **The Primitive**: Resource Public Key Infrastructure (RPKI) binds IP prefix blocks to authorized Origin ASNs via cryptographically signed Route Origin Authorizations (ROAs).
* **The Metric**: Every observed route announcement is evaluated against RIR trust anchors (ARIN, RIPE, APNIC):
  * `VALID`: Route matches registered ROA prefix and max-length.
  * `INVALID_ASN`: Prefix origin ASN does not match ROA (Immediate P1 Alert).
  * `INVALID_MAX_LENGTH`: Prefix is more specific than authorized (Sub-prefix hijack alert).
  * `NOT_FOUND`: Unregistered (flags high-risk unanchored prefix).

### 3.2 Continuous AS-Path Vector Tracking & Origin Mutation
* **The Metric**: Records the full sequential transit tuple:
  $$\text{AS-Path} = [\text{ASN}_1, \text{ASN}_2, \dots, \text{ASN}_k, \text{ASN}_{\text{origin}}]$$
* **Alert Invariants**:
  1. **Origin Flip**: $\text{ASN}_{\text{origin}}$ changes unexpectedly.
  2. **High-Risk Intermediate Transit**: Any appearance of sanctioned or high-risk state ASNs in the path.
  3. **Path Inflation**: Number of AS hops increases abnormally ($\Delta \text{hops} \ge 3$).

### 3.3 Radial Latency Correlation ($r$-Spike Detection)
* **The Physical Law**: Light travels through single-mode fiber optic cable at $\approx 200\text{ km/ms}$ ($\approx 5\mu\text{s/km}$).
* **The Metric**: A BGP detour that re-routes domestic US banking traffic through a foreign nation-state introduces a mathematically unavoidable physical latency floor:
  $$\Delta r_{\text{transit}} \ge \frac{2 \times \text{Distance}_{\text{detour}}}{c_{\text{fiber}}} \ge 60\text{ms} - 120\text{ms}$$
* **Forensic Power**: An instantaneous jump in the radial coordinate radius $r$ correlated with an AS-path change mathematically confirms an active physical route detour, even if the attacker perfectly proxies the target application.

### 3.4 Deterministic `HopHash`
* Computes an 8-character SHA-256 fingerprint over the intermediate IP hops and BGP ASNs:
  $$\text{HopHash} = \text{SHA256}(\text{IP}_1 \parallel \text{ASN}_1 \parallel \dots \parallel \text{IP}_k \parallel \text{ASN}_k)[..8]$$
* Any route mutation or detour flips `HopHash` instantly.

### 3.5 Multi-Vantage Consensus Swarm
* Probes the HVT concurrently from US-East, EU-West, APAC, and Tor exits.
* Detects localized or regional BGP poisoning where only specific geographic quadrants are poisoned while the target's home region remains normal.

---

## 4. Telemetry Schema for `path-xyzt` BGP Module

```json
{
  "endpoint": "api.citibank.com",
  "resolved_ip": "192.0.2.45",
  "observed_utc": "2026-09-09T14:52:00Z",
  "radial_latency_ms": 18.4,
  "bgp_provenance": {
    "announced_prefix": "192.0.2.0/24",
    "origin_asn": 13335,
    "origin_as_name": "CLOUDFLARENET",
    "as_path": [1299, 3356, 13335],
    "hop_count": 3,
    "rpki_status": "VALID",
    "is_subprefix_hijack": false,
    "hop_hash": "a4f891b2"
  },
  "anomaly_detection": {
    "origin_mutated": false,
    "path_inflated": false,
    "high_risk_transit_detected": false,
    "latency_r_spike": false,
    "verdict": "ROUTE_NORMAL"
  }
}
```
