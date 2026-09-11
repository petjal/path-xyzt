# path-xyzt: Last-Mile Traceroutes & The Anti-Black-Duck "Raw Data Stream" Architecture

**Author**: Pete Jalajas (`pjalajas@gmail.com`)  
**Repository**: `/home/petjal/dev/path-xyzt`  
**Date**: 2026-09-09  
**Core Architectural Doctrine**: (1) Deep Last-Mile Hop Forensics; (2) Inverting Legacy Dashboard Traps into a Pure Raw Telemetry Stream.

---

## 1. The Critical Forensic Importance of the "Last Mile"

### 1.1 Why BGP Alone is Blind
BGP AS-paths are macro-level abstractions: an Autonomous System (e.g. AS16509 Amazon or AS13335 Cloudflare) covers hundreds of data centers, thousands of routers, and millions of route paths worldwide. 

A target can maintain an apparently "valid" BGP route while suffering catastrophic last-mile interception or silent degradation. **Hop-by-hop traceroute—specifically the final 3 to 5 hops—is where the real physical ground truth lives.**

```
+-----------------------------------------------------------------------------------------+
|                                    THE LAST 5 HOPS                                      |
+-----------------------------------------------------------------------------------------+
| Hop N-4: Tier-1 Carrier Backbone     -> 4.68.70.12 (Level3 / Lumen Ashburn Core)        |
| Hop N-3: Internet Exchange (IXP)     -> 206.108.115.42 (Equinix Ashburn Fabric)         |
| Hop N-2: Target Border Router        -> 198.51.100.1 (cr1-ash.citi.com)                 |
| Hop N-1: DDoS Scrubbing / Firewalls  -> 198.51.100.25 (radware-scrub.citi.com)          |
| Hop N:   Hardware VIP Load Balancer  -> 198.51.100.80 (f5-vip-api.citi.com)             |
+-----------------------------------------------------------------------------------------+
```

### 1.2 What Happens in the Last Mile During Attacks & Outages
1. **Scrubbing Center Diversions (The Unannounced DDoS Trap)**:
   * When an enterprise (bank or exchange) activates emergency mitigation (Cloudflare Magic Transit, Akamai Prolexic, Radware DefensePro), the last 2 hops suddenly flip to an external scrubbing proxy.
   * Detecting this proves an active attack or misconfigured proxying in real-time.
2. **IXP Peering Fabric Hijacks & Interceptions**:
   * Traffic enters the correct target ASN, but is handed off at an unexpected Internet Exchange Point (e.g. Frankfurt or Miami instead of New York/Ashburn), adding $40\text{ms}$ latency.
3. **Data Center Failover / Hot-Standby Flips**:
   * Host reverse DNS (PTR records) on the penultimate hop changes from `dc1-ashburn` to `dc2-dallas`, alerting to unannounced internal enterprise failovers.
4. **Internal Congestion & Bottleneck Isolation**:
   * Per-hop RTT deltas: If Hop $N-1$ is $18\text{ms}$ and Hop $N$ is $190\text{ms}$, the bottleneck is unequivocally **inside the target enterprise perimeter** (VIP overload or firewall queue exhaustion), not in the transit carriers.

### 1.3 Telemetry Captured for Every Traceroute Hop
For every hop $k \in [1 \dots N]$:
* `hop_index`: Distance from observer (TTL value).
* `hop_ip`: Responder IPv4 / IPv6 address (or `*` if dropped).
* `hop_rtt_ms`: Synthetic Round-Trip Time with sub-millisecond precision.
* `hop_ptr`: Authoritative Reverse DNS lookup (e.g., `be-200-pe01.ashburn.va.ibone.comcast.net`).
* `hop_asn`: Mapped BGP ASN and AS Organization.
* `mpls_labels`: Captured MPLS label stack (if ICMP extensions RFC 4950 are enabled on backbone routers).

---

## 2. Architectural Design Principle: Raw Data Stream vs. UI Layer

### 2.1 The Dashboard Bloat Antipattern
* **Complexity Overhead**: Network monitoring systems frequently construct complex web application layers, bespoke reporting widgets, database aggregators, and custom alert engines.
* **Maintenance Drag**: Engineering resources become consumed maintaining visual interfaces, front-end state, and conflicting reporting formats rather than improving protocol measurement accuracy.

### 2.2 The Raw Immutable Data Pipeline
`path-xyzt` restricts its mandate to measurement and serializing immutable telemetry:
* **No Embedded UI or Dashboard Layers**: Zero custom policy engines, bespoke visual builders, or complex stateful applications.
* **Pure Telemetry Stream**: Delivers structured, cryptographically signed, unopinionated raw telemetry (NDJSON / Parquet).
* **Direct Pipeline Ingestion**: Designed for native ingestion into existing data lakes and SIEM infrastructure (Splunk, Datadog, Snowflake, ClickHouse).
* **Deterministic Core Invariants**:
  1. The probe measures empirical protocol states ($T, r, \theta, \phi$, last-mile traceroutes, BGP, TLS).
  2. Emits flat, self-describing records with cryptographic seals.
  3. Stateless execution with zero database or daemon dependencies.

---

## 3. Canonical Raw JSON Data Schema (Pristine Stream Output)

```json
{
  "schema_version": "1.0.0",
  "observation_id": "obs_9f82a1c0d4e5",
  "timestamp_utc": "2026-09-09T14:55:12.482Z",
  "vantage_point": {
    "vantage_id": "us-east-va-01",
    "vantage_asn": 16509,
    "vantage_geo": "Ashburn, VA, US"
  },
  "target": {
    "hostname": "api.citibank.com",
    "resolved_ip": "198.51.100.80",
    "port": 443
  },
  "polar_coordinates": {
    "latency_r_ms": 14.82,
    "topological_theta_rad": 1.2845,
    "anycast_phi_rad": 0.6812
  },
  "bgp_provenance": {
    "origin_asn": 13335,
    "origin_as_name": "CLOUDFLARENET",
    "as_path": [16509, 1299, 13335],
    "rpki_status": "VALID"
  },
  "traceroute": {
    "total_hops": 7,
    "hop_hash": "e4f81c9b",
    "last_mile_hops": [
      {
        "hop": 4,
        "ip": "4.68.70.12",
        "ptr": "ae1.ashburn.lumen.net",
        "asn": 3356,
        "rtt_ms": 11.20
      },
      {
        "hop": 5,
        "ip": "206.108.115.42",
        "ptr": "equinix-ashburn.cloudflare.com",
        "asn": 13335,
        "rtt_ms": 12.14
      },
      {
        "hop": 6,
        "ip": "172.68.12.1",
        "ptr": "edge-ashburn-01.cloudflare.com",
        "asn": 13335,
        "rtt_ms": 14.40
      },
      {
        "hop": 7,
        "ip": "198.51.100.80",
        "ptr": "api.citibank.com",
        "asn": 13335,
        "rtt_ms": 14.82
      }
    ]
  },
  "tls_fingerprint": {
    "version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "thumbprint_sha256": "3a8f1b2c...",
    "issuer_dn": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1, O=DigiCert Inc",
    "days_until_expiration": 234,
    "ocsp_stapled": true,
    "ocsp_status": "GOOD"
  }
}
```
