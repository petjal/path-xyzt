# path-xyzt: External High-Value-Target (HVT) Forensic Telemetry Architecture

**Author**: Pete Jalajas (`pjalajas@gmail.com`)  
**Repository**: `/home/petjal/dev/path-xyzt`  
**Date**: 2026-09-09  
**Target Scope**: External High-Value-Target (HVT) Public Infrastructure (`api.citibank.com`, `fidelity.com`, `coinbase.com`, major enterprise APIs)  

---

## 1. The Core Mandate: Outside-In Observability of High-Value Targets

`path-xyzt` is strictly an **outside-in forensic probe** monitoring external high-value public endpoints. It operates from distributed observer vantages to measure, fingerprint, and detect mutations in the target's public-facing infrastructure.

```
+-----------------------------------------------------------------------------------+
|                            HIGH-VALUE-TARGET (HVT)                                |
|                   (e.g., api.citibank.com, fidelity.com, aws.amazon.com)          |
+-----------------------------------------------------------------------------------+
       ^                               ^                              ^
       | BGP AS Path                   | TLS Handshake                | TCP/HTTP Fingerprint
       | HopHash & Latency             | Cert Thumbprint              | Remote OS, Skew & Blades
       |                               |                              |
+-----------------------------------------------------------------------------------+
|                                  PATH-XYZT                                        |
|                          EXTERNAL OBSERVATION SWARM                               |
|       - Vantage A (US-East)   - Vantage B (EU-West)   - Vantage C (APAC)          |
+-----------------------------------------------------------------------------------+
```

---

## 2. Telemetry Collected on High-Value Target Endpoints

### 2.1 Remote Network Trajectory & Minkowski Space ($X, Y, Z, T$)
* **BGP Transit Route Integrity**: Maps the exact sequence of Autonomous Systems (ASNs) carrying traffic into the HVT. Detects BGP route leaks and unauthorized sovereign transit detours (e.g. US banking traffic suddenly hopping through Russian or Chinese state telecoms).
* **Multi-Vantage DNS Disaggregation**: Queries authoritative nameservers from multiple global vantage points concurrently. Detects Anycast split-brain tampering, cache poisoning, and DNSSEC RRSIG anomalies.
* **Deterministic `HopHash`**: Computes an 8-character SHA-256 fingerprint over the intermediate IP hops and BGP ASNs leading directly to the target.

### 2.2 Remote Target Stack & Host Cluster Fingerprinting
* **Remote OS TCP/IP Fingerprinting (SYN-ACK Profiling)**:
  * Analyzes the HVT's response TCP SYN-ACK packet:
    * Initial TTL (64 = Linux/Unix, 128 = Windows Server, 255 = Cisco/Juniper core router).
    * TCP Window Size & Scale Factor.
    * TCP Option Ordering (MSS, SACK-Permitted, Timestamp, NOP, Window Scale).
  * Alerts when an endpoint claiming to be Linux suddenly returns Windows TCP stack semantics (or vice-versa), indicating reverse-proxy interception or SSL termination tampering.
* **Target Load-Balancer & Blade Cluster Mapping**:
  * Financial institutions distribute traffic across clusters of physical server blades behind hardware load-balancers (F5 BIG-IP, Citrix NetScaler, AWS ALB).
  * `path-xyzt` maps the backend blade pool via:
    1. **Reverse-Proxy Affinity Leakage**: Tracking load-balancer cookie mutations (`BIGipServer`, `AWSALB`, `X-Served-By`, `CF-RAY`).
    2. **Kohno Remote Clock-Skew Drift**: Measures the remote server's hardware crystal oscillator skew ($\Delta t / \Delta\text{clock}$) via TCP Timestamps (RFC 7323) or sub-millisecond HTTP Date header deltas to uniquely fingerprint individual physical blades inside the bank's server farm.
    3. **IPv6 EUI-64 MAC Recovery**: When target endpoints advertise public IPv6 addresses, checks for embedded 48-bit physical NIC MACs in the interface identifier.
* **TLS 1.3 Cryptographic Chain-of-Custody**:
  * Captures negotiated cipher suite, supported groups, and calculates the SHA-256 thumbprint of the target's leaf certificate.
  * Detects when different edge nodes serve different certificates for the same domain.

---

## 3. The Radial Coordinate Space for High-Value Targets

Instead of placing target endpoints on arbitrary Cartesian axes:

$$E_{\text{target}} = (T, r, \theta, \phi)$$

1. **Radius ($r$) - The Latency Perimeter**:
   * Measures the Round-Trip Time ($\text{ms}$) from the vantage point to the target.
   * If physical distance is static, $r$ should remain within a tight statistical band ($\pm 5\%$).
   * A sudden jump in $r$ (e.g. from $18\text{ms}$ to $75\text{ms}$) without a local network issue mathematically proves traffic is detouring through an intermediate inspection middlebox or unannounced BGP transit.
2. **Azimuth ($\theta$) - BGP Topological Quadrant**:
   * Encodes the origin and upstream peer ASNs of the target.
3. **Elevation ($\phi$) - Geographic Anycast Bearing**:
   * Encodes the geographic CDN edge location currently terminating the connection.

### 3.1 Exponent-Collapse Compression of HVT Time-Series
Monitoring 10,000 enterprise endpoints every 60 seconds generates massive telemetry. Because an HVT's routing trajectory and latency radius are normally stable:
* Radial coordinates concentrate tightly around predictable values.
* Exponent collapse allows high-frequency latency and routing vectors to be compressed by **1.5x–4x** using standard entropy coding, enabling long-term archival without bloated database infrastructure.

---

## 4. 3-Tier Forensic Backoff for Enterprise Audits

1. **Hot Forensic Buffer (Days 0–14)**:
   * 100% granular packet captures, raw TCP SYN-ACK flags, full traceroute hop lists, complete TLS cert chains, and raw HTTP headers.
   * Instant evidence generation when an alert fires.
2. **Warm Trajectory Ledger (Days 15–90)**:
   * Pruned trajectory: `(T, r, theta, phi, HopHash, RemoteOS_Code, BladeID, CertThumbprint)`.
   * Sufficient for quarterly SOC 2 audit verification and SLA dispute resolution.
3. **Cold Timechain Commitment (Day 91 to $\infty$)**:
   * Flat, append-only immutable record: Timestamp + Target ID + 8-char Hash Commitment.
