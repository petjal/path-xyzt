# path-xyzt: Enterprise Network Spatial Observatory & Forensic Trajectory Service

**Author**: petjal  
**Date**: 2026-09-09  
**Status**: Architectural Decoupling & Product Specification  
**Decoupling Principle**: path-xyzt = Enterprise B2B Network Forensic Observability.

---

## 1. The Radial Coordinate Breakthrough (Cartesian vs. Polar)

### 1.1 The Mathematical Mechanism
Recent 2025–2026 research into coordinate transformations (e.g., PolarQuant, PCDVQ, and spherical embedding compression) demonstrated massive compression gains by converting high-dimensional Cartesian representations $(x_1, x_2, \dots, x_n)$ into spherical/polar coordinates $(r, \theta_1, \theta_2, \dots, \theta_{n-1})$:

1. **Exponent Collapse**: In high-dimensional normalized spaces, angular distributions concentrate heavily around $\pi/2$ (orthogonality concentration). This allows IEEE 754 floating-point exponent bits to collapse into a uniform value, enabling lossless entropy compression of up to 1.5x–4x.
2. **Decoupling Magnitude from Direction**:
   * **Radius ($r$)**: Represents scalar depth, RTT latency, or hierarchy level.
   * **Angles ($\theta, \phi$)**: Represent topological orientation, ASN clustering, and routing quadrant.
3. **Cartesian Inefficiency in Network Mapping**:
   * Cartesian $(X, Y, Z)$ treats arbitrary network hops as flat Euclidean points without geometric meaning.
   * Polar $(r, \theta, \phi)$ naturally anchors to the **Observer Vantage**:
     * $r$: Measured network latency (Round-Trip Time in milliseconds or BGP AS-hop count).
     * $\theta$: Geographic and ASN cluster bearing (Americas, EMEA, APAC, Tor/I2P).
     * $\phi$: Ingress/Egress peering path orientation.

---

## 2. Technical Decoupling: Binary Artifact Verification vs. Active Path Telemetry

```
+-----------------------------------------------------------------------------+
|                      BINARY ARTIFACT INTEGRITY VERIFICATION                 |
|  - Role: Stateless cryptographic binary and release signature auditor       |
|  - Scope: SHA-256 digests, GPG / BIP-340 signatures, release manifest seals |
|  - Ingestion: Static append-only JSON, distributed immutable digests        |
+-----------------------------------------------------------------------------+
                                       |
                                (Clean Decoupling)
                                       v
+-----------------------------------------------------------------------------+
|                     PATH-XYZT ACTIVE NETWORK TELEMETRY                      |
|  - Role: Outside-in perimeter observatory & network trajectory sentinel     |
|  - Scope: BGP AS paths, multi-vantage DNSSEC, hop-hashes, radial latencies  |
|  - Forensics: Target endpoint MAC clustering, clock-skew, Anycast routing   |
|  - Storage: Unopinionated atomic NDJSON / Parquet records for SIEM analysis |
+-----------------------------------------------------------------------------+
```

---

## 3. path-xyzt Architecture

### 3.1 Network Minkowski Coordinates in Polar Notation
Every network observation event $E$ is committed as:
$$E = (T, r, \theta, \phi, \text{HopHash}, \text{CertThumbprint}, \text{MacGW})$$

* **$T$ (Temporal)**: UTC ISO-8601 timestamp + epoch millisecond anchor.
* **$r$ (Radial Latency)**: True synthetic RTT distance from observer vantage ($r = \text{RTT}_{\text{TCP-SYN-ACK}} / 2$).
* **$(\theta, \phi)$ (Directional Vector)**:
  * $\theta$: Autonomous System Number (ASN) topological quadrant.
  * $\phi$: Anycast edge egress geographic angle.
* **$\text{HopHash}$**: Deterministic SHA-256 digest of intermediate BGP/ICMP traceroute hop IPs:
  $$\text{HopHash} = \text{SHA256}(\text{IP}_1 \parallel \text{ASN}_1 \parallel \text{IP}_2 \parallel \dots \parallel \text{IP}_k)[..8]$$
* **$\text{CertThumbprint}$**: SHA-256 of server TLS 1.3 certificate.
* **$\text{MacGW}$**: Local Layer 2 Gateway MAC address (detects local evil-twin / ARP spoofing).

### 3.2 Key Enterprise Use Cases for path-xyzt
1. **BGP Route Hijack & Leak Detection**: Instant alerting when an institutional banking or exchange API endpoint hops through an unauthorized transit provider (e.g. state telecom transit detours intercepting traffic before re-routing).
2. **Anycast Split-Brain Sentinel**: Alerts when CDN edge nodes in different continents serve different payloads or TLS certificates for the same host.
3. **Endpoint Host Blade Rotation**: Detects when server clusters behind financial institutions (e.g., Citibank, Coinbase) unexpectedly swap physical/virtual blades using IPv6 EUI-64 MAC leakage and Kohno crystal clock-skew drift.
4. **SOC 2 Network Provenance Auditing**: Provides monthly cryptographic proof to institutional risk officers that their API traffic traversed authorized, cryptographically verified paths.

---

