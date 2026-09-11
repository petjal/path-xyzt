# path-xyzt: Local Engineering Architecture & Implementation Plan

**Author**: Pete Jalajas (`pjalajas@gmail.com`)  
**Repository**: `/home/petjal/dev/path-xyzt`  
**Date**: 2026-09-09  
**Status**: Architectural Blueprint (Phase 1 Local Implementation)  

---

## 1. Objective & Scope

To construct a standalone, zero-external-dependency Python 3 engineering package and CLI (`path-xyzt`) that monitors, measures, and cryptographically commits the **spatial network trajectory** of critical Internet endpoints (banking APIs, cloud backbones, fintech platforms, and exchange fabrics).

### Core Differentiators
1. **Polar / Radial Coordinate Space**: Replaces arbitrary Cartesian $(X, Y, Z)$ projections with an Observer-Centric Polar System $(T, r, \theta, \phi)$ where $r$ directly measures physical/synthetic latency (RTT), $\theta$ encodes topological ASN quadrants, and $\phi$ encodes Anycast geographic bearing.
2. **Layer 2 Boundary Verification**: Captures local gateway MAC addresses (`/proc/net/arp`) to guarantee the observation vantage itself has not been compromised by local ARP spoofing, rogue hypervisor vNICs, or evil-twin wireless bridges.
3. **Remote Server Blade Cluster Fingerprinting**: Uncovers the finite pool of backend physical/virtual blades behind enterprise load balancers via IPv6 EUI-64 MAC address leakage, UUIDv1 trace headers, and Kohno CPU crystal clock-skew drift ($\Delta t / \Delta\text{clock}$).
4. **3-Tier Exponential Retention Backoff**: Hot forensics (0–14d), Warm trajectory ledger (15–90d), and Cold immutable commitments (91d+) preventing storage rust while guaranteeing non-repudiation.

---

## 2. Mathematical Formalism: Polar Network Coordinates

### 2.1 Coordinate Mapping
Given an observer vantage point $V_0$ at latitude $\lambda_0$, longitude $\psi_0$, and local ASN $A_0$:
For any monitored destination endpoint $D$ observed at time $T$:

$$E = (T, r, \theta, \phi)$$

1. **$T$ (Time)**: UTC ISO-8601 string + Unix epoch millisecond timestamp.
2. **$r$ (Radial Latency)**: One-way synthetic network transit distance:
   $$r = \frac{\text{RTT}_{\text{TCP-SYN-ACK}}}{2} \quad (\text{milliseconds})$$
3. **$\theta$ (Topological ASN Bearing)**:
   Maps destination and transit Autonomous System Numbers to an angular quadrant $[0, 2\pi)$:
   $$\theta = 2\pi \cdot \left(\frac{\text{ASN}_{\text{origin}} \pmod{65536}}{65536}\right)$$
4. **$\phi$ (Anycast Geographic Elevation)**:
   Angular deviation from observer based on GeoIP/Anycast edge estimation $[-\pi/2, \pi/2]$:
   $$\phi = \arcsin\left(\sin \lambda_0 \sin \lambda_D + \cos \lambda_0 \cos \lambda_D \cos(\psi_D - \psi_0)\right)$$

### 2.2 Exponent-Collapse Entropy Compression
Because real-world network traffic to a stable destination clusters tightly in angle ($\theta, \phi$) around authoritative edge locations, the floating-point angle deltas exhibit extreme clustering around $\pi/2$ or zero. 

* **Mechanism**: Quantize angles into 16-bit fixed-point representation ($\Delta\theta = \frac{2\pi \cdot k}{65536}$).
* **Savings**: Transforms a multi-float Cartesian coordinate triplet $(12\text{ bytes})$ into a compact 4-byte packed tuple $(r_{\text{u16}}, \theta_{\text{u8}}, \phi_{\text{u8}})$, reducing raw telemetry wire storage by **66.7%** before entropy coding.

---

## 3. Directory Layout & Module Decomposition

```
/home/petjal/dev/path-xyzt/
├── SPECIFICATION.md              # Formal RFC-style technical specification
├── README.md                     # B2B executive portfolio overview
├── setup.py                      # Standard Python packaging (pip install -e .)
├── pathxyzt/
│   ├── __init__.py               # Package export & version string (0.1.0)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── coords.py             # Polar/radial transforms & exponent-collapse compression
│   │   └── models.py             # Dataclasses: Observation, Hop, ClusterProfile, Alert
│   ├── probe/
│   │   ├── __init__.py
│   │   ├── gateway.py            # Layer 2 Local Gateway MAC extraction (/proc/net/arp)
│   │   ├── dns_sentinel.py       # 3-Tier DNSSEC & Authoritative NS disaggregation
│   │   ├── traceroute.py         # ICMP/TCP SYN hop-by-hop tracer & HopHash generator
│   │   ├── tls_fingerprint.py    # TLS 1.3 handshake, cipher suite & cert thumbprint
│   │   └── blade_cluster.py      # EUI-64 MAC recovery, UUIDv1 & clock-skew heuristic
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── backoff.py            # Exponential decay engine (Hot -> Warm -> Cold)
│   │   └── ledger.py             # Append-only JSONL commitment journal
│   └── cli/
│       ├── __init__.py
│       └── main.py               # CLI subcommands: probe, audit, compress, daemon
└── tests/
    ├── __init__.py
    ├── test_coords.py            # Vector math, round-trip transforms & compression
    ├── test_gateway.py           # Parsing /proc/net/arp and mock gateway assertions
    ├── test_hophash.py           # Deterministic hop digest invariance
    ├── test_anomaly_detect.py    # Simulated BGP hijack, DNS spoof & blade mutation
    └── test_backoff.py           # Pruning schedule and cold commitment integrity
```

---

## 4. Phase-by-Phase Local Implementation Plan

### Phase 1: Core Mathematical Engine & Data Models (`pathxyzt/core/`)
* Implement `coords.py`:
  * `cartesian_to_polar(x, y, z) -> (r, theta, phi)`
  * `polar_to_cartesian(r, theta, phi) -> (x, y, z)`
  * `compress_trajectory(coords_list) -> bytes` (quantized bit-packing)
  * `decompress_trajectory(bytes_data) -> coords_list`
* Implement `models.py`:
  * Strongly-typed dataclasses with JSON serialization for `ObservationEvent`, `ProbeTarget`, and `RouteHop`.

### Phase 2: Probe & Telemetry Subsystems (`pathxyzt/probe/`)
* **Layer 2 Gateway (`gateway.py`)**:
  * Reads `/proc/net/arp` and `/sys/class/net/*/address` to determine local egress interface and default gateway MAC.
  * Guards against ARP poisoning by asserting MAC persistence across epochs.
* **BGP Trace & Hop-Hash (`traceroute.py`)**:
  * Executes non-privileged socket TTL stepping or parses system traceroute.
  * Resolves ASNs via local cymru DNS lookup or static routing cache.
  * Calculates canonical `HopHash` = $\text{SHA256}(\text{IP}_1 \parallel \text{ASN}_1 \dots)[..8]$.
* **TLS 1.3 Fingerprint (`tls_fingerprint.py`)**:
  * Connects over TLS 1.3 using Python standard library `ssl`.
  * Extracts peer certificate DER bytes, computes SHA-256 thumbprint, extracts SANs and issuer DN.
* **Server Blade Cluster Profiler (`blade_cluster.py`)**:
  * Checks for IPv6 addresses with bit 7 flipped and `FF:FE` in the middle (EUI-64 MAC recovery).
  * Extracts UUIDv1 from HTTP response headers (`X-Request-Id`, `Traceparent`) to recover target NIC MAC.
  * Calculates clock-skew delta against NTP reference time.

### Phase 3: Exponential Backoff & Ledger Journal (`pathxyzt/storage/`)
* Implement `ledger.py`:
  * Append-only atomic writes to `data/hot_buffer.jsonl`.
* Implement `backoff.py`:
  * Pruning routine that transitions records $> 14\text{ days}$ into `data/warm_ledger.jsonl` (collapsing hop details into `HopHash` + ASN path).
  * Routine that transitions records $> 90\text{ days}$ into `data/cold_timechain.jsonl` (minimal 10-byte commitment).

### Phase 4: CLI Interface & Test Suites (`pathxyzt/cli/` & `tests/`)
* Implement CLI subcommands:
  * `path-xyzt probe <domain/ip>`: Single-shot observation emitting full $XYZT$ polar record.
  * `path-xyzt monitor <domain/ip> --interval 60`: Continuous monitoring loop with alert triggers.
  * `path-xyzt compress <file>`: Benchmarks coordinate compression ratios.
* Run automated test suite:
  * 100% passing tests across vector math, ARP parsing, hop-hashing, and anomaly detection.

---

## 5. Verification & Assertions

1. **Pure Standard Library**: Zero mandatory third-party pip dependencies for core operations (runs natively on standard Linux Python 3.8+).
2. **Deterministic Hashing**: `HopHash` and `CertThumbprint` must produce identical output across different CPU architectures.
3. **No Network Root Requirement**: Core probes must operate with standard user privileges (TCP connect probes, `/proc/net/arp` reads).
