# path-xyzt: Project Foundation, Architecture & Value Recap

## 1. What Have We Got Here?
**`path-xyzt`** is an unopinionated, outside-in network telemetry and perimeter integrity data feed designed specifically for High-Value-Target (HVT) public endpoints (commercial banks, digital asset exchanges and custody platforms, clearing houses, critical API gateways).

Instead of building a heavyweight web application with complex dashboard layers, `path-xyzt` delivers a **structured, high-fidelity atomic telemetry stream** designed for direct ingestion into standard SIEMs and data lakes (Splunk, Datadog, Snowflake, ClickHouse).

---

## 2. Core Architectural Decisions Made & Validated

### A. OpSec & Identity Isolation
- **Engineering Focus**: High-assurance outside-in telemetry and enterprise systems architecture.
- **Enterprise Track**: `path-xyzt` lives transparently under Pete's professional GitHub identity:
  - Repository: `git@github.com:petjal/path-xyzt.git`
  - Author: `Pete Jalajas <pjalajas@gmail.com>`
  - Commits signed with GPG key: `474FEEF93A03F2DC623FD664E0E1BC3DA4E43BDB`

### B. Math & Data Model: Dropping Polar Coordinates
- **Decision**: Dropped abstract spherical coordinates $(r, \theta, \phi)$ to eliminate enterprise cognitive friction and artificial modulo mapping artifacts.
- **Model**: Replaced with **pure, orthogonal network primitives**:
  1. `latency_breakdown_ms`: DNS resolution, TCP SYN-ACK RTT, TLS handshake overhead.
  2. `routing_provenance`: BGP origin AS, prefix, RPKI validation state.
  3. `last_mile_signature`: Deep last 4 hops, peering router IPs, and `HopHash`.
  4. `impending_expiration_sentinel`: RDAP domain expiration, DNSSEC RRSIG rolling countdown, TLS leaf cert validity, and EPP lock status.
  5. `transport_security`: TLS version, cipher suite, and ALPN.

### C. The 3-Hour Cadence ("The Third Point Harmonic")
- **Mathematical Minimum**: Two samples in a workday only define a straight line ($y = mx + b$). Three samples are required to determine **curvature, acceleration, and peak diurnal congestion** ($y = ax^2 + bx + c$).
- **Cadence**: Every 3 hours (8 samples/day) with $\pm 10$ minutes of jitter:
  - Captures market open, midday transatlantic peak, and market close.
  - Aligns with 6-hour and 12-hour DNSSEC/OCSP maintenance windows.
  - Total daily bandwidth: $< 80\text{ KB/target/day}$ (completely polite and invisible).

### D. Probe Protocol Identification
- **RFC 9110 Compliance**: Avoids consumer browser mimicry that triggers automated abuse blacklisting.
- **Explicit Operator Attribution**:
  - RFC 9110 User-Agent: `User-Agent: path-xyzt/0.2.0 (+https://github.com/petjal/path-xyzt; contact: pjalajas@gmail.com)`
  - Transparent edge logs allow target network operators to inspect the public project repository and measurement methodology directly.

### E. Telemetry Variance Taxonomy
Categorized every probe metric into 4 statistical classes for zero-alarm customer ingestion:
1. **Class 1: Static Invariants** ($\Delta = 0$, e.g. AS number, cert SHA256, EPP locks).
2. **Class 2: Monotonic Decays** ($\frac{de}{dt} = -1.0$, e.g. domain, DNSSEC, cert expirations).
3. **Class 3: Bounded Oscillators** ($e \sim \mathcal{N}(\mu, \sigma^2)$, e.g. TCP RTT, TLS negotiation).
4. **Class 4: Discrete Sets** (multi-modal states, e.g. ECMP load-balanced `HopHash` toggling).

---

## 3. Current Live Artifacts & Code State

1. **Working Strawman Telemetry Engine**:
   - `/home/petjal/dev/path-xyzt/scripts/strawman_collector.py`
   - Fully functional, zero-root dependencies (`mtr`, `dig`, Python standard library).
2. **Live Probe Output Verified**:
   - `file:///dev/shm/coinbase_strawman_v2.json` (`api.coinbase.com`)
   - `file:///dev/shm/citibank_strawman.json` (`www.citibank.com`)
3. **Compiled Specifications in `/dev/shm/`**:
   - Full-Stack Hijack Surface: `file:///dev/shm/path_xyzt_full_stack_hijack_surface.html`
   - Core Model & Primitive Redesign: `file:///dev/shm/path_xyzt_core_model_evaluation.html`
   - Pre-DDoS Recon Detection: `file:///dev/shm/path_xyzt_pre_ddos_recon_detection.html`
   - Telemetry Variance Taxonomy: `file:///dev/shm/path_xyzt_telemetry_variance_taxonomy.html`
   - Empirical Variance Discovery: `file:///dev/shm/path_xyzt_empirical_variance_discovery.html`
   - 3-Hour Cadence & Sampling Math: `file:///dev/shm/path_xyzt_sampling_rate_math.html`
   - Probe Identity & Banner Strategy: `file:///dev/shm/path_xyzt_probe_identity_strategy.html`
   - Market Landscape & Value Thesis: `file:///dev/shm/path_xyzt_market_landscape_and_value_thesis.html`

