# path-xyzt: Telemetry Constellation & Variance Sensitivity Taxonomy

## 1. Concept: The Temporal Telemetry Vector / Array
At any sample epoch $t_k$, the HVT endpoint state is captured as an unopinionated vector of dimension $D$:
$$V(t_k) = [e_1(t_k), e_2(t_k), \dots, e_D(t_k)]$$

When sampled continuously over time ($t_0, t_1, t_2, \dots$):
- Most elements are strictly identical across consecutive epochs.
- A subset of elements drift within predictable, stationary bounds (bounded jitter).
- A critical subset exhibit monotonic decays (countdowns).
- A final class of elements are volatile or unconstrained (free-floating).

Effective analysis requires categorizing every element into its **Intrinsic Variance Class** so anomaly detection and compression algorithms apply the correct mathematical sensitivity.

---

## 2. The Four Variance Classes of Telemetry Elements

```
+-----------------------------------------------------------------------------+
|                        TELEMETRY CONSTELLATION ARRAY                        |
+-----------------------------------------------------------------------------+
| Class 1: INVARIANTS           | Zero-drift baseline. Any mutation is an     |
| (Static / Cryptographic)      | immediate event or critical alert.          |
|-------------------------------+---------------------------------------------|
| Class 2: MONOTONIC DECAYS     | Predictable linear erosion toward a cliff.  |
| (Expiration Sentinels)        | Deterministic, strictly decreasing.         |
|-------------------------------+---------------------------------------------|
| Class 3: BOUNDED OSCILLATORS  | Stationary distributions (Gaussian/Poisson).|
| (Physical / Network Jitter)   | Mean-reverting within standard deviations.  |
|-------------------------------+---------------------------------------------|
| Class 4: DISCRETE STRUCTURAL  | Unbounded or set-membership shifts.         |
| (Topology / BGP / Routing)    | Multi-modal state transitions.              |
+-----------------------------------------------------------------------------+
```

---

### Class 1: Invariants (Static / Cryptographic Proofs)
- **Expected Behavior**: $\Delta e_i = 0$ for weeks, months, or years.
- **Elements**:
  - `origin_asn` (e.g. `AS13335`)
  - `leaf_cert.sha256_fingerprint`
  - `domain_rdap.registrar`
  - `domain_rdap.epp_statuses` (e.g. `clientTransferProhibited`)
  - `dnssec_enabled` (boolean)
  - `tls_version` / `cipher_suite`
- **Analytical Sensitivity**: **Zero-Tolerance / Exact Match ($\Delta = 0$)**.
  - Any single-bit divergence triggers an immediate state transition event.
  - Storage/Wire: Exponent/run-length compression reduces this to near-zero bytes unless modified.

---

### Class 2: Monotonic Decays (Expiration Sentinels)
- **Expected Behavior**: $e_i(t_k) = e_i(t_0) - (t_k - t_0)$.
- **Elements**:
  - `domain_rdap.days_until_expiration` (years $\to$ 0)
  - `tls_leaf.days_until_expiration` (90 days $\to$ 0)
  - `dnssec_rrsig.hours_until_expiration` (48 hours $\to$ 0)
  - `ocsp.next_update_hours` (24 hours $\to$ 0)
- **Analytical Sensitivity**: **Derivative Audit & Cliff Proximity**.
  - Normal rate of change: $\frac{de_i}{dt} = -1.0$.
  - **Anomaly Type A (Renewal)**: Sudden step-function jump upward (e.g., cert renewed from 3 days to 90 days). Benign event.
  - **Anomaly Type B (Stall / Missed Renewal)**: Value breaches critical policy thresholds ($\tau_{warn}, \tau_{crit}$).
    - e.g., DNSSEC RRSIG $< 6\text{ hours}$ without renewal $\implies$ imminent global outage.

---

### Class 3: Bounded Oscillators (Physical & Processing Latency)
- **Expected Behavior**: Continuous real-valued variables exhibiting stationary or pseudo-stationary noise centered around a physical median:
  $$e_i(t) \sim \mathcal{N}(\mu, \sigma^2) \quad \text{or Heavy-Tailed Weibull}$$
- **Elements**:
  - `tcp_synack_rtt_ms` (e.g. $17.2\text{ ms} \pm 1.8\text{ ms}$)
  - `tls_handshake_ms` (e.g. $23.5\text{ ms} \pm 3.2\text{ ms}$)
  - `dns_resolution_ms` (e.g. $2.1\text{ ms} \pm 0.9\text{ ms}$)
- **Analytical Sensitivity**: **Statistical Process Control ($Z$-score / IQR Filtering)**.
  - Fluctuations within $[-3\sigma, +3\sigma]$ are suppressed as baseline noise.
  - A step-function shift in the rolling median ($\Delta \mu > 20\%$) indicates a physical reroute or fiber tap.
  - An asymmetric expansion in variance ($\sigma \to 5\sigma$) indicates line congestion or pre-DDoS state exhaustion.

---

### Class 4: Discrete Structural Mutators (Topology & Routing States)
- **Expected Behavior**: Discrete tokens or graphs that transition between finite sets of valid operational modes (multi-modal).
- **Elements**:
  - `last_mile_signature.hophash` (e.g., toggling between 2 valid ISP peering routers depending on ECMP load balancing).
  - `resolved_ip` (rotating through a pool of Anycast edge VIPs).
  - `bgp_prefix` (e.g., `/20` aggregating to `/24`).
- **Analytical Sensitivity**: **Set-Membership & State-Transition Graphs**.
  - Maintain a bounded historical set of known valid signatures: $\mathcal{S}_{valid} = \{H_1, H_2, H_3\}$.
  - If a new hash $H_{new} \notin \mathcal{S}_{valid}$ appears, flag as a route mutation.
  - Track transition frequency: rapid flapping between known states indicates route instability.

---

## 3. The Analysis Engine: Multi-Rate Sensitivity Filter

By applying these 4 variance classes, the ingestion pipeline avoids the classic "alert fatigue" problem:

```
Raw Telemetry Array V(t)
       |
       +---> [Class 1: Invariant Check] ----> Bitwise Diff == 0 ? PASS : CRITICAL_ALERT
       |
       +---> [Class 2: Sentinel Decay]  ----> Cliff Proximity < Threshold ? WARNING : PASS
       |
       +---> [Class 3: Bounded Jitter]  ----> |v - mu| / sigma > 3.0 ? ANOMALY : PASS
       |
       +---> [Class 4: Discrete State]  ----> v in S_known ? PASS : NEW_PEERING_EVENT
```

## 4. Customer Ingestion Alignment (SIEM-Native Model)
- **Raw Export**: The unopinionated NDJSON stream exports the raw array with zero loss.
- **Enriched Metadata**: Each element is tagged with its class (`invariant`, `decay`, `oscillator`, `discrete`).
- **Customer Benefit**: The customer's SIEM can apply standard mathematical functions directly:
  - Splunk / Datadog: `stddev(tcp_synack_rtt_ms)` on Class 3.
  - Threshold alert: `tls_leaf.days_remaining < 14` on Class 2.
  - Exact match rule: `origin_asn != previous(origin_asn)` on Class 1.
