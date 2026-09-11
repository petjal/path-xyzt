# path-xyzt: Empirical Variance Discovery & Emergent Class Inference

## 1. The Core Insight: Empirical Learning over Static Dogma
You cannot know a priori all operational behaviors across diverse global targets:
- An Anycast target like Cloudflare (`api.coinbase.com`) behaves very differently from an enterprise mainframe or private cloud VIP (`www.citibank.com`).
- A field that looks like a static invariant in theory might fluctuate dynamically in practice (e.g. DNS TTL or dynamic CDN edge IP rotation).
- A field that seems volatile might actually adhere to strict, quantized stepped modes.

Therefore, the engine must feature an **Empirical Variance Profiler**:
Rather than hardcoding field rules, the engine passively **observes the time-series behavior of each field** over $N$ epochs and automatically discovers its mathematical profile.

---

## 2. The Statistical Profiler Pipeline

For each element $e_i$ in the telemetry vector across a rolling window $T = [t_1, t_2, \dots, t_N]$:

```
Stream of Values e_i(t)
          |
          v
  [Cardinality & Type Check]
          |
          +---> Unique values == 1 over N epochs? 
          |         ===> Classifies as: CLASS 1 (STATIC INVARIANT)
          |
          +---> Monotonically decreasing with slope ~ -1.0/sec?
          |         ===> Classifies as: CLASS 2 (MONOTONIC DECAY)
          |
          +---> Continuous numeric, normal/skewed distribution, stationary mean?
          |         ===> Classifies as: CLASS 3 (BOUNDED OSCILLATOR)
          |              Auto-learns: mu, sigma, IQR, p95, p99
          |
          +---> Discrete values flipping among small finite set (|S| <= K)?
          |         ===> Classifies as: CLASS 4 (MULTI-MODAL DISCRETE SET)
          |              Auto-learns: Valid cluster set S_valid
          |
          +---> High entropy, unconstrained, or continuous drift?
                    ===> Classifies as: CLASS 5 (FREE UNBOUNDED / NON-STATIONARY)
                         Suppresses raw alerts, applies drift tracking
```

---

## 3. Real-World Emergent Discoveries We Will Encounter

### Discovery A: The "False Invariant" (ECMP Routing Flapping)
- **Theory**: We assumed `hophash` (last 4 hops) would stay constant until an ISP change.
- **Empirical Reality**: Many Tier 1 backbones (Comcast, Level 3, Telia) use Equal-Cost Multi-Path (ECMP) routing on flow hashes. Packet A hits router `172.68.52.21`; Packet B hits router `172.68.52.17`.
- **Discovery**: The engine observes that `hophash` doesn't change arbitrarily—it toggles between exactly 2 discrete hashes ($H_A, H_B$). The profiler automatically discovers that this element is not a broken invariant, but a **Bimodal Discrete Set (Class 4)**.

### Discovery B: The "Secret Maintenance Heartbeat" (Quantized Stepped Decays)
- **Theory**: DNSSEC RRSIG or OCSP responses decay smoothly to zero.
- **Empirical Reality**: Cloudflare or Akamai edge nodes re-sign or refresh OCSP on strict 6-hour or 12-hour cadence steps.
- **Discovery**: The engine sees a sawtooth waveform (sawtooth decay with periodic resets). The profiler learns the cadence ($\Delta t_{refresh} \approx 6\text{h}$) and can now alert if a refresh cycle is missed, **hours before the actual expiration occurs**.

### Discovery C: The "Diurnal Breathing Envelope" (Time-of-Day Oscillation)
- **Theory**: `tcp_synack_rtt_ms` has a fixed Gaussian mean $\mu$.
- **Empirical Reality**: Between 8:00 AM and 5:00 PM local time, congestion on residential/enterprise last-miles adds $+4\text{ms}$ of buffering latency. At night, latency drops.
- **Discovery**: The engine discovers diurnal periodicity ($24\text{h}$ sine envelope). Instead of alerting on $+4\text{ms}$ during peak business hours, it dynamically adjusts the $\mu(t)$ baseline.

---

## 4. The Self-Describing Data Bundle: `variance_profile`
When `path-xyzt` delivers raw data to the customer, it attaches the empirically discovered profile as an enriched descriptor:

```json
{
  "metric": "latency_breakdown_ms.tcp_synack_rtt_ms",
  "current_value": 18.2,
  "discovered_profile": {
    "class": "bounded_oscillator",
    "observation_epochs": 1440,
    "confidence_score": 0.994,
    "distribution": "stationary_gaussian",
    "learned_parameters": {
      "median_ms": 17.5,
      "iqr_ms": 1.4,
      "sigma_ms": 1.8,
      "p99_ms": 22.1
    },
    "status": "in_bounds",
    "z_score": 0.39
  }
}
```

## 5. Architectural Benefit: Zero Configuration for the Customer
- Customers do not have to write manual threshold configs for 50 different target endpoints.
- After a 24-hour observation burn-in, `path-xyzt` automatically stabilizes the sensitivity envelopes for each target.
- Alerts are generated strictly on **statistical phase transitions** (deviations from discovered empirical reality) rather than arbitrary guesses.

