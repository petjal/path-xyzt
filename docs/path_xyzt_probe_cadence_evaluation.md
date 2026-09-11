# path-xyzt: Probe Sampling Cadence & Scheduling Evaluation

## 1. The Core Stance: Raw Data First, Analysis Second
As established: **Avoid opinionated dashboard bloat.**
- We do NOT build opinionated analytics engines or complex statistical UIs on day 1.
- Our primary job is **unimpeachable, high-fidelity data capture and lossless persistence**.
- Customers (or downstream analysis jobs) ingest the raw time-series records and apply whatever math they want.

The immediate question: **What is a reasonable, fair, and high-signal starting probe frequency?**

---

## 2. Analyzing Potential Cadence Strategies

### Strategy A: 8-Hour Fixed Cadence (Every 8 Hours, e.g., 00:00, 08:00, 16:00 UTC)
- **Pros**:
  - Very lightweight: Only 3 probes/day per target.
  - Zero risk of triggering rate limits or IDS/WAF blocks.
  - Low storage footprint (approx. 9 KB / day / target in raw JSON).
- **Flaws**:
  - **Aliasing / Strobe Effect**: Sampling every 8 hours hits the *exact same three times of day* forever. You completely miss intermediate peak vs trough diurnal patterns (e.g. market open at 09:30 EST vs lunch lull vs market close at 16:00 EST).
  - **DNSSEC / OCSP Blindspots**: DNSSEC signatures and OCSP stapling often refresh on 6-hour windows. An 8-hour cadence creates a 16-hour blind window if a single sample fails.

---

### Strategy B: Harmonic Prime Offset (Every 3 or 4 Hours with Jitter)
- **Concept**: Probe every **4 hours with $\pm 15$ minutes of cryptographic jitter** (6 probes/day).
- **Pros**:
  - 6 samples per 24 hours covers every operational regime:
    - 00:00 UTC (Asia peak / US overnight)
    - 04:00 UTC (European morning ramp)
    - 08:00 UTC (London trading open)
    - 12:00 UTC (US East Coast pre-market / London overlap)
    - 16:00 UTC (US market close / West Coast peak)
    - 20:00 UTC (US evening transition)
  - Jitter prevents "thundering herd" synchrony and prevents remote WAFs from identifying rigid automated bot cron intervals.
  - Generates 6 records/day per target $\approx 18\text{ KB/day}$. Perfectly captures the diurnal curve without bloat.

---

### Strategy C: Golden Ratio / Rotating Phase Cadence (Every 5 or 7 Hours)
- **Concept**: Probe every **7 hours** (coprime with 24 hours).
- **Pros**:
  - The sample times automatically precess across the 24-hour clock day by day!
    - Day 1: 00:00, 07:00, 14:00, 21:00
    - Day 2: 04:00, 11:00, 18:00, 01:00
    - Day 3: 08:00, 15:00, 22:00, 05:00
  - Over a 7-day week, this samples every single hour of the day uniformly.
- **Flaws**:
  - Harder for human SREs to reason about ("Why didn't you probe at 08:00 today like yesterday?").

---

## 3. The "Fair & Courteous" Vantage Rule
When probing public enterprise infrastructure from the outside:
1. **Never look like a DoS or scraper**:
   - 1 single TCP connection + 1 single TLS handshake + 1 single MTR trace takes $< 500\text{ ms}$ and $< 10\text{ KB}$ of bandwidth.
   - Probing once every **4 hours** represents an imperceptible drop in the bucket (0.000001% of edge traffic).
2. **Always include a descriptive, courteous User-Agent**:
   - `User-Agent: path-xyzt/0.2.0 (outside-in network telemetry probe; contact: admin@xyzt.network)`
3. **Randomized Inter-Probe Jitter**:
   - Base interval: $T = 4\text{ hours} = 14,400\text{ seconds}$.
   - Add pseudo-random jitter: $\delta \sim \mathcal{U}(-900, +900)\text{ seconds}$ ($\pm 15\text{ minutes}$).

---

## 4. Recommended Starting Setup
- **Frequency**: **Every 4 Hours** (6 samples / day) + **$\pm 15$ min Jitter**.
- **Coverage**:
  - Fully samples the diurnal business day vs night cycle.
  - Reliably captures 6-hour and 12-hour DNSSEC / OCSP renewal steps.
  - Tracks RDAP domain expiration and TLS cert decay with high temporal resolution.
  - Ultra-lightweight: 6 records $\times$ 3 KB $\approx 18$ KB per target per day.

