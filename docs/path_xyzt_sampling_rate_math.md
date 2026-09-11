# path-xyzt: 3-Hour Cadence & The Mathematics of the "Third Point"

## 1. The Core Geometric Question
> *"If we do 3 hours we kind of guarantee 2 sample points per workday? Fair? Do we need 3 such samples to break the 2-point straight-line?"*

**Yes. Exactly.**
In mathematics, signal processing, and time-series analysis:
1. **Two points only define a straight line** ($y = mx + b$). Two points cannot detect curvature, acceleration, peaks, troughs, or diurnal inflection points.
2. **Three points are the fundamental mathematical minimum** required to:
   - Fit a parabola / second-order polynomial ($y = ax^2 + bx + c$).
   - Determine **curvature (convexity vs concavity)**: Is network congestion accelerating or decelerating?
   - Detect an **inflection / peak**: Did latency crest at midday and recover, or did it blow out?
   - Disprove a linear assumption: If $y_2 \neq \frac{y_1 + y_3}{2}$, the system is non-linear.

---

## 2. What a 3-Hour Cadence Yields in an 8–9 Hour Workday
A standard enterprise workday spans roughly 9 hours (e.g. 08:30 to 17:30):

```
       08:30 (Morning Open)             13:00 (Midday Lunch)            17:30 (Market Close)
                 |                                |                               |
                 v                                v                               v
Workday: [==== POINT 1 ======================== POINT 2 ======================= POINT 3 ====]
             (Hour ~8:30)                    (Hour ~11:30 / 12:30)           (Hour ~15:30 / 16:30)
```

With a **3-hour interval**, you don't just get 2 points—**you actually get 3 full sample points within the workday window**:
- **Sample 1 (Morning Opening Bell, ~08:30–09:00)**: Captures market-open packet surge, login traffic, and morning baseline.
- **Sample 2 (Midday Apex, ~11:30–12:30)**: Captures peak diurnal congestion and transatlantic peak volume (US East Coast + London trading overlap).
- **Sample 3 (Market Close / Afternoon Wind-Down, ~14:30–15:30)**: Captures end-of-day settlement and traffic subsiding.

---

## 3. The 3-Hour Global Distribution (8 Samples per 24 Hours)

Across a full 24-hour cycle, a 3-hour cadence provides **8 samples per day**:
1. `00:00 UTC` - Asia-Pacific afternoon trading
2. `03:00 UTC` - Asia-Pacific close / European pre-market
3. `06:00 UTC` - European morning
4. `09:00 UTC` - London morning peak
5. `12:00 UTC` - US East Coast market open / Transatlantic peak
6. `15:00 UTC` - US market afternoon peak
7. `18:00 UTC` - US East Coast wind-down / West Coast business hours
8. `21:00 UTC` - Global liquidity lull / night batch processing

### Is 8 Probes per Day "Fair" and Polite?
- **Total daily probe time**: $8 \text{ probes} \times 0.5 \text{ seconds} = 4.0 \text{ seconds}$ of connection time **per day**.
- **Total daily bandwidth**: $8 \text{ probes} \times \approx 10\text{ KB} = 80\text{ KB}$ **per day**.
- To an enterprise endpoint handling millions of requests per second, 8 probes a day is functionally invisible and well below any polite rate limit.

---

## 4. Why Breaking the 2-Point Line is Critical for Telemetry
- If you only sample at **09:00** and **17:00**:
  - If both read $18\text{ ms}$, you assume the entire day was flat and stable at $18\text{ ms}$.
  - You completely miss the fact that from 11:00 to 14:00, latency spiked to $65\text{ ms}$ due to an ISP peering saturate.
- With **Point 2 at 12:00**:
  - You immediately see the arch: $18\text{ ms} \to 65\text{ ms} \to 18\text{ ms}$.
  - The parabolic curve $a < 0$ proves diurnal queuing without ambiguity.

---

## 5. Conclusion: 3 Hours is the Sweet Spot
- **3 Hours (8 samples/day)**:
  - Guarantees **3 points across every standard workday**.
  - Breaks the straight-line ambiguity (proves curvature/peak).
  - Perfectly aligns with 3-hour sub-harmonics of 6-hour and 12-hour maintenance windows (DNSSEC, OCSP, BGP route flaps).
  - Completely polite ($< 100\text{ KB/day}$).

