# path-xyzt: Detecting Pre-DDoS Reconnaissance & Rehearsal from Outside-In

## 1. The Core Question
Can an outside-in, probe-based telemetry service (`path-xyzt`) detect an adversary **planning or practicing a DDoS attack** before the full flood hits?

---

## 2. Attacker Pre-DDoS Behavior: What Adversaries Actually Do
Sophisticated threat actors (nation-states, extortion cartels like Fancy Lazarus / REvil, or botnet operators) do not launch multi-terabit floods blind. They rehearse and reconnoiter:

1. **Pulse "Test-Fires" (Pulse Waves)**:
   - **Tactic**: Short, sharp bursts lasting 15 to 45 seconds at low/moderate volume (10–50 Gbps).
   - **Purpose**: Measure target scrubber mitigation threshold: Does Cloudflare/Akamai/Imperva auto-engage? How long is the mitigation spin-up latency (usually 30–90 seconds)? If the burst stops in 30 seconds, mitigation never triggers, but the attacker maps the backend headroom.
   - **Observable Telemetry**: Periodic micro-cliffs in TCP SYN-ACK latency ($r_{jitter}$) occurring every few hours at regular intervals without full connection drops.

2. **Scrubber Capacity & Origin Uncloaking Probes**:
   - **Tactic**: Attacker tests different ingress points or sends anomalous TCP options / non-standard MTUs to see which border scrubbing centers drop packets vs pass through to origin.
   - **Purpose**: Find origin IPs that bypass CDN protection (e.g. MX records, direct API endpoints, legacy subdomains).
   - **Observable Telemetry**: Peering ingress router shifts in the last-mile traceroute; transient TCP handshake failures on auxiliary endpoints while apex remains up.

3. **Amplification Factor Rehearsal (Reflector Scanning)**:
   - **Tactic**: Attacker probes authoritative nameservers, NTP pools, or memcached servers using spoofed target IP addresses to test reflection amplification ratios (e.g., DNS ANY queries returning 4,000-byte responses for 50-byte queries).
   - **Observable Telemetry**: Authoritative DNS response latency elongation; DNS timeouts from specific global resolver vantages.

4. **BGP Route Flapping & Sub-Prefix Probing**:
   - **Tactic**: Attacker checks if the target has automatic BGP Flowspec or BGP diversion to on-demand scrubbing centers (e.g., Radware, Neustar, Arbor).
   - **Purpose**: Intentionally trigger route flapping to see which T1 transit providers withdraw prefixes.
   - **Observable Telemetry**: Rapid churn in Cymru BGP prefix announcements or sudden appearances of specific `/24` sub-prefixes.

5. **State-Exhaustion Micro-Probes (Slowloris / TLS Handshake Stress)**:
   - **Tactic**: Opening low-rate TLS handshakes without completing them, or negotiating expensive cipher suites (e.g., DHE with 4096-bit keys) to measure CPU degradation on edge SSL terminators.
   - **Observable Telemetry**: Asymmetric stretch in `tls_handshake_ms` while raw `tcp_synack_rtt_ms` remains completely normal (indicating compute exhaustion on the TLS terminator rather than network bandwidth congestion).

---

## 3. The path-xyzt Pre-DDoS Diagnostic Matrix

| Pre-DDoS Rehearsal Signal | Indicator in path-xyzt Telemetry | Physical Interpretation |
|---|---|---|
| **Pulse Test-Fires** | Periodic 30s spikes in `tcp_synack_rtt_ms` ($>3\sigma$) every $N$ hours | Botnet dialing in mitigation reaction thresholds |
| **Edge Compute Exhaustion** | Ratio $\frac{\text{tls\_handshake\_ms}}{\text{tcp\_synack\_rtt\_ms}} > 4.0$ | TLS termination layer under state/CPU attack while transit is clear |
| **DNS Reflector Warming** | Authoritative `dns_resolution_ms` drift + packet drop | Authoritative NS under reflective query load |
| **Mitigation Trigger Drift** | `hophash` and `peering_ingress_ip` shifting to scrubbing centers | Target or ISP testing GRE tunnel rerouting to scrubbing centers |
| **MTU / Fragmentation Probing** | Dropped traceroute hops at specific packet sizes | Attacker mapping ICMP/UDP fragmentation behavior |

---

## 4. Why This is High-Value for High-Value Targets (HVTs)
- **Advance Warning**: Major financial institutions and crypto exchanges get targeted by extortionists who say: *"We will take you down at 14:00 UTC unless you pay."* Often, the extortionist runs a 2-minute test attack at 10:00 UTC to prove capability.
- **Differentiating Pre-Attack from ISP Glitch**:
  - A real ISP glitch causes transit hop drops across multiple hops.
  - A pre-DDoS rehearsal exhibits **target-specific asymmetry** (e.g., normal L3 transit, but anomalous L7 TLS negotiation delays or edge ingress queuing).

