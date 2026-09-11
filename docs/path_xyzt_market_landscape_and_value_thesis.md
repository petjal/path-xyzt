# path-xyzt: Competitive Landscape, Prior Art, & Unique Value Thesis

## 1. Prior Art & The Incumbent Landscape
Network monitoring, synthetic testing, and external attack surface management (EASM) are mature multi-billion dollar markets. Who currently touches this space, and where do they fall short?

### Category A: The Enterprise Synthetic Giants (Catchpoint, ThousandEyes / Cisco)
- **What they do**: ThousandEyes and Catchpoint place vantage probe agents across enterprise branches, cloud providers, and telco PoPs. They run synthetic traceroutes and web tests.
- **Their Business Model & Traps**:
  - **Legacy Enterprise SaaS Trap**: Massive, bloated SaaS portals full of custom dashboards, heavyweight agents, complex licensing tiers, and $150k–$500k/year enterprise contracts.
  - **Inflexible Data Ingestion**: They force customers to view data in *their* proprietary UI. Exporting raw, unopinionated L3/L4/L7 correlated wire bundles into customer SIEMs (Snowflake, Datadog) requires clumsy webhook integrations or expensive add-on licenses.
  - **Blindspots**: They focus on general web performance (DOM load times, CDN response times). They rarely correlate **last-mile BGP disaggregation + DNSSEC RRSIG rolling decay + registrar EPP lock stripping** into a single atomic temporal record.

### Category B: Internet-Wide Port Scanners (Shodan, Censys, Project Discovery)
- **What they do**: Scan the entire IPv4 address space once every few days/weeks to index listening ports, banners, and TLS certs.
- **Why they don't solve this need**:
  - **Temporal Granularity**: Scanning once every 2 weeks is useless for catching a 6-hour DNSSEC failure, a 30-second pre-DDoS pulse test, or a BGP route flap.
  - **No Active Last-Mile Forensics**: They do not run multi-hop traceroute delta forensics or track ingress peering router mutations (`HopHash`).

### Category C: Uptime Ping Checkers (Pingdom, Better Uptime, UptimeRobot)
- **What they do**: Cheap pings (HTTP GET / 200 OK) every 1 to 5 minutes.
- **Why they don't solve this need**:
  - **Zero Layer-by-Layer Forensic Depth**: If Pingdom gets a 200 OK, it reports "GREEN".
  - It has zero awareness that the TLS cert expires in 3 days, that the DNSSEC signature is expiring in 2 hours, that the registrar locks were stripped by a SIM-swapper 10 minutes ago, or that traffic was rerouted through a Russian transit AS via a BGP detour.

---

## 2. The Unfilled Customer Need: The "Outside-In Ground-Truth Stream"
What operational blindspots impact enterprise financial institutions, commercial banks, clearing houses, and critical infrastructure teams?

### Pain Point 1: "Our Internal Monitoring Only Sees What We Think We Own"
- Enterprise internal APM (Datadog, Prometheus, New Relic) runs inside AWS/GCP or inside the Kubernetes cluster.
- When an outage happens due to an external BGP hijack, an expired intermediate CA, a dropped parent TLD glue record, or an ISP peering saturation at the Boston IXP, **internal APM shows everything green**:
  - *"Our pods are running, CPU is at 12%, database latency is 2ms. Why can't customers in New York reach us?!"*
- They are blind to the external substrate.

### Pain Point 2: The "Multi-Tool Fragmented Fatigue"
- Today, an enterprise uses:
  - Tool 1 for Uptime (Pingdom)
  - Tool 2 for Cert Expiration (Venafi or custom bash script)
  - Tool 3 for Domain Expiration (Registrar email alerts, which go to an ex-employee's unmonitored inbox)
  - Tool 4 for BGP (BGPmon or ThousandEyes)
- When a domain expires or DNSSEC drops, **it still causes multi-million dollar outages** (e.g., Microsoft Teams expired cert outage, Google .ar domain lapse, Cisco Webex cert lapse).
- There is no single, lightweight feed that binds the **entire external perimeter** into an immutable temporal record.

### Pain Point 3: The "SaaS Dashboard Bloat Trap"
- Enterprise CISOs and Principal SREs hate buying another complex dashboard with 400 buttons that nobody logs into.
- They already pay millions of dollars for **Splunk, Datadog, Snowflake, or ClickHouse**.
- What they actually want is:
  > *"Do not give me another UI. Just give me a raw, pristine, high-fidelity JSON stream of our public endpoints' external reality every 3 hours that I can dump into our data lake."*

## 3. Technical Comparison & Architectural Trade-offs

| Dimension | Enterprise Synthetic Platforms (ThousandEyes / Catchpoint) | Endpoint Ping Checkers (Pingdom / Uptime) | path-xyzt Architecture |
|---|---|---|---|
| **Data Format** | Proprietary UI dashboard & metrics | Binary HTTP status | Unopinionated atomic NDJSON / Parquet stream |
| **Ingestion Model** | Portal view / vendor API | Basic alert webhook | SIEM & Data Lake native (Splunk, Datadog, Snowflake, ClickHouse) |
| **Cadence & Resolution** | High-frequency continuous (1-5 min) | High-frequency (1 min) | 3-Hour Harmonic (8 samples/day with $\pm 10$m jitter) |
| **Forensic Scope** | Segmented synthetic tests | HTTP status code only | Correlated L1/L3 Latency + Last-Mile `HopHash` + BGP/RPKI + DNSSEC RRSIG + RDAP Locks + TLS Leaf/OCSP |
| **Execution Footprint** | Heavy agent daemon / browser automation | Cloud ping workers | Lightweight zero-privilege single-pass CLI probe |

---

## 4. Operational Invariants & Forensic Utility

1. **Deterministic Multi-Layer Coverage**:
   - Outages from domain expiration, DNSSEC RRSIG signature exhaustion, or unlogged intermediate certificates are detected and committed before failure cascades occur.
2. **Peering & Route Detour Detection**:
   - Computes deterministic digests across the final intermediate hops (`HopHash`) and monitors BGP prefixes to flag silent traffic redirections that do not trigger HTTP status errors.
3. **Low-Overhead Pipeline Integrity**:
   - The probe operates statelessly, minimizing connection footprint while producing structured, reproducible cryptographic assertions.

