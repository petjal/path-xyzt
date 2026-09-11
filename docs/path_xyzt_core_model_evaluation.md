# path-xyzt: Core Data Model & Mathematical Representation

## 1. Dropping Polar vs Keeping Direct Network Primitives
The user noted no emotional attachment to polar coordinates. The question is: What gives enterprise SecOps, SRE, and FinTech infrastructure teams the highest signal-to-noise ratio with zero mathematical pretense?

### A. The Case for Dropping Polar Coordinates
- **Enterprise Alienation**: Network engineers at Citadel, Coinbase, or Stripe do not think in spherical angles $(\theta, \phi)$. When an on-call engineer gets paged at 3 AM, seeing `θ: 1.3963` requires cognitive translation.
- **Ambiguity & Artificial Binning**: Compressing 16-bit / 32-bit ASNs or hop distributions into $[0, 2\pi]$ creates artificial mapping artifacts (modulo boundary wraps, collisions).
- **False Analogies**: Network latency has triangle inequality violations (routing asymmetries, hot-potato routing, satellite downlinks). Treating it as Euclidean or polar distance can lead to flawed mathematical assumptions.

### B. The Replacement: Pure High-Precision Network Primitives
Instead of forcing polar coordinates, represent the endpoint telemetry using **three orthogonal physical vectors**:

1. **Temporal Vector (Latency Breakdown in ms)**:
   - `dns_lookup_ms`: Time to resolve authoritative name.
   - `tcp_synack_ms`: Round-trip time to edge ingress interface ($L_1/L_3$ physics).
   - `tls_handshake_ms`: Cryptographic negotiation overhead ($L_7$ processing).
   - `ttfb_ms`: Time to first byte of application response.
   - *Advantage*: Completely clear, standard across all RFCs, instantly actionable.

2. **Topological Vector (Routing & Provenance Fingerprint)**:
   - `origin_asn`: AS number owning the destination IP.
   - `bgp_prefix`: Longest-prefix match announced globally.
   - `rpki_state`: `VALID` | `INVALID` | `NOT_FOUND`.
   - `ingress_peering_ip`: First router inside the destination network.
   - `hophash`: Cryptographic hash (e.g. SHA-256 truncated) of the last 4 hops.
   - *Advantage*: Zero lossy compression. If `hophash` or `origin_asn` changes, an alert fires instantly.

3. **Sentinel Expiration State (Delta-T to Expiry)**:
   - `domain_rdap_days_remaining`: ICANN registration expiration.
   - `dnssec_rrsig_hours_remaining`: Authoritative DNSSEC zone signature countdown.
   - `tls_leaf_cert_days_remaining`: Certificate expiration.
   - `ocsp_freshness_hours`: Revocation status staleness.
   - *Advantage*: Quantifiable risk metrics directly tied to outage prevention.

---

## 2. Comparison Matrix

| Dimension | Polar Coordinates $(r, \theta, \phi)$ | Orthogonal Telemetry Primitives |
|---|---|---|
| **Intuitiveness** | Low (requires learning coordinate conventions) | High (industry-standard network metrics) |
| **SIEM Ingestion** | Requires custom parsers or math plugins | Native JSON / NDJSON / OpenTelemetry / Datadog schema |
| **False Positives** | High risk due to hash/angle collisions | Near zero (exact IP/ASN matching) |
| **Mathematical Soundness** | Metaphorical (Internet is not a sphere) | Literal (exact timestamps, RTTs, and ASNs) |
| **Enterprise Adoption** | "Academic / Novelty" pushback | Immediate credibility with TSEs and network architects |

---

## 3. Recommendation
- Drop $(r, \theta, \phi)$ from the primary schema.
- Retain the project name `path-xyzt` as a brand / conceptual nod to 4D telemetry (space + time), but structure the actual wire payload around clean, unambiguous primitives:
  - `latency_breakdown`
  - `routing_provenance`
  - `last_mile_signature`
  - `expiration_sentinel`
