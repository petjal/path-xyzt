# path-xyzt

**Unopinionated Outside-In Network Telemetry & Merkle Perimeter Proof Engine for High-Value Public Endpoints**

`path-xyzt` provides automated, continuous, outside-in telemetry and cryptographic perimeter proofs for critical public infrastructure (institutional banking, asset exchanges and custody platforms, clearing houses, and Tier-1 API gateways).

Rather than delivering a heavy, complex web dashboard with custom reporting layers, `path-xyzt` generates a high-fidelity, unopinionated atomic data stream (NDJSON / Parquet) designed for direct, seamless ingestion into enterprise SIEMs and data lakes (Splunk, Datadog, Snowflake, ClickHouse).

---

## Architecture Overview

```
                                      BundleSeal (Root Hash)
                         SHA-256(H_ROUTING || H_ZONE || H_TLS || H_ADMIN || H_PHYS)
                                                   |
        +------------------+-----------------------+-----------------------+------------------+
        |                  |                       |                       |                  |
    H_ROUTING            H_ZONE                  H_TLS                  H_ADMIN             H_PHYS
 (BGP & Peering)     (DNS & CAA RR)        (PKI & Handshake)        (RDAP & EPP)       (L1/L3 Physics)
        |                  |                       |                       |                  |
  +-----+-----+      +-----+-----+           +-----+-----+           +-----+-----+      +-----+-----+
Origin_AS  HopHash H_NS H_CAA H_EDGE     Leaf_SHA  Cipher_Suite Registrar EPP_Locks Quantized Quantized
Prefix     Ingress                       Issuer    ALPN         Exp_Epoch Statuses  RTT_Bucket Handshake
```

### Core Telemetry Vectors

1. **Physical & Connection Latency Breakdown (`latency_breakdown_ms`)**:
   - High-precision temporal separation: DNS lookup time, TCP SYN-ACK RTT (L1/L3 network transit), and TLS cryptographic negotiation overhead (L7 processing).
2. **Autonomous Routing & Provenance (`routing_provenance`)**:
   - Origin AS number, announced BGP prefix, RPKI ROA cryptographic validation state, and geographic origin.
3. **Deep Last-Mile Traceroute Forensics (`last_mile_signature`)**:
   - Hop-by-hop telemetry into the target edge ingress, ingress peering router IP identification, and deterministic last-mile `HopHash`.
4. **Impending Expiration Sentinel (`impending_expiration_sentinel`)**:
   - Multi-tier operational outage tripwires: ICANN RDAP domain registration countdown, DNSSEC RRSIG rolling signature expiration, TLS leaf and intermediate CA validity, and registrar EPP transfer/delete lock integrity.
5. **Hierarchical Merkle Trees (`BundleSeal` & `ZoneSeal`)**:
   - Cryptographic composite hashing across all structural pillars, enabling $O(1)$ delta scanning in customer data warehouses and instant logarithmic drill-down during incidents.

---

## Sampling Philosophy: The 3-Hour "Third Point Harmonic"

In signal processing, **two points only define a straight line** ($y = mx + b$). Three points are the fundamental mathematical requirement to determine **curvature, acceleration, and peak diurnal congestion** ($y = ax^2 + bx + c$).

- **Cadence**: Probed every 3 hours (8 samples per 24 hours) with $\pm 10$ minutes of randomized jitter.
- **Enterprise Workday Coverage**: Naturally captures 3 distinct moments across any 9-hour business day (Market Open, Midday Peak, Market Close).
- **Maintenance Synchrony**: Aligns with 6-hour and 12-hour automated certificate and DNSSEC maintenance refresh windows.
- **Polite & Courteous**: Consumes $< 80\text{ KB}$ of bandwidth and $< 4.0\text{ seconds}$ of total connection time per target per day.

---

## Project Documentation Index

All architectural specifications are located in the [`docs/`](docs/) directory:

- [Executive Recap & Foundation](docs/path_xyzt_executive_recap.md)
- [Hierarchical Multi-Tier Merkle Hashing](docs/path_xyzt_full_bundle_hierarchical_hashing.md)
- [DNS Zone Multipart Hashing (`ZoneSeal`)](docs/path_xyzt_dns_merkle_and_multipart_hashes.md)
- [Full-Stack Endpoint Hijack Surface (Electrons to Cloud)](docs/path_xyzt_full_stack_hijack_surface.md)
- [Pre-DDoS Reconnaissance & Rehearsal Detection](docs/path_xyzt_pre_ddos_recon_detection.md)
- [Telemetry Variance Taxonomy](docs/path_xyzt_telemetry_variance_taxonomy.md)
- [Empirical Variance Discovery & Profiling](docs/path_xyzt_empirical_variance_discovery.md)
- [3-Hour Cadence & Sampling Mathematics](docs/path_xyzt_sampling_rate_math.md)
- [Probe Identity & Banner Signaling Strategy](docs/path_xyzt_probe_identity_strategy.md)
- [Operational Infrastructure & Vantage Topology](docs/path_xyzt_infrastructure_architecture.md)
- [Core Data Model & Metric Redesign](docs/path_xyzt_core_model_evaluation.md)

---

## License & Contact

Author: Pete Jalajas (`pjalajas@gmail.com`)  
Repository: [github.com/petjal/path-xyzt](https://github.com/petjal/path-xyzt)  
License: Apache 2.0
