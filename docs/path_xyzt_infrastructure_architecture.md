# path-xyzt: Operational Infrastructure Architecture & Multi-Vantage Topology

## 1. The Core Infrastructure Philosophy
To deliver stateless data pipelines and complete operational reliability:
- **Never over-engineer premature infrastructure**: No Kubernetes, no bloated microservices, no expensive SaaS managed databases.
- **Strict adherence to the GEMINI.md protocol**:
  - Pete's existing `free-tier-hdd` GCP VM (`100.68.160.4`, `us-central1-a`) is strictly for light live sync / remotes (1GB RAM, standard HDD). Never overload it with compute or intensive polling loops.
- **The Probe Execution Profile**:
  - 1 probe = 1 TCP SYN-ACK + 1 TLS handshake + 1 `mtr` trace + 2 `dig` queries + 1 RDAP HTTP call.
  - Takes $< 500\text{ ms}$ CPU time and $< 10\text{ KB}$ network I/O.
  - Probing 100 targets every 3 hours requires only **800 probes per day**.
  - Total compute load: $\approx 7\text{ minutes}$ of CPU time **per 24 hours**.

---

## 2. Phase 1 (MVP / Bootstrap): The "Two-Vantage Asymmetric Spine"
Total Monthly Cost: **~$10 - $15 / month**.

```
+-----------------------------------------------------------------------------------------+
|                               PHASE 1 INFRASTRUCTURE TOPOLOGY                           |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   [Vantage Node 1: Primary Consumer/Eyeball ISP]                                        |
|   Location: Pete's T14 Laptop (Exeter, NH / Boston Metro)                               |
|   Network: Comcast Cable (AS7922) - Pure "Eyeball / Real-World Consumer" ISP Vantage.   |
|   Role: Probes targets from actual retail Internet perspective.                         |
|                                                                                         |
|                                   |                                                     |
|                      Tailscale Mesh Network (Encrypted)                                 |
|                                   |                                                     |
|                                   v                                                     |
|                                                                                         |
|   [Vantage Node 2: Primary Cloud / Datacenter Backbone]                                 |
|   Location: GCP `e2-micro` / `e2-small` (us-central1, Iowa or us-east4, Virginia)        |
|   Network: Google Cloud Global Fiber (AS15169) - Tier-1 Datacenter Backbone Vantage.    |
|   Role: Probes targets from cloud peering backbone + hosts static NDJSON / S3 sync.     |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```

### Why this 2-Vantage Setup is Scientifically Powerful:
- **Eyeball (AS7922 Comcast) vs Backbone (AS15169 GCP)**:
  - If Coinbase goes down on Comcast but is up on GCP $\implies$ **Comcast-to-Cloudflare regional peering failure (Boston IXP)**.
  - If Coinbase goes down on both $\implies$ **Target-wide outage / Cloudflare global failure**.
  - This 2-node differential gives immediate root-cause attribution without needing 50 servers.

---

## 3. Phase 2 (Commercial Multi-Continent Vantage: SKU 3 Delivery)
Total Monthly Cost: **~$35 - $50 / month**.

To deliver SKU 3 (`XYZT-GLOBAL-VANTAGE`) across 4 global regions, deploy **4 micro-instances** on commodity cloud infrastructure (GCP Spot / E2-micro or Hetzner Cloud / Vultr):

```
                        [Central Data Store / S3 Bucket]
                                        ^
                                        | (Encrypted Push: Parquet / NDJSON)
         +-----------------+------------+------------+-----------------+
         |                 |                         |                 |
     VANTAGE 1         VANTAGE 2                 VANTAGE 3         VANTAGE 4
      US-East           US-West                   Europe            Asia-Pacific
  (Virginia / Ashburn)  (Oregon)            (Frankfurt / London) (Tokyo / Singapore)
    GCP e2-micro      GCP e2-micro              Hetzner CX22       GCP e2-micro
      (~$6/mo)          (~$6/mo)                  (~$5/mo)           (~$8/mo)
```

### Cloud Provider Diversification (Anti-Cloud Monoculture)
- **Do not put all probes in Google Cloud (GCP)**:
  - If GCP experiences a global network routing incident, our entire monitoring network goes blind.
- **Mix Providers**:
  - Node 1: GCP us-east4 (Google backbone)
  - Node 2: Hetzner Europe (European independent transit: Telia/Arelion + DE-CIX)
  - Node 3: AWS us-west-2 (Amazon transit)
  - Node 4: Vultr / Linode Tokyo (Asian transit: NTT/Telstra)

---

## 4. The Node Software Stack (Ultra-Lean & Unbreakable)

Each probe node runs a single, statically verified or lightweight Python/Rust binary:

```
+-----------------------------------------------------------------------------+
|                            PROBE NODE SOFTWARE STACK                        |
+-----------------------------------------------------------------------------+
| OS:             Debian 12 / Ubuntu 24.04 LTS Minimal                         |
| Network Mesh:   Tailscale (zero public SSH ports exposed)                   |
| Scheduler:      systemd timer (every 3 hours + jitter)                      |
| Probe Engine:   `path-xyzt` CLI binary (Rust or Python 3.12)                |
| Dependencies:   Zero runtime daemons. Stateless execution.                  |
| Local Cache:    SQLite / Local append-only NDJSON file                      |
| Outbound Push:  HTTPS POST to central API / rsync / S3 sync                 |
+-----------------------------------------------------------------------------+
```

### Systemd Timer Setup:
- No cron daemon needed. A standard systemd timer:
  ```ini
  [Timer]
  OnCalendar=00/3:00:00
  RandomizedDelaySec=600
  Persistent=true
  ```
- Fires every 3 hours with up to 10 minutes of randomized jitter.

---

## 5. Central Ingestion & Distribution Layer (The API)
Where does the customer get their data?
1. **Direct Webhook / Alerting**:
   - Dispatched immediately if `BundleSeal` mutates or if an expiration window is breached.
2. **REST API Endpoint (`https://api.xyzt.network/v1/telemetry/targets/<domain>`)**:
   - Lightweight FastAPI / Go service running on a single small VM with a Postgres/ClickHouse database or simple daily partitioned Parquet files on Cloudflare R2 / AWS S3.
3. **Cloudflare R2 Bucket Sync (Zero Egress Fees)**:
   - Customers ingest daily Parquet files directly from an S3-compatible R2 bucket. Cloudflare charges **$0 egress fees**, meaning bandwidth costs are literally zero even if customers sync gigabytes of historical data.

---

## 6. Financial Overview: Infrastructure Run-Rate vs Revenue

| Line Item | Phase 1 (Bootstrap) | Phase 2 (Commercial) |
|---|---|---|
| **Probe Nodes** | $0 (T14 + existing GCP) | $30 / month (4 global nodes) |
| **Storage / S3 (R2)** | $0 (Local disk) | $5 / month |
| **API / Ingestion VM** | $0 (GCP Free Tier) | $15 / month |
| **Total Monthly CapEx/OpEx** | **~$5 - $10 / month** | **~$50 / month** |
| **Annual Infrastructure Cost** | **~$100 / year** | **~$600 / year** |
| **Projected Revenue (10 Customers on SKU 2)** | **$240,000 / year** | **$240,000 / year** |
| **Gross Margin** | **99.9%** | **99.7%** |

