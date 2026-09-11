# Live Strawman Telemetry Bundle: api.coinbase.com

**Observer Vantage**: `t14` (Exeter/Boston, Comcast AS7922)  
**Target Endpoint**: `api.coinbase.com:443`  
**Capture Timestamp**: `2026-09-09T15:02:35Z`  
**Execution Script**: `/home/petjal/dev/path-xyzt/scripts/strawman_collector.py`  

---

## 1. Raw Telemetry JSON Payload

```json
{
  "schema_version": "1.0.0-draft",
  "observation_id": "obs_7793b72149d8",
  "timestamp_utc": "2026-09-09T15:02:35Z",
  "target": {
    "hostname": "api.coinbase.com",
    "resolved_ip": "104.18.35.15",
    "port": 443
  },
  "polar_coordinates": {
    "latency_r_ms": 9.142,
    "topological_theta_rad": 1.2785,
    "anycast_phi_rad": 0.0
  },
  "bgp_provenance": {
    "origin_asn": 13335,
    "announced_prefix": "104.18.32.0/19",
    "rir": "arin",
    "rpki_status": "VALID"
  },
  "traceroute": {
    "total_hops": 9,
    "hop_hash": "1cd35be4",
    "all_hops": [
      {
        "hop": 1,
        "ip": "192.168.86.1",
        "ptr": "_gateway",
        "asn": null,
        "rtt_ms": 2.131
      },
      {
        "hop": 2,
        "ip": "10.0.0.1",
        "ptr": null,
        "asn": null,
        "rtt_ms": 3.511
      },
      {
        "hop": 3,
        "ip": "*",
        "ptr": null,
        "asn": null,
        "rtt_ms": null
      },
      {
        "hop": 4,
        "ip": "68.86.236.37",
        "ptr": "po-312-405-rur101.exeter.nh.boston.comcast.net",
        "asn": 7922,
        "rtt_ms": 11.094
      },
      {
        "hop": 5,
        "ip": "162.151.151.225",
        "ptr": "po-100-xar01.exeter.nh.boston.comcast.net",
        "asn": 7922,
        "rtt_ms": 12.268
      },
      {
        "hop": 6,
        "ip": "162.151.150.125",
        "ptr": "be-301-arsc1.needham.ma.boston.comcast.net",
        "asn": 7922,
        "rtt_ms": 16.462
      },
      {
        "hop": 7,
        "ip": "50.170.111.230",
        "ptr": null,
        "asn": 7922,
        "rtt_ms": 18.758
      },
      {
        "hop": 8,
        "ip": "172.68.52.21",
        "ptr": null,
        "asn": 13335,
        "rtt_ms": 22.253
      },
      {
        "hop": 9,
        "ip": "104.18.35.15",
        "ptr": null,
        "asn": 13335,
        "rtt_ms": 18.484
      }
    ],
    "last_mile_hops": [
      {
        "hop": 6,
        "ip": "162.151.150.125",
        "ptr": "be-301-arsc1.needham.ma.boston.comcast.net",
        "asn": 7922,
        "rtt_ms": 16.462
      },
      {
        "hop": 7,
        "ip": "50.170.111.230",
        "ptr": null,
        "asn": 7922,
        "rtt_ms": 18.758
      },
      {
        "hop": 8,
        "ip": "172.68.52.21",
        "ptr": null,
        "asn": 13335,
        "rtt_ms": 22.253
      },
      {
        "hop": 9,
        "ip": "104.18.35.15",
        "ptr": null,
        "asn": 13335,
        "rtt_ms": 18.484
      }
    ]
  },
  "tls_forensics": {
    "tls_version": "TLSv1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "thumbprint_sha256": "e600d9a63925f31e9cf7529a4d330d0154d0c56a3f467de46f10f1e45fa241ba",
    "leaf_cert": {
      "serial_number": "D00C9A4EA3D46D31139AB6306FD00DEF",
      "subject_cn": "coinbase.com",
      "issuer_o": "Google Trust Services",
      "issuer_cn": "WE1",
      "valid_from_utc": "2026-09-03T03:29:17Z",
      "valid_to_utc": "2026-12-02T04:29:12Z",
      "days_until_expiration": 83,
      "san_count": 4,
      "has_wildcard": true,
      "sample_sans": [
        "coinbase.com",
        "*.coinbase.com",
        "*.cloud.coinbase.com",
        "*.console.cloud.coinbase.com"
      ]
    },
    "ocsp_stapled": false
  },
  "blade_and_load_balancer": {
    "server_banner": "Vercel",
    "load_balancer_cookies": [],
    "trace_headers": {
      "CF-RAY": "a38713619e3dfbd0-IAD"
    },
    "clock_skew_ms": null
  }
}
```

---

## 2. Key Forensic Discoveries from this Live Probe

1. **The Last-Mile Ingress Point**:
   * Hops 1–7 are inside the Comcast access network (`AS7922`), routing through Exeter, NH &rarr; Needham, MA.
   * **Hop 8 (`172.68.52.21`)** is the exact physical handoff into **Cloudflare Anycast peering (`AS13335`)**.
   * **Hop 9 (`104.18.35.15`)** is the final terminating edge VIP.
   * **Forensic Value**: If an attacker attempts BGP diversion or if Comcast routing flips to an unexpected transit provider, Hop 8 changes instantly and mutates `hop_hash: "1cd35be4"`.
2. **TLS Certificate Freshness & Lifecycle**:
   * The cert was issued **less than 1 week ago** (Valid From: `2026-09-03T03:29:17Z`).
   * It uses Google Trust Services (`WE1`) with an 83-day countdown.
   * It uses wildcard SANs (`*.coinbase.com`).
   * **OCSP Stapling is FALSE**: Coinbase is currently failing to staple OCSP responses, forcing clients to make synchronous lookups or fail open.
3. **Edge POP & Origin Infrastructure Revealed**:
   * `CF-RAY: a38713619e3dfbd0-IAD` reveals the connection was terminated at the **Dulles / Ashburn, VA (IAD)** Cloudflare data center.
   * `Server: Vercel` reveals Coinbase's public API reverse proxy layer is fronted by Vercel edge workers.
