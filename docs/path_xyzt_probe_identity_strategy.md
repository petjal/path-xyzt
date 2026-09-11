# path-xyzt: Probe Identity, Stealth vs Transparency, & Banner Signaling

## 1. Operational Rationale
When an outside-in probe samples public endpoints:
- Should it attempt **stealth** (mimicking consumer browser user agents)?
- Or should it declare **transparent identification** via structured protocol headers?
- What are the operational, firewall, and operator-hygiene implications?

---

## 2. The Case Against Stealth (Why Mimicry Fails)
1. **Stealth Triggers Malicious Attribution**:
   - When a security analyst or edge firewall inspects automated TCP connections and traceroutes originating from a headless IP with consumer browser headers (`Mozilla/5.0...`), the traffic is categorized as an unauthenticated crawler or vulnerability probe.
   - Result: WAF automated IP-blocking, rate-limiting, or abuse escalations.
2. **Standard Public Protocol Probing**:
   - The probe performs standard DNS queries, TCP SYN-ACK RTT measurements, and TLS handshakes against public endpoints.
   - Operating under RFC-compliant identification provides clear attribution.

---

## 3. Courteous Operator Transparency (The RFC 9110 Model)
Standard network measurement platforms (Shadowserver, Censys, Project Sonar) utilize structured, explicit identification:
1. **Clear Operator Identification**:
   - Declares the project origin, purpose (`public-telemetry-probe`), and contact mechanism directly in protocol headers.
2. **Defensive Abuse Prevention**:
   - Network operators reviewing edge logs can immediately identify the traffic as scheduled measurement and access project documentation.
3. **Reproducible Traceability**:
   - Provides public documentation linking the measurement methodology directly to the repository specification.

---

## 4. Header & URL Mechanics: Where to Put the Banner

### A. The User-Agent Header (Primary Channel)
- The User-Agent is the RFC-standard field for identifying automated agents.
- **Recommended String**:
  ```http
  User-Agent: path-xyzt/0.2.0 (+https://github.com/petjal/path-xyzt; public-telemetry-probe; telemetry@xyzt.network)
  ```
- **Why this works**:
  - Complies with RFC 9110 (User-Agent formatting: `product / version (comment)`).
  - Includes a direct clickable link to the repository/project page.
  - States purpose: `public-telemetry-probe`.
  - Provides a contact email: prevents firewall bans by giving an escalation path.

### B. The Request URI / Tail Flags
- **Targeting `#path-xyzt` (Fragments)**:
  - Note: HTTP fragment identifiers (`#...`) are **client-side only** and are **never transmitted to the server** over the wire in an HTTP request!
  - If you query `GET /#path-xyzt HTTP/1.1`, the HTTP client strips everything after `#`. The server only receives `GET / HTTP/1.1`.
- **Targeting Query Parameters (`?ref=path-xyzt`)**:
  - Probing `GET /?ref=path-xyzt` reaches server access logs, BUT:
  - **Risk**: Some caching engines (Cloudflare, Akamai) treat unique query strings as cache-busting misses, forcing a request back to the origin server. We want to test the normal cache/edge ingress, not intentionally bust origin caches.
  - **Verdict**: Keep the request path clean (`GET / HTTP/1.1` or target API path), and keep the banner strictly in the **headers**.

### C. Custom Enterprise Identification Headers
We can also pass courteous custom headers:
```http
X-Probe-Provider: path-xyzt
X-Probe-Purpose: network-provenance-and-health-telemetry
X-Probe-Source: us-east-t14-01
X-Probe-Contact: https://github.com/petjal/path-xyzt
```
- Network engineering and SOC teams immediately recognize these as professional monitoring headers.

---

## 5. Conclusion & Recommendation
- **Drop stealth**: Stealth looks suspicious, invites blacklisting, and wastes a prime marketing touchpoint.
- **Adopt Courteous Transparency**:
  - Set a clean, RFC-compliant User-Agent pointing to Pete's GitHub repo.
  - Add explicit probe purpose metadata.
  - Let every access log entry act as a silent, unignorable B2B business card.

