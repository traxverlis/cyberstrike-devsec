# Active Scan Report — Level 2

---

## Report Header

| Field             | Value                        |
|-------------------|------------------------------|
| **Target**        | `<!-- TARGET_HOST -->`       |
| **IP Range**      | `<!-- IP_RANGE -->`          |
| **Scan Date**     | `2026-05-15 10:36 UTC`         |
| **Scan Duration** | `<!-- SCAN_DURATION -->`     |
| **Analyst**       | `<!-- ANALYST_NAME -->`      |
| **Report Version**| 1.0                          |
| **Classification**| CONFIDENTIAL — RESTRICTED    |

### Tools Used

| Tool             | Version | Purpose                              |
|------------------|---------|--------------------------------------|
| nmap             | x.x     | Port & service enumeration           |
| testssl.sh       | x.x     | SSL/TLS analysis                     |
| nikto            | x.x     | Web server misconfiguration scanning |
| wapiti           | x.x     | Web vulnerability scanning           |
| nuclei (passive) | x.x     | Passive CVE/template matching        |
| whatweb          | x.x     | Technology fingerprinting            |
| cors-scanner     | x.x     | CORS misconfiguration detection      |
| securityheaders  | x.x     | HTTP security headers analysis       |

> **Authorization Reference:** Consent Document ID `<!-- CONSENT_DOC_ID -->` — Level 2 authorized.

---

## Executive Summary

> *(Non-technical overview. Max 10 lines.)*

This Level 2 active scan was conducted against `<!-- TARGET_HOST -->` on `2026-05-15 10:36 UTC` under explicit written authorization (consent level 2). The scan covered external attack surface enumeration, service fingerprinting, SSL/TLS configuration review, web security headers, CORS policies, and passive vulnerability detection.

**Attack Surface Overview:**

- Open ports discovered: `0`
- Web endpoints analyzed: `<!-- ENDPOINT_COUNT -->`
- SSL/TLS issues found: `<!-- TLS_ISSUE_COUNT -->`
- Security header gaps: `<!-- HEADER_ISSUE_COUNT -->`
- Vulnerabilities identified: `0` (Critical: `<!--C-->` / High: `<!--H-->` / Medium: `<!--M-->` / Low: `<!--L-->`)

**Top Risks Discovered:**

1. `<!-- TOP_RISK_1 -->`
2. `<!-- TOP_RISK_2 -->`
3. `<!-- TOP_RISK_3 -->`

---

## 1. Ports & Services

### 1.1 Open Ports Summary

| Port | Protocol | Service | Version | State | Notes |
|------|----------|---------|---------|-------|-------|
| 80   | TCP      | HTTP    |         | open  |       |
| 443  | TCP      | HTTPS   |         | open  |       |
| ...  | ...      | ...     | ...     | ...   | ...   |

### 1.2 CVEs Associated with Detected Services

| Port | Service | Version | CVE ID | CVSS | Description | Severity |
|------|---------|---------|--------|------|-------------|----------|
|      |         |         |        |      |             |          |

### 1.3 nmap Raw Summary

```
<!-- PASTE nmap -sV -sC -O OUTPUT HERE -->
```

---

## 2. SSL/TLS Analysis

> Tool: `testssl.sh`

### 2.1 Protocol Support

| Protocol   | Supported | Notes                      |
|------------|-----------|----------------------------|
| TLS 1.3    | ✅ / ❌   |                            |
| TLS 1.2    | ✅ / ❌   |                            |
| TLS 1.1    | ✅ / ❌   | ⚠️ Deprecated              |
| TLS 1.0    | ✅ / ❌   | ⚠️ Deprecated              |
| SSLv3      | ✅ / ❌   | 🔴 Critical if enabled     |
| SSLv2      | ✅ / ❌   | 🔴 Critical if enabled     |

### 2.2 Cipher Suites

| Cipher Suite | Key Exchange | Auth | Encryption | MAC | Rating |
|--------------|-------------|------|------------|-----|--------|
|              |             |      |            |     |        |

**Weak/Deprecated Ciphers Detected:**

| Cipher | Issue | Recommendation |
|--------|-------|----------------|
|        |       |                |

### 2.3 Certificate Details

| Field                | Value                        |
|----------------------|------------------------------|
| Subject              |                              |
| Issuer               |                              |
| Valid From           |                              |
| Valid Until          |                              |
| SANs                 |                              |
| Key Algorithm        |                              |
| Key Size             |                              |
| Signature Algorithm  |                              |
| CT Logs              | ✅ / ❌                      |
| OCSP Stapling        | ✅ / ❌                      |

### 2.4 SSL/TLS Findings

| ID     | Finding          | Severity | Description | Recommendation |
|--------|------------------|----------|-------------|----------------|
| TLS-01 |                  |          |             |                |

---

## 3. Security Headers

> Tool: `securityheaders` / curl manual check

| Header                            | Status           | Value Observed | Issue | Recommendation |
|-----------------------------------|------------------|----------------|-------|----------------|
| Strict-Transport-Security (HSTS)  | ✅ Present / ❌ Missing / ⚠️ Misconfigured |  |  |  |
| Content-Security-Policy           | ✅ / ❌ / ⚠️     |                |       |                |
| X-Frame-Options                   | ✅ / ❌ / ⚠️     |                |       |                |
| X-Content-Type-Options            | ✅ / ❌ / ⚠️     |                |       |                |
| Referrer-Policy                   | ✅ / ❌ / ⚠️     |                |       |                |
| Permissions-Policy                | ✅ / ❌ / ⚠️     |                |       |                |
| X-XSS-Protection                  | ✅ / ❌ / ⚠️     | (deprecated)   |       |                |
| Cache-Control                     | ✅ / ❌ / ⚠️     |                |       |                |
| Cross-Origin-Embedder-Policy      | ✅ / ❌ / ⚠️     |                |       |                |
| Cross-Origin-Opener-Policy        | ✅ / ❌ / ⚠️     |                |       |                |
| Cross-Origin-Resource-Policy      | ✅ / ❌ / ⚠️     |                |       |                |

**Overall Header Score:** `<!-- A/B/C/D/F -->`

---

## 4. CORS Configuration

> Tool: `cors-scanner` / manual curl

### 4.1 Findings

| Endpoint | Origin Tested | Access-Control-Allow-Origin | Credentials Allowed | Issue | Severity |
|----------|-------------|----------------------------|---------------------|-------|----------|
|          |             |                            |                     |       |          |

### 4.2 CORS Impact Analysis

<!-- Describe potential impact: credential theft, cross-origin data exfiltration, etc. -->

**Recommendation:** `<!-- e.g., Restrict ACAO to specific trusted origins, never use wildcard with credentials -->`

---

## 5. Web Vulnerabilities

> Tools: nikto, wapiti, nuclei (passive templates only — Level 2)

### 5.1 Findings Table

| ID     | Tool   | Type                     | URL / Parameter | Severity | CVSS | Description |
|--------|--------|--------------------------|-----------------|----------|------|-------------|
| WEB-01 | nikto  |                          |                 |          |      |             |
| WEB-02 | wapiti |                          |                 |          |      |             |
| WEB-03 | nuclei |                          |                 |          |      |             |

### 5.2 Detailed Findings

#### WEB-01 — `<!-- Title -->`

- **Severity:** `<!-- Critical / High / Medium / Low / Info -->`
- **CVSS Score:** `<!-- x.x -->`
- **Tool:** `<!-- tool name -->`
- **URL:** `<!-- affected URL -->`
- **Description:** `<!-- Technical description -->`
- **Evidence:**
  ```
  <!-- Paste relevant tool output -->
  ```
- **Recommendation:** `<!-- Fix guidance -->`

---

## 6. Technologies Exposed

> Tool: whatweb, nuclei fingerprinting

| Component       | Technology | Version Detected | Latest Version | CVEs Known | Severity |
|-----------------|------------|-----------------|----------------|------------|----------|
| Web Server      |            |                 |                |            |          |
| CMS / Framework |            |                 |                |            |          |
| Frontend        |            |                 |                |            |          |
| Backend Runtime |            |                 |                |            |          |
| Database (inferred) |        |                 |                |            |          |
| WAF / CDN       |            |                 |                |            |          |

**Outdated / Vulnerable Components:**

| Component | Detected Version | CVE | CVSS | Recommendation |
|-----------|-----------------|-----|------|----------------|
|           |                 |     |      |                |

---

## 7. Prioritized Recommendations

| Priority | Finding Ref | Title | Effort | Impact | Recommended Action |
|----------|-------------|-------|--------|--------|-------------------|
| 🔴 Critical |          |       | Low    | High   |                   |
| 🟠 High     |          |       |        |        |                   |
| 🟡 Medium   |          |       |        |        |                   |
| 🟢 Low      |          |       |        |        |                   |

---

## Appendix A — Commands Used

```bash
# Port & Service Scan
nmap -sV -sC -O -p- --open -oA nmap_results <TARGET>

# SSL/TLS Analysis
testssl.sh --full --json <TARGET>:443

# Web Server Scan
nikto -h https://<TARGET> -output nikto_results.txt

# Web Vulnerability Scan
wapiti -u https://<TARGET> -o wapiti_results/ -f html

# Technology Fingerprinting
whatweb -a 3 https://<TARGET>

# Nuclei Passive Scan
nuclei -u https://<TARGET> -tags passive -o nuclei_results.txt

# CORS Check
# cors-scanner or manual:
curl -H "Origin: https://evil.example.com" -I https://<TARGET>/api/endpoint

# Security Headers
curl -I https://<TARGET>
```

---

## Appendix B — Raw Tool Output

> Attach or reference output files stored in `results/` directory.

| File | Tool | Description |
|------|------|-------------|
| `nmap_results.xml` | nmap | Full port scan output |
| `testssl_results.json` | testssl.sh | SSL/TLS detailed output |
| `nikto_results.txt` | nikto | Web server findings |
| `wapiti_results/` | wapiti | Web vulnerability report |
| `whatweb_results.txt` | whatweb | Technology fingerprint |
| `nuclei_results.txt` | nuclei | Passive template matches |

---

*Report generated by CyberStrike DevSec — Level 2 Active Scan*  
*Classification: CONFIDENTIAL — Not for distribution without authorization*


---

## Auto-Generated Findings

*Generated by generate-report.py — review and edit before delivery.*

### Severity Distribution (Auto-Generated)

```
Severity Distribution
──────────────────────────────────────────────────
🔴 Critical                                  (0)
🟠 High                                      (0)
🟡 Medium                                    (0)
🟢 Low                                       (0)
ℹ️ Info                                      (0)
──────────────────────────────────────────────────
Total: 0
```

