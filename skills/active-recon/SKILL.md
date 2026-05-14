# SKILL.md — Active Reconnaissance Workflow
# CyberStrike DevSec | Level 2 Active Scan
# skill: active-recon

## Purpose

Automated active reconnaissance workflow that systematically identifies open
ports, running services, web technologies, SSL/TLS weaknesses, security header
gaps, CORS misconfigurations, and exposed technology fingerprints.

This skill produces a normalized, severity-graded reconnaissance report
suitable for inclusion in a Level 2 security assessment.

---

## ⚠️ MANDATORY PREREQUISITE — READ BEFORE PROCEEDING

**THIS SKILL MUST NOT BE EXECUTED WITHOUT WRITTEN AUTHORIZATION.**

Before running any step of this workflow:

1. Confirm existence of a signed consent file at a known path
2. Verify the target hostname/IP matches the authorized scope in the consent file
3. Log the consent file path, authorization date, and authorizing party
4. If no consent file is found → **STOP. Do not proceed.**

```
Consent verification command:
  cat /path/to/consent/signed_consent_<target>.md
  
Required fields in consent file:
  - target_scope: (must match scan target)
  - authorization_level: Level 2 (minimum)
  - authorized_by: (name + role)
  - authorization_date: (ISO 8601)
  - signature: (digital or wet)
```

---

## Workflow Overview

```
Step 1: Consent Verification
Step 2: OS & Service Detection (nmap -sV -sC)
Step 3: Web Technology Fingerprinting (whatweb)
Step 4: SSL/TLS Analysis (testssl.sh)
Step 5: Security Headers Check (curl + analysis)
Step 6: CORS Misconfiguration Test (cors-scanner)
Step 7: Passive Technology Nuclei Scan (nuclei passive)
Step 8: Results Normalization & Report Generation
```

---

## Step 1: Consent Verification

```bash
# Verify consent file exists and is valid
CONSENT_FILE="/path/to/consent/signed_consent_${TARGET_HOSTNAME}.md"
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SCAN_ID="recon-$(date +%Y%m%d-%H%M%S)-${TARGET_HOSTNAME}"

if [ ! -f "${CONSENT_FILE}" ]; then
  echo "[ABORT] No consent file found at ${CONSENT_FILE}"
  echo "[ABORT] Scan ${SCAN_ID} terminated — authorization required"
  exit 1
fi

echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] Consent verified: ${CONSENT_FILE}"
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] Starting Level 2 Active Recon"
```

**Audit log entry format (append to scan_audit.log):**
```
[TIMESTAMP] [SCAN_ID] ACTION=CONSENT_VERIFIED target=TARGET consent_file=PATH
[TIMESTAMP] [SCAN_ID] ACTION=SCAN_START skill=active-recon operator=OPERATOR_ID
```

---

## Step 2: OS & Service Detection

**Tool:** `tools/nmap.yaml`

**Configuration:**
- Scan type: `-sV -sC` (version + default scripts)
- Timing: T3 (normal — balanced speed/accuracy)
- Initial ports: top 100 (escalate to top 1000 if Level 2+ authorized)
- Output: XML for parsing

```bash
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] ACTION=NMAP_START target=${TARGET}"

nmap -sV -sC -T3 \
  --top-ports 100 \
  -oX "${OUTPUT_DIR}/nmap_initial.xml" \
  "${TARGET}"

# If authorized for broader scan:
# nmap -sV -sC -T3 --top-ports 1000 -oX "${OUTPUT_DIR}/nmap_extended.xml" "${TARGET}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [${SCAN_ID}] ACTION=NMAP_COMPLETE output=${OUTPUT_DIR}/nmap_initial.xml"
```

**Parse key findings:**
- Open ports and services
- Service versions (for CVE lookup)
- OS detection results
- Interesting script output (http-title, ssl-cert, etc.)

---

## Step 3: Web Technology Fingerprinting

**Tool:** `tools/whatweb.yaml`

**Configuration:**
- Aggression: 1 (single request, stealthy)
- Output: JSON

```bash
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] ACTION=WHATWEB_START target=${TARGET_URL}"

whatweb -a 1 \
  --log-json="${OUTPUT_DIR}/whatweb.json" \
  --follow-redirect=always \
  "${TARGET_URL}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [${SCAN_ID}] ACTION=WHATWEB_COMPLETE output=${OUTPUT_DIR}/whatweb.json"
```

**Extract key findings:**
- Web server (Apache/nginx/IIS + version)
- CMS (WordPress/Drupal/Joomla + version)
- Frameworks (React/Angular/Laravel/etc.)
- JavaScript libraries with versions
- Analytics/tracking tools

---

## Step 4: SSL/TLS Analysis

**Tool:** `tools/testssl.yaml`

**Configuration:**
- Checks: all (protocols + ciphers + vulnerabilities + certificates)
- Output: JSON
- Severity filter: LOW and above

```bash
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] ACTION=TESTSSL_START target=${TARGET_HOST}:${TARGET_PORT}"

testssl.sh \
  --severity LOW \
  --wide \
  --jsonfile="${OUTPUT_DIR}/testssl" \
  "${TARGET_HOST}:${TARGET_PORT}"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [${SCAN_ID}] ACTION=TESTSSL_COMPLETE output=${OUTPUT_DIR}/testssl.json"
```

**Key checks:**
- Supported TLS versions (flag SSLv2/SSLv3/TLS1.0/TLS1.1 as deprecated)
- Weak ciphers (RC4, DES, EXPORT, NULL)
- Known vulnerabilities (HEARTBLEED, POODLE, BEAST, ROBOT, etc.)
- Certificate validity, expiry, chain trust
- Certificate transparency compliance

---

## Step 5: Security Headers Check

**Tool:** `tools/security-headers.yaml`

**Configuration:**
- Follow redirects: yes
- Output: JSON

```bash
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] ACTION=HEADERS_START target=${TARGET_URL}"

# Fetch headers
HEADERS=$(curl -s -I -L \
  --max-time 10 \
  -H "User-Agent: Mozilla/5.0 (compatible; SecurityAudit/1.0)" \
  "${TARGET_URL}" 2>/dev/null)

# Save raw headers for analysis
echo "${HEADERS}" > "${OUTPUT_DIR}/http_headers_raw.txt"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [${SCAN_ID}] ACTION=HEADERS_COMPLETE output=${OUTPUT_DIR}/http_headers_raw.txt"

# Analyze with security-headers tool (see tool YAML for analysis rules)
# Key headers to check:
#   Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
#   X-Content-Type-Options, Referrer-Policy, Permissions-Policy
# Also flag: Server, X-Powered-By (information disclosure)
```

---

## Step 6: CORS Misconfiguration Test

**Tool:** `tools/cors-scanner.yaml`

**Configuration:**
- Test multiple Origin payloads
- Check for reflected origins and wildcard+credentials

```bash
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] ACTION=CORS_START target=${TARGET_URL}"

ORIGINS=(
  "https://evil.com"
  "null"
  "https://${TARGET_HOST}.evil.com"
  "https://evil.${TARGET_HOST}"
  "http://${TARGET_HOST}"
  "https://localhost"
  "https://127.0.0.1"
)

for ORIGIN in "${ORIGINS[@]}"; do
  RESPONSE=$(curl -s -I \
    -H "Origin: ${ORIGIN}" \
    -H "Access-Control-Request-Method: GET" \
    --max-time 10 \
    "${TARGET_URL}" 2>/dev/null)
  
  ACAO=$(echo "${RESPONSE}" | grep -i "access-control-allow-origin" | tr -d '\r\n')
  ACAC=$(echo "${RESPONSE}" | grep -i "access-control-allow-credentials" | tr -d '\r\n')
  
  echo "{\"origin\": \"${ORIGIN}\", \"acao\": \"${ACAO}\", \"acac\": \"${ACAC}\"}" \
    >> "${OUTPUT_DIR}/cors_results.jsonl"
done

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [${SCAN_ID}] ACTION=CORS_COMPLETE output=${OUTPUT_DIR}/cors_results.jsonl"
```

---

## Step 7: Passive Nuclei Scan

**Tool:** `tools/nuclei-passive.yaml`

**Configuration:**
- Templates: technologies, exposures, misconfiguration, ssl
- Severity: info, low
- No interactsh (no external callbacks)

```bash
SCAN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[${SCAN_TIMESTAMP}] [${SCAN_ID}] ACTION=NUCLEI_START target=${TARGET_URL}"

nuclei \
  -u "${TARGET_URL}" \
  -t technologies/ -t exposures/ -t misconfiguration/ -t ssl/ \
  -severity info,low \
  -rate-limit 100 \
  -timeout 10 \
  -no-interactsh \
  -json \
  -o "${OUTPUT_DIR}/nuclei_passive.json"

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [${SCAN_ID}] ACTION=NUCLEI_COMPLETE output=${OUTPUT_DIR}/nuclei_passive.json"
```

---

## Step 8: Results Normalization & Report

Aggregate all tool outputs into a normalized report with consistent severity levels.

### Severity Scale

| Level    | Description                                      |
|----------|--------------------------------------------------|
| CRITICAL | Immediate risk, exploitable without prerequisites |
| HIGH     | Significant risk, easily exploitable             |
| MEDIUM   | Moderate risk, requires some conditions          |
| LOW      | Minimal direct risk, defense-in-depth issue      |
| INFO     | Informational, no direct risk                    |

### Output Directory Structure

```
${OUTPUT_DIR}/
├── scan_metadata.json          # Scan ID, timestamps, consent ref, target
├── nmap_initial.xml            # Port/service scan results
├── nmap_extended.xml           # (optional) Extended port scan
├── whatweb.json                # Technology fingerprinting
├── testssl.json                # SSL/TLS analysis
├── http_headers_raw.txt        # Raw HTTP headers
├── cors_results.jsonl          # CORS test results (one JSON per line)
├── nuclei_passive.json         # Nuclei passive findings
├── scan_audit.log              # Chronological action log
└── report_level2_recon.json    # Aggregated normalized report
```

### Report Structure

```json
{
  "scan_id": "recon-20260514-120000-example.com",
  "scan_type": "active-recon",
  "level": 2,
  "target": "example.com",
  "target_url": "https://example.com",
  "consent_reference": "/path/to/consent.md",
  "scan_start": "2026-05-14T12:00:00Z",
  "scan_end": "2026-05-14T12:45:00Z",
  "operator": "analyst@company.com",
  "summary": {
    "total_findings": 0,
    "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    "tools_executed": []
  },
  "findings": [
    {
      "id": "FINDING-001",
      "source_tool": "testssl",
      "category": "ssl",
      "title": "TLS 1.0 supported",
      "severity": "MEDIUM",
      "description": "...",
      "evidence": "...",
      "recommendation": "...",
      "references": []
    }
  ]
}
```

---

## Abort Conditions

Stop the scan immediately if:
- Target does not respond to initial nmap ping (may indicate wrong target)
- Target IP resolves to unexpected hostname (scope mismatch)
- Rate limiting or WAF blocking detected after >3 consecutive failures
- Any tool returns errors suggesting the target is a production system not in scope
- An automated defensive system (fail2ban, etc.) appears to block the scanner IP

Log abort reason with timestamp in `scan_audit.log`.

---

## References

- Tools used: `tools/nmap.yaml`, `tools/whatweb.yaml`, `tools/testssl.yaml`,
  `tools/security-headers.yaml`, `tools/cors-scanner.yaml`, `tools/nuclei-passive.yaml`
- Consent framework: `docs/consent-framework.md`
- Report template: `templates/report_level2.json`
