# DevSec Full Security Report
<!-- Template Version: 1.0 | CyberStrikeAI DevSec Team Role -->

---

## Report Header

| Field              | Value                          |
|--------------------|--------------------------------|
| **Project**        | {{project_name}}               |
| **Repository**     | {{repository_url}}             |
| **Branch**         | {{branch_name}}                |
| **Commit**         | {{commit_sha}}                 |
| **Report Date**    | {{report_date}}                |
| **Report Version** | {{report_version}}             |
| **Analyzed By**    | CyberStrikeAI / {{analyst}}    |
| **Team**           | {{team_name}}                  |
| **Scope**          | {{scope_description}}          |
| **Frameworks**     | {{frameworks_and_languages}}   |
| **Scan Duration**  | {{scan_duration}}              |

---

## Executive Summary

### Global Security Score

```
Score: {{global_score}} / 100   [{{score_label}}]   Risk Level: {{risk_level}}
```

> {{one_paragraph_summary}}

### Vulnerability Count by Severity

| Severity     | Count            | Trend vs Last Scan     |
|--------------|------------------|------------------------|
| 🔴 Critical  | {{count_critical}} | {{trend_critical}}   |
| 🟠 High      | {{count_high}}     | {{trend_high}}       |
| 🟡 Medium    | {{count_medium}}   | {{trend_medium}}     |
| 🔵 Low       | {{count_low}}      | {{trend_low}}        |
| ℹ️ Info      | {{count_info}}     | {{trend_info}}       |
| **Total**    | **{{count_total}}**| {{trend_total}}      |

### Top 3 Risks

1. **{{risk_1_title}}** — {{risk_1_description}} *(CVSS: {{risk_1_cvss}})*
2. **{{risk_2_title}}** — {{risk_2_description}} *(CVSS: {{risk_2_cvss}})*
3. **{{risk_3_title}}** — {{risk_3_description}} *(CVSS: {{risk_3_cvss}})*

---

## Dashboard — Vulnerabilities by Category

```
Category                  Critical  High  Medium  Low   Total
─────────────────────────────────────────────────────────────
Dependencies (CVE)        [{{d_c}}]  [{{d_h}}]  [{{d_m}}]  [{{d_l}}]  [{{d_t}}]
SAST / Code Quality       [{{s_c}}]  [{{s_h}}]  [{{s_m}}]  [{{s_l}}]  [{{s_t}}]
Secrets / Credentials     [{{k_c}}]  [{{k_h}}]  [{{k_m}}]  [{{k_l}}]  [{{k_t}}]
Supply Chain              [{{sc_c}}] [{{sc_h}}] [{{sc_m}}] [{{sc_l}}] [{{sc_t}}]
Infrastructure / Config   [{{i_c}}]  [{{i_h}}]  [{{i_m}}]  [{{i_l}}]  [{{i_t}}]
─────────────────────────────────────────────────────────────
TOTAL                     [{{tc}}]   [{{th}}]   [{{tm}}]   [{{tl}}]   [{{tt}}]

Severity Distribution (ASCII bar chart)
Critical ████░░░░░░░░░░░░░░░░  {{pct_critical}}%
High     ████████░░░░░░░░░░░░  {{pct_high}}%
Medium   ████████████░░░░░░░░  {{pct_medium}}%
Low      ████████████████░░░░  {{pct_low}}%
```

---

## Section 1 — CVE / Dependency Vulnerabilities

> **Scanner:** {{dependency_scanner}} | **SBOM:** {{sbom_tool}}

| CVE ID          | Package          | Current Version | Fixed Version  | CVSS | Severity | Description                        | Status     |
|-----------------|------------------|-----------------|----------------|------|----------|------------------------------------|------------|
| {{cve_1_id}}    | {{cve_1_pkg}}    | {{cve_1_cur}}   | {{cve_1_fix}}  | {{cve_1_cvss}} | 🔴 Critical | {{cve_1_desc}} | {{cve_1_status}} |
| {{cve_2_id}}    | {{cve_2_pkg}}    | {{cve_2_cur}}   | {{cve_2_fix}}  | {{cve_2_cvss}} | 🟠 High     | {{cve_2_desc}} | {{cve_2_status}} |
| {{cve_3_id}}    | {{cve_3_pkg}}    | {{cve_3_cur}}   | {{cve_3_fix}}  | {{cve_3_cvss}} | 🟡 Medium   | {{cve_3_desc}} | {{cve_3_status}} |
| *(add rows...)*  |                  |                 |                |      |          |                                    |            |

**Status values:** `Open` | `Accepted Risk` | `False Positive` | `In Progress` | `Fixed`

### Notable CVE Details

#### {{cve_detail_1_id}} — {{cve_detail_1_title}}

- **Package:** `{{cve_detail_1_package}}@{{cve_detail_1_version}}`
- **CVSS:** {{cve_detail_1_cvss}} ({{cve_detail_1_vector}})
- **Description:** {{cve_detail_1_description}}
- **Exploitability:** {{cve_detail_1_exploitability}}
- **Fix:** Upgrade to `{{cve_detail_1_fixed_version}}`
- **Reference:** {{cve_detail_1_nvd_url}}

---

## Section 2 — OWASP Top 10 Assessment

> **Assessment Date:** {{owasp_date}} | **Standard:** OWASP Top 10 2021

| #   | Category                                  | Status     | Findings | Notes                        |
|-----|-------------------------------------------|------------|----------|------------------------------|
| A01 | Broken Access Control                     | {{a01_status}} | {{a01_count}} | {{a01_notes}} |
| A02 | Cryptographic Failures                    | {{a02_status}} | {{a02_count}} | {{a02_notes}} |
| A03 | Injection                                 | {{a03_status}} | {{a03_count}} | {{a03_notes}} |
| A04 | Insecure Design                           | {{a04_status}} | {{a04_count}} | {{a04_notes}} |
| A05 | Security Misconfiguration                 | {{a05_status}} | {{a05_count}} | {{a05_notes}} |
| A06 | Vulnerable & Outdated Components          | {{a06_status}} | {{a06_count}} | {{a06_notes}} |
| A07 | Identification & Authentication Failures  | {{a07_status}} | {{a07_count}} | {{a07_notes}} |
| A08 | Software & Data Integrity Failures        | {{a08_status}} | {{a08_count}} | {{a08_notes}} |
| A09 | Security Logging & Monitoring Failures    | {{a09_status}} | {{a09_count}} | {{a09_notes}} |
| A10 | Server-Side Request Forgery (SSRF)        | {{a10_status}} | {{a10_count}} | {{a10_notes}} |

**Status values:** `✅ Pass` | `❌ Fail` | `⚠️ Warning` | `➖ N/A`

---

## Section 3 — SAST (Static Analysis)

> **Scanner:** Semgrep {{semgrep_version}} | **Rules:** {{semgrep_ruleset}}

### 3.1 Secrets & Hardcoded Credentials

| File                    | Line | Type              | Severity | Entropy | Action Required          |
|-------------------------|------|-------------------|----------|---------|--------------------------|
| {{secret_1_file}}       | {{secret_1_line}} | {{secret_1_type}} | 🔴 Critical | {{secret_1_entropy}} | Rotate immediately, use vault |
| {{secret_2_file}}       | {{secret_2_line}} | {{secret_2_type}} | 🔴 Critical | {{secret_2_entropy}} | {{secret_2_action}}          |
| *(add rows...)*          |      |                   |          |         |                          |

### 3.2 Dangerous Code Patterns

| Rule ID                | File                  | Line | Severity | Pattern Description              | CWE      |
|------------------------|-----------------------|------|----------|----------------------------------|----------|
| {{rule_1_id}}          | {{rule_1_file}}       | {{rule_1_line}} | {{rule_1_sev}} | {{rule_1_desc}} | {{rule_1_cwe}} |
| {{rule_2_id}}          | {{rule_2_file}}       | {{rule_2_line}} | {{rule_2_sev}} | {{rule_2_desc}} | {{rule_2_cwe}} |
| *(add rows...)*         |                       |      |          |                                  |          |

---

## Section 4 — Supply Chain Security

> **Scanner:** Syft + OSV-Scanner | **SBOM Format:** {{sbom_format}}

### 4.1 License Compliance

| Package              | License       | Risk Level | Notes                             |
|----------------------|---------------|------------|-----------------------------------|
| {{lic_1_pkg}}        | {{lic_1_lic}} | {{lic_1_risk}} | {{lic_1_notes}}               |
| *(add rows...)*       |               |            |                                   |

**Policy:** {{license_policy_summary}}

### 4.2 Abandoned / Unmaintained Packages

| Package              | Last Commit   | Maintainer Status | Alternative               |
|----------------------|---------------|-------------------|---------------------------|
| {{aband_1_pkg}}      | {{aband_1_date}} | {{aband_1_status}} | {{aband_1_alternative}} |
| *(add rows...)*       |               |                   |                           |

### 4.3 Typosquatting Suspects

| Package (found)       | Likely Target | Risk  | Action          |
|-----------------------|---------------|-------|-----------------|
| {{typo_1_found}}      | {{typo_1_target}} | {{typo_1_risk}} | {{typo_1_action}} |
| *(add rows...)*        |               |       |                 |

---

## Section 5 — Remediations

### Priority Matrix

| Priority | Finding                    | Effort       | Sprint     |
|----------|---------------------------|--------------|------------|
| P0       | {{p0_finding}}             | Quick Win    | Sprint 1   |
| P1       | {{p1_finding}}             | {{p1_effort}} | Sprint 1  |
| P2       | {{p2_finding}}             | {{p2_effort}} | Sprint 2  |
| P3       | {{p3_finding}}             | {{p3_effort}} | Sprint 3  |

---

### Code Examples

#### Example 1 — SQL Injection (Java)

**Before (vulnerable):**
```java
// CWE-89: SQL Injection via string concatenation
String query = "SELECT * FROM users WHERE username = '" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**After (fixed):**
```java
// Use PreparedStatement with parameterized query
String query = "SELECT * FROM users WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

---

#### Example 2 — Hardcoded Secret (C#)

**Before (vulnerable):**
```csharp
// CWE-798: Hardcoded credential
private const string ApiKey = "sk-prod-abc123secretkey";
var client = new HttpClient();
client.DefaultRequestHeaders.Add("X-API-Key", ApiKey);
```

**After (fixed):**
```csharp
// Read from environment variable or secret manager
var apiKey = Environment.GetEnvironmentVariable("API_KEY")
    ?? throw new InvalidOperationException("API_KEY not configured");
var client = new HttpClient();
client.DefaultRequestHeaders.Add("X-API-Key", apiKey);
```

---

#### Example 3 — Prototype Pollution (JavaScript/TypeScript)

**Before (vulnerable):**
```javascript
// CWE-1321: Prototype pollution via recursive merge
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key]; // __proto__ can be overwritten
  }
}
```

**After (fixed):**
```javascript
// Use Object.assign with null prototype or structured clone
function merge(target, source) {
  const safeSource = JSON.parse(JSON.stringify(source)); // strip prototype
  return Object.assign(Object.create(null), target, safeSource);
}
```

---

#### Example 4 — Insecure Dependency (Python)

**Before (vulnerable):**
```python
# requirements.txt — pinned to vulnerable version
requests==2.25.0  # CVE-2023-32681: redirect header leakage
```

**After (fixed):**
```python
# requirements.txt — upgrade to patched version
requests>=2.31.0
```

---

#### Example 5 — COBOL: Unvalidated External Input

**Before (vulnerable):**
```cobol
* CWE-20: Input not validated before use in file operation
MOVE WS-USER-INPUT TO WS-FILENAME
OPEN INPUT WS-FILENAME
```

**After (fixed):**
```cobol
* Validate input against allowed filename pattern before use
MOVE WS-USER-INPUT TO WS-FILENAME
PERFORM VALIDATE-FILENAME
IF WS-VALIDATION-STATUS = 'VALID'
    OPEN INPUT WS-FILENAME
ELSE
    PERFORM LOG-INVALID-INPUT-ERROR
END-IF
```

---

## Sprint Roadmap

### Sprint 1 — Critical (Immediate)
> Target: {{sprint1_end_date}}

- [ ] {{sprint1_task_1}}
- [ ] {{sprint1_task_2}}
- [ ] {{sprint1_task_3}}
- [ ] Rotate all exposed secrets in {{secret_store}}
- [ ] Upgrade `{{critical_pkg}}` to `{{critical_pkg_fixed}}`

### Sprint 2 — High Severity
> Target: {{sprint2_end_date}}

- [ ] {{sprint2_task_1}}
- [ ] {{sprint2_task_2}}
- [ ] {{sprint2_task_3}}

### Sprint 3 — Medium / Hardening
> Target: {{sprint3_end_date}}

- [ ] {{sprint3_task_1}}
- [ ] {{sprint3_task_2}}
- [ ] Implement SBOM generation in CI pipeline
- [ ] Add Semgrep to pre-commit hooks

---

## Annexes

### Annex A — Scan Commands (Reproducible)

```bash
# 1. Dependency scanning with Grype
grype dir:{{project_path}} --output table --fail-on critical

# 2. Container/filesystem scan with Trivy
trivy fs {{project_path}} --severity CRITICAL,HIGH --format json -o trivy-results.json

# 3. SAST with Semgrep
semgrep --config=p/owasp-top-ten --config=p/secrets \
  --json -o semgrep-results.json {{project_path}}

# 4. Secret detection with Gitleaks
gitleaks detect --source={{project_path}} \
  --report-format json --report-path gitleaks-results.json

# 5. .NET audit
dotnet list package --vulnerable --include-transitive

# 6. NPM audit
npm audit --json > npm-audit-results.json

# 7. Maven dependency check
mvn org.owasp:dependency-check-maven:check \
  -DfailBuildOnCVSS=7 -Dformat=JSON

# 8. Python packages
pip-audit --format json -o pip-audit-results.json

# 9. SBOM generation
syft packages {{project_path}} -o spdx-json > sbom.spdx.json

# 10. OSV vulnerability scan against SBOM
osv-scanner --sbom sbom.spdx.json --format json
```

### Annex B — Tool Versions

| Tool      | Version Used         |
|-----------|----------------------|
| Grype     | {{grype_version}}    |
| Trivy     | {{trivy_version}}    |
| Semgrep   | {{semgrep_version}}  |
| Gitleaks  | {{gitleaks_version}} |
| Syft      | {{syft_version}}     |
| OSV       | {{osv_version}}      |

### Annex C — References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [NVD CVE Database](https://nvd.nist.gov/vuln/search)
- [OSV Advisory Database](https://osv.dev/)
- [CWE List](https://cwe.mitre.org/data/index.html)
- [Semgrep Rules](https://semgrep.dev/r)

---

*Report generated by CyberStrikeAI DevSec Team | {{report_date}} | Confidential — Internal Use Only*
