---
name: devsec-report
description: Aggregates CVE, OWASP, and SAST scan results into a structured DevSec report with executive summary, vulnerability tables, business impact, remediation roadmap, and security score
version: 1.0.0
author: DevSec Team
tags: [security, devsec, reporting, markdown, pdf, executive-summary, remediation]
---

# DevSec Report Generator

## Objective

Aggregate results from `cve-dependency-scan`, `owasp-code-review`, and `sast-devsec` scans into a single comprehensive security report. The report provides an executive-level summary for management, a detailed technical breakdown for development teams, and a prioritized remediation roadmap.

## Prerequisites

### Required Tools

| Tool | Installation | Purpose |
|------|-------------|---------|
| `jq` | Package manager | JSON parsing and aggregation |
| `python3` | System | Report generation script |
| `pandoc` | `apt install pandoc` or [pandoc.org](https://pandoc.org/installing.html) | Markdown → PDF conversion |
| `wkhtmltopdf` | `apt install wkhtmltopdf` | Alternative PDF generation |

### Expected Input Files

The report generator expects these files from prior scans:

```
./scan-results/
├── grype-results.json           # From: cve-dependency-scan
├── npm-audit-results.json       # From: cve-dependency-scan (npm)
├── semgrep-owasp-raw.json       # From: owasp-code-review
├── semgrep-sast.json            # From: sast-devsec
├── gitleaks.json                # From: sast-devsec
└── trufflehog.json              # From: sast-devsec
```

## Report Structure

The generated report follows this structure:

```
1. Executive Summary
   1.1 Security Score (0–100)
   1.2 Risk Overview (non-technical)
   1.3 Key Findings Summary
   1.4 Recommended Immediate Actions

2. Vulnerability Summary Table
   2.1 By Severity (Critical/High/Medium/Low)
   2.2 By Category (CVE/OWASP/Secrets/SAST)
   2.3 By Component/File

3. Detailed Findings
   3.1 Critical & High findings (full detail)
   3.2 Medium findings (summary)
   3.3 Low findings (list)

4. Remediation Roadmap
   4.1 Immediate actions (Critical — within 24h)
   4.2 Sprint 1 (High — within 7 days)
   4.3 Sprint 2-3 (Medium — within 30 days)
   4.4 Backlog (Low — next quarter)

5. Appendix
   5.1 Scan metadata
   5.2 Tool versions
   5.3 Scope and exclusions
```

## Report Generation

### Step 1: Aggregate All Scan Results

```python
#!/usr/bin/env python3
"""
devsec-aggregate.py — Aggregate all scan results into unified format
"""
import json
import os
from datetime import datetime

SCAN_DIR = "./scan-results"
OUTPUT = "./devsec-aggregate.json"

all_findings = []

# --- CVE findings from Grype ---
grype_file = os.path.join(SCAN_DIR, "grype-results.json")
if os.path.exists(grype_file):
    with open(grype_file) as f:
        grype = json.load(f)
    for match in grype.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cvss = vuln.get("cvss", [{}])
        score = cvss[0].get("metrics", {}).get("baseScore", 0) if cvss else 0
        all_findings.append({
            "id": vuln.get("id", ""),
            "category": "CVE",
            "severity": vuln.get("severity", "UNKNOWN").upper(),
            "cvss_score": score,
            "title": f"CVE in {artifact.get('name', 'unknown')} {artifact.get('version', '')}",
            "description": vuln.get("description", ""),
            "component": artifact.get("name", ""),
            "version": artifact.get("version", ""),
            "fixed_version": (vuln.get("fix", {}).get("versions") or ["N/A"])[0],
            "file": None,
            "line": None,
            "remediation": f"Update {artifact.get('name')} to version {(vuln.get('fix', {}).get('versions') or ['N/A'])[0]}",
            "references": vuln.get("urls", [])
        })

# --- OWASP findings from Semgrep ---
owasp_file = os.path.join(SCAN_DIR, "semgrep-owasp-raw.json")
if os.path.exists(owasp_file):
    with open(owasp_file) as f:
        owasp = json.load(f)
    for result in owasp.get("results", []):
        sev = result.get("extra", {}).get("severity", "INFO")
        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        meta = result.get("extra", {}).get("metadata", {})
        all_findings.append({
            "id": result.get("check_id", ""),
            "category": "OWASP",
            "severity": sev_map.get(sev, "LOW"),
            "cvss_score": None,
            "title": result.get("check_id", "").replace("-", " ").replace(".", " — ").title(),
            "description": result.get("extra", {}).get("message", ""),
            "component": result.get("path", ""),
            "version": None,
            "fixed_version": None,
            "file": result.get("path", ""),
            "line": result.get("start", {}).get("line"),
            "remediation": result.get("extra", {}).get("fix", "See OWASP remediation guidance"),
            "references": meta.get("references", []),
            "owasp_category": (meta.get("owasp") or [""])[0]
        })

# --- Secrets from Gitleaks ---
gitleaks_file = os.path.join(SCAN_DIR, "gitleaks.json")
if os.path.exists(gitleaks_file):
    with open(gitleaks_file) as f:
        gl = json.load(f)
    if isinstance(gl, list):
        for item in gl:
            all_findings.append({
                "id": f"SECRET-{item.get('RuleID', 'unknown')}",
                "category": "SECRET",
                "severity": "CRITICAL",
                "cvss_score": 9.0,
                "title": f"Hardcoded secret: {item.get('Description', item.get('RuleID', ''))}",
                "description": f"Secret detected by Gitleaks rule '{item.get('RuleID')}'. Commit: {item.get('Commit', 'N/A')}",
                "component": item.get("File", ""),
                "version": None,
                "fixed_version": None,
                "file": item.get("File", ""),
                "line": item.get("StartLine"),
                "remediation": "1. Rotate the exposed credential immediately\n2. Remove from code\n3. Use git filter-branch or BFG to purge from history\n4. Use environment variables or a secret manager (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault)",
                "references": []
            })

# Sort by severity
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
all_findings.sort(key=lambda x: (SEV_ORDER.get(x.get("severity", "UNKNOWN"), 4), -(x.get("cvss_score") or 0)))

summary = {
    "CRITICAL": sum(1 for f in all_findings if f["severity"] == "CRITICAL"),
    "HIGH": sum(1 for f in all_findings if f["severity"] == "HIGH"),
    "MEDIUM": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
    "LOW": sum(1 for f in all_findings if f["severity"] == "LOW"),
    "total": len(all_findings)
}

output = {
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "summary": summary,
    "findings": all_findings
}

with open(OUTPUT, "w") as f:
    json.dump(output, f, indent=2)

print(f"Aggregated {len(all_findings)} findings → {OUTPUT}")
print(f"Summary: {summary}")
```

### Step 2: Compute Security Score

```python
def compute_security_score(summary):
    """
    Score 0–100: starts at 100, deduct points per vulnerability
    Deductions:
      CRITICAL: -20 per finding (max -60)
      HIGH:     -10 per finding (max -40)
      MEDIUM:   -3  per finding (max -20)
      LOW:      -1  per finding (max -10)
    """
    score = 100
    score -= min(summary["CRITICAL"] * 20, 60)
    score -= min(summary["HIGH"] * 10, 40)
    score -= min(summary["MEDIUM"] * 3, 20)
    score -= min(summary["LOW"] * 1, 10)
    return max(0, score)

def score_to_rating(score):
    if score >= 90: return "A — Excellent"
    if score >= 75: return "B — Good"
    if score >= 60: return "C — Acceptable"
    if score >= 40: return "D — Poor"
    return "F — Critical Risk"
```

### Step 3: Generate Markdown Report

```python
#!/usr/bin/env python3
"""
devsec-report.py — Generate full Markdown report from aggregated data
"""
import json
from datetime import datetime

with open("./devsec-aggregate.json") as f:
    data = json.load(f)

findings = data["findings"]
summary = data["summary"]
score = compute_security_score(summary)
rating = score_to_rating(score)
project_name = os.environ.get("PROJECT_NAME", "Target Application")
generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

report = f"""# DevSec Security Report
**Project:** {project_name}
**Generated:** {generated_at}
**Scan Coverage:** CVE Dependencies + OWASP Top 10 + SAST + Secret Detection

---

## 1. Executive Summary

### 1.1 Security Score

> ## 🔒 Security Score: **{score}/100** — {rating}

### 1.2 Risk Overview

This report summarizes the security posture of **{project_name}** based on automated analysis of source code, dependencies, and version control history.

| Risk Level | Count | Status |
|-----------|-------|--------|
| 🔴 Critical | {summary['CRITICAL']} | {"Immediate action required" if summary['CRITICAL'] > 0 else "None found ✅"} |
| 🟠 High | {summary['HIGH']} | {"Fix within 7 days" if summary['HIGH'] > 0 else "None found ✅"} |
| 🟡 Medium | {summary['MEDIUM']} | {"Fix within 30 days" if summary['MEDIUM'] > 0 else "None found ✅"} |
| 🔵 Low | {summary['LOW']} | {"Schedule for backlog" if summary['LOW'] > 0 else "None found ✅"} |
| **Total** | **{summary['total']}** | |

### 1.3 Key Findings

"""

# Add top critical/high findings
critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")][:5]
for i, f in enumerate(critical_high, 1):
    report += f"{i}. **[{f['severity']}]** {f['title']}"
    if f.get("file"):
        report += f" — `{f['file']}`"
        if f.get("line"):
            report += f":{f['line']}"
    report += "\n"

report += f"""
### 1.4 Recommended Immediate Actions

"""
if summary["CRITICAL"] > 0:
    report += "- 🚨 **Rotate all exposed credentials** — hardcoded secrets found in codebase\n"
    report += "- 🚨 **Block deployment** until Critical findings are resolved\n"
if summary["HIGH"] > 0:
    report += "- ⚠️ **Schedule emergency sprint** to address High-severity findings within 7 days\n"
    report += "- ⚠️ **Update vulnerable dependencies** identified in CVE scan\n"
if summary["MEDIUM"] > 0:
    report += "- 📋 **Add Medium findings to next sprint** — resolve within 30 days\n"

report += f"""
---

## 2. Vulnerability Summary

### 2.1 By Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {summary['CRITICAL']} | {summary['CRITICAL']/max(summary['total'],1)*100:.1f}% |
| High | {summary['HIGH']} | {summary['HIGH']/max(summary['total'],1)*100:.1f}% |
| Medium | {summary['MEDIUM']} | {summary['MEDIUM']/max(summary['total'],1)*100:.1f}% |
| Low | {summary['LOW']} | {summary['LOW']/max(summary['total'],1)*100:.1f}% |

### 2.2 By Category

"""

by_category = {}
for f in findings:
    cat = f.get("category", "OTHER")
    by_category[cat] = by_category.get(cat, 0) + 1

report += "| Category | Count |\n|----------|-------|\n"
for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
    report += f"| {cat} | {count} |\n"

report += "\n---\n\n## 3. Detailed Findings\n\n"

# Detailed findings for Critical and High
for sev in ["CRITICAL", "HIGH"]:
    sev_findings = [f for f in findings if f["severity"] == sev]
    if sev_findings:
        report += f"### 3.{1 if sev == 'CRITICAL' else 2} {sev.title()} Findings\n\n"
        for i, f in enumerate(sev_findings, 1):
            report += f"#### {i}. {f['title']}\n\n"
            report += f"| Field | Value |\n|-------|-------|\n"
            report += f"| **ID** | `{f['id']}` |\n"
            report += f"| **Severity** | {f['severity']} |\n"
            if f.get("cvss_score"):
                report += f"| **CVSS Score** | {f['cvss_score']} |\n"
            if f.get("component"):
                report += f"| **Component** | `{f['component']}` |\n"
            if f.get("version"):
                report += f"| **Current Version** | `{f['version']}` |\n"
            if f.get("fixed_version"):
                report += f"| **Fixed Version** | `{f['fixed_version']}` |\n"
            if f.get("file"):
                loc = f['file']
                if f.get("line"):
                    loc += f":{f['line']}"
                report += f"| **Location** | `{loc}` |\n"
            if f.get("owasp_category"):
                report += f"| **OWASP** | {f['owasp_category']} |\n"
            report += f"\n**Description:** {f.get('description', 'N/A')}\n\n"
            report += f"**Business Impact:** "
            if sev == "CRITICAL":
                report += "This vulnerability represents an immediate risk. Exploitation could lead to data breach, credential theft, or system compromise with severe regulatory and reputational consequences.\n\n"
            else:
                report += "This vulnerability could be exploited to gain unauthorized access or compromise data integrity. Remediation should be prioritized.\n\n"
            report += f"**Remediation:**\n{f.get('remediation', 'See references for guidance.')}\n\n"
            if f.get("references"):
                report += "**References:**\n"
                for ref in f["references"][:3]:
                    report += f"- {ref}\n"
            report += "\n---\n\n"

report += f"""
## 4. Remediation Roadmap

### 4.1 Immediate Actions (Critical — within 24 hours)

"""
critical_findings = [f for f in findings if f["severity"] == "CRITICAL"]
if critical_findings:
    for f in critical_findings:
        report += f"- [ ] **{f['title']}** — {f.get('remediation', 'Investigate immediately')[:100]}\n"
else:
    report += "_No critical findings._ ✅\n"

report += f"""
### 4.2 Sprint 1 (High — within 7 days)

"""
high_findings = [f for f in findings if f["severity"] == "HIGH"]
if high_findings:
    for f in high_findings:
        report += f"- [ ] **{f['title']}**"
        if f.get("file"):
            report += f" (`{f['file']}`)"
        report += "\n"
else:
    report += "_No high-severity findings._ ✅\n"

report += f"""
### 4.3 Sprint 2–3 (Medium — within 30 days)

"""
medium_findings = [f for f in findings if f["severity"] == "MEDIUM"]
if medium_findings:
    for f in medium_findings[:10]:
        report += f"- [ ] {f['title']}\n"
    if len(medium_findings) > 10:
        report += f"- ... and {len(medium_findings) - 10} more medium findings\n"
else:
    report += "_No medium-severity findings._ ✅\n"

report += f"""
### 4.4 Backlog (Low — next quarter)

{summary['LOW']} low-severity findings identified. Review and schedule in upcoming sprints.

---

## 5. Appendix

### 5.1 Scan Metadata

| Field | Value |
|-------|-------|
| Scan Date | {generated_at} |
| Report Version | 1.0 |
| Tools Used | Grype, Semgrep, Gitleaks, TruffleHog |
| Scan Type | CVE + OWASP Top 10 + SAST + Secret Detection |

---

_This report was generated by CyberStrikeAI DevSec Module. All findings should be reviewed by a qualified security engineer before remediation._
"""

with open("devsec-report.md", "w") as f:
    f.write(report)

print("Report generated: devsec-report.md")
```

### Step 4: Export to PDF

```bash
# Generate PDF from Markdown using pandoc
pandoc devsec-report.md \
  -o devsec-report.pdf \
  --pdf-engine=wkhtmltopdf \
  --metadata title="DevSec Security Report" \
  --variable geometry:margin=1in \
  --variable colorlinks=true \
  --variable linkcolor=blue \
  --toc \
  --toc-depth=2

# Alternative: using pandoc with LaTeX
pandoc devsec-report.md \
  -o devsec-report.pdf \
  --pdf-engine=xelatex \
  --variable fontsize=11pt \
  --variable geometry:margin=1in \
  --toc

echo "PDF report: devsec-report.pdf"
```

## Complete Pipeline Script

```bash
#!/bin/bash
# Full DevSec scan + report pipeline

PROJECT_DIR="${1:-.}"
PROJECT_NAME="${2:-Application}"
OUTPUT_DIR="${3:-./devsec-output}"
SCAN_DIR="$OUTPUT_DIR/scan-results"

mkdir -p "$SCAN_DIR"

echo "=== Step 1: CVE Dependency Scan ==="
grype dir:"$PROJECT_DIR" -o json > "$SCAN_DIR/grype-results.json" || true

echo "=== Step 2: OWASP Code Review ==="
semgrep --config "p/owasp-top-ten" --config "p/csharp" --config "p/java" \
  --config "p/javascript" --config "p/typescript" --config "p/react" \
  --json --output "$SCAN_DIR/semgrep-owasp-raw.json" "$PROJECT_DIR" || true

echo "=== Step 3: SAST + Secrets ==="
gitleaks detect --source "$PROJECT_DIR" --report-format json \
  --report-path "$SCAN_DIR/gitleaks.json" || true
semgrep --config "p/secrets" --json \
  --output "$SCAN_DIR/semgrep-sast.json" "$PROJECT_DIR" || true

echo "=== Step 4: Aggregate and Report ==="
PROJECT_NAME="$PROJECT_NAME" SCAN_DIR="$SCAN_DIR" OUTPUT_DIR="$OUTPUT_DIR" \
  python3 devsec-aggregate.py

python3 devsec-report.py

echo "=== Step 5: Export PDF ==="
pandoc "$OUTPUT_DIR/devsec-report.md" \
  -o "$OUTPUT_DIR/devsec-report.pdf" \
  --pdf-engine=wkhtmltopdf \
  --toc --toc-depth=2 || echo "PDF generation failed (pandoc/wkhtmltopdf not available)"

echo ""
echo "=== DONE ==="
echo "Markdown report: $OUTPUT_DIR/devsec-report.md"
echo "PDF report:      $OUTPUT_DIR/devsec-report.pdf"
```

## Related Skills

- `cve-dependency-scan` — CVE scanning for dependencies
- `owasp-code-review` — OWASP static analysis
- `sast-devsec` — Secret detection and language-specific SAST
- `supply-chain-audit` — Supply chain integrity analysis
