# Usage Guide — CyberStrikeAI DevSec

This guide covers day-to-day usage of CyberStrikeAI security tools for development teams.

---

## Table of Contents

1. [5 Essential Commands](#5-essential-commands)
2. [Scanning a C#/.NET Project](#scanning-a-cnet-project)
3. [Scanning a Java/Maven Project](#scanning-a-javamaven-project)
4. [Scanning a React/TypeScript Project](#scanning-a-reacttypescript-project)
5. [Scanning a COBOL Project](#scanning-a-cobol-project)
6. [Interpreting CVE Results](#interpreting-cve-results)
7. [Interpreting OWASP Results](#interpreting-owasp-results)
8. [Generating and Sharing Reports](#generating-and-sharing-reports)
9. [FAQ](#faq)

---

## 5 Essential Commands

These five commands cover the majority of daily DevSec needs:

> **Windows users:** See [Windows Usage](#windows-powershell-usage) for PowerShell equivalents of every command in this guide.

```bash
# 1. Quick CVE scan of current directory
grype dir:. --severity high

# 2. SAST scan for code vulnerabilities
semgrep scan --config auto .

# 3. Scan for secrets accidentally committed
gitleaks detect --source .

# 4. Full OWASP dependency audit
trivy fs . --severity HIGH,CRITICAL

# 5. Generate SBOM + OSV scan
syft dir:. -o cyclonedx-json=sbom.json && \
    osv-scanner --sbom=sbom.json
```

---

## Scanning a C#/.NET Project

### Step 1 — Restore dependencies first

```bash
cd /path/to/your/dotnet-project
dotnet restore
```

### Step 2 — CVE scan on NuGet packages

```bash
# Grype detects NuGet packages from *.csproj and packages.lock.json
grype dir:. \
    --output table \
    --severity high

# More detailed JSON output
grype dir:. \
    --output json \
    --file security-reports/cve-results.json \
    --add-cpes-if-none
```

### Step 3 — SAST scan (C# rules)

```bash
# Semgrep has specific C# / .NET rulesets
semgrep scan \
    --config "p/csharp" \
    --config "p/owasp-top-ten" \
    --json \
    --output security-reports/sast-results.json \
    .
```

### Step 4 — Secret scan

```bash
gitleaks detect \
    --source . \
    --report-format json \
    --report-path security-reports/secrets.json
```

### Step 5 — Review results

```bash
# Show CVE summary
jq '.matches | group_by(.vulnerability.severity) | map({severity: .[0].vulnerability.severity, count: length})' \
    security-reports/cve-results.json

# Show SAST findings by rule
jq '[.results[] | {rule: .check_id, file: .path, line: .start.line, message: .extra.message}]' \
    security-reports/sast-results.json
```

---

## Scanning a Java/Maven Project

### Step 1 — Build first

```bash
cd /path/to/java-project
mvn dependency:resolve -q
# or for Gradle:
./gradlew dependencies
```

### Step 2 — CVE scan on Maven/Gradle dependencies

```bash
# Grype reads pom.xml, build.gradle, and JAR files
grype dir:. \
    --output table \
    --severity high

# Include transitive dependencies
trivy fs . \
    --severity HIGH,CRITICAL \
    --format table
```

### Step 3 — SAST scan (Java rules)

```bash
semgrep scan \
    --config "p/java" \
    --config "p/owasp-top-ten" \
    --config "p/spring-boot" \
    --json \
    --output security-reports/java-sast.json \
    src/
```

### Step 4 — Check for deserialization issues specifically

```bash
# Custom Semgrep rule for Java deserialization
semgrep scan \
    --config "p/java-deserialization" \
    --output security-reports/deser-findings.json \
    src/
```

### Step 5 — Generate SBOM

```bash
syft dir:. \
    -o cyclonedx-json=security-reports/java-sbom.json

# Scan SBOM against OSV database
osv-scanner --sbom=security-reports/java-sbom.json
```

---

## Scanning a React/TypeScript Project

### Step 1 — Install dependencies

```bash
cd /path/to/react-project
npm ci   # prefer ci over install for reproducible results
```

### Step 2 — npm audit (baseline)

```bash
npm audit --json > security-reports/npm-audit.json || true
npm audit --audit-level=high
```

### Step 3 — CVE scan with Grype

```bash
# Grype reads package-lock.json and node_modules
grype dir:. \
    --output table \
    --severity high
```

### Step 4 — SAST scan (JavaScript/TypeScript rules)

```bash
semgrep scan \
    --config "p/javascript" \
    --config "p/typescript" \
    --config "p/react" \
    --config "p/xss" \
    --config "p/owasp-top-ten" \
    --json \
    --output security-reports/ts-sast.json \
    src/

# Review XSS-specific findings
jq '[.results[] | select(.check_id | contains("xss"))]' \
    security-reports/ts-sast.json
```

### Step 5 — Secret scan (especially for .env files)

```bash
# Gitleaks checks .env files, config files, etc.
gitleaks detect \
    --source . \
    --report-format json \
    --report-path security-reports/ts-secrets.json

# Also check for secrets in git history
gitleaks detect \
    --source . \
    --log-opts="--all" \
    --report-format json \
    --report-path security-reports/ts-secrets-history.json
```

### Step 6 — Dependency confusion check

```bash
# Trivy checks for typosquatting and dependency confusion
trivy fs . \
    --scanners vuln,secret \
    --format json \
    --output security-reports/ts-trivy.json
```

---

## Scanning a COBOL Project

COBOL is primarily scanned for:
- Hardcoded credentials in source files
- SQL injection in embedded SQL (EXEC SQL)
- Buffer overflows in data definitions

### Step 1 — Secret scan (most critical for COBOL)

```bash
# Gitleaks with extended patterns for COBOL
gitleaks detect \
    --source . \
    --report-format json \
    --report-path security-reports/cobol-secrets.json \
    --config .gitleaks-cobol.toml
```

Create `.gitleaks-cobol.toml` for COBOL-specific patterns:

```toml
[extend]
useDefault = true

[[rules]]
id = "cobol-hardcoded-password"
description = "Hardcoded password in COBOL"
regex = '''(?i)(PASSWORD|PASSWD|PWD|PASS)\s+(PIC|VALUE)\s+['"]([^'"]{4,})['"]'''
tags = ["cobol", "password", "credentials"]

[[rules]]
id = "cobol-hardcoded-userid"
description = "Hardcoded user ID in COBOL"
regex = '''(?i)(USER-ID|USERID|USERNAME)\s+VALUE\s+['"]([^'"]{3,})['"]'''
tags = ["cobol", "credentials"]

[[rules]]
id = "cobol-db-connection-string"
description = "Hardcoded database connection in COBOL"
regex = '''(?i)CONNECT\s+TO\s+['"][^'"]+['"]\s+USER\s+['"][^'"]+['"]'''
tags = ["cobol", "database", "credentials"]
```

### Step 2 — SAST for COBOL SQL injection

```bash
# Semgrep COBOL rules (community rules)
semgrep scan \
    --config "r/cobol" \
    --json \
    --output security-reports/cobol-sast.json \
    . || true

# Manual grep patterns for SQL injection risks
grep -rn "EXEC SQL" . \
    --include="*.cbl" --include="*.cob" --include="*.CBL" \
    > security-reports/cobol-sql-usage.txt
```

### Step 3 — Check for unsafe data definitions

```bash
# Find OCCURS without DEPENDING ON (potential buffer issues)
grep -rn "OCCURS\s\+[0-9]\+\s\+TIMES" . \
    --include="*.cbl" --include="*.cob" \
    > security-reports/cobol-occurs.txt

echo "Review cobol-occurs.txt — verify bounds are validated in PROCEDURE DIVISION"
```

---

## Interpreting CVE Results

### CVSS Score Scale

| CVSS Score | Severity | Action Required |
|------------|----------|-----------------|
| 9.0 – 10.0 | **Critical** | Fix immediately — block deployment |
| 7.0 – 8.9 | **High** | Fix within 7 days |
| 4.0 – 6.9 | **Medium** | Fix within 30 days |
| 0.1 – 3.9 | **Low** | Fix in next release cycle |
| 0.0 | **None** | Informational only |

### What a CVE Entry Means

```json
{
  "vulnerability": {
    "id": "CVE-2021-44228",           // CVE identifier
    "severity": "Critical",           // Severity level
    "cvss": {
      "score": 10.0,                  // CVSS base score
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    },
    "description": "Apache Log4j2...", // Human-readable description
    "fix": {
      "versions": ["2.17.1"]          // Versions that fix the issue
    }
  },
  "artifact": {
    "name": "log4j-core",             // Affected package
    "version": "2.14.1",              // Your current version
    "locations": ["pom.xml"]          // Where it's declared
  }
}
```

### CVSS Vector Breakdown

The CVSS vector `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` means:
- **AV:N** — Attack Vector: Network (exploitable remotely)
- **AC:L** — Attack Complexity: Low (no special conditions)
- **PR:N** — Privileges Required: None (no authentication)
- **UI:N** — User Interaction: None (no user action needed)
- **S:C** — Scope: Changed (impacts beyond the vulnerable component)
- **C:H** — Confidentiality: High
- **I:H** — Integrity: High
- **A:H** — Availability: High

### Prioritization Framework

```
1. CRITICAL + Network exploitable + No authentication → Fix NOW
2. HIGH + direct dependency → Fix this sprint
3. HIGH + transitive dependency → Fix next sprint
4. MEDIUM → Add to backlog
5. LOW → Optional / next release
```

---

## Interpreting OWASP Results

### OWASP Top 10 (2021) Priority Guide

| Rank | Category | Priority |
|------|----------|----------|
| A01 | Broken Access Control | 🔴 Critical |
| A02 | Cryptographic Failures | 🔴 Critical |
| A03 | Injection (SQL, LDAP, OS) | 🔴 Critical |
| A04 | Insecure Design | 🟠 High |
| A05 | Security Misconfiguration | 🟠 High |
| A06 | Vulnerable Components | 🟠 High |
| A07 | Authentication Failures | 🟠 High |
| A08 | Software/Data Integrity Failures | 🟡 Medium |
| A09 | Security Logging Failures | 🟡 Medium |
| A10 | SSRF | 🟡 Medium |

### Reading Semgrep OWASP Output

```json
{
  "check_id": "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli",
  "path": "src/main/java/UserService.java",
  "start": { "line": 42 },
  "end": { "line": 42 },
  "extra": {
    "message": "Detected SQL statement constructed with user input. This could lead to SQL injection.",
    "severity": "ERROR",
    "metadata": {
      "owasp": ["A03:2021 - Injection"],
      "cwe": ["CWE-89: Improper Neutralization of Special Elements"]
    }
  }
}
```

**What to do:**
1. Open `src/main/java/UserService.java` line 42
2. Find the SQL string concatenation
3. Replace with parameterized query (see remediation guide)
4. Re-run scan to verify fix

---

## Generating and Sharing Reports

### Generate a Markdown Report

```bash
#!/usr/bin/env bash
TARGET="${1:-.}"
OUTPUT="${2:-./security-report.md}"

mkdir -p "$(dirname "$OUTPUT")"

# Run scans
grype dir:"$TARGET" --output json --file /tmp/grype.json 2>/dev/null || true
semgrep scan --config auto --json --output /tmp/semgrep.json "$TARGET" 2>/dev/null || true
gitleaks detect --source "$TARGET" --report-format json --report-path /tmp/gitleaks.json 2>/dev/null || true

# Parse counts
CVE_CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' /tmp/grype.json 2>/dev/null || echo 0)
CVE_HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' /tmp/grype.json 2>/dev/null || echo 0)
SAST=$(jq '.results | length' /tmp/semgrep.json 2>/dev/null || echo 0)
SECRETS=$(jq '. | length' /tmp/gitleaks.json 2>/dev/null || echo 0)

STATUS="✅ PASSED"
[ "$CVE_CRITICAL" -gt 0 ] || [ "$SECRETS" -gt 0 ] && STATUS="❌ FAILED"

# Write report
cat > "$OUTPUT" <<EOF
# Security Scan Report

**Date:** $(date -u "+%Y-%m-%d %H:%M UTC")
**Target:** $TARGET
**Status:** $STATUS

## Summary

| Check | Count | Status |
|-------|-------|--------|
| CVE Critical | $CVE_CRITICAL | $([ "$CVE_CRITICAL" -gt 0 ] && echo "❌" || echo "✅") |
| CVE High | $CVE_HIGH | $([ "$CVE_HIGH" -gt 0 ] && echo "⚠️" || echo "✅") |
| SAST Findings | $SAST | $([ "$SAST" -gt 0 ] && echo "⚠️" || echo "✅") |
| Secrets | $SECRETS | $([ "$SECRETS" -gt 0 ] && echo "❌" || echo "✅") |

## CVE Details

\`\`\`json
$(jq '[.matches[] | {id: .vulnerability.id, severity: .vulnerability.severity, package: .artifact.name, version: .artifact.version, fix: .vulnerability.fix.versions}] | sort_by(.severity)' /tmp/grype.json 2>/dev/null || echo "[]")
\`\`\`

## SAST Findings

\`\`\`json
$(jq '[.results[] | {rule: .check_id, file: .path, line: .start.line, message: .extra.message}]' /tmp/semgrep.json 2>/dev/null || echo "[]")
\`\`\`

---
*Generated by CyberStrikeAI DevSec*
EOF

echo "Report written to: $OUTPUT"
```

### Générer un rapport manuellement

```bash
export PATH="$PATH:$HOME/.local/bin"
python3 scripts/generate-report.py \
  --results-dir ./security-reports \
  --output ./security-reports/report.pdf \
  --level 1 --format pdf
```

---

## FAQ

### Q: I'm getting too many false positives — how do I suppress them?

Add a `.semgrepignore` file for SAST:

```
# .semgrepignore
tests/
**/*_test.go
**/*.spec.ts
vendor/
node_modules/
```

For CVE false positives, add a suppression in `~/.cyberstrike/config.yaml`:

```yaml
suppress:
  - cve_id: CVE-2022-XXXXX
    reason: "Not exploitable — dependency not used at runtime"
    expires: "2026-06-30"
    ticket: "JIRA-1234"
```

### Q: How do I suppress a specific Gitleaks warning?

Add an inline comment in your code:

```python
API_KEY = "test-key-for-unit-tests"  # gitleaks:allow
```

Or add to `.gitleaksignore`:

```
# .gitleaksignore
path/to/test/fixtures/test-credentials.json
```

### Q: Semgrep is finding issues in test files — how do I exclude them?

```bash
semgrep scan \
    --config auto \
    --exclude-rule "p/secrets" \
    --exclude "tests/" \
    --exclude "**/*.test.*" \
    .
```

### Q: How do I update the vulnerability databases?

```bash
# Grype — update vulnerability database
grype db update

# Trivy — update vulnerability database
trivy image --download-db-only

# OSV — always fetches latest (no local cache needed)
```

### Q: A critical CVE is in a transitive dependency I can't update — what now?

1. **Check if exploitable** — Is the vulnerable code path actually reachable?
2. **Check for workarounds** — Many CVEs have configuration-based mitigations.
3. **Add suppression with justification** — Document why it's not exploitable.
4. **Track in issue tracker** — Create a ticket to fix when the direct dep provides an update.
5. **Implement compensating controls** — WAF rules, input validation, network isolation.

### Q: How do I customize scan rules for my organization?

Create custom Semgrep rules in `~/.cyberstrike/rules/`:

```yaml
# ~/.cyberstrike/rules/company-policy.yaml
rules:
  - id: no-console-log-in-production
    patterns:
      - pattern: console.log(...)
    message: "console.log() should not appear in production code"
    severity: WARNING
    languages: [javascript, typescript]
    metadata:
      company-policy: "SEC-001"
```

Run with:

```bash
semgrep scan --config ~/.cyberstrike/rules/ .
```

### Q: How do I integrate results with Jira?

```bash
#!/usr/bin/env bash
# Post critical CVEs as Jira tickets (requires jira-cli)
jq -r '.matches[] | select(.vulnerability.severity=="Critical") | 
    "CRITICAL CVE: \(.vulnerability.id) in \(.artifact.name) \(.artifact.version) — fix: \(.vulnerability.fix.versions | join(", "))"' \
    security-reports/grype-results.json | \
while read -r title; do
    jira create \
        --project "SEC" \
        --type "Security" \
        --priority "Critical" \
        --summary "$title" \
        --label "cve" "devsec"
done
```


---

## Windows PowerShell Usage

All Linux/macOS `bash` commands in this guide have PowerShell equivalents.
Use `scripts\scan.ps1` for scanning and `scripts\make.bat` for a `make`-like experience.

### 5 Essential Commands — Windows

```powershell
# 1. Quick CVE scan of current directory
grype dir:. --severity high

# 2. SAST scan for code vulnerabilities
semgrep scan --config auto .

# 3. Scan for secrets accidentally committed
gitleaks detect --source .

# 4. Full OWASP dependency audit
trivy fs . --severity HIGH,CRITICAL

# 5. Generate SBOM + OSV scan
syft dir:. -o cyclonedx-json=sbom.json
osv-scanner --sbom=sbom.json
```

### Using `scan.ps1` — Quick Reference

```powershell
# Quick scan (secrets + critical CVEs), < 2 min
.\scripts\scan.ps1 -Target . -Mode quick

# Full scan: all tools
.\scripts\scan.ps1 -Target "C:\Projects\MyApp" -Mode full

# Full scan with explicit language
.\scripts\scan.ps1 -Target . -Mode full -Lang csharp

# CI/CD mode — exits with code 1 on Critical findings
.\scripts\scan.ps1 -Target . -Mode cicd -Output ".\reports\scan.md"
```

### Using `make.bat` — Quick Reference

```batch
REM Install tools (run as Administrator)
make.bat install

REM Verify all tools are in PATH
make.bat verify

REM CVE scan
make.bat scan-cve TARGET=.\myproject

REM OWASP SAST scan
make.bat scan-owasp TARGET=.\myproject LANG=csharp

REM Full scan
make.bat scan-full TARGET=.\myproject

REM Full scan + Markdown report
make.bat report TARGET=.\myproject OUTPUT=.\security-reports\report.md

REM CI/CD mode
./scripts/scan.sh --target ./myproject --mode cicd
```

---

## Scanning a C#/.NET Project — Windows

### Step 1 — Restore dependencies

```powershell
Set-Location "C:\Projects\MyDotNetApp"
dotnet restore
```

### Step 2 — CVE scan on NuGet packages

```powershell
# Grype detects NuGet packages from *.csproj and packages.lock.json
grype "dir:$PWD" --output table --severity high

# JSON output for CI
$reportDir = Join-Path $PWD 'security-reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
grype "dir:$PWD" --output json --file "$reportDir\cve-results.json" --add-cpes-if-none
```

### Step 3 — SAST scan (C# rules)

```powershell
semgrep scan `
    --config "p/csharp" `
    --config "p/owasp-top-ten" `
    --json `
    --output "$reportDir\sast-results.json" `
    .
```

### Step 4 — Secret scan

```powershell
gitleaks detect `
    --source . `
    --report-format json `
    --report-path "$reportDir\secrets.json"
```

### Step 5 — Review results (PowerShell JSON parsing)

```powershell
# CVE summary by severity
$grype = Get-Content "$reportDir\cve-results.json" | ConvertFrom-Json
$grype.matches | Group-Object { $_.vulnerability.severity } |
    Select-Object Name, Count | Sort-Object Count -Descending

# SAST findings
$semgrep = Get-Content "$reportDir\sast-results.json" | ConvertFrom-Json
$semgrep.results | Select-Object -First 10 |
    ForEach-Object { [PSCustomObject]@{ Rule=$_.check_id; File=$_.path; Line=$_.start.line; Message=$_.extra.message } }
```

---

## Scanning a Java/Maven Project — Windows

```powershell
Set-Location "C:\Projects\MyJavaApp"

# CVE scan
$reportDir = Join-Path $PWD 'security-reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
grype "dir:$PWD" --output json --file "$reportDir\grype.json"

# SAST (Java + OWASP)
semgrep scan --config "p/java" --config "p/owasp-top-ten" `
    --json --output "$reportDir\semgrep.json" --metrics off .

# OSV-Scanner on pom.xml / build.gradle
osv-scanner --recursive "$PWD" --format json | Out-File "$reportDir\osv.json" -Encoding UTF8
```

---

## Scanning a React/TypeScript Project — Windows

```powershell
Set-Location "C:\Projects\MyReactApp"

# Install deps first
npm install

# CVE via npm audit
npm audit --json | Out-File "security-reports\npm-audit.json" -Encoding UTF8

# Grype scan
$reportDir = Join-Path $PWD 'security-reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
grype "dir:$PWD" --output json --file "$reportDir\grype.json"

# SAST (React/TypeScript)
semgrep scan --config "p/javascript" --config "p/typescript" --config "p/react" `
    --config "p/owasp-top-ten" --json --output "$reportDir\semgrep.json" --metrics off .

# Secret scan
gitleaks detect --source . --report-format json --report-path "$reportDir\gitleaks.json" --no-banner --exit-code 0
```

---

## Scanning a COBOL Project — Windows

```powershell
Set-Location "C:\Projects\MyCobolApp"

$reportDir = Join-Path $PWD 'security-reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# Secret scan (COBOL often has hardcoded credentials)
gitleaks detect --source . --report-format json --report-path "$reportDir\gitleaks.json" --no-banner --exit-code 0

# SAST (generic OWASP rules)
semgrep scan --config "p/owasp-top-ten" --json --output "$reportDir\semgrep.json" --metrics off .

# SBOM generation
syft "dir:$PWD" -o cyclonedx-json="$reportDir\sbom.json"
```

---

## Environment Variables — Windows

Set environment variables in PowerShell profile (`$PROFILE`) or Windows system settings:

```powershell
# Add to $PROFILE (permanent for current user)
$env:NVD_API_KEY         = "your-nvd-api-key-here"
$env:SEMGREP_APP_TOKEN   = "your-semgrep-token"
$env:CYBERSTRIKE_LICENSE = "your-license-key"

# Or set system-wide (requires Admin)
[Environment]::SetEnvironmentVariable('NVD_API_KEY', 'your-key', 'Machine')
```

---

## FAQ — Windows Specific

### Q: `scan.ps1` returns "running scripts is disabled"

Run once to allow scripts for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Or for all users (requires Admin):

```powershell
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
```

### Q: Path contains spaces and a tool fails

Always wrap paths in quotes and use `Join-Path`:

```powershell
$target = Join-Path "C:\Users\My User\Projects" "MyApp"
grype "dir:`"$target`""
```

### Q: How do I update the vulnerability databases on Windows?

```powershell
# Grype
grype db update

# Trivy
trivy image --download-db-only
```

### Q: How do I run scans in WSL2?

If you have WSL2, you can use the Linux-native scripts from within WSL:

```powershell
# Launch WSL and run the bash scan script
wsl bash scripts/scan.sh --target /mnt/c/Projects/MyApp --mode full
```
