# CyberStrikeAI DevSec

[![Security Scan](https://img.shields.io/github/actions/workflow/status/cyberstrike/devsec/devsec-scan.yml?label=Security%20Scan&logo=github&style=flat-square)](../../actions/workflows/devsec-scan.yml)
[![Security Gate](https://img.shields.io/badge/Security%20Gate-Enabled-brightgreen?style=flat-square&logo=shield)](../../security)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-Covered-blue?style=flat-square)](https://owasp.org/Top10/)
[![Windows Compatible](https://img.shields.io/badge/Windows-Compatible-0078D6?style=flat-square&logo=windows)](docs/installation.md#windows-installation)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CyberStrikeAI](https://img.shields.io/badge/Powered%20by-CyberStrikeAI-purple?style=flat-square)](https://cyberstrike.ai)

> **DevSec extension for CyberStrikeAI teams** — automated security scanning for CVE dependencies, OWASP Top 10, secrets, supply chain, and IaC across C#/.NET, COBOL, Java, React, JavaScript/TypeScript, and Python.

---

## Platform Support

| Platform | Status | Script | Package Manager |
|----------|--------|--------|-----------------|
| ✅ Linux | Fully supported | `scripts/install.sh` + `scripts/scan.sh` | apt, curl |
| ✅ macOS | Fully supported | `scripts/install.sh` + `scripts/scan.sh` | Homebrew |
| ✅ Windows | Fully supported | `scripts/install.ps1` + `scripts/scan.ps1` | winget / Chocolatey |

---

## Overview

CyberStrikeAI DevSec is a multi-agent security analysis extension designed to integrate seamlessly into development workflows and CI/CD pipelines. It combines best-in-class open-source security tools — Grype, Trivy, Semgrep, Gitleaks, TruffleHog, Syft, Checkov — orchestrated by CyberStrikeAI's reasoning agents to deliver prioritized, actionable security findings with concrete code-level remediation guidance.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CyberStrikeAI DevSec Architecture                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                       CyberStrikeAI Core                        │   │
│   │  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────┐ │   │
│   │  │  Orchestrator │  │  Quick Scan   │  │   Deep Analysis      │ │   │
│   │  │  (Full audit) │  │  (CI/CD gate) │  │  (Pre-release audit) │ │   │
│   │  └──────┬───────┘  └───────┬───────┘  └──────────┬───────────┘ │   │
│   └─────────┼──────────────────┼────────────────────┼─────────────┘   │
│             │                  │                    │                  │
│   ┌─────────▼──────────────────▼────────────────────▼─────────────┐   │
│   │                        Skills Layer                             │   │
│   │  ┌──────────────┐ ┌────────────┐ ┌──────────┐ ┌────────────┐  │   │
│   │  │ cve-dependency│ │owasp-code- │ │sast-devsec│ │supply-chain│  │   │
│   │  │     -scan     │ │  review    │ │           │ │  -audit    │  │   │
│   │  └──────────────┘ └────────────┘ └──────────┘ └────────────┘  │   │
│   │  ┌──────────────┐ ┌────────────┐ ┌────────────────────────┐   │   │
│   │  │cobol-security │ │dotnet-     │ │    devsec-report       │   │   │
│   │  │               │ │security    │ │                        │   │   │
│   │  └──────────────┘ └────────────┘ └────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                        Tools Layer                               │   │
│   │                                                                  │   │
│   │  CVE       │ Grype  │ Trivy  │ OSV-Scanner │ dotnet-vulnerable  │   │
│   │  SAST      │ Semgrep                                            │   │
│   │  Secrets   │ Gitleaks  │ TruffleHog                            │   │
│   │  SBOM      │ Syft                                               │   │
│   │  IaC       │ Checkov                                            │   │
│   │  Java      │ Maven Dependency Check                             │   │
│   │  Python    │ pip-audit                                          │   │
│   │  Node      │ npm-audit                                          │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     Output Layer                                 │   │
│   │  Markdown Reports │ SARIF (GitHub Security) │ PDF │ JSON (CI)   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Linux / macOS

```bash
# 1. Install all tools
./scripts/install.sh

# 2. Scan your project
./scripts/scan.sh --target ./your-project --mode full

# 3. View results
ls ./security-reports/
```

Or using Make:

```bash
make scan-full TARGET=./your-project
```

### Windows (PowerShell)

```powershell
# 1. Install all tools (run as Administrator)
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install.ps1

# 2. Scan your project
.\scripts\scan.ps1 -Target .\your-project -Mode full

# 3. View results
Get-ChildItem .\your-project\security-reports\
```

Or using `make.bat`:

```batch
scripts\make.bat scan-full TARGET=.\your-project
```

---

## Features

| Feature | Status | Description |
|---------|--------|-------------|
| CVE Dependency Scan | ✅ Ready | Grype + Trivy + OSV-Scanner + ecosystem-native tools |
| OWASP Top 10 Analysis | ✅ Ready | Semgrep with curated OWASP ruleset |
| Secret Detection | ✅ Ready | Gitleaks + TruffleHog (git history + filesystem) |
| Supply Chain Audit | ✅ Ready | SBOM generation, typosquatting, license compliance |
| COBOL Security | ✅ Ready | SQL injection, credentials, COMP-1/2, COPY books |
| .NET/C# Security | ✅ Ready | NuGet audit, unsafe code, XXE, deserialization |
| IaC Security | ✅ Ready | Checkov for Terraform, Dockerfile, Kubernetes |
| GitHub Actions CI/CD | ✅ Ready | Matrix strategy, SARIF upload, PR comments |
| Security Gate | ✅ Ready | Blocks merge on Critical CVEs or exposed secrets |
| Executive Reports | ✅ Ready | Management summaries with risk scoring |
| CI/CD JSON Output | ✅ Ready | Structured JSON for pipeline integration |
| Java Support | ✅ Ready | Maven Dependency Check + Semgrep Java rules |
| Python Support | ✅ Ready | pip-audit + Semgrep Python rules |
| React/TS Support | ✅ Ready | Semgrep React/TypeScript rulesets |
| SBOM Generation | ✅ Ready | CycloneDX + SPDX via Syft |
| PDF Reports | 🔄 Requires pandoc | `pandoc devsec-report.md -o report.pdf` |
| DAST / Active Scan | 📋 Not included | Requires separate authorization — not in scope |

---

## Supported Languages & Frameworks

| Language / Framework | CVE Scan | SAST | Secrets | Supply Chain |
|---------------------|----------|------|---------|-------------|
| **C# / .NET** | ✅ dotnet + grype | ✅ semgrep p/csharp | ✅ gitleaks | ✅ NuGet lock |
| **COBOL** | ⚠️ Partial (JARs) | ✅ Custom rules | ✅ gitleaks | ⚠️ Manual |
| **Java** | ✅ Maven DC + grype | ✅ semgrep p/java | ✅ gitleaks | ✅ SBOM |
| **React** | ✅ npm-audit | ✅ semgrep p/react | ✅ gitleaks | ✅ SBOM |
| **JavaScript** | ✅ npm-audit + grype | ✅ semgrep p/javascript | ✅ gitleaks | ✅ SBOM |
| **TypeScript** | ✅ npm-audit + grype | ✅ semgrep p/typescript | ✅ gitleaks | ✅ SBOM |
| **Python** | ✅ pip-audit + grype | ✅ semgrep p/python | ✅ gitleaks | ✅ SBOM |
| **Terraform / IaC** | ✅ checkov | ✅ checkov | ✅ gitleaks | ✅ checkov |
| **Docker** | ✅ trivy | ✅ checkov | ✅ gitleaks | ✅ SBOM |
| **Kubernetes** | ✅ trivy | ✅ checkov | ✅ gitleaks | — |

---

## Scanning Tools

| Tool | Version | Purpose | License |
|------|---------|---------|---------|
| [Grype](https://github.com/anchore/grype) | latest | CVE scanner for SBOMs and filesystems | Apache 2.0 |
| [Trivy](https://github.com/aquasecurity/trivy) | latest | Universal scanner (CVE + secrets + IaC + config) | Apache 2.0 |
| [Semgrep](https://semgrep.dev) | latest | SAST with OWASP rules | LGPL 2.1 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | latest | Secret & credential detection | MIT |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | latest | Deep secret scanning with entropy analysis | AGPL 3.0 |
| [Syft](https://github.com/anchore/syft) | latest | SBOM generator (CycloneDX, SPDX) | Apache 2.0 |
| [Checkov](https://www.checkov.io) | latest | IaC security (Terraform, Docker, K8s) | Apache 2.0 |
| [OSV-Scanner](https://google.github.io/osv-scanner/) | latest | Google OSV advisory database | Apache 2.0 |
| [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) | latest | Java/Maven CVE scanning | Apache 2.0 |
| [pip-audit](https://github.com/pypa/pip-audit) | latest | Python package vulnerability audit | Apache 2.0 |
| npm-audit | built-in | Node.js package vulnerability audit | npm |

---

## Scan Modes

### Quick Mode (~30-60s)
Fast scan for secrets and critical CVEs only. Ideal for pre-commit hooks or draft PR checks.

```bash
./scripts/scan.sh --target . --mode quick
```

### Full Mode (~5-15min)
Complete scan: CVE + OWASP SAST + secrets + SBOM + IaC + TruffleHog. For code reviews and sprint security checks.

```bash
./scripts/scan.sh --target . --mode full
```

### CI/CD Mode
Structured JSON output with strict exit codes. Designed for automated pipeline gates.

```bash
./scripts/scan.sh --target . --mode cicd --output ./reports
# Exit 0 = PASS, Exit 1 = FAIL (Critical found)
```

---

## CI/CD Integration

### GitHub Actions

The included workflow (`.github/workflows/devsec-scan.yml`) provides:

- **Parallel matrix**: CVE scan, OWASP SAST, secret detection, and IaC scan run simultaneously
- **SARIF upload**: Results appear in the GitHub Security tab
- **PR comment**: Automatic comment with findings summary on every pull request
- **Security gate**: Merge blocked if Critical CVEs or exposed secrets are found

```yaml
# Already included — activate by pushing to your repo
# The workflow triggers on push and pull_request to main/master/develop
```

### GitLab CI

```yaml
# .gitlab-ci.yml
devsec-scan:
  stage: security
  image: ubuntu:22.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl jq python3-pip
    - ./scripts/install.sh --skip-go
  script:
    - ./scripts/scan.sh --target . --mode cicd --output ./security-reports
  artifacts:
    when: always
    paths:
      - security-reports/
    expire_in: 30 days
  allow_failure: false
```

### Azure DevOps

```yaml
# azure-pipelines.yml
- stage: Security
  jobs:
  - job: DevSecScan
    displayName: 'CyberStrikeAI DevSec Scan'
    pool:
      vmImage: 'ubuntu-latest'
    steps:
    - script: ./scripts/install.sh
      displayName: 'Install scan tools'
    - script: ./scripts/scan.sh --target $(Build.SourcesDirectory) --mode cicd
      displayName: 'Run security scan'
    - task: PublishBuildArtifacts@1
      condition: always()
      inputs:
        pathtoPublish: 'security-reports'
        artifactName: 'security-reports'
```

---

## Demo / Screenshots

```
╔══════════════════════════════════════════════════════════════╗
║          CyberStrikeAI DevSec — Security Scanner 🔍          ║
╚══════════════════════════════════════════════════════════════╝

  Target   : /workspace/my-dotnet-app
  Mode     : full
  Started  : 2025-05-14 17:30:00 UTC

━━━ Scan 1/7: Secret Detection ━━━━━━━━━━━━━━━━━━━━━━━━
  ❌ Secrets found: 1 — rotate credentials immediately!
     [aws-access-token] src/config/aws.cs:14 — AWS access token

━━━ Scan 2/7: CVE Dependency Scan ━━━━━━━━━━━━━━━━━━━━━
  ❌ Critical CVEs: 2
     [CVE-2023-44487] System.Net.Http@4.3.0 → fix: 4.3.4
     [CVE-2021-21293] Newtonsoft.Json@12.0.3 → fix: 13.0.3
  ⚠️  High CVEs: 5
  ✅ CVE scan complete — Critical: 2 | High: 5 | Medium: 8 | Low: 12

  ┌────────────────────────────────────────────┐
  │  Secrets    Critical   High       SAST     │
  │  1          2          5          3        │
  └────────────────────────────────────────────┘

  ❌ SECURITY GATE: FAILED
  • CRITICAL: 1 secret(s) exposed — rotate immediately
  • CRITICAL: 2 critical CVE(s) — update dependencies
```

---

## Docker Usage

Run scans without installing tools locally:

```bash
# Start all services
docker compose up -d

# Run a full scan against your project
docker compose run --rm grype dir:/workspace --severity high

# Run Semgrep SAST
docker compose run --rm semgrep semgrep --config p/owasp-top-ten /workspace

# Run Gitleaks
docker compose run --rm gitleaks detect --source /workspace --report-format json

# Generate SBOM
docker compose run --rm syft dir:/workspace -o cyclonedx-json > sbom.json
```

Override the workspace path:

```bash
PROJECT_PATH=/path/to/your/project docker compose run --rm grype dir:/workspace
```

---

## Available Make Targets

```bash
make help              # Show all targets
make scan-cve          # CVE scan only (Grype + Trivy)
make scan-sast         # SAST only (Semgrep)
make scan-secrets      # Secret scan only (Gitleaks)
make scan-owasp        # OWASP dependency scan (Syft + OSV)
make scan-full         # All scans combined
make report            # Generate Markdown security report
make sbom              # Generate SBOM only
make install-tools     # Install all tools
make verify            # Verify tool installations
make update-dbs        # Update CVE databases
make clean             # Remove scan results
make docker-scan       # Run full scan via Docker (no local install)
```

---

## Directory Structure

```
cyberstrike-devsec/
├── .github/
│   └── workflows/
│       └── devsec-scan.yml        # GitHub Actions CI/CD workflow
├── agents/
│   ├── devsec-orchestrator.md     # Full audit orchestration agent
│   ├── devsec-quick-scan.md       # CI/CD pipeline agent (<2 min)
│   └── devsec-deep-analysis.md    # Pre-release deep analysis agent
├── docs/
│   ├── installation.md            # Installation guide
│   ├── usage-guide.md             # Usage documentation
│   ├── ci-cd-integration.md       # CI/CD integration guide
│   └── remediation-guide.md       # Security remediation guidance
├── reports/
│   └── templates/
│       ├── devsec-full-report.md  # Full security report template
│       ├── devsec-cicd-report.md  # CI/CD gate report template
│       └── executive-summary.md   # Executive summary template
├── roles/
│   ├── devsec-audit.yaml          # RSSI/compliance auditor role
│   ├── devsec-ci-pipeline.yaml    # Automated pipeline role (JSON output)
│   └── devsec-team.yaml           # Developer-friendly role
├── scripts/
│   ├── install.sh                 # One-command tool installation
│   └── scan.sh                    # Unified scan script (quick/full/cicd)
├── skills/
│   ├── cve-dependency-scan/       # CVE scanning across ecosystems
│   ├── cobol-security/            # COBOL-specific security analysis
│   ├── dotnet-security/           # .NET/C# security analysis
│   ├── owasp-code-review/         # OWASP Top 10 static analysis
│   ├── sast-devsec/               # Advanced SAST + secret detection
│   ├── supply-chain-audit/        # Supply chain integrity analysis
│   └── devsec-report/             # Report generation and aggregation
├── tools/
│   ├── checkov.yaml               # IaC scanner (Terraform, Docker, K8s)
│   ├── dotnet-audit.yaml          # NuGet vulnerability audit
│   ├── dotnet-vulnerable.yaml     # dotnet list package --vulnerable
│   ├── gitleaks.yaml              # Secret detection
│   ├── grype.yaml                 # CVE scanner
│   ├── maven-dependency-check.yaml # Java/Maven CVE scan
│   ├── npm-audit.yaml             # Node.js audit
│   ├── osv-scanner.yaml           # Google OSV scanner
│   ├── pip-audit.yaml             # Python audit
│   ├── semgrep.yaml               # SAST
│   ├── syft.yaml                  # SBOM generator
│   ├── trivy.yaml                 # Universal scanner
│   └── trufflehog.yaml            # Deep secret scanner
├── docker-compose.yml             # Containerized scan environment
├── Makefile                       # Make targets for common operations
├── AUDIT.md                       # Project audit report
└── README.md                      # This file
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-skill`)
3. Add your skill or improvement
4. Ensure all tool names in YAML match existing `tools/*.yaml` definitions
5. Test with `make scan-full TARGET=./test-project`
6. Submit a pull request

### Adding a New Skill

```bash
mkdir -p skills/my-new-skill
cat > skills/my-new-skill/SKILL.md <<EOF
---
name: my-new-skill
description: What this skill does
version: 1.0.0
---
# ...
EOF
```

### Adding a New Tool

```bash
cat > tools/my-tool.yaml <<EOF
name: "my-tool"
command: "my-tool"
enabled: true
short_description: "..."
description: |
  ...
parameters:
  - name: "target"
    type: "string"
    required: true
    format: "positional"
    position: 0
EOF
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

## Security

Found a vulnerability in this project? Please do **not** open a public issue. Email `security@cyberstrike.ai` with details. We aim to respond within 48 hours.

---

*CyberStrikeAI DevSec — Built for security-conscious development teams.*
