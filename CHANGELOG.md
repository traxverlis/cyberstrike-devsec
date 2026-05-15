# CHANGELOG

All notable changes to CyberStrikeAI DevSec are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version scheme: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.0] — 2026-05-15

### Fixed
- **`generate-report.py`** : ajout des parseurs semgrep, gitleaks, grype, trivy, checkov, trufflehog (rapport était vide — 0 findings affichés avant correction)
- **`generate-report.py`** : génération PDF via weasyprint (plus besoin de xelatex/LaTeX)
- **`devsec-pipeline.py`** : `--level` ne passait plus à `verify-consent.py` — corrigé
- **`devsec-pipeline.py`** : nmap utilisait `-oJ` inexistant — remplacé par `-oX` (XML)
- **`scripts/scan-web.sh`** : nouveau script simplifié Level 2 (lit `devsec.conf`)
- **`devsec.conf`** : fichier de config central (plus de Makefile)

### Removed
- **`Makefile`** : supprimé — remplacé par `devsec.conf` + scripts directs
- **`scripts/make.bat`** : supprimé

### Documentation
- `README.md` : réécrit complètement (plus de références make, ajout IA, devsec.conf, scan-web.sh)
- `INSTALL.md` : guide débutant de zéro, toutes commandes incluses
- `USAGE.md` : guide d'utilisation complet avec section IA
- `config.example.yaml` : format corrigé (plat, compatible parseur)
- `docs/installation.md` : marqué déprécié → pointer vers INSTALL.md

---

## [3.0.0] — 2026-05-15

### Added
- **`scripts/ai_analyzer.py`** : module d'analyse IA OpenAI-compatible
  - Triage intelligent (faux positifs / vrais positifs)
  - Top 5 failles avec exemples de fix en code
  - Synthèse exécutive pour RSSI/CTO
  - Plan de remédiation classé effort/impact
- **`config.yaml`** : configuration provider IA (format à plat)
- **`scripts/copilot-token.sh`** : récupère le token Copilot depuis OpenClaw
- **Flag `--ai`** dans `scan.sh` et `devsec-pipeline.py`
- **Génération PDF automatique** en fin de scan (pandoc + weasyprint)
- **`vuln-target/app.py`** : site Flask vulnérable v1 (SQLi, XSS, secrets, path traversal, cmd injection)
- **`vuln-target/app2.py`** : site Flask vulnérable v2 (SQLi, XSS stocké, IDOR, auth bypass)

### Changed
- `devsec-pipeline.py` : génère MD + HTML + PDF en fin de pipeline
- `scan.sh` : génère MD + HTML + PDF en fin de scan

---

## [2.0.0] — 2026-05-14

### Added — Level 2: Active Light Scan
- **`skills/active-recon/SKILL.md`** — Automated active reconnaissance: nmap, whatweb, testssl, security headers, CORS
- **`skills/web-vulnerability-scan/SKILL.md`** — Light web vulnerability scanning with Nikto, Wapiti, Nuclei (passive templates)
- **`agents/active-scan-orchestrator.md`** — Level 2 orchestrator agent with full audit logging
- **`roles/pentest-level2.yaml`** — Role definition with restricted toolset (no exploitation)
- **`tools/nmap.yaml`** — Port/service enumeration tool definition
- **`tools/nikto.yaml`** — Web server misconfiguration scanner
- **`tools/nuclei-passive.yaml`** — Nuclei with passive/misconfiguration templates only
- **`tools/testssl.yaml`** — SSL/TLS analysis tool
- **`tools/security-headers.yaml`** — HTTP security headers checker
- **`tools/cors-scanner.yaml`** — CORS misconfiguration detector
- **`tools/whatweb.yaml`** — Web technology fingerprinting
- **`tools/wapiti.yaml`** — Web vulnerability scanner (light mode)
- **`reports/templates/level2-active-scan-report.md`** — Level 2 report template

### Added — Level 3: Full Penetration Test
- **`skills/pentest-full/SKILL.md`** — Full-scope pentest following OWASP WSTG with consent gate
- **`skills/api-pentest/SKILL.md`** — REST/GraphQL/gRPC API security testing (OWASP API Top 10)
- **`skills/auth-bypass/SKILL.md`** — Authentication bypass: JWT attacks, OAuth, session flaws, MFA bypass
- **`agents/pentest-orchestrator.md`** — Level 3 orchestrator with HARD STOP consent gate
- **`roles/pentest-level3.yaml`** — Full toolset role (sqlmap, ffuf, zaproxy, jwt-tool, metasploit, etc.)
- **`tools/sqlmap.yaml`** — SQL injection exploitation tool
- **`tools/ffuf.yaml`** — Fuzzing framework for directories, parameters, endpoints
- **`tools/jwt-tool.yaml`** — JWT analysis and exploitation
- **`tools/zaproxy.yaml`** — OWASP ZAP DAST scanner
- **`tools/nuclei-exploit.yaml`** — Nuclei with exploitation templates
- **`tools/feroxbuster.yaml`** — Recursive content discovery
- **`tools/idor-scanner.yaml`** — IDOR vulnerability detection
- **`tools/oauth-tester.yaml`** — OAuth 2.0 misconfiguration testing
- **`reports/templates/level3-pentest-report.md`** — Level 3 pentest report template
- **`reports/templates/pentest-finding-template.md`** — Individual finding template with PoC sections

### Added — Consent System
- **`scripts/consent/generate-consent.py`** — Generate signed PDF consent documents with QR codes
- **`scripts/consent/verify-consent.py`** — Verify consent PDF integrity and token validity
- **`scripts/consent/send-consent.py`** — Email consent documents to stakeholders
- **`scripts/consent/requirements.txt`** — Consent subsystem dependencies
- **`docs/consent-workflow.md`** — Complete consent workflow documentation
- **`reports/templates/consent-form.md`** — Consent form template

### Added — Pipeline & Orchestration
- **`scripts/devsec-pipeline.py`** — Main async pipeline orchestrator (all 3 levels)
- **`scripts/notify.py`** — Multi-channel notification (Slack, Teams, email, webhooks)
- **`scripts/audit-trail.py`** — Cryptographic audit trail with PDF export
- **`scripts/generate-report.py`** — Report aggregation from multi-tool JSON outputs

### Added — CI/CD
- **`.github/workflows/devsec-level2.yml`** — GitHub Actions workflow for Level 2 active scanning
- **`.github/workflows/devsec-level3.yml`** — GitHub Actions workflow for Level 3 pentest
- **`docs/pipeline-architecture.md`** — Architecture and pipeline documentation

### Added — Docker
- Level 2 services in `docker-compose.yml`: nmap, nuclei, testssl, nikto, wapiti, zaproxy
- Level 3 services: sqlmap, ffuf, jwt-tool
- Persistent volumes: `consents`, `nuclei-templates`

---

## [1.1.0] — 2026-03-20

### Added — Windows Support
- **`scripts/install.ps1`** — PowerShell installation script with winget/Chocolatey support
- **`scripts/scan.ps1`** — PowerShell scan script mirroring scan.sh functionality
- **`scripts/make.bat`** — Windows batch wrapper for Makefile targets
- Platform detection in all scripts (Linux/macOS/Windows)
- Windows prerequisites section in `docs/installation.md`

### Added — GitHub Copilot Integration
- **`docs/github-copilot-integration.md`** — Integration guide for GitHub Copilot in security workflows
- Copilot prompt templates for vulnerability triage and remediation
- VS Code extension configuration recommendations
- GitHub Copilot Autofix integration patterns

### Changed
- README updated with Windows quick start and platform compatibility table
- `docker-compose.yml` updated with Windows volume path compatibility notes

---

## [1.0.0] — 2026-01-15

### Added — Level 1: Static Analysis (Passive)
- **`skills/cve-dependency-scan/SKILL.md`** — CVE scanning across .NET, npm, Maven, Python, COBOL
- **`skills/owasp-code-review/SKILL.md`** — OWASP Top 10 static analysis (A01–A10)
- **`skills/sast-devsec/SKILL.md`** — SAST + secret detection (Gitleaks, TruffleHog, Semgrep)
- **`skills/supply-chain-audit/SKILL.md`** — SBOM, typosquatting, license compliance
- **`skills/devsec-report/SKILL.md`** — Report aggregation and generation
- **`skills/cobol-security/SKILL.md`** — COBOL-specific security patterns
- **`skills/dotnet-security/SKILL.md`** — .NET/C# security analysis
- **`agents/devsec-orchestrator.md`** — Full audit orchestration agent
- **`agents/devsec-quick-scan.md`** — CI/CD pipeline agent (<2 min)
- **`agents/devsec-deep-analysis.md`** — Pre-release deep analysis agent
- **`roles/devsec-audit.yaml`** — RSSI/compliance auditor role
- **`roles/devsec-team.yaml`** — Developer-friendly role
- **`roles/devsec-ci-pipeline.yaml`** — Automated pipeline role
- **`tools/`** — 13 tool definitions: grype, trivy, semgrep, gitleaks, syft, trufflehog, checkov, osv-scanner, dotnet-audit, dotnet-vulnerable, npm-audit, maven-dependency-check, pip-audit
- **`.github/workflows/devsec-scan.yml`** — GitHub Actions CI/CD with SARIF upload
- **`docker-compose.yml`** — Containerized scan environment
- **`Makefile`** — 15+ targets for common operations
- **`scripts/install.sh`** — One-command tool installation (Linux/macOS)
- **`scripts/scan.sh`** — Unified scan script (quick/full/cicd modes)
- **`docs/installation.md`**, **`docs/usage-guide.md`**, **`docs/ci-cd-integration.md`**, **`docs/remediation-guide.md`**
- **`reports/templates/`** — Full report, CI/CD report, executive summary templates
- **`config.example.yaml`** — Example configuration file

---

[2.0.0]: https://github.com/cyberstrike/devsec/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/cyberstrike/devsec/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/cyberstrike/devsec/releases/tag/v1.0.0
