# Pipeline Architecture — CyberStrikeAI DevSec

## Table of Contents

1. [Overview](#overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Level Decision Flow](#level-decision-flow)
4. [Component Descriptions](#component-descriptions)
5. [Integration with CyberStrikeAI](#integration-with-cyberstrike-ai)
6. [Environment Variables](#environment-variables)
7. [Usage Examples](#usage-examples)

---

## Overview

The CyberStrikeAI DevSec pipeline is a three-level security automation framework designed to cover the full spectrum of DevSecOps needs — from lightweight CI/CD static analysis (Level 1) to full penetration testing (Level 3).

Every level above 1 requires a **signed consent document** and is governed by a robust **audit trail** to ensure legal compliance and full traceability.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     CyberStrikeAI DevSec Pipeline                       │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │   Level 1    │    │   Level 2    │    │        Level 3           │  │
│  │  Static Only │    │  Active Light│    │    Full Pentest          │  │
│  │  (No consent │    │  (Consent    │    │  (Consent + 2 Approvers) │  │
│  │   required)  │    │   required)  │    │                          │  │
│  └──────┬───────┘    └──────┬───────┘    └────────────┬─────────────┘  │
│         │                  │                          │                 │
│         ▼                  ▼                          ▼                 │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                   devsec-pipeline.py                            │   │
│  │  ┌────────────┐  ┌────────────────┐  ┌───────────────────────┐ │   │
│  │  │ Parse Args │→ │Consent Verify  │→ │ Level 3 Confirmation  │ │   │
│  │  └────────────┘  │(verify-consent)│  │ (CONFIRM prompt)      │ │   │
│  │                  └────────────────┘  └───────────────────────┘ │   │
│  │                                                                 │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │              Parallel Scan Execution (asyncio)           │  │   │
│  │  │                                                          │  │   │
│  │  │  ┌─────────┐ ┌─────────┐ ┌────────┐ ┌────────────────┐ │  │   │
│  │  │  │  Grype  │ │Semgrep  │ │Gitleaks│ │  nmap / Nuclei  │ │  │   │
│  │  │  │  (CVE)  │ │  (SAST) │ │(Secrets│ │  testssl/nikto  │ │  │   │
│  │  │  └────┬────┘ └────┬────┘ └───┬────┘ └───────┬────────┘ │  │   │
│  │  │       └──────────┴──────────┴───────────────┘          │  │   │
│  │  │                           │                             │  │   │
│  │  │                    raw/*.json                           │  │   │
│  │  └──────────────────────────┬───────────────────────────┘  │   │
│  │                             │                               │   │
│  │  ┌──────────────────────────▼───────────────────────────┐  │   │
│  │  │              generate-report.py                      │  │   │
│  │  │  JSON summary + HTML report + score calculation      │  │   │
│  │  └──────────────────────────┬───────────────────────────┘  │   │
│  │                             │                               │   │
│  │  ┌──────────────┐  ┌────────▼─────────┐  ┌────────────┐   │   │
│  │  │ audit-trail  │  │   notify.py      │  │ Exit code  │   │   │
│  │  │   .py        │  │ email/slack/teams│  │  0/1/2/3   │   │   │
│  │  └──────────────┘  └──────────────────┘  └────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### GitHub Actions Workflows

```
Repository
├── .github/workflows/
│   ├── devsec-level2.yml      ← Manual trigger, consent required
│   │     Jobs: verify-consent → install-tools → scan → notify → create-issues
│   │
│   └── devsec-level3.yml      ← Manual trigger, environment approval (2 reviewers)
│         Jobs: request-approval → verify-consent → audit-trail-start
│               → pentest → audit-trail-end → notify-rssi → create-confidential-issue
```

### Storage Layout

```
~/.devsec/audit/
└── YYYY-MM-DD.jsonl   ← Append-only audit log (chained hashes)

./reports/
└── level{N}_YYYYMMDD_HHMMSS/
    ├── raw/
    │   ├── grype-results.json
    │   ├── semgrep-results.json
    │   ├── gitleaks-results.json
    │   ├── nmap-results.json      (L2+)
    │   ├── nuclei-results.json    (L2+)
    │   ├── testssl-results.json   (L2+)
    │   ├── nikto-results.json     (L2+)
    │   └── zap-full.json          (L3)
    ├── summary.json
    ├── findings.json
    └── report.html
```

---

## Level Decision Flow

```
                        ┌─────────────────┐
                        │   Start Scan    │
                        └────────┬────────┘
                                 │
                    ┌────────────▼────────────┐
                    │  What is your use case? │
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼────────────────────────────┐
          │                      │                            │
          ▼                      ▼                            ▼
 ┌─────────────────┐   ┌─────────────────────┐   ┌─────────────────────────┐
 │ CI/CD pipeline  │   │ Pre-prod assessment │   │ Formal security audit   │
 │ Code review     │   │ QA environment scan │   │ Bug bounty preparation  │
 │ Dev branch scan │   │ Staging validation  │   │ Compliance (PCI, ISO27k)│
 └────────┬────────┘   └──────────┬──────────┘   └──────────────┬──────────┘
          │                       │                              │
          ▼                       ▼                              ▼
     LEVEL 1                 LEVEL 2                       LEVEL 3
  Static Analysis          Active Light                Full Pentest
  No consent needed        Consent required            Consent + 2 approvers
                                                       CONFIRM prompt
          │                       │                              │
          ▼                       ▼                              ▼
  grype, semgrep,        + nmap, nuclei,             + ZAP active scan,
  gitleaks, trivy          testssl, nikto              sqlmap, full exploit
```

---

## Component Descriptions

### `scripts/devsec-pipeline.py`
Main orchestrator. Parses CLI arguments, validates consent, runs scans in parallel via `asyncio`, collects results, generates reports, sends notifications, and records audit trail entries.

**Exit codes:**
| Code | Meaning |
|------|---------|
| 0 | Pass — no critical findings |
| 1 | Critical findings detected |
| 2 | Runtime error |
| 3 | Consent invalid or not provided |

### `scripts/audit-trail.py`
Append-only JSONL audit log stored in `~/.devsec/audit/YYYY-MM-DD.jsonl`. Each entry includes a SHA-256 hash of its content chained with the previous entry's hash (lightweight blockchain pattern). Supports `append`, `verify`, `list`, and `export-pdf` commands.

### `scripts/notify.py`
Multi-channel notification dispatcher. Supports:
- **email** — SMTP or SendGrid API, with optional PDF attachment
- **slack** — Webhook with color-coded severity attachment
- **teams** — Adaptive Card via Teams webhook
- **github** — Create GitHub Issues for critical/high findings

### `scripts/consent/verify-consent.py`
Validates signed consent PDF documents before any active scanning. Checks digital signature, expiry, and required scope fields. Returns a consent_id (hash) for audit trail reference.

### `.github/workflows/devsec-level2.yml`
GitHub Actions workflow for Level 2 scans, triggered manually via `workflow_dispatch`. Installs tools, verifies consent artifact, runs scans, uploads report, and optionally notifies via SendGrid and creates GitHub Issues.

### `.github/workflows/devsec-level3.yml`
GitHub Actions workflow for Level 3 pentests. Uses GitHub Environments (`pentest-approval`) to enforce 2-reviewer approval before execution. Encrypts report with GPG and notifies RSSI via email.

---

## Integration with CyberStrikeAI

The pipeline integrates with the CyberStrikeAI analysis engine in several ways:

1. **AI-powered triage** — Pass `--ai-model claude-sonnet-4-5` to enable AI-assisted finding prioritization in `generate-report.py`.
2. **SAST enhancement** — Semgrep results are fed to CyberStrikeAI for context-aware false positive filtering.
3. **Remediation suggestions** — The report generator can query CyberStrikeAI for fix recommendations per finding.
4. **Language detection** — `--lang auto` delegates to CyberStrikeAI's language detector for optimal scan rule selection.

```
devsec-pipeline.py
      │
      ├── generate-report.py ──→ CyberStrikeAI API (claude-sonnet-4-5)
      │         │                    ├── /analyze (finding triage)
      │         │                    ├── /remediate (fix suggestions)
      │         │                    └── /detect-lang (language detection)
      │         │
      │         └── HTML/PDF Report with AI insights
      │
      └── AI Model: configurable via --ai-model
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SENDGRID_API_KEY` | For email via SendGrid | API key for email notifications |
| `SENDGRID_FROM` | No | Sender email (default: devsec-noreply@yourdomain.com) |
| `SMTP_HOST` | No | SMTP server (fallback to localhost) |
| `SMTP_PORT` | No | SMTP port (default: 587) |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASS` | No | SMTP password |
| `SLACK_WEBHOOK_URL` | For Slack notifications | Incoming webhook URL |
| `TEAMS_WEBHOOK_URL` | For Teams notifications | Incoming webhook URL |
| `GITHUB_TOKEN` | For GitHub Issues | Personal access token or Actions token |
| `GITHUB_REPOSITORY` | No | Default repo for issue creation (owner/repo) |
| `NVD_API_KEY` | No | NVD API key for Grype (increases rate limit) |
| `RSSI_EMAIL` | For Level 3 | RSSI notification email (GitHub Actions secret) |
| `GPG_RECIPIENT` | For Level 3 | GPG fingerprint for report encryption |

---

## Usage Examples

### Level 1 — Static analysis in CI

```bash
python scripts/devsec-pipeline.py \
  --target ./my-app \
  --level 1 \
  --lang auto
```

### Level 2 — Pre-production active scan

```bash
python scripts/devsec-pipeline.py \
  --target https://staging.company.com \
  --level 2 \
  --consent ./consent-signed.pdf \
  --notify-email security@company.com \
  --output ./reports/staging-2024-01-15
```

### Level 3 — Full pentest (interactive)

```bash
python scripts/devsec-pipeline.py \
  --target https://prod.company.com \
  --level 3 \
  --lang auto \
  --source-dir ./src \
  --consent ./consent-pentest-signed.pdf \
  --ai-model claude-sonnet-4-5 \
  --notify-email rssi@company.com \
  --operator "John Doe (OSCP)"
# → Prompts for CONFIRM before executing
```

### Dry run — validate without scanning

```bash
python scripts/devsec-pipeline.py \
  --target https://app.company.com \
  --level 2 \
  --consent ./consent.pdf \
  --dry-run
```

### Audit trail

```bash
# View today's audit log
python scripts/audit-trail.py list

# Verify integrity
python scripts/audit-trail.py verify

# Export PDF for compliance
python scripts/audit-trail.py export-pdf --output audit-2024-01.pdf --date 2024-01-15
```

### GitHub Actions — Level 2

```
Repository → Actions → DevSec Level 2 — Active Light Scan → Run workflow
  target_url: https://staging.company.com
  scan_type: light
  notify_email: team@company.com
```

### GitHub Actions — Level 3

```
Repository → Actions → DevSec Level 3 — Full Pentest → Run workflow
  (requires 2 reviewers in Settings → Environments → pentest-approval)
  target_url: https://app.company.com
  consent_document_url: https://secure-storage.com/consent-signed.pdf
  scope: "app.company.com and all subdomains, excluding *.internal.company.com"
  test_types: web,network,sqli,auth
```
---

## Moteur PTES — Architecture adaptative

Le pipeline Level 2+ utilise un moteur PTES (Penetration Testing Execution Standard)
qui orchestre les scans en phases enchaînées plutôt qu'en séquence plate.

### PTESContext — Contexte partagé

```python
PTESContext:
  target          # URL/IP cible
  hosts           # Hôtes découverts
  open_ports      # Ports ouverts avec services
  http_endpoints  # URLs HTTP à tester (enrichi par chaque phase)
  technologies    # CMS/frameworks détectés
  vulnerabilities # Vulnérabilités identifiées
  attack_surface  # Modèle de menace (vecteurs d'attaque)
```

### Flux Phase 1 → Phase 7

```
Phase 2 — Information Gathering
  nmap -sV -sC → open_ports enrichi
  whatweb → technologies enrichi
  subfinder → http_endpoints enrichi (sous-domaines)
  testssl → analyse TLS de CHAQUE port TLS découvert par nmap
  enum4linux → si port 139/445 dans open_ports
         ↓
Phase 3 — Threat Modeling
  → Analyse automatique de open_ports + technologies
  → attack_surface.vectors : [web, cms-wordpress, database-exposed, ...]
         ↓
Phase 4 — Vulnerability Analysis
  nuclei  → ALL http_endpoints (pas juste le target principal)
  nikto   → CHAQUE port HTTP dans open_ports
  gobuster → CHAQUE port HTTP → résultats → http_endpoints enrichi
  dalfox  → endpoints avec ?params dans http_endpoints
  wapiti  → crawler + SQLi/XSS/CSRF sur http_endpoints
         ↓
Phase 5 — Exploitation (Level 3)
  sqlmap  → endpoints avec SQLi détecté en Phase 4
  hydra   → services SSH/FTP/RDP dans open_ports
  ffuf    → endpoints avec query params
         ↓
Phase 6 — Post-Exploitation (Level 3)
  → IDOR candidates depuis http_endpoints numériques
  → Impact estimation depuis vulnerabilities
         ↓
Phase 7 — Reporting
  → generate-report.py → PDF
  → ai_analyzer.py → analyse IA (si --ai)
  → ptes_context.json sauvegardé
```

### Chargement dynamique (Option C)

Aucune commande hardcodée dans le code :
- `ToolLoader` lit `tools/*.yaml` → construit les commandes CLI
- `PromptLoader` lit `agents/*.md` + `skills/*/SKILL.md` + `roles/*.yaml` → construit les prompts IA
- Le level filtre les outils via `roles/devsec-team.yaml` (allowed_tools)

