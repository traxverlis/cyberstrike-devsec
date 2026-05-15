# CyberStrikeAI DevSec

[![Security Scan](https://img.shields.io/github/actions/workflow/status/cyberstrike/devsec/devsec-scan.yml?label=Security%20Scan&logo=github&style=flat-square)](../../actions/workflows/devsec-scan.yml)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-Covered-blue?style=flat-square)](https://owasp.org/Top10/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CyberStrikeAI](https://img.shields.io/badge/Powered%20by-CyberStrikeAI-purple?style=flat-square)](https://cyberstrike.ai)

> **Extension DevSec pour CyberStrikeAI** — scan automatisé CVE, OWASP Top 10, secrets, supply chain et IaC.  
> Supporte C#/.NET, COBOL, Java, React, JavaScript/TypeScript, Python.  
> **Mode IA intégré** : analyse GitHub Copilot, OpenAI, Ollama (local) ou tout provider compatible.

---

## Démarrage rapide

```bash
# 1. Cloner
git clone https://github.com/cyberstrike/devsec.git && cd devsec

# 2. Installer les outils
bash scripts/install.sh

# 3. Configurer la cible dans devsec.conf
#    TARGET=./mon-projet   (Level 1 — code source)
#    TARGET_URL=https://...  (Level 2 — site web)

# 4. Scanner
./scripts/scan.sh          # Level 1 — code source
./scripts/scan-web.sh      # Level 2 — site web (nécessite consentement)
```

Le rapport PDF est généré automatiquement dans `./security-reports/report.pdf`.

---

## Architecture 3 niveaux

```
┌─────────────────────────────────────────────────────────────────┐
│  LEVEL 3 — FULL PENTEST                   🔴 CONSENTEMENT L3    │
│  sqlmap, ffuf, zaproxy, jwt-tool, nuclei-exploit, metasploit    │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 2 — SCAN ACTIF                     🟡 CONSENTEMENT L2    │
│  nmap, nikto, nuclei, testssl, cors-scanner, security-headers   │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 1 — ANALYSE STATIQUE               🟢 SANS AUTORISATION  │
│  grype, trivy, semgrep, gitleaks, trufflehog, syft, checkov     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Configuration

Toute la config dans **`devsec.conf`** à la racine :

```ini
# Cible (Level 1)
TARGET=./mon-projet

# Cible (Level 2 — site web)
TARGET_URL=https://app.example.com

# Mode : quick | full | cicd
MODE=full

# Activer l'analyse IA
AI=false
AI_MODEL=gpt-4o

# Consentement Level 2
CONSENT=./reports/consent/consent-signed.pdf
```

---

## Usage

### Level 1 — Analyse statique (code source)

```bash
# Scan rapide (~30s) — secrets + CVE critiques
./scripts/scan.sh --mode quick

# Scan complet (~5-15min)
./scripts/scan.sh

# Avec analyse IA (GitHub Copilot)
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
./scripts/scan.sh --ai
```

### Level 2 — Scan actif (site web)

```bash
# Étape 1 — Générer le document de consentement
python3 scripts/consent/generate-consent.py \
  --target "https://app.example.com" \
  --scope "/*" \
  --requestor "Ton Nom" --company "Ta Société" \
  --tester "Red Team" \
  --duration "2026-06-01 to 2026-06-08" \
  --test-types "recon,headers,cors,ssl,nikto,nmap" \
  --exclusions "aucune" \
  --output reports/consent/consent-draft.pdf

# Étape 2 — Faire signer, renommer en consent-signed.pdf

# Étape 3 — Lancer le scan
./scripts/scan-web.sh
```

### Rapport PDF

Les rapports sont générés automatiquement après chaque scan :

```
security-reports/
├── report.pdf      ← à envoyer au client
├── report.html     ← consultation navigateur
├── report.md       ← texte brut
└── ai_analysis.md  ← analyse IA (si --ai activé)
```

---

## Mode IA

L'IA (GitHub Copilot, OpenAI, Ollama…) analyse les résultats et enrichit le rapport :

- **Triage** — faux positifs détectés, vrais positifs priorisés
- **Top 5 failles** avec exemples de fix en code
- **Synthèse exécutive** lisible par un RSSI/CTO
- **Plan de remédiation** classé effort/impact

```bash
# Configurer dans config.yaml (copier depuis config.example.yaml)
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
./scripts/scan.sh --ai          # Level 1 avec IA
./scripts/scan-web.sh --ai      # Level 2 avec IA

# Ou relancer l'analyse IA sur un scan existant
python3 scripts/ai_analyzer.py \
  --findings reports/mon-scan/summary.json \
  --output reports/mon-scan/ai_analysis.md \
  --verbose
```

Providers supportés : **GitHub Copilot · OpenAI · Anthropic · Ollama · DeepSeek · Azure OpenAI**

---

## Flow de consentement (Level 2 & 3)

```
generate-consent.py → PDF envoyé au client → signé → verify-consent.py → token → scan
```

```bash
# Générer
python3 scripts/consent/generate-consent.py --target URL --scope "/*" ...

# Vérifier le PDF signé
python3 scripts/consent/verify-consent.py \
  --consent reports/consent/consent-signed.pdf \
  --target https://app.example.com \
  --token-out reports/consent/token.json
```

---

## Outils intégrés

| Catégorie | Outils |
|-----------|--------|
| CVE | Grype, Trivy, OSV-Scanner |
| SAST | Semgrep (OWASP ruleset) |
| Secrets | Gitleaks, TruffleHog |
| SBOM | Syft (CycloneDX, SPDX) |
| IaC | Checkov (Terraform, Docker, K8s) |
| Web actif | nmap, Nikto, Nuclei, testssl.sh |
| Python | pip-audit |
| Rapports | pandoc + weasyprint (PDF sans LaTeX) |

---

## Installation

Voir **[INSTALL.md](INSTALL.md)** pour le guide complet (Linux, macOS, Windows).

```bash
# Linux/macOS — installation automatique
bash scripts/install.sh

# Vérifier les outils
export PATH="$PATH:$HOME/.local/bin"
for tool in grype trivy semgrep gitleaks trufflehog nuclei nikto weasyprint; do
  command -v $tool &>/dev/null && echo "✅ $tool" || echo "❌ $tool"
done
```

---

## Langages supportés

| Langage | CVE | SAST | Secrets | Supply Chain |
|---------|-----|------|---------|-------------|
| **Python** | ✅ pip-audit + grype | ✅ semgrep | ✅ gitleaks | ✅ SBOM |
| **JavaScript/TypeScript** | ✅ npm-audit + grype | ✅ semgrep | ✅ gitleaks | ✅ SBOM |
| **Java** | ✅ Maven DC + grype | ✅ semgrep | ✅ gitleaks | ✅ SBOM |
| **C# / .NET** | ✅ dotnet + grype | ✅ semgrep | ✅ gitleaks | ✅ NuGet |
| **React** | ✅ npm-audit | ✅ semgrep | ✅ gitleaks | ✅ SBOM |
| **COBOL** | ⚠️ Partiel | ✅ Règles custom | ✅ gitleaks | ⚠️ Manuel |
| **Terraform/IaC** | ✅ checkov | ✅ checkov | ✅ gitleaks | ✅ checkov |
| **Docker** | ✅ trivy | ✅ checkov | ✅ gitleaks | ✅ SBOM |

---

## Documentation

| Fichier | Contenu |
|---------|---------|
| [INSTALL.md](INSTALL.md) | Installation de zéro (guide débutant) |
| [USAGE.md](USAGE.md) | Guide d'utilisation complet |
| [COMMANDS.md](COMMANDS.md) | Historique des commandes et bugs résolus |
| [docs/consent-workflow.md](docs/consent-workflow.md) | Flow de consentement Level 2/3 |
| [docs/pipeline-architecture.md](docs/pipeline-architecture.md) | Architecture technique |
| [docs/remediation-guide.md](docs/remediation-guide.md) | Guide de remédiation par langage |

---

*CyberStrikeAI DevSec — construit pour les équipes de développement soucieuses de la sécurité.*
