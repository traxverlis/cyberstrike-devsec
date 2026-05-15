# COMMANDS.md — Référence des commandes CyberStrikeAI DevSec

> Guide de référence complet — toutes les commandes du projet, modes et options.
> Mis à jour : 2026-05-15 — Version 3.3.0

---

## Table des matières

1. [Installation](#1-installation)
2. [Scan Level 1 — code source](#2-scan-level-1--code-source)
3. [Scan Level 2 — site web](#3-scan-level-2--site-web)
4. [Mode Docker](#4-mode-docker)
5. [Mode IA — GitHub Copilot](#5-mode-ia--github-copilot)
6. [Consentement Level 2/3](#6-consentement-level-23)
7. [Rapports PDF](#7-rapports-pdf)
8. [Pipeline direct](#8-pipeline-direct)
9. [Analyse IA standalone](#9-analyse-ia-standalone)
10. [Vérification outils](#10-vérification-outils)

---

## 1. Installation

### Installation locale complète (Linux/macOS)

```bash
git clone https://github.com/traxverlis/cyberstrike-devsec.git
cd cyberstrike-devsec
bash scripts/install.sh
source ~/.bashrc
```

### Installation Docker (Windows/Linux/macOS — sans installer les outils)

```bash
git clone https://github.com/traxverlis/cyberstrike-devsec.git
cd cyberstrike-devsec
docker build -t cyberstrike-devsec .
```

---

## 2. Scan Level 1 — code source

### Via devsec.conf (recommandé)

```bash
# Éditer devsec.conf
TARGET=./mon-projet
MODE=full

# Lancer
./scripts/scan.sh
```

### Via options directes

```bash
export PATH="$PATH:$HOME/.local/bin"

# Scan rapide (~30s) — secrets + CVE critiques
./scripts/scan.sh --target ./mon-projet --mode quick

# Scan complet (~5-15min)
./scripts/scan.sh --target ./mon-projet --mode full

# Scan CI/CD — JSON + exit codes stricts
./scripts/scan.sh --target . --mode cicd --output ./reports

# Scan avec analyse IA
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
./scripts/scan.sh --target ./mon-projet --mode full --ai
```

### Options scan.sh

| Option | Description | Défaut |
|--------|-------------|--------|
| `--target <path>` | Projet à scanner | `.` |
| `--output <path>` | Dossier des rapports | `./security-reports` |
| `--mode <mode>` | `quick` / `full` / `cicd` / `pipeline` | `full` |
| `--severity <level>` | `critical` / `high` / `medium` / `low` | `high` |
| `--no-git` | Ne pas scanner l'historique git | `false` |
| `--ai` | Activer l'analyse IA | `false` |
| `--ai-config <path>` | Chemin vers config.yaml IA | auto |
| `--docker` | Lancer dans le conteneur Docker | `false` |

### Codes de sortie

| Code | Signification |
|------|--------------|
| `0` | Aucun finding critique |
| `1` | Findings critiques détectés |
| `2` | Erreur de scan |

---

## 3. Scan Level 2 — site web

### Via devsec.conf (recommandé)

```bash
# Éditer devsec.conf
TARGET_URL=https://app.exemple.com
CONSENT=./reports/consent/consent-signed.pdf

# Lancer
./scripts/scan-web.sh
```

### Via options directes

```bash
./scripts/scan-web.sh \
  --target https://app.exemple.com \
  --consent ./reports/consent/consent-signed.pdf \
  --output ./reports/scan-$(date +%Y%m%d)
```

### Options scan-web.sh

| Option | Description |
|--------|-------------|
| `--target <url>` | URL cible |
| `--consent <pdf>` | PDF de consentement signé |
| `--output <dir>` | Dossier de sortie |
| `--ai` | Activer l'analyse IA |
| `--docker` | Lancer dans le conteneur Docker |

---

## 4. Mode Docker

### Build unique

```bash
docker build -t cyberstrike-devsec .
```

### Commandes conteneur

```bash
# Scan Level 1
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/reports:/reports \
  cyberstrike-devsec scan --mode full --output /reports

# Scan Level 2
docker run --rm \
  -v $(pwd)/reports:/reports \
  --network=host \
  cyberstrike-devsec scan-web \
    --target https://app.exemple.com \
    --consent /reports/consent-signed.pdf

# Avec IA
docker run --rm \
  -v $(pwd):/workspace \
  -e GITHUB_COPILOT_TOKEN="ton-token" \
  cyberstrike-devsec scan --ai

# Shell interactif
docker run --rm -it -v $(pwd):/workspace cyberstrike-devsec shell

# Vérifier les outils
docker run --rm cyberstrike-devsec verify

# Aide
docker run --rm cyberstrike-devsec help
```

### Windows PowerShell

```powershell
docker run --rm `
  -v ${PWD}:/workspace `
  -v ${PWD}/reports:/reports `
  cyberstrike-devsec scan --mode full --output /reports
```

### Via docker compose

```bash
cp .env.example .env    # Configurer PROJECT_PATH, GITHUB_COPILOT_TOKEN...
docker compose run devsec scan --mode full
docker compose run devsec verify
```

### Via scripts avec --docker

```bash
# Lancer dans Docker automatiquement (construit l'image si besoin)
./scripts/scan.sh --docker --mode full
./scripts/scan-web.sh --docker --target https://app.exemple.com
```

---

## 5. Mode IA — GitHub Copilot

### Configuration

```bash
# config.yaml (format à plat)
base_url: "https://api.githubcopilot.com"
api_key: "${GITHUB_COPILOT_TOKEN}"
model: "claude-opus-4.6"
reasoning_effort: "medium"    # low | medium | high
temperature: 0.1
max_tokens: 4096
```

### Récupérer le token Copilot (depuis OpenClaw)

```bash
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
```

### Scan avec IA

```bash
# Level 1
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
./scripts/scan.sh --mode full --ai

# Level 2
./scripts/scan-web.sh --ai
```

### Providers supportés

| Provider | base_url | api_key |
|----------|----------|---------|
| GitHub Copilot | `https://api.githubcopilot.com` | `${GITHUB_COPILOT_TOKEN}` |
| OpenAI | `https://api.openai.com/v1` | `${OPENAI_API_KEY}` |
| Ollama (local) | `http://localhost:11434/v1` | `ollama` |
| DeepSeek | `https://api.deepseek.com/v1` | `${DEEPSEEK_API_KEY}` |

---

## 6. Consentement Level 2/3

```bash
export PATH="$PATH:$HOME/.local/bin"

# Étape 1 — Générer le PDF de consentement
python3 scripts/consent/generate-consent.py \
  --target "https://app.exemple.com" \
  --scope "/*, /api/*" \
  --requestor "Alice Martin" \
  --company "CyberStrikeAI" \
  --tester "Red Team Alpha" \
  --duration "2026-06-01 to 2026-06-08" \
  --test-types "recon,headers,cors,ssl,nikto,nmap" \
  --exclusions "production DB, /internal/*" \
  --output reports/consent/consent-draft.pdf

# Étape 2 — Faire signer le PDF → consent-signed.pdf

# Étape 3 — Vérifier
python3 scripts/consent/verify-consent.py \
  --consent reports/consent/consent-signed.pdf \
  --target "https://app.exemple.com" \
  --token-out reports/consent/token.json

# Étape 4 — Scanner
./scripts/scan-web.sh \
  --target https://app.exemple.com \
  --consent reports/consent/consent-signed.pdf
```

---

## 7. Rapports PDF

```bash
export PATH="$PATH:$HOME/.local/bin"

# Depuis security-reports/ (après scan.sh)
python3 scripts/generate-report.py \
  --results-dir ./security-reports \
  --output ./security-reports/report.pdf \
  --level 1 --format pdf

# Depuis un dossier de pipeline Level 2
python3 scripts/generate-report.py \
  --results-dir ./reports/mon-scan/raw \
  --output ./reports/mon-scan/report.pdf \
  --level 2 --format pdf

# Formats disponibles
python3 scripts/generate-report.py ... --format md    # Markdown
python3 scripts/generate-report.py ... --format html  # HTML
python3 scripts/generate-report.py ... --format pdf   # PDF (weasyprint)
```

---

## 8. Pipeline direct

```bash
export PATH="$PATH:$HOME/.local/bin"

# Level 1 — analyse statique
python3 scripts/devsec-pipeline.py \
  --target ./mon-projet \
  --level 1

# Level 2 — scan actif (PTES)
python3 scripts/devsec-pipeline.py \
  --target https://app.exemple.com \
  --level 2 \
  --consent reports/consent/consent-signed.pdf \
  --output reports/scan-$(date +%Y%m%d)

# Level 2 avec IA
python3 scripts/devsec-pipeline.py \
  --target https://app.exemple.com \
  --level 2 \
  --consent reports/consent/consent-signed.pdf \
  --ai --ai-model claude-opus-4.6

# Level 3 — pentest complet
python3 scripts/devsec-pipeline.py \
  --target https://app.exemple.com \
  --level 3 \
  --consent reports/consent/consent-signed.pdf \
  --output reports/pentest-$(date +%Y%m%d)
```

### Options devsec-pipeline.py

| Option | Description |
|--------|-------------|
| `--target` | URL ou chemin cible (obligatoire) |
| `--level 1\|2\|3` | Niveau de scan (obligatoire) |
| `--consent <pdf>` | PDF signé (obligatoire Level 2+) |
| `--output <dir>` | Dossier de sortie |
| `--ai` | Activer l'analyse IA |
| `--ai-model <model>` | Modèle IA |
| `--ai-config <yaml>` | Config provider IA |
| `--lang <lang>` | Langage cible (`auto` par défaut) |
| `--dry-run` | Simuler sans exécuter |
| `--notify-email <email>` | Envoyer rapport par email |

---

## 9. Analyse IA standalone

```bash
export PATH="$PATH:$HOME/.local/bin"
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)

# Sur un summary.json existant
python3 scripts/ai_analyzer.py \
  --findings reports/mon-scan/summary.json \
  --output reports/mon-scan/ai_analysis.md \
  --level 2 \
  --verbose

# Résultat : fichier Markdown avec triage, top 5 failles, synthèse exécutive
```

---

## 10. Vérification outils

### Installation locale

```bash
export PATH="$PATH:$HOME/.local/bin"
for tool in grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit \
            nuclei nikto testssl.sh nmap whatweb gobuster dirb feroxbuster dalfox \
            subfinder hydra wapiti ffuf sqlmap enum4linux pandoc weasyprint; do
  command -v $tool &>/dev/null && echo "✅ $tool" || echo "❌ $tool"
done
```

### Mode Docker

```bash
docker run --rm cyberstrike-devsec verify
```

---

## Bugs connus et corrections appliquées

| Fichier | Bug | Statut |
|---------|-----|--------|
| `install.sh` | URL trufflehog incorrecte (`_linux_amd64` sans version) | ✅ Corrigé |
| `install.sh` | `pip install` bloqué Debian → pipx | ✅ Corrigé |
| `devsec-pipeline.py` | `--level` passé à `verify-consent.py` qui ne l'accepte pas | ✅ Corrigé |
| `devsec-pipeline.py` | nmap utilisait `-oJ` inexistant → `-oX` (XML) | ✅ Corrigé |
| `generate-report.py` | Parseurs semgrep/gitleaks/grype manquants → 0 findings | ✅ Corrigé |
| `generate-report.py` | PDF via xelatex → weasyprint (plus besoin de LaTeX) | ✅ Corrigé |
| `tools/nmap.yaml` + 3 autres | YAML invalide (guillemets, backticks) | ✅ Corrigé |
| `Makefile` | Heredoc cassé, supprimé | ✅ Supprimé → devsec.conf |
