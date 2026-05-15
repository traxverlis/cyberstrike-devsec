# 📖 Guide d'utilisation — CyberStrikeAI DevSec

> **Pour débutants** — Ce guide couvre tout : scanner un projet, analyser un site web,
> interpréter les résultats et transmettre les rapports PDF à un client.
> Toutes les commandes sont prêtes à copier-coller.

---

## Table des matières

1. [Avant de commencer](#1-avant-de-commencer)
2. [Niveau 1 — Scanner un projet (code source)](#2-niveau-1--scanner-un-projet-code-source)
3. [Niveau 2 — Scanner un site web (scan actif)](#3-niveau-2--scanner-un-site-web-scan-actif)
4. [Comprendre les résultats](#4-comprendre-les-résultats)
5. [Les rapports PDF clients](#5-les-rapports-pdf-clients)
6. [Exemple complet — de zéro à rapport](#6-exemple-complet--de-zéro-à-rapport)
7. [Référence des commandes](#7-référence-des-commandes)

---

## 1. Avant de commencer

Chaque fois que tu ouvres un terminal, exécute cette commande pour avoir accès à tous les outils :

```bash
export PATH="$PATH:$HOME/.local/bin"
```

Pour ne plus avoir à le faire à chaque fois, l'ajouter une fois pour toutes :

```bash
echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
source ~/.bashrc
```

Toujours travailler depuis le dossier du projet :

```bash
cd /chemin/vers/cyberstrike-devsec
```

---

## 2. Niveau 1 — Scanner un projet (code source)

Le **Niveau 1** analyse le code source d'un projet localement.
Il ne génère aucun trafic réseau — aucune autorisation requise.

**Ce qu'il détecte :**
- Secrets et clés API oubliés dans le code
- Dépendances vulnérables (CVE)
- Failles de sécurité dans le code (OWASP Top 10)
- Problèmes de configuration (Docker, Kubernetes, Terraform)

---

### Scan rapide (~30 secondes)

Idéal pour une vérification rapide avant un commit.

```bash
export PATH="$PATH:$HOME/.local/bin"
./scripts/scan.sh --target /chemin/vers/ton-projet --mode quick
```

**Exemple :**
```bash
./scripts/scan.sh --target ./mon-app-react --mode quick
```

---

### Scan complet (~5 à 15 minutes)

Analyse approfondie. À faire avant chaque livraison ou release.

```bash
export PATH="$PATH:$HOME/.local/bin"
./scripts/scan.sh --target /chemin/vers/ton-projet --mode full
```

**Exemple :**
```bash
./scripts/scan.sh --target ./mon-app-react --mode full
```

À la fin, trois fichiers sont générés automatiquement dans `./security-reports/` :

| Fichier | Contenu |
|---------|---------|
| `report.pdf` | **Rapport PDF** à envoyer au client |
| `report.html` | Rapport HTML consultable dans un navigateur |
| `report.md` | Rapport texte brut |

---

### Scan CI/CD (intégration continue)

Retourne un code de sortie 0 (succès) ou 1 (échec) — pour bloquer un déploiement.

```bash
export PATH="$PATH:$HOME/.local/bin"
./scripts/scan.sh --target . --mode cicd --output ./reports
```

---

### Changer le répertoire de sortie des rapports

Par défaut les rapports vont dans `./security-reports/`. Pour changer :

```bash
./scripts/scan.sh --target ./mon-projet --mode full --output ./mes-rapports
```

---

## 3. Niveau 2 — Scanner un site web (scan actif)

Le **Niveau 2** envoie de vraies requêtes vers un site web pour tester sa sécurité.
⚠️ **Il est obligatoire d'avoir une autorisation écrite** avant de lancer ce niveau.

**Ce qu'il détecte en plus du Niveau 1 :**
- Ports ouverts (nmap)
- Vulnérabilités web (nuclei)
- En-têtes de sécurité manquants
- Configuration SSL/TLS faible

Le processus se déroule en **4 étapes**.

---

### Étape 1 — Générer le document d'autorisation (PDF)

Ce document doit être signé par le client avant tout scan.

```bash
export PATH="$PATH:$HOME/.local/bin"
mkdir -p reports/consent

python3 scripts/consent/generate-consent.py \
  --target "https://site-du-client.com" \
  --scope "/api/*, /admin/*, /*" \
  --requestor "Ton Nom" \
  --company "Nom de ton entreprise" \
  --tester "Nom de l'équipe pentest" \
  --duration "2026-06-01 to 2026-06-08" \
  --test-types "recon,headers,cors,ssl,nikto,nmap" \
  --exclusions "base de données, /internal/*, /pay/*" \
  --output reports/consent/consent-draft.pdf
```

> ✏️ **Remplace les valeurs** entre guillemets par les informations réelles du projet client.
> `--duration` : dates de début et fin du test au format `YYYY-MM-DD to YYYY-MM-DD`.

Le PDF est généré dans `reports/consent/consent-draft.pdf`. Tu peux l'ouvrir et l'envoyer au client pour signature.

---

### Étape 2 — Obtenir la signature du client

Envoie le PDF généré au client. Il doit :
1. Lire le document
2. Remplir et signer les 3 blocs de signature
3. Te renvoyer le PDF signé

Enregistre le PDF signé sous : `reports/consent/consent-signed.pdf`

> 📧 Si tu veux envoyer le document par email directement depuis le script (serveur SMTP requis) :
> ```bash
> python3 scripts/consent/send-consent.py \
>   --pdf reports/consent/consent-draft.pdf \
>   --to-email client@example.com \
>   --to-name "Prénom Nom du client" \
>   --from-email tonemail@tonentreprise.com \
>   --smtp-host smtp.tonentreprise.com \
>   --smtp-user tonemail@tonentreprise.com \
>   --smtp-pass TON_MOT_DE_PASSE_SMTP
> ```

---

### Étape 3 — Vérifier le document signé

Une fois le PDF signé reçu, vérifier son intégrité avant de lancer le scan :

```bash
export PATH="$PATH:$HOME/.local/bin"

python3 scripts/consent/verify-consent.py \
  --consent reports/consent/consent-signed.pdf \
  --target "https://site-du-client.com" \
  --token-out reports/consent/consent-token.json
```

**Résultat attendu :**
```
[OK]    Consent file found
[OK]    Signatures : All signature fields are present and appear filled
[OK]    Date window : Within authorization window
[PASS]  Consent verification PASSED. Token written to: reports/consent/consent-token.json
```

Si la vérification échoue, le scan **ne peut pas démarrer**. Contacter le client pour re-signer.

---

### Étape 4 — Lancer le scan Niveau 2

```bash
export PATH="$PATH:$HOME/.local/bin"

python3 scripts/devsec-pipeline.py \
  --target "https://site-du-client.com" \
  --level 2 \
  --lang auto \
  --consent "reports/consent/consent-signed.pdf" \
  --output "reports/scan-client-$(date +%Y%m%d)"
```

> ⏱️ Durée estimée : 1 à 5 minutes selon la taille du site.

À la fin, le dossier `reports/scan-client-YYYYMMDD/` contient :

| Fichier | Contenu |
|---------|---------|
| `report.pdf` | **Rapport PDF** à envoyer au client ✅ |
| `report.html` | Rapport HTML |
| `report.md` | Rapport texte |
| `summary.json` | Données brutes JSON |
| `raw/` | Résultats bruts de chaque outil |

---

## 4. Comprendre les résultats

### Le score de sécurité

À la fin de chaque scan, un score de 0 à 100 est affiché :

| Score | Grade | Signification |
|-------|-------|---------------|
| 85–100 | A | Excellent — peu de risques |
| 70–84 | B | Bon — quelques points à corriger |
| 50–69 | C | Moyen — corrections recommandées |
| 30–49 | D | Faible — corrections urgentes |
| 0–29 | F | Critique — ne pas déployer |

### Les niveaux de sévérité

| Sévérité | Couleur | Action requise |
|----------|---------|----------------|
| 🔴 Critical | Rouge | Corriger **immédiatement** avant tout déploiement |
| 🟠 High | Orange | Corriger dans les **7 jours** |
| 🟡 Medium | Jaune | Corriger dans les **30 jours** |
| 🟢 Low | Vert | Corriger à la prochaine itération |
| ℹ️ Info | Bleu | Informatif — pas d'action urgente |

### Les types de findings

| Type | Outil | Ce que ça veut dire |
|------|-------|---------------------|
| CVE | grype, trivy | Une dépendance utilisée a une vulnérabilité connue |
| SAST | semgrep | Le code contient un pattern dangereux (injection SQL, XSS...) |
| Secret | gitleaks, trufflehog | Une clé API ou mot de passe est dans le code |
| IaC | checkov | Un fichier de config (Dockerfile, Terraform) est mal sécurisé |
| Web | nuclei, nikto | Le site web expose des vulnérabilités HTTP |

---

## 5. Les rapports PDF clients

### Où trouver les rapports

Après chaque scan :
- **Niveau 1** (scan.sh) → `./security-reports/report.pdf`
- **Niveau 2** (pipeline) → `./reports/<nom-du-scan>/report.pdf`

### Générer un rapport manuellement

Si tu veux regénérer un rapport depuis des résultats existants :

```bash
export PATH="$PATH:$HOME/.local/bin"

# Rapport PDF Level 1 (depuis security-reports/)
python3 scripts/generate-report.py \
  --results-dir ./security-reports \
  --output ./security-reports/report.pdf \
  --level 1 \
  --format pdf

# Rapport PDF Level 2 (depuis un dossier de pipeline)
python3 scripts/generate-report.py \
  --results-dir ./reports/scan-client-20260601/raw \
  --output ./reports/scan-client-20260601/report.pdf \
  --level 2 \
  --format pdf
```

### Générer les 3 formats à la fois (MD + HTML + PDF)

```bash
export PATH="$PATH:$HOME/.local/bin"
RESULTS_DIR="./security-reports"
OUTPUT_BASE="./security-reports/report"

python3 scripts/generate-report.py --results-dir $RESULTS_DIR --output ${OUTPUT_BASE}.md   --level 1 --format md
python3 scripts/generate-report.py --results-dir $RESULTS_DIR --output ${OUTPUT_BASE}.html --level 1 --format html
python3 scripts/generate-report.py --results-dir $RESULTS_DIR --output ${OUTPUT_BASE}.pdf  --level 1 --format pdf
```

---

## 6. Exemple complet — de zéro à rapport

### Cas 1 — Audit d'un code source (Level 1)

Tu reçois le code source d'une application. Objectif : rapport PDF de sécurité en 2 commandes.

```bash
cd /chemin/vers/cyberstrike-devsec
export PATH="$PATH:$HOME/.local/bin"

# 1. Configurer la cible dans devsec.conf
echo 'TARGET=./chemin/vers/app' >> devsec.conf

# 2. Scanner + rapport PDF automatique
./scripts/scan.sh

# Rapport disponible dans :
# ./security-reports/report.pdf
```

Avec analyse IA :

```bash
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
./scripts/scan.sh --ai
# → security-reports/report.pdf contient la section 🤖 Analyse IA
```

---

### Cas 2 — Audit d'un site web client (Level 2)

```bash
cd /chemin/vers/cyberstrike-devsec
export PATH="$PATH:$HOME/.local/bin"

# 1. Créer un dossier pour ce client
mkdir -p reports/client-acme/consent

# 2. Générer le document d'autorisation
python3 scripts/consent/generate-consent.py \
  --target "https://app.acme.com" \
  --scope "/*, /api/*" \
  --requestor "Alice Martin" \
  --company "CyberStrikeAI" \
  --tester "Red Team Alpha" \
  --duration "2026-06-10 to 2026-06-17" \
  --test-types "recon,headers,cors,ssl,nikto,nmap" \
  --exclusions "base de production, /internal/*" \
  --output reports/client-acme/consent/consent-draft.pdf

# → Envoyer le PDF au client, attendre le retour signé
# → Sauvegarder sous reports/client-acme/consent/consent-signed.pdf

# 3. Vérifier le document signé
python3 scripts/consent/verify-consent.py \
  --consent reports/client-acme/consent/consent-signed.pdf \
  --target "https://app.acme.com" \
  --token-out reports/client-acme/consent/token.json

# 4. Configurer devsec.conf
cat >> devsec.conf << 'EOF'
TARGET_URL=https://app.acme.com
CONSENT=./reports/client-acme/consent/consent-signed.pdf
EOF

# 5. Lancer le scan
./scripts/scan-web.sh

# Rapport disponible dans :
# ./security-reports/report.pdf
```

---

## 7. Référence des commandes

### scan.sh

```
./scripts/scan.sh [options]

Options :
  --target  <chemin>    Projet à scanner (défaut: .)
  --output  <chemin>    Dossier de sortie des rapports (défaut: ./security-reports)
  --mode    <mode>      quick | full | cicd (défaut: full)
  --severity <niveau>   critical | high | medium | low (défaut: high)
  --no-git              Ne pas scanner l'historique git (plus rapide)

Exemples :
  ./scripts/scan.sh --target ./mon-app --mode quick
  ./scripts/scan.sh --target ./mon-app --mode full --output ./rapports
  ./scripts/scan.sh --target . --mode cicd

Codes de sortie :
  0 = Aucun finding critique/high
  1 = Findings critiques détectés
  2 = Erreur de scan
```

### Moteur PTES — fonctionnement

Quand tu lances un scan Level 2 ou 3, le moteur PTES s'exécute automatiquement :

```
Phase 2 — Information Gathering
  nmap         → ports ouverts → nourrit Phase 4 (nikto sur chaque port)
  whatweb      → technologies → nourrit Phase 3 (threat modeling)
  subfinder    → sous-domaines → ajoutés comme endpoints à tester
  testssl      → analyse TLS sur chaque port HTTPS découvert
  enum4linux   → énumération SMB si port 139/445 détecté

Phase 3 — Threat Modeling (automatique)
  → WordPress détecté → vecteur CMS ajouté
  → MySQL port ouvert → vecteur database-exposed ajouté

Phase 4 — Vulnerability Analysis
  nuclei       → teste TOUS les endpoints (target + ports découverts)
  nikto        → teste CHAQUE port HTTP séparément
  gobuster     → brute-force répertoires sur chaque port HTTP
  dalfox       → XSS sur tous les endpoints avec paramètres ?
  wapiti       → crawler + SQLi/XSS/CSRF/LFI

Phase 5 — Exploitation (Level 3 uniquement)
  sqlmap       → teste les endpoints identifiés vulnérables à SQLi
  ffuf         → fuzzing paramètres
  hydra        → brute-force SSH/FTP/RDP découverts par nmap
```

### Niveau 3 — Pentest complet (Level 3)

```bash
export PATH="$PATH:$HOME/.local/bin"

# Level 3 — consentement signé OBLIGATOIRE + confirmation
python3 scripts/devsec-pipeline.py \
  --target "https://app.client.com" \
  --level 3 \
  --consent "reports/consent/consent-signed.pdf" \
  --confirm \          # non-interactif (CI/CD, scripts)
  --output "reports/pentest-$(date +%Y%m%d)"

# Outils Level 3 activés en plus du Level 2 :
#   sqlmap    → exploitation SQLi automatique
#   ffuf      → fuzzing endpoints et paramètres
#   dalfox    → exploitation XSS
#   hydra     → brute-force SSH/FTP/RDP
#   feroxbuster → discovery récursif profond
#   nuclei    → templates exploitation CVE
#   zaproxy   → scan actif OWASP ZAP (optionnel, nécessite Java)
```

> ⚠️ **ZAP** : nécessite Java. Installation recommandée via Docker :
> `docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://target`

### devsec-pipeline.py (Niveau 2 & 3)

```
python3 scripts/devsec-pipeline.py [options]

Options obligatoires :
  --target  <url>       URL du site à scanner (ex: https://app.example.com)
  --level   <1|2|3>     Niveau du scan
  --consent <fichier>   PDF signé (obligatoire pour level 2 et 3)

Options facultatives :
  --output  <dossier>   Dossier de sortie (défaut: ./reports/<timestamp>)
  --lang    <langue>    Langue du projet (auto, python, java, js, csharp, cobol)

Exemples :
  python3 scripts/devsec-pipeline.py --target https://app.example.com --level 1
  python3 scripts/devsec-pipeline.py --target https://app.example.com --level 2 --consent reports/consent/consent-signed.pdf
```

### generate-consent.py

```
python3 scripts/consent/generate-consent.py [options]

Options obligatoires :
  --target     <url>       URL/IP cible du pentest
  --scope      <périmètre> Chemins inclus dans le test
  --requestor  <nom>       Nom du demandeur
  --company    <société>   Nom de la société cliente
  --tester     <équipe>    Nom de l'équipe de test
  --duration   <période>   "YYYY-MM-DD to YYYY-MM-DD"
  --test-types <liste>     Types de tests (recon,headers,cors,ssl,nikto,nmap,sqli,xss)
  --exclusions <liste>     Ce qui est exclu du périmètre
  --output     <fichier>   Chemin du PDF généré
```

### verify-consent.py

```
python3 scripts/consent/verify-consent.py [options]

Options :
  --consent   <fichier>   PDF signé à vérifier
  --target    <url>       URL cible à faire correspondre avec le document
  --token-out <fichier>   Où écrire le token JSON si validé

Codes de sortie :
  0 = Document valide → scan autorisé
  1 = Document invalide → scan bloqué
```

### generate-report.py

```
python3 scripts/generate-report.py [options]

Options :
  --results-dir <dossier>  Dossier contenant les résultats JSON des outils
  --output      <fichier>  Fichier de sortie (ex: ./rapport.pdf)
  --level       <1|2|3>    Niveau du scan (pour le template)
  --format      <format>   md | html | pdf

Exemples :
  python3 scripts/generate-report.py --results-dir ./security-reports --output ./rapport.pdf --level 1 --format pdf
  python3 scripts/generate-report.py --results-dir ./reports/scan/raw --output ./rapport.html --level 2 --format html
```

### Raccourcis disponibles

```bash
# Lancement simplifié (lit devsec.conf automatiquement)
./scripts/scan.sh                              # Scan code source (Level 1)
./scripts/scan-web.sh                         # Scan site web (Level 2)

# Avec options ponctuelles (écrase devsec.conf)
./scripts/scan.sh --target ./mon-projet --mode quick
./scripts/scan.sh --target ./mon-projet --mode full --ai
./scripts/scan-web.sh --target https://monsite.com --consent ./doc-signe.pdf

# Vérifier les outils installés
for tool in grype trivy semgrep gitleaks trufflehog syft checkov \
            nuclei nikto nmap whatweb gobuster dalfox subfinder hydra wapiti weasyprint; do
  command -v $tool &>/dev/null && echo "✅ $tool" || echo "❌ $tool"
done
```

---

## 8. Mode Docker (sans installation locale)

Le mode Docker permet de lancer tous les scans **sans rien installer** sur ta machine.
Fonctionne sur Windows, macOS et Linux.

### Prérequis

- [Docker Desktop](https://docs.docker.com/get-docker/) installé et démarré

### Construction de l'image (une seule fois)

```bash
# Cloner le projet
git clone https://github.com/traxverlis/cyberstrike-devsec.git
cd cyberstrike-devsec

# Construire l'image (~10-15 minutes la première fois)
docker build -t cyberstrike-devsec .

# Vérifier que les 25+ outils sont bien installés
docker run --rm cyberstrike-devsec verify
```

### Scan d'un projet (Level 1)

```bash
# Linux / macOS
docker run --rm \
  -v $(pwd):/workspace \
  -v $(pwd)/reports:/reports \
  cyberstrike-devsec scan --mode full --output /reports

# Windows PowerShell
docker run --rm `
  -v ${PWD}:/workspace `
  -v ${PWD}/reports:/reports `
  cyberstrike-devsec scan --mode full --output /reports
```

### Scan d'un site web (Level 2)

```bash
docker run --rm \
  -v $(pwd)/reports:/reports \
  --network=host \
  cyberstrike-devsec scan-web \
    --target https://app.exemple.com \
    --consent /reports/consent-signed.pdf
```

### Avec l'analyse IA

```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e GITHUB_COPILOT_TOKEN="ton-token" \
  cyberstrike-devsec scan --mode full --ai
```

### Avec docker compose

```bash
cp .env.example .env
# Éditer .env (PROJECT_PATH, GITHUB_COPILOT_TOKEN...)
docker compose run devsec scan --mode full
docker compose run devsec verify
```

### Flag --docker (auto-conteneur)

```bash
# Utilise les scripts normaux — lance automatiquement dans Docker
./scripts/scan.sh --docker --mode full
./scripts/scan-web.sh --docker --target https://app.exemple.com
```

---

## 9. Mode avec IA — GitHub Copilot

Par défaut, les scans tournent **sans IA** — les outils (grype, semgrep, gitleaks...) font leur travail et génèrent un rapport.

En ajoutant `--ai`, l'IA (GitHub Copilot ou autre) analyse les résultats et enrichit le rapport avec :
- **Triage intelligent** — faux positifs écartés, vraies failles priorisées par exploitabilité réelle
- **Top 5 vulnérabilités critiques** avec exemples de fix en code
- **Synthèse exécutive** lisible par un RSSI ou un CTO
- **Plan de remédiation** classé par effort / impact

---

### Étape 1 — Configurer le provider IA

Ouvre `config.yaml` et choisis ton provider :

```yaml
# config.yaml (format à plat)
base_url: "https://api.githubcopilot.com"
api_key: "${GITHUB_COPILOT_TOKEN}"
model: "claude-opus-4.6"
reasoning_effort: "medium"  # low | medium | high
```

Puis exporte ta clé API :

```bash
# GitHub Copilot — récupérer le token automatiquement depuis OpenClaw
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)

# Ou manuellement si tu connais ton token
export GITHUB_COPILOT_TOKEN="ton-token-copilot"

# Ou OpenAI
export OPENAI_API_KEY="sk-..."
# (modifier base_url dans config.yaml en conséquence)
```

---

### Étape 2 — Lancer un scan avec analyse IA

#### Level 1 — Analyse statique + IA

```bash
export PATH="$PATH:$HOME/.local/bin"
export GITHUB_COPILOT_TOKEN="ton-token"

./scripts/scan.sh --target ./mon-projet --mode full --ai
```

#### Level 2 — Scan actif + IA

```bash
export PATH="$PATH:$HOME/.local/bin"
export GITHUB_COPILOT_TOKEN="ton-token"

python3 scripts/devsec-pipeline.py \
  --target "https://app.client.com" \
  --level 2 \
  --consent "reports/consent/consent-signed.pdf" \
  --ai \
  --ai-model "claude-opus-4.6" \
  --output "reports/scan-client-ai"
```

#### Avec un modèle local (Ollama — aucune clé, aucun internet)

```bash
# 1. Installer et démarrer Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3:8b

# 2. Modifier config.yaml :
# base_url: "http://localhost:11434/v1"
# api_key: "ollama"
# model: "llama3:8b"

# 3. Scanner
./scripts/scan.sh --target ./mon-projet --mode full --ai
```

---

### Ce que contient le rapport PDF en mode IA

Le rapport PDF possède une section supplémentaire **🤖 Analyse IA** :

```
## 🤖 Analyse IA
Modèle : claude-opus-4.6 via api.githubcopilot.com

### Triage & Priorisation
[L'IA analyse les 60 findings, écarte 5 faux positifs (clés API dans la doc),
 et priorise les 3 CVE exploitables...]

### Analyse CVE
[Pour chaque CVE high/critical : version qui corrige, vecteur d'attaque,
 workaround si mise à jour impossible...]

### Secrets exposés
[Distinction vrais/faux positifs, procédure de rotation urgente...]

### Synthèse exécutive
[5 lignes pour le RSSI / CTO...]
```

---

### Lancer l'analyse IA seule (sur des résultats existants)

```bash
export PATH="$PATH:$HOME/.local/bin"
export GITHUB_COPILOT_TOKEN="ton-token"

python3 scripts/ai_analyzer.py \
  --findings reports/scan-client/summary.json \
  --output reports/scan-client/ai_analysis.md \
  --level 2 \
  --verbose
```

---

### Comparaison modes sans IA / avec IA

| | Sans IA (`--mode full`) | Avec IA (`--mode full --ai`) |
|---|---|---|
| Outils de scan | grype, semgrep, gitleaks... | identiques |
| Triage | Score brut | IA priorise par exploitabilité réelle |
| Faux positifs | Non filtrés | Détectés et signalés |
| Fix suggestións | Non | Oui, avec exemples de code |
| Synthèse exécutive | Non | Oui (pour RSSI/CTO) |
| Connexion internet | Non (sauf outils actifs) | Oui (vers le provider IA) |
| Coût | 0 | 0 si GitHub Copilot actif |
| Durée supplémentaire | — | +30 à 60 secondes |

---

*Ce guide couvre 100% des cas d'usage courants. En cas de problème, consulter `INSTALL.md` pour les dépendances ou ouvrir une issue sur GitHub.*
