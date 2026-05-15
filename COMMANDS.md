# COMMANDS.md — Historique des commandes CyberStrikeAI DevSec

> Toutes les commandes lancées lors de la session de découverte du projet (2026-05-15)

---

## 1. Exploration initiale

```bash
# Lister les fichiers du projet
ls /home/ubuntu/.openclaw/workspace/cyberstrike-devsec/

# Lire le README
cat /home/ubuntu/.openclaw/workspace/cyberstrike-devsec/README.md

# Vérifier l'historique git
cd /home/ubuntu/.openclaw/workspace/cyberstrike-devsec
git log --oneline
git log --stat --format="%H%n%an <%ae>%n%ad%n%s%n%b%n---"
```

---

## 2. Audit des scripts

```bash
# Lister tous les scripts
find scripts/ -type f | sort

# Vérifier les permissions
ls -la scripts/*.sh scripts/*.ps1 scripts/*.py scripts/*.bat scripts/consent/*.py

# Vérifier la syntaxe bash
bash -n scripts/scan.sh && echo "OK"
bash -n scripts/install.sh && echo "OK"

# Vérifier la syntaxe Python
python3 -m py_compile scripts/audit-trail.py
python3 -m py_compile scripts/devsec-pipeline.py
python3 -m py_compile scripts/generate-report.py
python3 -m py_compile scripts/notify.py
python3 -m py_compile scripts/consent/generate-consent.py
python3 -m py_compile scripts/consent/send-consent.py
python3 -m py_compile scripts/consent/verify-consent.py

# Vérifier les dépendances Python disponibles
python3 -c "import reportlab, qrcode, PIL, requests, pdfplumber"

# Vérifier les outils de scan disponibles
for tool in grype trivy semgrep gitleaks trufflehog syft checkov osv-scanner; do
  command -v $tool &>/dev/null && echo "✅ $tool" || echo "❌ $tool (absent)"
done
```

---

## 3. Installation des outils (install.sh)

```bash
cd /home/ubuntu/.openclaw/workspace/cyberstrike-devsec
bash scripts/install.sh
```

### Résultat : 6/10 installés automatiquement
| Outil | Statut |
|-------|--------|
| grype 0.112.0 | ✅ |
| trivy 0.70.0 | ✅ |
| semgrep | ❌ (pip bloqué — env géré) |
| gitleaks 8.30.1 | ✅ |
| syft 1.44.0 | ✅ |
| osv-scanner 2.3.8 | ✅ |
| trufflehog | ❌ (URL 404 dans install.sh) |
| checkov | ❌ (pip bloqué) |
| pip-audit | ❌ (pip bloqué) |

### Fix manuel — semgrep, checkov, pip-audit (via pipx)

```bash
pip3 install pipx --break-system-packages
export PATH="$PATH:$HOME/.local/bin"
pipx install semgrep
pipx install checkov
pipx install pip-audit
```

### Fix manuel — trufflehog (URL corrigée)

```bash
# Le script install.sh utilise une URL incorrecte (trufflehog_linux_amd64.tar.gz)
# Le bon format est : trufflehog_<VERSION>_linux_amd64.tar.gz
LATEST=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r '.tag_name' | tr -d 'v')
URL="https://github.com/trufflesecurity/trufflehog/releases/download/v${LATEST}/trufflehog_${LATEST}_linux_amd64.tar.gz"
curl -fsSL "$URL" -o /tmp/trufflehog.tar.gz
tar -xz -C /tmp -f /tmp/trufflehog.tar.gz trufflehog
sudo mv /tmp/trufflehog /usr/local/bin/trufflehog && sudo chmod +x /usr/local/bin/trufflehog
```

### Installation de nuclei, nikto, testssl (non inclus dans install.sh)

```bash
# nuclei
NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name')
NUCLEI_VER_NUM=$(echo $NUCLEI_VER | tr -d 'v')
curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER_NUM}_linux_amd64.zip" -o /tmp/nuclei.zip
unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin
sudo mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei && sudo chmod +x /usr/local/bin/nuclei

# nikto
sudo apt-get install -y nikto

# testssl
curl -fsSL https://testssl.sh/testssl.sh -o /tmp/testssl.sh
chmod +x /tmp/testssl.sh && sudo cp /tmp/testssl.sh /usr/local/bin/testssl.sh
```

### Vérification finale — 10/10

```bash
export PATH="$PATH:$HOME/.local/bin"
for tool in grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit nuclei nikto testssl.sh; do
  command -v $tool &>/dev/null && echo "✅ $tool" || echo "❌ $tool"
done
```

---

## 4. Scans de l'infrastructure

### Scan Quick (~30s)

```bash
cd /home/ubuntu/.openclaw/workspace/cyberstrike-devsec
export PATH="$PATH:$HOME/.local/bin"
bash scripts/scan.sh --target . --mode quick
```

**Résultats :**
- 🔴 Secrets : 5 (faux positifs dans doc/templates)
- 🟡 CVE High : 3 (`actions/download-artifact v4` — `GHSA-cxww-7g56-2vh6`)
- 🟢 CVE Critical : 0

### Scan Full (~18s)

```bash
bash scripts/scan.sh --target . --mode full
```

**Résultats :**
- 🔴 Secrets : 5 (gitleaks — faux positifs)
- 🟡 CVE High : 3 (même CVE x3 workflows)
- 🟠 SAST : 7 erreurs (injections GitHub Actions dans workflows L2/L3)
- ✅ OSV : 0
- ✅ TruffleHog : 0
- ✅ SBOM : 21 composants
- Rapports dans `./security-reports/`

---

## 5. Flow Level 2 — Consentement + Scan actif

### Étape 1 — Générer le PDF de consentement

```bash
cd /home/ubuntu/.openclaw/workspace/cyberstrike-devsec
export PATH="$PATH:$HOME/.local/bin"
mkdir -p reports/consent

python3 scripts/consent/generate-consent.py \
  --target "https://app.example.com" \
  --scope "/api/*, /admin/*, /*.app.example.com" \
  --requestor "Julien" \
  --company "CyberStrikeAI" \
  --tester "Red Team Alpha" \
  --duration "2026-05-15 to 2026-05-22" \
  --test-types "recon,headers,cors,ssl,nikto,nmap" \
  --exclusions "production DB, /internal/*, /pay/*" \
  --output reports/consent/consent-draft.pdf
```

### Étape 2 — Envoyer pour signature (en prod)

```bash
python3 scripts/consent/send-consent.py \
  --pdf reports/consent/consent-draft.pdf \
  --to-email cto@example.com \
  --to-name "CTO Example" \
  --from-email security@cyberstrike.ai \
  --smtp-host smtp.example.com \
  --smtp-user user \
  --smtp-pass secret
```

> ℹ️ En test local : copier le draft en signé et régénérer avec signatures remplies.

### Étape 3 — Vérifier le document signé

```bash
python3 scripts/consent/verify-consent.py \
  --consent reports/consent/consent-signed.pdf \
  --target "https://app.example.com" \
  --token-out reports/consent/consent-token.json
```

**Token généré :** `reports/consent/consent-token.json` (statut `APPROVED`)

### Étape 4 — Lancer le scan Level 2

```bash
python3 scripts/devsec-pipeline.py \
  --target "https://app.example.com" \
  --level 2 \
  --lang auto \
  --consent "reports/consent/consent-signed.pdf" \
  --output "reports/level2_$(date +%Y%m%d_%H%M%S)"
```

---

## 6. Bugs découverts et corrigés

| Fichier | Bug | Fix |
|---------|-----|-----|
| `scripts/install.sh` | URL TruffleHog incorrecte (`trufflehog_linux_amd64.tar.gz`) | Utiliser `trufflehog_<VERSION>_linux_amd64.tar.gz` |
| `scripts/install.sh` | `pip install semgrep/checkov/pip-audit` bloqué (env géré Debian) | Utiliser `pipx install` |
| `scripts/devsec-pipeline.py` ligne 123 | Passe `--level` à `verify-consent.py` qui ne l'accepte pas | Supprimer `"--level", str(level)` de la liste d'args |
| `scripts/generate-report.py` | Reçoit `--summary` comme arg mais ne le reconnaît pas | Minor — rapport HTML généré quand même |

---

## 7. Génération de rapports PDF

### Installation des dépendances PDF

```bash
# pandoc
sudo apt-get install -y pandoc

# Dépendances système pour weasyprint
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2 libffi-dev

# weasyprint via pipx
export PATH="$PATH:$HOME/.local/bin"
pipx install weasyprint

# Tester
echo "<html><body><h1>Test</h1></body></html>" > /tmp/test.html
weasyprint /tmp/test.html /tmp/test.pdf && echo "PDF OK"
```

### Générer un rapport PDF manuellement

```bash
export PATH="$PATH:$HOME/.local/bin"

# Level 1 — depuis security-reports/
python3 scripts/generate-report.py \
  --results-dir ./security-reports \
  --output ./security-reports/report.pdf \
  --level 1 \
  --format pdf

# Level 2 — depuis un dossier de pipeline
python3 scripts/generate-report.py \
  --results-dir ./reports/level2_xxx/raw \
  --output ./reports/level2_xxx/report.pdf \
  --level 2 \
  --format pdf
```

### Bugs corrigés dans generate-report.py et devsec-pipeline.py

| Fichier | Modification |
|---------|-------------|
| `scripts/generate-report.py` | Remplacé `_convert_with_pandoc` (pandoc+xelatex uniquement) par une stratégie HTML→PDF via weasyprint, avec fallback xelatex |
| `scripts/devsec-pipeline.py` | Génération auto de MD + HTML + PDF en fin de pipeline (3 appels à generate-report.py) |
| `scripts/scan.sh` | Ajout d'un bloc PDF Report Generation avant le résumé final |

---

## 8. Site HTTP vulnérable (target de test)

```bash
# Démarrer le site vulnérable
cd /home/ubuntu/.openclaw/workspace/cyberstrike-devsec/vuln-target
pip3 install flask --break-system-packages  # ou pipx
python3 app.py
# → http://localhost:5000
```

### Failles intentionnelles

| Faille | Endpoint | Description |
|--------|----------|-------------|
| SQL Injection | `GET /search?q=...` | Paramètre injecté dans la requête SQLite |
| XSS réfléchi | `GET /greet?name=...` | Input non échappé dans le HTML |
| Secret exposé | `GET /debug` | Clé API en clair dans la réponse |
| Headers manquants | Tous | Pas de CSP, X-Frame-Options, etc. |

---

## 8. Scan Level 2 sur la target vulnérable

```bash
cd /home/ubuntu/.openclaw/workspace/cyberstrike-devsec
export PATH="$PATH:$HOME/.local/bin"

# Générer le consentement pour la target locale
python3 scripts/consent/generate-consent.py \
  --target "http://localhost:5000" \
  --scope "/*" \
  --requestor "Julien" \
  --company "CyberStrikeAI" \
  --tester "Red Team Alpha" \
  --duration "$(date +%Y-%m-%d) to $(date -d '+7 days' +%Y-%m-%d)" \
  --test-types "recon,headers,cors,nikto,nmap,xss,sqli" \
  --exclusions "aucune" \
  --output reports/consent/consent-localhost-signed.pdf

# Vérifier
python3 scripts/consent/verify-consent.py \
  --consent reports/consent/consent-localhost-signed.pdf \
  --target "http://localhost:5000" \
  --token-out reports/consent/consent-token-localhost.json

# Scanner
python3 scripts/devsec-pipeline.py \
  --target "http://localhost:5000" \
  --level 2 \
  --lang auto \
  --consent "reports/consent/consent-localhost-signed.pdf" \
  --output "reports/level2_localhost_$(date +%Y%m%d_%H%M%S)"
```
