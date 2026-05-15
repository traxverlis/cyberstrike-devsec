# 📦 Guide d'installation — CyberStrikeAI DevSec

> **Pour débutants** — Suit ce guide de A à Z. Toutes les commandes sont prêtes à copier-coller.
> Aucune commande supplémentaire à inventer.

---

## Table des matières

1. [Prérequis système](#1-prérequis-système)
2. [Récupérer le dépôt](#2-récupérer-le-dépôt)
3. [Installer les outils de scan](#3-installer-les-outils-de-scan)
4. [Installer les dépendances Python](#4-installer-les-dépendances-python)
5. [Installer les outils de rapports PDF](#5-installer-les-outils-de-rapports-pdf)
6. [Vérifier l'installation](#6-vérifier-linstallation)
7. [Problèmes connus](#7-problèmes-connus)

---

## 1. Prérequis système

### Systèmes supportés

| Système | Statut |
|---------|--------|
| Ubuntu 22.04 / 24.04 | ✅ Recommandé |
| Debian 11 / 12 | ✅ Supporté |
| macOS 13+ | ✅ Supporté |
| Windows 10/11 | ✅ Via PowerShell (voir section Windows) |

### Ce dont tu as besoin avant de commencer

- **Git** — pour cloner le dépôt
- **Python 3.10+** — pour les scripts d'analyse
- **curl** — pour télécharger les outils
- **jq** — pour parser le JSON
- Accès **sudo** (droits administrateur)

**Vérifier que tu as tout :**

```bash
git --version
python3 --version
curl --version | head -1
jq --version
```

Si une commande renvoie `command not found`, l'installer :

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-pip curl jq unzip wget
```

---

## 2. Récupérer le dépôt

```bash
# Cloner le dépôt
git clone https://github.com/cyberstrike/devsec.git cyberstrike-devsec

# Aller dans le dossier
cd cyberstrike-devsec

# Vérifier que tout est là
ls
```

Tu dois voir : `README.md`, `scripts/`, `agents/`, `skills/`, `tools/`, `devsec.conf`, etc.

---

## 3. Installer les outils de scan

Lance le script d'installation fourni — il installe la majorité des outils automatiquement :

```bash
bash scripts/install.sh
```

> ⏱️ Durée estimée : 2 à 5 minutes selon ta connexion.

À la fin, le script affiche un résumé du type :
```
✅ grype    ✅ trivy    ✅ gitleaks    ✅ syft    ✅ osv-scanner
⚠️  semgrep  ⚠️  checkov  ⚠️  pip-audit  ⚠️  trufflehog
```

Si des outils sont marqués `⚠️ NOT FOUND`, passe à la section suivante pour les installer manuellement.

---

### 3a. Installer les outils manquants manuellement

#### semgrep, checkov, pip-audit

Sur Ubuntu/Debian, `pip install` est bloqué par le système. Il faut utiliser **pipx** :

```bash
# Installer pipx
pip3 install pipx --break-system-packages

# Ajouter pipx au PATH
echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
export PATH="$PATH:$HOME/.local/bin"

# Installer les outils
pipx install semgrep
pipx install checkov
pipx install pip-audit
```

#### trufflehog

Le script `install.sh` contient un bug d'URL pour trufflehog. Voici la commande corrigée :

```bash
# Récupérer la dernière version
LATEST=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
  | jq -r '.tag_name' | tr -d 'v')

# Télécharger et installer
curl -fsSL \
  "https://github.com/trufflesecurity/trufflehog/releases/download/v${LATEST}/trufflehog_${LATEST}_linux_amd64.tar.gz" \
  -o /tmp/trufflehog.tar.gz

tar -xz -C /tmp -f /tmp/trufflehog.tar.gz trufflehog
sudo mv /tmp/trufflehog /usr/local/bin/trufflehog
sudo chmod +x /usr/local/bin/trufflehog
```

#### nuclei

```bash
# Récupérer la dernière version
NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
  | jq -r '.tag_name')
NUCLEI_VER_NUM=$(echo $NUCLEI_VER | tr -d 'v')

# Télécharger et installer
curl -fsSL \
  "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER_NUM}_linux_amd64.zip" \
  -o /tmp/nuclei.zip

unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin
sudo mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei
sudo chmod +x /usr/local/bin/nuclei
```

#### nikto

```bash
sudo apt-get install -y nikto
```

#### testssl.sh

```bash
curl -fsSL https://testssl.sh/testssl.sh -o /tmp/testssl.sh
chmod +x /tmp/testssl.sh
sudo cp /tmp/testssl.sh /usr/local/bin/testssl.sh
```

---

## 4. Installer les dépendances Python

Les scripts Python du projet (pipeline, consentement, rapports) nécessitent quelques librairies :

```bash
# Dans le dossier du projet
pip3 install -r requirements.txt --break-system-packages
```

Pour les scripts de consentement (génération PDF de demande d'autorisation) :

```bash
pip3 install -r scripts/consent/requirements.txt --break-system-packages
```

> Ces dépendances incluent : `reportlab`, `qrcode`, `Pillow`, `requests`, `pdfplumber`, `rich`.

---

## 5. Installer les outils de rapports PDF

Les rapports PDF sont générés automatiquement en fin de scan via **pandoc** et **weasyprint**.

```bash
# pandoc (conversion Markdown → HTML)
sudo apt-get install -y pandoc

# Dépendances système pour weasyprint
sudo apt-get install -y \
  libpango-1.0-0 \
  libpangoft2-1.0-0 \
  libpangocairo-1.0-0 \
  libgdk-pixbuf2.0-0 \
  libcairo2 \
  libffi-dev

# weasyprint (conversion HTML → PDF, sans LaTeX)
export PATH="$PATH:$HOME/.local/bin"
pipx install weasyprint
```

Tester que la génération PDF fonctionne :

```bash
export PATH="$PATH:$HOME/.local/bin"
echo "<html><body><h1>Test CyberStrikeAI</h1></body></html>" > /tmp/test.html
weasyprint /tmp/test.html /tmp/test.pdf
ls -lh /tmp/test.pdf
```

Tu dois voir un fichier `test.pdf` de quelques Ko. Si c'est le cas, tout est prêt.

---

## 6. Vérifier l'installation

Lance cette commande pour vérifier que tous les outils sont bien installés :

```bash
export PATH="$PATH:$HOME/.local/bin"

for tool in grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit nuclei nikto testssl.sh pandoc weasyprint; do
  command -v $tool &>/dev/null \
    && echo "✅ $tool — OK" \
    || echo "❌ $tool — MANQUANT (voir section 3)"
done
```

**Résultat attendu :** tous les outils marqués ✅.

---

## 7. Problèmes connus

### `externally-managed-environment` lors de `pip install`

**Cause :** Debian/Ubuntu bloque `pip install` en dehors d'un virtualenv depuis Python 3.11+.

**Solution :** Utiliser `pipx` (voir section 3a) ou ajouter `--break-system-packages` :

```bash
pip3 install <paquet> --break-system-packages
```

### `trufflehog: command not found` après `install.sh`

**Cause :** Bug dans `install.sh` — l'URL de téléchargement est incorrecte.

**Solution :** Suivre la section 3a — Installation manuelle de trufflehog.

### `weasyprint: cannot load library 'libpango-1.0-0'`

**Cause :** Dépendances système manquantes.

**Solution :**
```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2
```

### `verify-consent.py: error: unrecognized arguments: --level`

**Cause :** Bug dans `scripts/devsec-pipeline.py` (ligne 123 dans la version initiale).

**Statut :** ✅ Corrigé dans le dépôt — si tu rencontres cette erreur, mets à jour le dépôt :
```bash
git pull
```

---

## Installation sur macOS

Les étapes sont identiques sauf pour les dépendances système — utiliser **Homebrew** :

```bash
# Installer Homebrew si absent
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Dépendances système
brew install git python curl jq unzip pandoc pango

# Puis reprendre à l'étape 3 (install.sh fonctionne sur macOS)
bash scripts/install.sh
```

---

## Installation sur Windows (PowerShell)

```powershell
# Ouvrir PowerShell en tant qu'Administrateur

# 1. Autoriser l'exécution de scripts
Set-ExecutionPolicy Bypass -Scope Process -Force

# 2. Installer les outils
.\scripts\install.ps1

# 3. Vérifier
.\scripts\scan.ps1 -Target . -Mode quick
```

---

*Installation complète estimée : 5 à 10 minutes sur une connexion standard.*
