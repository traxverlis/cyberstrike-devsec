# 📦 Guide d'installation — CyberStrikeAI DevSec

> **Pour débutants** — Deux commandes suffisent pour tout installer.
> Aucune étape manuelle requise.

---

## Table des matières

1. [Prérequis système](#1-prérequis-système)
2. [Récupérer le dépôt](#2-récupérer-le-dépôt)
3. [Tout installer en une commande](#3-tout-installer-en-une-commande)
4. [Vérifier l'installation](#4-vérifier-linstallation)
5. [Problèmes connus](#5-problèmes-connus)

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
- Accès **sudo** (droits administrateur)

**Vérifier que tu as tout :**

```bash
git --version
python3 --version
curl --version | head -1
```

Si une commande renvoie `command not found` :

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-pip curl
```

---

## 2. Récupérer le dépôt

```bash
git clone https://github.com/traxverlis/cyberstrike-devsec.git
cd cyberstrike-devsec
```

Tu dois voir : `README.md`, `scripts/`, `agents/`, `skills/`, `tools/`, `devsec.conf`, etc.

---

## 3. Tout installer en une commande

```bash
bash scripts/install.sh
```

Ce script installe **tout en automatique** :

**Outils Level 1 — Analyse statique :**
- ✅ grype, trivy, osv-scanner — scan CVE dépendances
- ✅ semgrep — SAST OWASP Top 10
- ✅ gitleaks, trufflehog — détection secrets
- ✅ syft — génération SBOM
- ✅ checkov, pip-audit — IaC + Python

**Outils Level 2 — Scan actif (PTES Phase 2-4) :**
- ✅ nmap — ports et services
- ✅ whatweb, subfinder — fingerprinting et sous-domaines
- ✅ nuclei, nikto — vulnérabilités web
- ✅ testssl.sh — analyse TLS/SSL
- ✅ gobuster, dirb, feroxbuster — découverte d'endpoints
- ✅ wapiti — scan web (SQLi, XSS, CSRF...)
- ✅ dalfox — scanner XSS
- ✅ enum4linux — énumération SMB

**Outils Level 3 — Pentest (PTES Phase 5-6) :**
- ✅ sqlmap — exploitation SQLi
- ✅ ffuf — fuzzing
- ✅ hydra — brute-force credentials

**Infrastructure :**
- ✅ Dépendances Python — requirements.txt + scripts/consent/requirements.txt
- ✅ Génération PDF — pandoc + weasyprint (test automatique inclus)
- ✅ PATH — mis à jour dans `~/.bashrc`

> ⏱️ Durée estimée : 3 à 8 minutes selon ta connexion.

À la fin, tu verras un résumé :

```
━━━ Résumé de l'installation ━━━━━━━━━━━━━━━━━━━━━━━

  ✅  grype           grype 0.112.0
  ✅  trivy           Version: 0.70.0
  ✅  semgrep         1.163.0
  ✅  gitleaks        8.30.1
  ✅  trufflehog      3.95.3
  ...
  ✅  whatweb         0.5.5
  ✅  gobuster        3.6.0
  ✅  dalfox          2.13.0
  ✅  subfinder       2.x
  ✅  hydra           9.x
  ✅  weasyprint      WeasyPrint version 68.1

  Score : 26/26 outils opérationnels

  ✅ Installation complète ! CyberStrikeAI DevSec est prêt.

  Prochaine étape :
  1. Recharge ton terminal : source ~/.bashrc
  2. Lance un scan         : ./scripts/scan.sh
```

---

## 4. Vérifier l'installation

Après un `source ~/.bashrc` (ou nouveau terminal) :

```bash
export PATH="$PATH:$HOME/.local/bin"

for tool in grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit \
            nuclei nikto testssl.sh nmap whatweb subfinder gobuster dirb feroxbuster \
            wapiti dalfox enum4linux sqlmap ffuf hydra pandoc weasyprint; do
  command -v $tool &>/dev/null \
    && echo "✅ $tool" \
    || echo "❌ $tool — MANQUANT (voir section 5)"
done
```

**Résultat attendu :** tous les outils marqués ✅.

---

## 5. Problèmes connus

### `externally-managed-environment` lors de `pip install`

**Cause :** Debian/Ubuntu bloque `pip install` hors virtualenv depuis Python 3.11+.
**Solution :** Le script utilise automatiquement `pipx` pour les outils Python. Si ça échoue manuellement :

```bash
pip3 install pipx --break-system-packages
export PATH="$PATH:$HOME/.local/bin"
pipx install semgrep
```

### `weasyprint: cannot load library 'libpango-1.0-0'`

**Cause :** Dépendances système manquantes (normalement installées par `install.sh`).
**Solution :**

```bash
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2
```

### Un outil spécifique a échoué

Relance le script — il saute automatiquement les outils déjà installés :

```bash
bash scripts/install.sh
```

---

## macOS

```bash
# Installer Homebrew si absent
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Puis lancer le script normalement
bash scripts/install.sh
```

---

## Windows (PowerShell)

```powershell
# Ouvrir PowerShell en tant qu'Administrateur
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install.ps1
```

---

---

## Alternative : Mode Docker (recommandé sur Windows)

Si tu es sur Windows ou que tu ne veux pas installer les outils localement :

```bash
# 1. Installer Docker Desktop
# https://docs.docker.com/get-docker/

# 2. Cloner le projet
git clone https://github.com/traxverlis/cyberstrike-devsec.git
cd cyberstrike-devsec

# 3. Construire l'image (une seule fois)
docker build -t cyberstrike-devsec .

# 4. Scanner
docker run --rm -v $(pwd):/workspace cyberstrike-devsec scan

# Windows PowerShell :
docker run --rm -v ${PWD}:/workspace cyberstrike-devsec scan
```

**L'image contient les 25+ outils préinstallés** — aucune installation locale requise.
Voir `README.md` pour toutes les options Docker.

*Installation complète estimée : 3 à 8 minutes sur une connexion standard.*
