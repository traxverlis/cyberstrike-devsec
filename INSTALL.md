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
- ✅ Outils de scan — grype, trivy, semgrep, gitleaks, trufflehog, syft, osv-scanner, checkov, pip-audit
- ✅ Outils web — nuclei, nikto, testssl.sh
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
  ...
  ✅  weasyprint      WeasyPrint version 68.1

  Score : 14/14 outils opérationnels

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

for tool in grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit nuclei nikto testssl.sh pandoc weasyprint; do
  command -v $tool &>/dev/null \
    && echo "✅ $tool" \
    || echo "❌ $tool — MANQUANT"
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

*Installation complète estimée : 3 à 8 minutes sur une connexion standard.*
