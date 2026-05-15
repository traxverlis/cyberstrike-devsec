# ⚠️ vuln-target — Applications web intentionnellement vulnérables

> **ATTENTION : Ces applications contiennent des failles de sécurité volontaires.**
> Elles sont uniquement destinées à servir de cibles pour les tests de CyberStrikeAI DevSec.
> **NE PAS déployer en production.**

---

## Contenu

| Fichier | Port | Failles intentionnelles |
|---------|------|------------------------|
| `app.py` | 5000 | SQL Injection, XSS réfléchi, secret hardcodé, path traversal, command injection |
| `app2.py` | 5001 | SQL Injection, XSS stocké, IDOR, auth bypass, API sans auth |

## Démarrage

```bash
# App v1 (port 5000)
python3 vuln-target/app.py

# App v2 (port 5001)
python3 vuln-target/app2.py
```

## Usage

Ces apps sont utilisées comme cibles pour les scans de sécurité DevSec :

```bash
# Depuis la racine du projet
export PATH="$PATH:$HOME/.local/bin"

# Scan Level 1 — code source
./scripts/scan.sh --target vuln-target/ --mode full

# Scan Level 2 — site web actif
./scripts/scan-web.sh
# (après avoir configuré TARGET_URL=http://localhost:5001 dans devsec.conf)
```

## Failles intentionnelles

Les secrets présents dans ces fichiers (`supersecret123`, `admin123`, etc.)
sont des **valeurs fictives de démonstration**. Ils sont volontairement insécures
pour permettre aux outils (gitleaks, semgrep...) de les détecter lors des tests.
