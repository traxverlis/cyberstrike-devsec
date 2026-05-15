#!/usr/bin/env bash
# =============================================================================
# docker-entrypoint.sh — Point d'entrée CyberStrikeAI DevSec Container
#
# Usage depuis le conteneur :
#   docker run --rm -v $(pwd):/workspace cyberstrike-devsec scan
#   docker run --rm -v $(pwd):/workspace cyberstrike-devsec scan --mode quick
#   docker run --rm -v $(pwd):/workspace -v $(pwd)/reports:/reports \
#              cyberstrike-devsec scan-web --target https://site.com --consent /reports/consent.pdf
#   docker run --rm cyberstrike-devsec verify
#   docker run --rm cyberstrike-devsec help
# =============================================================================
set -euo pipefail

export PATH="/root/.local/bin:/usr/local/bin:${PATH}"

# Couleurs
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'

COMMAND="${1:-help}"
shift || true

banner() {
  echo -e "${BOLD}${CYAN}"
  echo "  ╔══════════════════════════════════════════════════════╗"
  echo "  ║     CyberStrikeAI DevSec — Container v3.3.0  🐳     ║"
  echo "  ╚══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

case "$COMMAND" in

  # ── Scan Level 1 (code source) ─────────────────────────────────────────────
  scan)
    banner
    # Par défaut, scanner /workspace si TARGET n'est pas passé
    if [[ "$*" != *"--target"* ]]; then
      exec bash /app/scripts/scan.sh --target /workspace "$@"
    else
      exec bash /app/scripts/scan.sh "$@"
    fi
    ;;

  # ── Scan Level 2 (site web) ────────────────────────────────────────────────
  scan-web)
    banner
    exec bash /app/scripts/scan-web.sh "$@"
    ;;

  # ── Pipeline direct (Level 1/2/3) ──────────────────────────────────────────
  pipeline)
    banner
    exec python3 /app/scripts/devsec-pipeline.py "$@"
    ;;

  # ── Génération de consentement ─────────────────────────────────────────────
  consent)
    banner
    exec python3 /app/scripts/consent/generate-consent.py "$@"
    ;;

  # ── Vérification consentement ──────────────────────────────────────────────
  verify-consent)
    banner
    exec python3 /app/scripts/consent/verify-consent.py "$@"
    ;;

  # ── Génération rapport PDF ─────────────────────────────────────────────────
  report)
    banner
    exec python3 /app/scripts/generate-report.py "$@"
    ;;

  # ── Vérification des outils installés ─────────────────────────────────────
  verify)
    banner
    echo -e "${BOLD}Vérification des outils dans le conteneur :${RESET}\n"
    PASS=0; FAIL=0
    for tool in grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit \
                nuclei nikto testssl.sh nmap whatweb gobuster dirb feroxbuster dalfox \
                subfinder hydra wapiti ffuf sqlmap enum4linux pandoc weasyprint zaproxy; do
      if command -v "$tool" &>/dev/null; then
        VER=$(${tool} --version 2>&1 | head -1 || echo "ok")
        printf "  ${GREEN}✅${RESET}  %-20s %s\n" "$tool" "${VER:0:40}"
        ((PASS++)) || true
      else
        printf "  ${RED}❌${RESET}  %-20s NON INSTALLÉ\n" "$tool"
        ((FAIL++)) || true
      fi
    done
    echo ""
    echo -e "  Score : ${BOLD}${PASS}/$((PASS+FAIL))${RESET} outils opérationnels"
    [[ $FAIL -eq 0 ]] && echo -e "\n  ${GREEN}✅ Conteneur prêt !${RESET}" \
                       || echo -e "\n  ${YELLOW}⚠️  Certains outils manquent${RESET}"
    ;;

  # ── Shell interactif ───────────────────────────────────────────────────────
  shell|bash|sh)
    banner
    echo -e "  Ouverture d'un shell interactif dans le conteneur...\n"
    exec /bin/bash
    ;;

  # ── Aide ───────────────────────────────────────────────────────────────────
  help|--help|-h)
    banner
    cat << 'EOF'
Commandes disponibles :

  scan          Scan Level 1 — analyse statique du code source
  scan-web      Scan Level 2 — scan actif d'un site web
  pipeline      Pipeline direct (--level 1|2|3)
  consent       Générer un document de consentement PDF
  verify-consent  Vérifier un consentement signé
  report        Générer un rapport PDF depuis des résultats existants
  verify        Vérifier les outils installés dans le conteneur
  shell         Ouvrir un shell bash interactif
  help          Afficher cette aide

Exemples :

  # Scan rapide du répertoire courant
  docker run --rm -v $(pwd):/workspace cyberstrike-devsec scan --mode quick

  # Scan complet avec rapport dans ./reports
  docker run --rm \
    -v $(pwd):/workspace \
    -v $(pwd)/reports:/reports \
    cyberstrike-devsec scan --mode full --output /reports

  # Scan avec IA (GitHub Copilot)
  docker run --rm \
    -v $(pwd):/workspace \
    -v $(pwd)/reports:/reports \
    -e GITHUB_COPILOT_TOKEN="votre-token" \
    cyberstrike-devsec scan --mode full --ai

  # Scan site web Level 2
  docker run --rm \
    -v $(pwd)/reports:/reports \
    cyberstrike-devsec scan-web \
      --target https://app.example.com \
      --consent /reports/consent-signed.pdf

  # Shell interactif
  docker run --rm -it \
    -v $(pwd):/workspace \
    cyberstrike-devsec shell

  # Vérifier tous les outils
  docker run --rm cyberstrike-devsec verify

Volumes :
  /workspace  → Projet à scanner (monter avec -v $(pwd):/workspace)
  /reports    → Rapports de sortie (monter avec -v $(pwd)/reports:/reports)

EOF
    ;;

  # ── Fallback — passer la commande directement ──────────────────────────────
  *)
    exec "$COMMAND" "$@"
    ;;
esac
