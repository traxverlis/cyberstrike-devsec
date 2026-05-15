#!/usr/bin/env bash
# =============================================================================
# CyberStrikeAI DevSec — scan-web.sh
# Scan Level 2 (site web actif) — lit la config dans devsec.conf
#
# Usage simple :
#   ./scripts/scan-web.sh
#
# Ou avec options ponctuelles :
#   ./scripts/scan-web.sh --target https://monsite.com --consent ./doc-signe.pdf
#
# ⚠️  Nécessite un document de consentement signé — voir USAGE.md
# =============================================================================
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

export PATH="$PATH:$HOME/.local/bin"

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET_URL="https://app.example.com"
CONSENT=""
OUTPUT=""
AI_MODE=false
AI_MODEL_FROM_CONF="gpt-4o"
DOCKER_MODE=false
CONFIRM_L3=false
DEV_MODE=false

# ── Charger devsec.conf ───────────────────────────────────────────────────────
CONF="$(dirname "$0")/../devsec.conf"
[[ ! -f "$CONF" ]] && CONF="./devsec.conf"
if [[ -f "$CONF" ]]; then
  while IFS='=' read -r key val; do
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$key" ]] && continue
    key="${key// /}"
    val="${val%%#*}"; val="${val//\"/}"; val="${val//\'/}"
    val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"
    case "$key" in
      TARGET_URL) TARGET_URL="$val" ;;
      CONSENT)    CONSENT="$val" ;;
      OUTPUT)     OUTPUT="$val" ;;
      AI)         [[ "$val" == "true" ]] && AI_MODE=true ;;
      AI_MODEL)   AI_MODEL_FROM_CONF="$val" ;;
    esac
  done < "$CONF"
  echo -e "  ${DIM}[devsec.conf chargé]${RESET}"
fi

# ── Overrides ligne de commande ───────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)  TARGET_URL="$2"; shift 2 ;;
    --consent) CONSENT="$2"; shift 2 ;;
    --output)  OUTPUT="$2"; shift 2 ;;
    --confirm) CONFIRM_L3=true; shift ;;
    --dev)     DEV_MODE=true; shift ;;
    --docker)  DOCKER_MODE=true; shift ;;
    --ai)      AI_MODE=true; shift ;;
    --help|-h)
      echo "Usage: ./scripts/scan-web.sh [--target URL] [--consent PDF] [--output DIR] [--ai] [--docker] [--dev]"
      echo "Config par défaut dans devsec.conf"
      exit 0 ;;
    *) echo "Option inconnue: $1"; exit 1 ;;
  esac
done

# Dossier de sortie auto si non défini
[[ -z "$OUTPUT" ]] && OUTPUT="reports/scan-web-$(date +%Y%m%d_%H%M%S)"

echo -e "\n${BOLD}${CYAN}╔═══════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║     CyberStrikeAI DevSec — Scan Web Level 2       ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════╝${RESET}\n"
echo -e "  Cible   : ${BOLD}$TARGET_URL${RESET}"
echo -e "  Sortie  : ${BOLD}$OUTPUT${RESET}"
echo -e "  IA      : ${BOLD}$([ "$AI_MODE" == "true" ] && echo "activée ($AI_MODEL_FROM_CONF)" || echo "désactivée")${RESET}"
echo -e "  Consent : ${BOLD}${CONSENT:-non défini}${RESET}\n"


# ── Mode Docker ───────────────────────────────────────────────────────────────
if [[ "$DOCKER_MODE" == "true" ]]; then
  if ! command -v docker &>/dev/null; then
    echo -e "${RED}❌ Docker non trouvé. Installer Docker : https://docs.docker.com/get-docker/${RESET}"
    exit 1
  fi
  if ! docker image inspect cyberstrike-devsec:latest &>/dev/null 2>&1; then
    echo -e "${CYAN}  ➜ Construction de l'image Docker (première fois ~10-15min)...${RESET}"
    docker build -t cyberstrike-devsec:latest "$(dirname "$0")/.."
  fi
  echo -e "${CYAN}  ➜ Lancement du scan web dans le conteneur Docker...${RESET}"
  DOCKER_ARGS=(
    "--rm" "--network=host"
    "-v" "$(realpath "${OUTPUT:-./security-reports}"):/reports"
  )
  [[ -f "$CONSENT" ]] && DOCKER_ARGS+=("-v" "$(realpath "$CONSENT"):/reports/consent-signed.pdf:ro")
  [[ -n "${GITHUB_COPILOT_TOKEN:-}" ]] && DOCKER_ARGS+=("-e" "GITHUB_COPILOT_TOKEN=${GITHUB_COPILOT_TOKEN}")

  SCAN_ARGS=("scan-web" "--target" "$TARGET_URL" "--consent" "/reports/consent-signed.pdf" "--output" "/reports")
  [[ "$CONFIRM_L3" == "true" ]] && SCAN_ARGS+=("--confirm")
  [[ "$DEV_MODE" == "true" ]]   && SCAN_ARGS+=("--dev")
  [[ "$AI_MODE" == "true" ]] && SCAN_ARGS+=("--ai")

  exec docker run "${DOCKER_ARGS[@]}" cyberstrike-devsec:latest "${SCAN_ARGS[@]}"
fi

# ── Vérifications préalables ──────────────────────────────────────────────────
if [[ "$DEV_MODE" == "true" ]]; then
  echo -e "${YELLOW}⚡ Mode DEV — consentement ignoré (scan de ton propre projet)${RESET}"
  CONSENT=""
elif [[ -z "$CONSENT" || ! -f "$CONSENT" ]]; then
  echo -e "${RED}❌ Document de consentement manquant ou introuvable : ${CONSENT:-'(non défini dans devsec.conf)'}${RESET}"
  echo ""
  echo -e "  Pour générer le document :"
  echo -e "  ${CYAN}python3 scripts/consent/generate-consent.py \\${RESET}"
  echo -e "  ${CYAN}    --target \"$TARGET_URL\" --scope \"/*\" \\${RESET}"
  echo -e "  ${CYAN}    --requestor \"Ton Nom\" --company \"Ta Société\" \\${RESET}"
  echo -e "  ${CYAN}    --tester \"Red Team\" --duration \"$(date +%Y-%m-%d) to $(date -d '+7 days' +%Y-%m-%d 2>/dev/null || date +%Y-%m-%d)\" \\${RESET}"
  echo -e "  ${CYAN}    --test-types \"recon,headers,cors,ssl,nikto,nmap\" \\${RESET}"
  echo -e "  ${CYAN}    --exclusions \"aucune\" --output reports/consent/consent-draft.pdf${RESET}"
  echo ""
  echo -e "  Puis mettre CONSENT=./reports/consent/consent-signed.pdf dans devsec.conf"
  exit 1
fi

# ── Vérifier le consentement ──────────────────────────────────────────────────
echo -e "${CYAN}  ► Vérification du consentement...${RESET}"
if ! python3 scripts/consent/verify-consent.py \
    --consent "$CONSENT" \
    --target "$TARGET_URL" \
    --token-out "$OUTPUT/.consent-token.json" 2>&1 | grep -q "PASSED"; then
  echo -e "${RED}❌ Consentement invalide ou expiré — scan annulé${RESET}"
  exit 1
fi
echo -e "${GREEN}  ✅ Consentement validé${RESET}\n"

# ── Lancer le pipeline Level 2 ────────────────────────────────────────────────
AI_FLAG=""
[[ "$AI_MODE" == "true" ]] && AI_FLAG="--ai --ai-model $AI_MODEL_FROM_CONF"

python3 scripts/devsec-pipeline.py \
  --target "$TARGET_URL" \
  --level 2 \
  --consent "$CONSENT" \
  --output "$OUTPUT" \
  $AI_FLAG 2>&1

echo ""
echo -e "${GREEN}${BOLD}✅ Rapport disponible : $OUTPUT/report.pdf${RESET}"
