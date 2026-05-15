#!/usr/bin/env bash
# =============================================================================
# CyberStrikeAI DevSec — install.sh
# Installation complète en une seule commande
#
# Couvre :
#   - Outils de scan (grype, trivy, semgrep, gitleaks, trufflehog, syft,
#                     osv-scanner, checkov, pip-audit, nuclei, nikto, testssl)
#   - Dépendances Python (requirements.txt + scripts/consent/requirements.txt)
#   - Génération PDF (pandoc + weasyprint)
#
# Usage :
#   bash scripts/install.sh
#   bash scripts/install.sh --dry-run      (simuler sans installer)
#   bash scripts/install.sh --skip-python  (sauter pip/pipx tools)
# =============================================================================
set -euo pipefail

# ── Couleurs ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ── Options ───────────────────────────────────────────────────────────────────
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
SKIP_PYTHON=false
DRY_RUN=false
FAILED=()
OK=()

for arg in "$@"; do
  case $arg in
    --skip-python) SKIP_PYTHON=true ;;
    --dry-run)     DRY_RUN=true ;;
    --prefix=*)    INSTALL_PREFIX="${arg#*=}" ;;
    --help|-h)
      echo "Usage: bash scripts/install.sh [--dry-run] [--skip-python] [--prefix=/path]"
      exit 0 ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
log()     { echo -e "${CYAN}  ➜ $*${RESET}"; }
ok()      { echo -e "${GREEN}  ✅ $*${RESET}"; OK+=("$1"); }
warn()    { echo -e "${YELLOW}  ⚠️  $*${RESET}"; }
fail()    { echo -e "${RED}  ❌ $*${RESET}"; FAILED+=("$1"); }
header()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
is_ok()   { command -v "$1" &>/dev/null; }
run()     { [[ "$DRY_RUN" == "true" ]] && echo -e "${DIM}  [dry] $*${RESET}" || eval "$@"; }

# ── Détecter l'OS ─────────────────────────────────────────────────────────────
if   [[ "$OSTYPE" == "darwin"* ]];     then OS="macos"
elif [[ -f /etc/debian_version ]];     then OS="debian"
elif [[ -f /etc/redhat-release ]];     then OS="rhel"
elif [[ -f /etc/arch-release ]];       then OS="arch"
else                                        OS="unknown"
fi

# ── Bannière ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║     CyberStrikeAI DevSec — Installation complète 🛡️  ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  OS       : ${BOLD}${OS}${RESET}"
echo -e "  Prefix   : ${BOLD}${INSTALL_PREFIX}${RESET}"
[[ "$DRY_RUN" == "true" ]] && echo -e "  ${YELLOW}Mode : DRY RUN — aucune installation réelle${RESET}"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
# PARTIE 1 — Dépendances système
# ═════════════════════════════════════════════════════════════════════════════
header "1/5 — Dépendances système"

install_sys_deps() {
  case "$OS" in
    macos)
      is_ok brew || { error "Homebrew requis : https://brew.sh"; exit 1; }
      run "brew install curl wget jq git unzip 2>/dev/null || true"
      ;;
    debian)
      run "sudo apt-get update -qq"
      run "sudo apt-get install -y -qq curl wget jq git tar unzip gnupg lsb-release \
        apt-transport-https ca-certificates python3 python3-pip pipx pandoc \
        libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
        libgdk-pixbuf2.0-0 libcairo2 libffi-dev nikto"
      ;;
    rhel)
      run "sudo dnf install -y curl wget jq git tar unzip gnupg python3 python3-pip nikto 2>/dev/null || \
           sudo yum install -y curl wget jq git tar unzip gnupg python3 python3-pip"
      run "sudo dnf install -y pandoc 2>/dev/null || warn 'pandoc non dispo via dnf — installer manuellement'"
      ;;
    arch)
      run "sudo pacman -Sy --noconfirm curl wget jq git tar unzip python python-pip pandoc nikto"
      ;;
    *)
      warn "OS inconnu — s'assurer que curl, wget, jq, git, python3, pandoc, nikto sont installés"
      ;;
  esac
}

install_sys_deps && ok "sys-deps" || warn "Certaines dépendances système ont échoué"

# ═════════════════════════════════════════════════════════════════════════════
# PARTIE 2 — Outils de scan binaires
# ═════════════════════════════════════════════════════════════════════════════
header "2/5 — Outils de scan"

# ── grype ─────────────────────────────────────────────────────────────────────
if is_ok grype; then
  ok "grype (déjà installé : $(grype version 2>&1 | head -1))"
else
  log "Installation de grype..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install anchore/grype/grype"
  else
    run "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b '$INSTALL_PREFIX'"
  fi
  is_ok grype && ok "grype" || fail "grype"
fi

# ── trivy ─────────────────────────────────────────────────────────────────────
if is_ok trivy; then
  ok "trivy (déjà installé : $(trivy --version 2>&1 | head -1))"
else
  log "Installation de trivy..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install aquasecurity/trivy/trivy"
  elif [[ "$OS" == "debian" ]]; then
    run "wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null"
    run "echo 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' | sudo tee /etc/apt/sources.list.d/trivy.list"
    run "sudo apt-get update -qq && sudo apt-get install -y trivy"
  else
    TRIVY_VER=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r .tag_name)
    run "curl -sSfL 'https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_Linux-64bit.tar.gz' | sudo tar -xz -C '$INSTALL_PREFIX' trivy"
  fi
  is_ok trivy && ok "trivy" || fail "trivy"
fi

# ── gitleaks ──────────────────────────────────────────────────────────────────
if is_ok gitleaks; then
  ok "gitleaks (déjà installé)"
else
  log "Installation de gitleaks..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install gitleaks"
  else
    GL_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
    run "curl -sSfL 'https://github.com/gitleaks/gitleaks/releases/download/${GL_VER}/gitleaks_${GL_VER#v}_linux_x64.tar.gz' | sudo tar -xz -C '$INSTALL_PREFIX' gitleaks"
  fi
  is_ok gitleaks && ok "gitleaks" || fail "gitleaks"
fi

# ── trufflehog ────────────────────────────────────────────────────────────────
if is_ok trufflehog; then
  ok "trufflehog (déjà installé)"
else
  log "Installation de trufflehog..."
  TH_VER=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r '.tag_name' | tr -d 'v')
  ARCH="amd64"; [[ "$(uname -m)" =~ arm|aarch ]] && ARCH="arm64"
  OS_SUFFIX="linux"; [[ "$OS" == "macos" ]] && OS_SUFFIX="darwin"
  run "curl -sSfL 'https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_${OS_SUFFIX}_${ARCH}.tar.gz' -o /tmp/trufflehog.tar.gz"
  run "tar -xz -C /tmp -f /tmp/trufflehog.tar.gz trufflehog"
  run "sudo mv /tmp/trufflehog '$INSTALL_PREFIX/trufflehog' && sudo chmod +x '$INSTALL_PREFIX/trufflehog'"
  is_ok trufflehog && ok "trufflehog" || fail "trufflehog"
fi

# ── syft ──────────────────────────────────────────────────────────────────────
if is_ok syft; then
  ok "syft (déjà installé)"
else
  log "Installation de syft..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install anchore/syft/syft"
  else
    run "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b '$INSTALL_PREFIX'"
  fi
  is_ok syft && ok "syft" || fail "syft"
fi

# ── osv-scanner ───────────────────────────────────────────────────────────────
if is_ok osv-scanner; then
  ok "osv-scanner (déjà installé)"
else
  log "Installation de osv-scanner..."
  OSV_VER=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest | jq -r .tag_name)
  ARCH="amd64"; [[ "$(uname -m)" =~ arm|aarch ]] && ARCH="arm64"
  OS_SUFFIX="linux"; [[ "$OS" == "macos" ]] && OS_SUFFIX="darwin"
  run "curl -sSfL 'https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_${OS_SUFFIX}_${ARCH}' -o /tmp/osv-scanner"
  run "chmod +x /tmp/osv-scanner && sudo mv /tmp/osv-scanner '$INSTALL_PREFIX/osv-scanner'"
  is_ok osv-scanner && ok "osv-scanner" || fail "osv-scanner"
fi

# ── nuclei ────────────────────────────────────────────────────────────────────
if is_ok nuclei; then
  ok "nuclei (déjà installé)"
else
  log "Installation de nuclei..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install nuclei"
  else
    NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name')
    NUCLEI_NUM="${NUCLEI_VER#v}"
    ARCH="amd64"; [[ "$(uname -m)" =~ arm|aarch ]] && ARCH="arm64"
    run "curl -sSfL 'https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_NUM}_linux_${ARCH}.zip' -o /tmp/nuclei.zip"
    run "unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin && sudo mv /tmp/nuclei_bin/nuclei '$INSTALL_PREFIX/nuclei' && sudo chmod +x '$INSTALL_PREFIX/nuclei'"
    run "rm -f /tmp/nuclei.zip"
  fi
  is_ok nuclei && ok "nuclei" || fail "nuclei"
fi

# ── nikto (installé en partie 1 via apt sur debian) ──────────────────────────
if is_ok nikto; then
  ok "nikto (déjà installé)"
else
  log "Installation de nikto..."
  case "$OS" in
    macos)   run "brew install nikto" ;;
    rhel)    run "sudo dnf install -y nikto 2>/dev/null || sudo yum install -y nikto" ;;
    arch)    run "sudo pacman -Sy --noconfirm nikto" ;;
    *)       warn "nikto : installe-le via ton gestionnaire de paquets" ;;
  esac
  is_ok nikto && ok "nikto" || warn "nikto non installé (optionnel)"
fi

# ── testssl.sh ────────────────────────────────────────────────────────────────
if is_ok testssl.sh; then
  ok "testssl.sh (déjà installé)"
else
  log "Installation de testssl.sh..."
  run "curl -sSfL https://testssl.sh/testssl.sh -o /tmp/testssl.sh"
  run "chmod +x /tmp/testssl.sh && sudo cp /tmp/testssl.sh '$INSTALL_PREFIX/testssl.sh'"
  is_ok testssl.sh && ok "testssl.sh" || warn "testssl.sh non installé (optionnel)"
fi

# ── whatweb ──────────────────────────────────────────────────────────────────
if is_ok whatweb; then
  ok "whatweb (déjà installé)"
else
  log "Installation de whatweb..."
  case "$OS" in
    macos)   run "brew install whatweb" ;;
    debian)  run "sudo apt-get install -y whatweb -qq" ;;
    rhel)    run "sudo dnf install -y whatweb 2>/dev/null || warn 'whatweb non dispo via dnf'" ;;
    *)       warn "whatweb : installer manuellement" ;;
  esac
  is_ok whatweb && ok "whatweb" || warn "whatweb non installé (optionnel)"
fi

# ── gobuster ──────────────────────────────────────────────────────────────────
if is_ok gobuster; then
  ok "gobuster (déjà installé)"
else
  log "Installation de gobuster..."
  case "$OS" in
    macos)   run "brew install gobuster" ;;
    debian)  run "sudo apt-get install -y gobuster -qq" ;;
    rhel)    run "sudo dnf install -y gobuster 2>/dev/null || warn 'gobuster non dispo'" ;;
    *)       warn "gobuster : installer manuellement" ;;
  esac
  is_ok gobuster && ok "gobuster" || warn "gobuster non installé (optionnel)"
fi

# ── dirb ──────────────────────────────────────────────────────────────────────
if is_ok dirb; then
  ok "dirb (déjà installé)"
else
  log "Installation de dirb..."
  case "$OS" in
    macos)   run "brew install dirb" ;;
    debian)  run "sudo apt-get install -y dirb -qq" ;;
    *)       warn "dirb : installer manuellement" ;;
  esac
  is_ok dirb && ok "dirb" || warn "dirb non installé (optionnel)"
fi

# ── hydra ─────────────────────────────────────────────────────────────────────
if is_ok hydra; then
  ok "hydra (déjà installé)"
else
  log "Installation de hydra..."
  case "$OS" in
    macos)   run "brew install hydra" ;;
    debian)  run "sudo apt-get install -y hydra -qq" ;;
    rhel)    run "sudo dnf install -y hydra 2>/dev/null || warn 'hydra non dispo'" ;;
    *)       warn "hydra : installer manuellement" ;;
  esac
  is_ok hydra && ok "hydra" || warn "hydra non installé (optionnel)"
fi

# ── enum4linux ────────────────────────────────────────────────────────────────
if is_ok enum4linux; then
  ok "enum4linux (déjà installé)"
else
  log "Installation de enum4linux-ng..."
  run "curl -fsSL https://raw.githubusercontent.com/cddmp/enum4linux-ng/main/enum4linux-ng.py -o /tmp/enum4linux-ng.py"
  run "echo '#!/bin/bash\npython3 /usr/local/bin/enum4linux-ng.py \"\$@\"' | sudo tee /usr/local/bin/enum4linux > /dev/null"
  run "sudo cp /tmp/enum4linux-ng.py /usr/local/bin/enum4linux-ng.py && sudo chmod +x /usr/local/bin/enum4linux"
  is_ok enum4linux && ok "enum4linux" || warn "enum4linux non installé (optionnel)"
fi

# ── subfinder ─────────────────────────────────────────────────────────────────
if is_ok subfinder; then
  ok "subfinder (déjà installé)"
else
  log "Installation de subfinder..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install subfinder"
  else
    SUBFINDER_VER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r .tag_name)
    SUBFINDER_NUM="${SUBFINDER_VER#v}"
    run "curl -fsSL 'https://github.com/projectdiscovery/subfinder/releases/download/\${SUBFINDER_VER}/subfinder_\${SUBFINDER_NUM}_linux_amd64.zip' -o /tmp/subfinder.zip"
    run "unzip -q /tmp/subfinder.zip -d /tmp/subfinder_bin && sudo mv /tmp/subfinder_bin/subfinder '$INSTALL_PREFIX/subfinder' && sudo chmod +x '$INSTALL_PREFIX/subfinder'"
    run "rm -f /tmp/subfinder.zip"
  fi
  is_ok subfinder && ok "subfinder" || warn "subfinder non installé (optionnel)"
fi

# ── dalfox ────────────────────────────────────────────────────────────────────
if is_ok dalfox; then
  ok "dalfox (déjà installé)"
else
  log "Installation de dalfox..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install dalfox"
  else
    DALFOX_VER=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | jq -r .tag_name)
    run "curl -fsSL 'https://github.com/hahwul/dalfox/releases/download/\${DALFOX_VER}/dalfox-linux-amd64.tar.gz' -o /tmp/dalfox.tar.gz"
    run "tar -xz -C /tmp -f /tmp/dalfox.tar.gz && sudo mv /tmp/dalfox-linux-amd64 '$INSTALL_PREFIX/dalfox' && sudo chmod +x '$INSTALL_PREFIX/dalfox'"
    run "rm -f /tmp/dalfox.tar.gz"
  fi
  is_ok dalfox && ok "dalfox" || warn "dalfox non installé (optionnel)"
fi

# ── feroxbuster ───────────────────────────────────────────────────────────────
if is_ok feroxbuster; then
  ok "feroxbuster (déjà installé)"
else
  log "Installation de feroxbuster..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install feroxbuster"
  else
    FEROX_VER=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | jq -r .tag_name)
    run "curl -fsSL 'https://github.com/epi052/feroxbuster/releases/download/\${FEROX_VER}/x86_64-linux-feroxbuster.tar.gz' -o /tmp/feroxbuster.tar.gz"
    run "tar -xz -C /tmp -f /tmp/feroxbuster.tar.gz feroxbuster 2>/dev/null && sudo mv /tmp/feroxbuster '$INSTALL_PREFIX/feroxbuster' && sudo chmod +x '$INSTALL_PREFIX/feroxbuster'"
    run "rm -f /tmp/feroxbuster.tar.gz"
  fi
  is_ok feroxbuster && ok "feroxbuster" || warn "feroxbuster non installé (optionnel)"
fi

# ── ffuf ──────────────────────────────────────────────────────────────────────
if is_ok ffuf; then
  ok "ffuf (déjà installé)"
else
  log "Installation de ffuf..."
  if [[ "$OS" == "macos" ]]; then
    run "brew install ffuf"
  else
    FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r .tag_name)
    FFUF_NUM="${FFUF_VER#v}"
    run "curl -fsSL 'https://github.com/ffuf/ffuf/releases/download/\${FFUF_VER}/ffuf_\${FFUF_NUM}_linux_amd64.tar.gz' -o /tmp/ffuf.tar.gz"
    run "tar -xz -C /tmp -f /tmp/ffuf.tar.gz ffuf && sudo mv /tmp/ffuf '$INSTALL_PREFIX/ffuf' && sudo chmod +x '$INSTALL_PREFIX/ffuf'"
    run "rm -f /tmp/ffuf.tar.gz"
  fi
  is_ok ffuf && ok "ffuf" || warn "ffuf non installé (optionnel)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# PARTIE 3 — Outils Python via pipx (semgrep, checkov, pip-audit)
# ═════════════════════════════════════════════════════════════════════════════
header "3/5 — Outils Python (pipx)"

if [[ "$SKIP_PYTHON" == "true" ]]; then
  warn "Étape 3 ignorée (--skip-python)"
else
  export PATH="$PATH:$HOME/.local/bin"

  # S'assurer que pipx est disponible
  if ! is_ok pipx; then
    log "Installation de pipx..."
    run "pip3 install pipx --break-system-packages 2>/dev/null || pip3 install pipx"
    run "pipx ensurepath 2>/dev/null || true"
    export PATH="$PATH:$HOME/.local/bin"
  fi

  for tool in semgrep checkov pip-audit; do
    if is_ok "$tool"; then
      ok "$tool (déjà installé)"
    else
      log "Installation de $tool via pipx..."
      run "pipx install $tool 2>&1 | tail -2"
      is_ok "$tool" && ok "$tool" || fail "$tool"
    fi
  done
fi

# ═════════════════════════════════════════════════════════════════════════════
# PARTIE 4 — Dépendances Python du projet
# ═════════════════════════════════════════════════════════════════════════════
header "4/5 — Dépendances Python du projet"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -f "$PROJECT_DIR/requirements.txt" ]]; then
  log "Installation de requirements.txt..."
  run "pip3 install -r '$PROJECT_DIR/requirements.txt' --break-system-packages -q 2>/dev/null || \
       pip3 install -r '$PROJECT_DIR/requirements.txt' -q"
  ok "requirements.txt"
else
  warn "requirements.txt introuvable dans $PROJECT_DIR"
fi

if [[ -f "$PROJECT_DIR/scripts/consent/requirements.txt" ]]; then
  log "Installation de scripts/consent/requirements.txt..."
  run "pip3 install -r '$PROJECT_DIR/scripts/consent/requirements.txt' --break-system-packages -q 2>/dev/null || \
       pip3 install -r '$PROJECT_DIR/scripts/consent/requirements.txt' -q"
  ok "consent/requirements.txt"
fi

# ═════════════════════════════════════════════════════════════════════════════
# PARTIE 5 — Génération PDF (pandoc + weasyprint)
# ═════════════════════════════════════════════════════════════════════════════
header "5/5 — Génération PDF (pandoc + weasyprint)"

# pandoc (installé en partie 1 sur debian/arch, sinon homebrew)
if is_ok pandoc; then
  ok "pandoc (déjà installé : $(pandoc --version | head -1))"
else
  log "Installation de pandoc..."
  case "$OS" in
    macos)   run "brew install pandoc" ;;
    rhel)    run "sudo dnf install -y pandoc 2>/dev/null || warn 'pandoc indisponible — télécharger depuis https://pandoc.org'" ;;
    debian)  run "sudo apt-get install -y pandoc -qq" ;;
    *)       warn "pandoc : installe depuis https://pandoc.org" ;;
  esac
  is_ok pandoc && ok "pandoc" || warn "pandoc non installé"
fi

# weasyprint
export PATH="$PATH:$HOME/.local/bin"
if is_ok weasyprint; then
  ok "weasyprint (déjà installé)"
else
  log "Installation de weasyprint via pipx..."
  run "pipx install weasyprint 2>&1 | tail -2"
  is_ok weasyprint && ok "weasyprint" || fail "weasyprint"
fi

# Test rapide de génération PDF
if is_ok weasyprint && [[ "$DRY_RUN" == "false" ]]; then
  echo "<html><body><h1>CyberStrikeAI DevSec OK</h1></body></html>" > /tmp/_devsec_test.html
  if weasyprint /tmp/_devsec_test.html /tmp/_devsec_test.pdf 2>/dev/null && [[ -s /tmp/_devsec_test.pdf ]]; then
    ok "Génération PDF fonctionnelle ✓"
    rm -f /tmp/_devsec_test.html /tmp/_devsec_test.pdf
  else
    warn "weasyprint installé mais le test PDF a échoué — vérifier libpango"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# RÉSUMÉ FINAL
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${CYAN}  Résumé de l'installation${RESET}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Vérification complète de tous les outils attendus
ALL_TOOLS=(grype trivy semgrep gitleaks trufflehog syft osv-scanner checkov pip-audit nuclei nikto testssl.sh nmap whatweb gobuster dirb feroxbuster dalfox subfinder hydra wapiti ffuf jq pandoc weasyprint)
PASS=0; FAIL=0
for tool in "${ALL_TOOLS[@]}"; do
  if is_ok "$tool"; then
    VER=$(${tool} --version 2>&1 | head -1 | tr -d '\n' || echo "ok")
    printf "  ${GREEN}✅${RESET}  %-15s %s\n" "$tool" "${VER:0:40}"
    ((PASS++)) || true
  else
    printf "  ${RED}❌${RESET}  %-15s NON INSTALLÉ\n" "$tool"
    ((FAIL++)) || true
  fi
done

echo ""
echo -e "  Score : ${BOLD}${PASS}/${#ALL_TOOLS[@]}${RESET} outils opérationnels"
echo ""

# Ajouter le PATH au profil si pas déjà présent
if ! grep -q 'HOME/.local/bin' ~/.bashrc 2>/dev/null; then
  echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
  echo -e "  ${DIM}→ PATH mis à jour dans ~/.bashrc${RESET}"
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo -e "  ${YELLOW}⚠️  Outils en échec : ${FAILED[*]}${RESET}"
  echo -e "  Consulte INSTALL.md section '7. Problèmes connus'"
  echo ""
fi

if [[ $FAIL -eq 0 ]]; then
  echo -e "  ${GREEN}${BOLD}✅ Installation complète ! CyberStrikeAI DevSec est prêt.${RESET}"
else
  echo -e "  ${YELLOW}${BOLD}⚠️  Installation partielle — certains outils manquent.${RESET}"
  echo -e "  Les scans fonctionneront, mais certaines fonctionnalités seront limitées."
fi

echo ""
echo -e "  ${BOLD}Prochaine étape :${RESET}"
echo -e "  ${CYAN}1. Recharge ton terminal : source ~/.bashrc${RESET}"
echo -e "  ${CYAN}2. Lance un scan         : ./scripts/scan.sh${RESET}"
echo ""
