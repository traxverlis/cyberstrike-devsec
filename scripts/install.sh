#!/usr/bin/env bash
# =============================================================================
# CyberStrikeAI DevSec — install.sh
# Automatic installation of all DevSec scanning tools
# Supports: Linux (apt/yum/dnf) and macOS (Homebrew)
#
# Usage:
#   ./scripts/install.sh
#   ./scripts/install.sh --skip-python     (skip semgrep/pip-audit)
#   ./scripts/install.sh --prefix /custom  (install binaries to custom path)
# =============================================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local/bin}"
SKIP_PYTHON=false
SKIP_GO=false
DRY_RUN=false
FAILED_TOOLS=()
INSTALLED_TOOLS=()
SKIPPED_TOOLS=()

# ── Parse arguments ───────────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --skip-python) SKIP_PYTHON=true ;;
    --skip-go)     SKIP_GO=true ;;
    --dry-run)     DRY_RUN=true ;;
    --prefix=*)    INSTALL_PREFIX="${arg#*=}" ;;
    --help|-h)
      echo "Usage: $0 [--skip-python] [--skip-go] [--prefix=/path] [--dry-run]"
      exit 0
      ;;
  esac
done

# ── Helper functions ──────────────────────────────────────────────────────────
log()     { echo -e "${CYAN}  ➜ $*${RESET}"; }
success() { echo -e "${GREEN}  ✅ $*${RESET}"; }
warn()    { echo -e "${YELLOW}  ⚠️  $*${RESET}"; }
error()   { echo -e "${RED}  ❌ $*${RESET}"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"; echo -e "${BOLD}${CYAN}  $*${RESET}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}\n"; }

is_installed() { command -v "$1" > /dev/null 2>&1; }

# Detect OS
detect_os() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macos"
  elif [[ -f /etc/debian_version ]]; then
    echo "debian"
  elif [[ -f /etc/redhat-release ]] || [[ -f /etc/fedora-release ]]; then
    echo "rhel"
  elif [[ -f /etc/arch-release ]]; then
    echo "arch"
  else
    echo "unknown"
  fi
}

OS=$(detect_os)

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║     CyberStrikeAI DevSec — Tool Installer 🛡️      ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  OS detected     : ${BOLD}${OS}${RESET}"
echo -e "  Install prefix  : ${BOLD}${INSTALL_PREFIX}${RESET}"
echo -e "  Skip Python     : ${BOLD}${SKIP_PYTHON}${RESET}"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  warn "DRY RUN mode — no packages will be installed"
  echo ""
fi

# ── Step 1: System Dependencies ──────────────────────────────────────────────
header "Step 1: System Dependencies"

install_system_deps() {
  log "Installing: curl, wget, jq, git, tar, unzip"
  if [[ "$DRY_RUN" == "true" ]]; then return 0; fi

  case "$OS" in
    macos)
      if ! is_installed brew; then
        error "Homebrew not found. Install from https://brew.sh then re-run."
        exit 1
      fi
      brew install curl wget jq git 2>/dev/null || true
      ;;
    debian)
      sudo apt-get update -qq
      sudo apt-get install -y -qq curl wget jq git tar unzip gnupg lsb-release \
        apt-transport-https ca-certificates software-properties-common
      ;;
    rhel)
      sudo dnf install -y curl wget jq git tar unzip gnupg 2>/dev/null || \
      sudo yum install -y curl wget jq git tar unzip gnupg
      ;;
    arch)
      sudo pacman -Sy --noconfirm curl wget jq git tar unzip
      ;;
    *)
      warn "Unknown OS — skipping system dependency install. Ensure curl, wget, jq, git are available."
      ;;
  esac
  success "System dependencies installed"
}

install_system_deps

# ── Step 2: Grype (Anchore CVE Scanner) ──────────────────────────────────────
header "Step 2: Grype — CVE Vulnerability Scanner"

install_grype() {
  if is_installed grype; then
    success "Grype already installed: $(grype version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("grype (pre-existing)")
    return 0
  fi
  log "Downloading Grype..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install Grype"; return 0; fi

  if [[ "$OS" == "macos" ]]; then
    brew install anchore/grype/grype
  else
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sudo sh -s -- -b "$INSTALL_PREFIX"
  fi
  success "Grype installed: $(grype version 2>&1 | head -1)"
  INSTALLED_TOOLS+=("grype")
}

install_grype || { error "Failed to install Grype"; FAILED_TOOLS+=("grype"); }

# ── Step 3: Trivy (Aqua Security) ────────────────────────────────────────────
header "Step 3: Trivy — Universal Security Scanner"

install_trivy() {
  if is_installed trivy; then
    success "Trivy already installed: $(trivy --version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("trivy (pre-existing)")
    return 0
  fi
  log "Downloading Trivy..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install Trivy"; return 0; fi

  case "$OS" in
    macos)
      brew install aquasecurity/trivy/trivy
      ;;
    debian)
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        | sudo tee /etc/apt/sources.list.d/trivy.list
      sudo apt-get update -qq && sudo apt-get install -y trivy
      ;;
    rhel)
      TRIVY_VER=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | jq -r .tag_name)
      curl -sSfL \
        "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_Linux-64bit.rpm" \
        -o /tmp/trivy.rpm
      sudo rpm -i /tmp/trivy.rpm
      ;;
    *)
      TRIVY_VER=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | jq -r .tag_name)
      curl -sSfL \
        "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VER}/trivy_${TRIVY_VER#v}_Linux-64bit.tar.gz" \
        | sudo tar -xz -C "$INSTALL_PREFIX" trivy
      ;;
  esac
  success "Trivy installed: $(trivy --version 2>&1 | head -1)"
  INSTALLED_TOOLS+=("trivy")
}

install_trivy || { error "Failed to install Trivy"; FAILED_TOOLS+=("trivy"); }

# ── Step 4: Semgrep (SAST) ───────────────────────────────────────────────────
header "Step 4: Semgrep — Static Analysis (SAST)"

install_semgrep() {
  if [[ "$SKIP_PYTHON" == "true" ]]; then
    warn "Skipping Semgrep (--skip-python)"
    SKIPPED_TOOLS+=("semgrep")
    return 0
  fi
  if is_installed semgrep; then
    success "Semgrep already installed: $(semgrep --version 2>&1)"
    INSTALLED_TOOLS+=("semgrep (pre-existing)")
    return 0
  fi
  log "Installing Semgrep via pip..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install Semgrep"; return 0; fi

  if ! is_installed python3; then
    error "Python 3 not found. Install Python 3.9+ to use Semgrep."
    FAILED_TOOLS+=("semgrep")
    return 1
  fi
  pip3 install semgrep --quiet || pip install semgrep --quiet
  success "Semgrep installed: $(semgrep --version 2>&1)"
  INSTALLED_TOOLS+=("semgrep")
}

install_semgrep || { error "Failed to install Semgrep"; FAILED_TOOLS+=("semgrep"); }

# ── Step 5: Gitleaks (Secret Detection) ──────────────────────────────────────
header "Step 5: Gitleaks — Secret & Credential Scanner"

install_gitleaks() {
  if is_installed gitleaks; then
    success "Gitleaks already installed: $(gitleaks version 2>&1)"
    INSTALLED_TOOLS+=("gitleaks (pre-existing)")
    return 0
  fi
  log "Downloading Gitleaks..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install Gitleaks"; return 0; fi

  if [[ "$OS" == "macos" ]]; then
    brew install gitleaks
  else
    GL_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
      | jq -r .tag_name)
    curl -sSfL \
      "https://github.com/gitleaks/gitleaks/releases/download/${GL_VER}/gitleaks_${GL_VER#v}_linux_x64.tar.gz" \
      | sudo tar -xz -C "$INSTALL_PREFIX" gitleaks
  fi
  success "Gitleaks installed: $(gitleaks version 2>&1)"
  INSTALLED_TOOLS+=("gitleaks")
}

install_gitleaks || { error "Failed to install Gitleaks"; FAILED_TOOLS+=("gitleaks"); }

# ── Step 6: Syft (SBOM Generator) ────────────────────────────────────────────
header "Step 6: Syft — SBOM Generator"

install_syft() {
  if is_installed syft; then
    success "Syft already installed: $(syft version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("syft (pre-existing)")
    return 0
  fi
  log "Downloading Syft..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install Syft"; return 0; fi

  if [[ "$OS" == "macos" ]]; then
    brew install anchore/syft/syft
  else
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
      | sudo sh -s -- -b "$INSTALL_PREFIX"
  fi
  success "Syft installed: $(syft version 2>&1 | head -1)"
  INSTALLED_TOOLS+=("syft")
}

install_syft || { error "Failed to install Syft"; FAILED_TOOLS+=("syft"); }

# ── Step 7: OSV-Scanner (Google) ─────────────────────────────────────────────
header "Step 7: OSV-Scanner — Google OSV Database"

install_osv_scanner() {
  if [[ "$SKIP_GO" == "true" ]]; then
    warn "Skipping osv-scanner (--skip-go)"
    SKIPPED_TOOLS+=("osv-scanner")
    return 0
  fi
  if is_installed osv-scanner; then
    success "OSV-Scanner already installed: $(osv-scanner --version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("osv-scanner (pre-existing)")
    return 0
  fi
  log "Installing OSV-Scanner..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install OSV-Scanner"; return 0; fi

  if [[ "$OS" == "macos" ]]; then
    brew install osv-scanner 2>/dev/null || true
  fi

  # Try pre-built binary from GitHub releases
  OSV_VER=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest \
    | jq -r .tag_name 2>/dev/null || echo "")

  if [[ -n "$OSV_VER" ]]; then
    ARCH="amd64"
    [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]] && ARCH="arm64"
    OS_SUFFIX="linux"
    [[ "$OS" == "macos" ]] && OS_SUFFIX="darwin"
    BINARY_URL="https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_${OS_SUFFIX}_${ARCH}"
    curl -sSfL "$BINARY_URL" -o /tmp/osv-scanner
    chmod +x /tmp/osv-scanner
    sudo mv /tmp/osv-scanner "$INSTALL_PREFIX/osv-scanner"
    success "OSV-Scanner installed: $(osv-scanner --version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("osv-scanner")
  elif is_installed go; then
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest
    success "OSV-Scanner installed via Go"
    INSTALLED_TOOLS+=("osv-scanner")
  else
    warn "Cannot install osv-scanner: no pre-built binary and Go not found"
    warn "Install Go 1.21+ or download from: https://github.com/google/osv-scanner/releases"
    SKIPPED_TOOLS+=("osv-scanner")
  fi
}

install_osv_scanner || { warn "Failed to install OSV-Scanner (optional)"; SKIPPED_TOOLS+=("osv-scanner"); }

# ── Step 8: TruffleHog (Advanced Secret Scanner) ─────────────────────────────
header "Step 8: TruffleHog — Deep Secret Scanner"

install_trufflehog() {
  if is_installed trufflehog; then
    success "TruffleHog already installed: $(trufflehog --version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("trufflehog (pre-existing)")
    return 0
  fi
  log "Downloading TruffleHog..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install TruffleHog"; return 0; fi

  if [[ "$OS" == "macos" ]]; then
    brew install trufflehog 2>/dev/null || true
  fi

  TH_VER=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
    | jq -r .tag_name 2>/dev/null || echo "")
  if [[ -n "$TH_VER" ]]; then
    ARCH="amd64"
    [[ "$(uname -m)" == "arm64" || "$(uname -m)" == "aarch64" ]] && ARCH="arm64"
    OS_SUFFIX="linux"
    [[ "$OS" == "macos" ]] && OS_SUFFIX="darwin"
    curl -sSfL \
      "https://github.com/trufflesecurity/trufflehog/releases/download/${TH_VER}/trufflehog_${OS_SUFFIX}_${ARCH}.tar.gz" \
      | sudo tar -xz -C "$INSTALL_PREFIX" trufflehog
    success "TruffleHog installed: $(trufflehog --version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("trufflehog")
  else
    warn "Could not determine latest TruffleHog version — skipping"
    SKIPPED_TOOLS+=("trufflehog")
  fi
}

install_trufflehog || { warn "Failed to install TruffleHog (optional)"; SKIPPED_TOOLS+=("trufflehog"); }

# ── Step 9: Checkov (IaC Security) ───────────────────────────────────────────
header "Step 9: Checkov — IaC Security Scanner"

install_checkov() {
  if [[ "$SKIP_PYTHON" == "true" ]]; then
    warn "Skipping Checkov (--skip-python)"
    SKIPPED_TOOLS+=("checkov")
    return 0
  fi
  if is_installed checkov; then
    success "Checkov already installed: $(checkov --version 2>&1 | head -1)"
    INSTALLED_TOOLS+=("checkov (pre-existing)")
    return 0
  fi
  log "Installing Checkov via pip..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install Checkov"; return 0; fi

  pip3 install checkov --quiet || pip install checkov --quiet
  success "Checkov installed: $(checkov --version 2>&1 | head -1)"
  INSTALLED_TOOLS+=("checkov")
}

install_checkov || { warn "Failed to install Checkov (optional)"; SKIPPED_TOOLS+=("checkov"); }

# ── Step 10: pip-audit (Python) ──────────────────────────────────────────────
header "Step 10: pip-audit — Python Dependency Auditor"

install_pip_audit() {
  if [[ "$SKIP_PYTHON" == "true" ]]; then
    warn "Skipping pip-audit (--skip-python)"
    SKIPPED_TOOLS+=("pip-audit")
    return 0
  fi
  if is_installed pip-audit; then
    success "pip-audit already installed: $(pip-audit --version 2>&1)"
    INSTALLED_TOOLS+=("pip-audit (pre-existing)")
    return 0
  fi
  log "Installing pip-audit..."
  if [[ "$DRY_RUN" == "true" ]]; then success "[DRY] Would install pip-audit"; return 0; fi

  pip3 install pip-audit --quiet || pip install pip-audit --quiet
  success "pip-audit installed: $(pip-audit --version 2>&1)"
  INSTALLED_TOOLS+=("pip-audit")
}

install_pip_audit || { warn "Failed to install pip-audit (optional)"; SKIPPED_TOOLS+=("pip-audit"); }

# ── Post-installation verification ───────────────────────────────────────────
header "Post-Installation Verification"

ALL_TOOLS=("grype" "trivy" "semgrep" "gitleaks" "syft" "osv-scanner" "trufflehog" "checkov" "pip-audit" "jq")
PASS_COUNT=0
FAIL_COUNT=0

for tool in "${ALL_TOOLS[@]}"; do
  if is_installed "$tool"; then
    VER=$(${tool} --version 2>&1 | head -1 | sed 's/.*version //i' | awk '{print $1}' || echo "ok")
    printf "  ${GREEN}✅${RESET}  %-15s %s\n" "$tool" "$VER"
    ((PASS_COUNT++)) || true
  else
    printf "  ${YELLOW}⚠️ ${RESET}  %-15s NOT FOUND\n" "$tool"
    ((FAIL_COUNT++)) || true
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Installation Summary${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Tools available  : ${GREEN}${BOLD}${PASS_COUNT}/${#ALL_TOOLS[@]}${RESET}"

if [[ ${#INSTALLED_TOOLS[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${GREEN}Installed:${RESET}"
  for t in "${INSTALLED_TOOLS[@]}"; do echo "    • $t"; done
fi

if [[ ${#SKIPPED_TOOLS[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${YELLOW}Skipped (optional):${RESET}"
  for t in "${SKIPPED_TOOLS[@]}"; do echo "    • $t"; done
fi

if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
  echo ""
  echo -e "  ${RED}Failed (required):${RESET}"
  for t in "${FAILED_TOOLS[@]}"; do echo "    • $t"; done
fi

echo ""

if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
  error "Some required tools failed to install. Check the errors above."
  echo ""
  echo "  Quick fixes:"
  echo "  • Run with sudo if permission errors"
  echo "  • Check your internet connection"
  echo "  • Try: make install-tools (alternative method)"
  exit 1
else
  success "CyberStrikeAI DevSec is ready! 🛡️"
  echo ""
  echo "  Next steps:"
  echo "  • Scan your project : ./scripts/scan.sh --target ./your-project"
  echo "  • Or via Make       : make scan-full TARGET=./your-project"
  echo "  • Verify tools      : make verify"
  echo ""
fi
