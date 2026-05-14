#!/usr/bin/env bash
# =============================================================================
# CyberStrikeAI DevSec — scan.sh
# Complete security scan script with multiple modes
#
# Usage:
#   ./scripts/scan.sh [options]
#
# Options:
#   --target  <path>    Project to scan (default: .)
#   --output  <path>    Output directory for reports (default: ./security-reports)
#   --mode    <mode>    Scan mode: quick | full | cicd (default: full)
#   --severity <level>  Minimum severity: critical | high | medium | low (default: high)
#   --no-git            Skip git history scanning (faster for large repos)
#   --help              Show this help
#
# Exit codes:
#   0 — No critical/high findings (or mode allows)
#   1 — Critical findings found (in cicd mode, or --mode quick with findings)
#   2 — Tool error / scan failure
# =============================================================================
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET="."
OUTPUT="./security-reports"
MODE="full"
SEVERITY="high"
NO_GIT=false
SCAN_START=$(date +%s)

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="$2"; shift 2 ;;
    --output)   OUTPUT="$2"; shift 2 ;;
    --mode)     MODE="$2"; shift 2 ;;
    --severity) SEVERITY="$2"; shift 2 ;;
    --no-git)   NO_GIT=true; shift ;;
    --help|-h)
      sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1 (use --help for usage)"
      exit 1
      ;;
  esac
done

# Validate mode
case "$MODE" in
  quick|full|cicd) ;;
  *) echo "Invalid mode: $MODE. Use: quick, full, or cicd"; exit 1 ;;
esac

# ── Helper functions ──────────────────────────────────────────────────────────
log()     { echo -e "${CYAN}  ➜ $*${RESET}"; }
success() { echo -e "${GREEN}  ✅ $*${RESET}"; }
warn()    { echo -e "${YELLOW}  ⚠️  $*${RESET}"; }
error()   { echo -e "${RED}  ❌ $*${RESET}"; }
info()    { echo -e "${DIM}     $*${RESET}"; }

is_available() { command -v "$1" > /dev/null 2>&1; }

progress() {
  local step=$1; local total=$2; local label=$3
  local pct=$(( step * 100 / total ))
  local filled=$(( pct / 5 ))
  local bar=""
  for ((i=0; i<20; i++)); do
    if [ $i -lt $filled ]; then bar="${bar}█"; else bar="${bar}░"; fi
  done
  printf "\r  ${CYAN}[${bar}]${RESET} %3d%%  %s        " "$pct" "$label"
}

elapsed() {
  local now; now=$(date +%s)
  local diff=$(( now - SCAN_START ))
  echo "${diff}s"
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────
if [[ ! -d "$TARGET" ]]; then
  error "Target directory not found: $TARGET"
  exit 2
fi

TARGET=$(realpath "$TARGET")
mkdir -p "$OUTPUT"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════════════════╗"
echo "  ║     CyberStrikeAI DevSec — Security Scanner 🔍    ║"
echo "  ╚═══════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Target   : ${BOLD}${TARGET}${RESET}"
echo -e "  Output   : ${BOLD}${OUTPUT}${RESET}"
echo -e "  Mode     : ${BOLD}${MODE}${RESET}"
echo -e "  Severity : ${BOLD}${SEVERITY}${RESET}"
echo -e "  Started  : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# ── Mode descriptions ─────────────────────────────────────────────────────────
case "$MODE" in
  quick)
    echo -e "  ${YELLOW}Quick mode:${RESET} Secrets + Critical CVEs only (~30-60s)"
    STEPS=2
    ;;
  full)
    echo -e "  ${CYAN}Full mode:${RESET} Complete scan — CVE + SAST + Secrets + Supply Chain + IaC"
    STEPS=7
    ;;
  cicd)
    echo -e "  ${CYAN}CI/CD mode:${RESET} JSON output, strict exit codes, critical CVEs + secrets"
    STEPS=4
    ;;
esac
echo ""

# ── Counters ──────────────────────────────────────────────────────────────────
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
SECRETS=0
SAST_ERRORS=0
CURRENT_STEP=0

update_progress() {
  CURRENT_STEP=$(( CURRENT_STEP + 1 ))
  progress "$CURRENT_STEP" "$STEPS" "$1"
  echo ""
}

# ── Scan 1: Secrets (all modes) ───────────────────────────────────────────────
echo -e "${BOLD}━━━ Scan 1/${STEPS}: Secret Detection ━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if is_available gitleaks; then
  GITLEAKS_OPTS="--source $TARGET --report-format json --report-path $OUTPUT/gitleaks.json --no-banner"
  if [[ "$NO_GIT" == "true" ]]; then
    GITLEAKS_OPTS="$GITLEAKS_OPTS --no-git"
  fi
  # shellcheck disable=SC2086
  gitleaks detect $GITLEAKS_OPTS --exit-code 0 2>/dev/null || true
  SECRETS=$(jq 'if type == "array" then length else 0 end' "$OUTPUT/gitleaks.json" 2>/dev/null || echo 0)
  if [[ "$SECRETS" -gt 0 ]]; then
    error "Secrets found: $SECRETS — rotate credentials immediately!"
    jq -r '.[] | "     [\(.RuleID)] \(.File):\(.StartLine) — \(.Description)"' \
      "$OUTPUT/gitleaks.json" 2>/dev/null | head -10
  else
    success "No secrets detected"
  fi
else
  warn "gitleaks not installed — secret scan skipped"
  warn "Run: ./scripts/install.sh"
fi
update_progress "Secret scan"

# ── Scan 2: CVE (all modes) ───────────────────────────────────────────────────
echo -e "${BOLD}━━━ Scan 2/${STEPS}: CVE Dependency Scan ━━━━━━━━━━━━━━━━━━━━━${RESET}"

if is_available grype; then
  FAIL_ON="critical"
  [[ "$SEVERITY" == "high" ]] && FAIL_ON="high"

  grype dir:"$TARGET" \
    --output json \
    --file "$OUTPUT/grype.json" \
    --add-cpes-if-none \
    --quiet 2>/dev/null || true

  CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' \
    "$OUTPUT/grype.json" 2>/dev/null || echo 0)
  HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' \
    "$OUTPUT/grype.json" 2>/dev/null || echo 0)
  MEDIUM=$(jq '[.matches[] | select(.vulnerability.severity=="Medium")] | length' \
    "$OUTPUT/grype.json" 2>/dev/null || echo 0)
  LOW=$(jq '[.matches[] | select(.vulnerability.severity=="Low")] | length' \
    "$OUTPUT/grype.json" 2>/dev/null || echo 0)

  if [[ "$CRITICAL" -gt 0 ]]; then
    error "Critical CVEs: $CRITICAL"
    jq -r '.matches[] | select(.vulnerability.severity=="Critical") |
      "     [\(.vulnerability.id)] \(.artifact.name)@\(.artifact.version) → fix: \(.vulnerability.fix.versions | join(", "))"' \
      "$OUTPUT/grype.json" 2>/dev/null | head -5
  fi
  [[ "$HIGH" -gt 0 ]] && warn "High CVEs: $HIGH"
  success "CVE scan complete — Critical: $CRITICAL | High: $HIGH | Medium: $MEDIUM | Low: $LOW"
else
  warn "grype not installed — CVE scan skipped"
fi
update_progress "CVE scan"

# ── Quick mode: stop here ─────────────────────────────────────────────────────
if [[ "$MODE" == "quick" ]]; then
  echo ""
  echo -e "${BOLD}━━━ Quick Mode Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
  TOTAL_BLOCKERS=$(( SECRETS + CRITICAL ))
  if [[ "$TOTAL_BLOCKERS" -gt 0 ]]; then
    error "BLOCKERS FOUND: Secrets=$SECRETS | Critical CVEs=$CRITICAL"
    exit 1
  else
    success "No blockers found (quick scan)"
    exit 0
  fi
fi

# ── Scan 3: OWASP SAST (full + cicd) ─────────────────────────────────────────
echo -e "${BOLD}━━━ Scan 3/${STEPS}: OWASP SAST (Semgrep) ━━━━━━━━━━━━━━━━━━━${RESET}"

if is_available semgrep; then
  SEMGREP_CONFIGS="--config p/owasp-top-ten --config p/secrets"

  # Detect and add language-specific configs
  find "$TARGET" -name "*.cs" -o -name "*.csproj" | grep -q . 2>/dev/null \
    && SEMGREP_CONFIGS="$SEMGREP_CONFIGS --config p/csharp --config p/dotnet"
  find "$TARGET" -name "*.java" | grep -q . 2>/dev/null \
    && SEMGREP_CONFIGS="$SEMGREP_CONFIGS --config p/java"
  find "$TARGET" -name "*.ts" -o -name "*.tsx" -o -name "*.jsx" | grep -q . 2>/dev/null \
    && SEMGREP_CONFIGS="$SEMGREP_CONFIGS --config p/javascript --config p/typescript --config p/react"
  find "$TARGET" -name "*.py" | grep -q . 2>/dev/null \
    && SEMGREP_CONFIGS="$SEMGREP_CONFIGS --config p/python"

  # shellcheck disable=SC2086
  semgrep scan \
    $SEMGREP_CONFIGS \
    --json \
    --output "$OUTPUT/semgrep.json" \
    --metrics off \
    "$TARGET" 2>/dev/null || true

  SAST_ERRORS=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' \
    "$OUTPUT/semgrep.json" 2>/dev/null || echo 0)
  SAST_WARNINGS=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' \
    "$OUTPUT/semgrep.json" 2>/dev/null || echo 0)

  [[ "$SAST_ERRORS" -gt 0 ]] && warn "SAST High/Critical: $SAST_ERRORS"
  success "SAST scan complete — Errors: $SAST_ERRORS | Warnings: $SAST_WARNINGS"
else
  warn "semgrep not installed — SAST scan skipped"
fi
update_progress "SAST scan"

# ── Scan 4: Supply Chain SBOM (full mode only) ────────────────────────────────
if [[ "$MODE" == "full" ]]; then
  echo -e "${BOLD}━━━ Scan 4/${STEPS}: SBOM Generation ━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  if is_available syft; then
    syft dir:"$TARGET" \
      -o cyclonedx-json="$OUTPUT/sbom.json" \
      --quiet 2>/dev/null
    COMPONENTS=$(jq '.components | length' "$OUTPUT/sbom.json" 2>/dev/null || echo 0)
    success "SBOM generated — $COMPONENTS components inventoried"
  else
    warn "syft not installed — SBOM generation skipped"
  fi
  update_progress "SBOM"

  # ── Scan 5: OSV-Scanner ───────────────────────────────────────────────────
  echo -e "${BOLD}━━━ Scan 5/${STEPS}: OSV Database Scan ━━━━━━━━━━━━━━━━━━━━━${RESET}"

  if is_available osv-scanner && [[ -f "$OUTPUT/sbom.json" ]]; then
    osv-scanner \
      --sbom="$OUTPUT/sbom.json" \
      --format json \
      --output "$OUTPUT/osv.json" 2>/dev/null || true
    OSV_VULNS=$(jq '.results | length' "$OUTPUT/osv.json" 2>/dev/null || echo 0)
    success "OSV scan complete — $OSV_VULNS findings"
  elif ! is_available osv-scanner; then
    warn "osv-scanner not installed — OSV scan skipped"
  else
    warn "SBOM not available — OSV scan skipped"
  fi
  update_progress "OSV scan"

  # ── Scan 6: IaC (Checkov) ────────────────────────────────────────────────
  echo -e "${BOLD}━━━ Scan 6/${STEPS}: IaC Security (Checkov) ━━━━━━━━━━━━━━━━${RESET}"

  if is_available checkov; then
    # Check for IaC files
    IAC_FOUND=false
    find "$TARGET" -name "*.tf" -o -name "Dockerfile*" -o -name "*.yaml" -o -name "*.yml" \
      | grep -q . 2>/dev/null && IAC_FOUND=true

    if [[ "$IAC_FOUND" == "true" ]]; then
      checkov \
        --directory "$TARGET" \
        --framework all \
        --output json \
        --output-file-path "$OUTPUT/checkov.json" \
        --soft-fail \
        --compact \
        --quiet 2>/dev/null || true
      CHECKOV_FAILED=$(jq '
        if type == "array" then
          [.[] | .results.failed_checks | length] | add // 0
        else
          .results.failed_checks | length // 0
        end
      ' "$OUTPUT/checkov.json" 2>/dev/null || echo 0)
      success "Checkov IaC scan complete — $CHECKOV_FAILED failed checks"
    else
      info "No IaC files found (Terraform, Dockerfile, Kubernetes) — skipping"
    fi
  else
    warn "checkov not installed — IaC scan skipped"
  fi
  update_progress "IaC scan"

  # ── Scan 7: TruffleHog ────────────────────────────────────────────────────
  echo -e "${BOLD}━━━ Scan 7/${STEPS}: TruffleHog Deep Secret Scan ━━━━━━━━━━━${RESET}"

  if is_available trufflehog && [[ "$NO_GIT" == "false" ]]; then
    trufflehog git "file://$TARGET" \
      --no-verification \
      --json \
      > "$OUTPUT/trufflehog.json" 2>/dev/null || true
    TH_FINDINGS=$(wc -l < "$OUTPUT/trufflehog.json" 2>/dev/null || echo 0)
    [[ "$TH_FINDINGS" -gt 0 ]] && warn "TruffleHog findings: $TH_FINDINGS"
    success "TruffleHog scan complete — $TH_FINDINGS potential secrets"
  elif [[ "$NO_GIT" == "true" ]]; then
    info "TruffleHog skipped (--no-git mode)"
  else
    warn "trufflehog not installed — deep secret scan skipped"
  fi
  update_progress "TruffleHog"
fi

# ── Trivy (cicd mode) ─────────────────────────────────────────────────────────
if [[ "$MODE" == "cicd" ]]; then
  echo -e "${BOLD}━━━ Scan 3/${STEPS}: Trivy Filesystem Scan ━━━━━━━━━━━━━━━━━${RESET}"

  if is_available trivy; then
    trivy fs "$TARGET" \
      --format json \
      --output "$OUTPUT/trivy.json" \
      --scanners vuln,secret,config \
      --severity CRITICAL,HIGH \
      --no-progress \
      --quiet 2>/dev/null || true
    TRIVY_CRITICAL=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' \
      "$OUTPUT/trivy.json" 2>/dev/null || echo 0)
    success "Trivy scan complete — Critical: $TRIVY_CRITICAL"
    CRITICAL=$(( CRITICAL + TRIVY_CRITICAL ))
  else
    warn "trivy not installed — Trivy scan skipped"
  fi
  update_progress "Trivy"
fi

# ── Final Report Generation ───────────────────────────────────────────────────
SCAN_END=$(date +%s)
DURATION=$(( SCAN_END - SCAN_START ))

echo ""
echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${CYAN}║              CyberStrikeAI DevSec — SCAN REPORT           ║${RESET}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  Duration  : ${BOLD}${DURATION}s${RESET}"
echo -e "  Mode      : ${BOLD}${MODE}${RESET}"
echo -e "  Target    : ${BOLD}${TARGET}${RESET}"
echo ""
echo "  ┌────────────────────────────────────────────┐"
printf "  │  %-10s %-10s %-10s %-10s │\n" "Secrets" "Critical" "High" "SAST"
printf "  │  %-10s %-10s %-10s %-10s │\n" "$SECRETS" "$CRITICAL" "$HIGH" "$SAST_ERRORS"
echo "  └────────────────────────────────────────────┘"
echo ""

TOTAL_BLOCKERS=$(( SECRETS + CRITICAL ))

if [[ "$MODE" == "cicd" ]]; then
  # CI/CD mode: JSON output to stdout for pipeline consumption
  GATE="PASS"
  [[ "$TOTAL_BLOCKERS" -gt 0 ]] && GATE="FAIL"

  cat > "$OUTPUT/gate-result.json" <<EOF
{
  "scan_id": "$(uname -n)-$(date +%s)",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "cicd",
  "overall_status": "$GATE",
  "blocker_count": $TOTAL_BLOCKERS,
  "summary": {
    "secrets": $SECRETS,
    "critical_cves": $CRITICAL,
    "high_cves": $HIGH,
    "sast_errors": $SAST_ERRORS
  },
  "reports_dir": "$OUTPUT",
  "duration_seconds": $DURATION
}
EOF

  cat "$OUTPUT/gate-result.json"
  echo ""

  if [[ "$GATE" == "FAIL" ]]; then
    echo -e "${RED}${BOLD}❌ SECURITY GATE: FAIL${RESET}"
    exit 1
  else
    echo -e "${GREEN}${BOLD}✅ SECURITY GATE: PASS${RESET}"
    exit 0
  fi
fi

# ── Human-readable final summary ─────────────────────────────────────────────
echo "  Reports saved to: $OUTPUT/"
echo ""
ls -1 "$OUTPUT"/*.json "$OUTPUT"/*.sarif 2>/dev/null | while read -r f; do
  SIZE=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
  printf "    %-45s %s\n" "$(basename "$f")" "$SIZE"
done
echo ""

if [[ "$TOTAL_BLOCKERS" -gt 0 ]]; then
  echo -e "${RED}${BOLD}  ❌ SECURITY GATE: FAILED${RESET}"
  echo ""
  [[ "$SECRETS" -gt 0 ]] && echo -e "  ${RED}• CRITICAL: $SECRETS secret(s) exposed — rotate immediately${RESET}"
  [[ "$CRITICAL" -gt 0 ]] && echo -e "  ${RED}• CRITICAL: $CRITICAL critical CVE(s) — update dependencies${RESET}"
  echo ""
  echo "  Run deep analysis: make scan-full TARGET=$TARGET"
  exit 1
else
  if [[ "$HIGH" -gt 0 ]] || [[ "$SAST_ERRORS" -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}  ⚠️  SECURITY GATE: PASSED with warnings${RESET}"
    echo ""
    [[ "$HIGH" -gt 0 ]] && echo -e "  ${YELLOW}• $HIGH high-severity CVE(s) — fix within 7 days${RESET}"
    [[ "$SAST_ERRORS" -gt 0 ]] && echo -e "  ${YELLOW}• $SAST_ERRORS high SAST finding(s) — review required${RESET}"
  else
    echo -e "${GREEN}${BOLD}  ✅ SECURITY GATE: PASSED${RESET}"
  fi
  echo ""
  echo "  For full analysis: ./scripts/scan.sh --target $TARGET --mode full"
  exit 0
fi
