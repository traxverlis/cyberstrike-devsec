# CyberStrikeAI DevSec — Makefile
# Usage: make <target> [TARGET=./your-project] [OUTPUT=./report.md]
#
# Examples:
#   make scan-cve TARGET=./my-app
#   make scan-full TARGET=./my-app
#   make report TARGET=./my-app OUTPUT=./reports/security-report.md
#   make install-tools
#   make verify

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET         ?= .
OUTPUT         ?= ./security-reports/report.md
REPORTS_DIR    ?= ./security-reports
SEVERITY       ?= HIGH
NVD_API_KEY    ?= $(shell echo $$NVD_API_KEY)

# Colors
RED    := \033[0;31m
GREEN  := \033[0;32m
YELLOW := \033[1;33m
CYAN   := \033[0;36m
RESET  := \033[0m

# Tool versions (for install targets)
SYFT_VERSION  ?= latest
GRYPE_VERSION ?= latest

.PHONY: help scan-cve scan-sast scan-secrets scan-owasp scan-full \
        report install-tools verify clean docker-scan \
        check-deps sbom update-dbs

# ── Default target ────────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo ""
	@echo "$(CYAN)CyberStrikeAI DevSec — Available targets$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf ""} /^[a-zA-Z_-]+:.*?##/ \
		{ printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(YELLOW)Variables:$(RESET)"
	@echo "  TARGET    Path to scan (default: .)"
	@echo "  OUTPUT    Report output path (default: ./security-reports/report.md)"
	@echo "  SEVERITY  Minimum severity (default: HIGH)"
	@echo ""
	@echo "$(YELLOW)Examples:$(RESET)"
	@echo "  make scan-cve TARGET=./my-project"
	@echo "  make scan-full TARGET=./my-project"
	@echo "  make report TARGET=./my-project OUTPUT=./my-report.md"
	@echo ""

# ── Scan targets ──────────────────────────────────────────────────────────────

scan-cve: check-deps ## Scan for CVE vulnerabilities (Grype + Trivy)
	@echo "$(CYAN)=== CVE Vulnerability Scan ===$(RESET)"
	@echo "  Target  : $(TARGET)"
	@echo "  Severity: $(SEVERITY)"
	@echo ""
	@mkdir -p $(REPORTS_DIR)

	@echo "$(YELLOW)Running Grype...$(RESET)"
	@grype dir:$(TARGET) \
		--output table \
		--severity $(SEVERITY) \
		--add-cpes-if-none; GRYPE_EXIT=$$?; \
	grype dir:$(TARGET) \
		--output json \
		--file $(REPORTS_DIR)/grype-results.json \
		--add-cpes-if-none > /dev/null 2>&1; \
	echo ""

	@echo "$(YELLOW)Running Trivy...$(RESET)"
	@trivy fs $(TARGET) \
		--severity $(SEVERITY),CRITICAL \
		--format table; TRIVY_EXIT=$$?; \
	trivy fs $(TARGET) \
		--severity $(SEVERITY),CRITICAL \
		--format json \
		--output $(REPORTS_DIR)/trivy-results.json > /dev/null 2>&1; \
	echo ""

	@CRITICAL=$$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' \
		$(REPORTS_DIR)/grype-results.json 2>/dev/null || echo 0); \
	if [ "$$CRITICAL" -gt "0" ]; then \
		echo "$(RED)❌ Found $$CRITICAL Critical CVE(s) — action required!$(RESET)"; \
		exit 1; \
	else \
		echo "$(GREEN)✅ No Critical CVEs found$(RESET)"; \
	fi

scan-sast: check-deps ## Run SAST analysis (Semgrep)
	@echo "$(CYAN)=== SAST Analysis (Semgrep) ===$(RESET)"
	@echo "  Target: $(TARGET)"
	@echo ""
	@mkdir -p $(REPORTS_DIR)

	@semgrep scan \
		--config auto \
		--json \
		--output $(REPORTS_DIR)/semgrep-results.json \
		$(TARGET) || true

	@semgrep scan \
		--config auto \
		$(TARGET) || true

	@FINDINGS=$$(jq '.results | length' $(REPORTS_DIR)/semgrep-results.json 2>/dev/null || echo 0); \
	echo ""; \
	echo "$(YELLOW)SAST Findings: $$FINDINGS$(RESET)"

scan-secrets: check-deps ## Scan for secrets and credentials (Gitleaks)
	@echo "$(CYAN)=== Secret Scan (Gitleaks) ===$(RESET)"
	@echo "  Target: $(TARGET)"
	@echo ""
	@mkdir -p $(REPORTS_DIR)

	@gitleaks detect \
		--source $(TARGET) \
		--report-format json \
		--report-path $(REPORTS_DIR)/gitleaks-results.json \
		--exit-code 1 || LEAK_EXIT=$$?

	@SECRETS=$$(jq '. | length' $(REPORTS_DIR)/gitleaks-results.json 2>/dev/null || echo 0); \
	if [ "$$SECRETS" -gt "0" ]; then \
		echo "$(RED)❌ Found $$SECRETS potential secret(s) — rotate credentials immediately!$(RESET)"; \
		jq '.[] | "  [\(.RuleID)] \(.File):\(.StartLine) — \(.Description)"' \
			$(REPORTS_DIR)/gitleaks-results.json -r; \
		exit 1; \
	else \
		echo "$(GREEN)✅ No secrets detected$(RESET)"; \
	fi

scan-owasp: check-deps ## Run OWASP dependency analysis (Syft + OSV-Scanner)
	@echo "$(CYAN)=== OWASP Dependency Analysis ===$(RESET)"
	@echo "  Target: $(TARGET)"
	@echo ""
	@mkdir -p $(REPORTS_DIR)

	@echo "$(YELLOW)Generating SBOM with Syft...$(RESET)"
	@syft dir:$(TARGET) \
		-o cyclonedx-json=$(REPORTS_DIR)/sbom.json
	@echo "  SBOM written to $(REPORTS_DIR)/sbom.json"
	@echo ""

	@echo "$(YELLOW)Scanning SBOM with OSV-Scanner...$(RESET)"
	@if command -v osv-scanner > /dev/null 2>&1; then \
		osv-scanner \
			--sbom=$(REPORTS_DIR)/sbom.json \
			--format table 2>&1 | tee $(REPORTS_DIR)/osv-results.txt || true; \
	else \
		echo "$(YELLOW)osv-scanner not found — skipping OSV scan$(RESET)"; \
		echo "Install with: go install github.com/google/osv-scanner/cmd/osv-scanner@latest"; \
	fi

scan-full: check-deps ## Run all scans (CVE + SAST + Secrets + OWASP)
	@echo "$(CYAN)╔══════════════════════════════════════╗$(RESET)"
	@echo "$(CYAN)║   CyberStrikeAI Full Security Scan   ║$(RESET)"
	@echo "$(CYAN)╚══════════════════════════════════════╝$(RESET)"
	@echo "  Target: $(TARGET)"
	@echo "  Output: $(REPORTS_DIR)"
	@echo ""
	@mkdir -p $(REPORTS_DIR)

	@echo "$(CYAN)[1/4] CVE Scan$(RESET)"
	@$(MAKE) scan-cve TARGET=$(TARGET) REPORTS_DIR=$(REPORTS_DIR) || CVE_FAILED=1

	@echo ""
	@echo "$(CYAN)[2/4] SAST Scan$(RESET)"
	@$(MAKE) scan-sast TARGET=$(TARGET) REPORTS_DIR=$(REPORTS_DIR) || SAST_FAILED=1

	@echo ""
	@echo "$(CYAN)[3/4] Secret Scan$(RESET)"
	@$(MAKE) scan-secrets TARGET=$(TARGET) REPORTS_DIR=$(REPORTS_DIR) || SECRET_FAILED=1

	@echo ""
	@echo "$(CYAN)[4/4] OWASP Scan$(RESET)"
	@$(MAKE) scan-owasp TARGET=$(TARGET) REPORTS_DIR=$(REPORTS_DIR) || OWASP_FAILED=1

	@echo ""
	@echo "$(CYAN)=== Scan Complete ===$(RESET)"
	@CVE_CRITICAL=$$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' \
		$(REPORTS_DIR)/grype-results.json 2>/dev/null || echo 0); \
	SECRETS=$$(jq '. | length' $(REPORTS_DIR)/gitleaks-results.json 2>/dev/null || echo 0); \
	SAST=$$(jq '.results | length' $(REPORTS_DIR)/semgrep-results.json 2>/dev/null || echo 0); \
	echo ""; \
	echo "  CVE Critical : $$CVE_CRITICAL"; \
	echo "  Secrets      : $$SECRETS"; \
	echo "  SAST Findings: $$SAST"; \
	echo ""; \
	if [ "$$CVE_CRITICAL" -gt "0" ] || [ "$$SECRETS" -gt "0" ]; then \
		echo "$(RED)❌ Security gate FAILED$(RESET)"; \
		exit 1; \
	else \
		echo "$(GREEN)✅ Security gate PASSED$(RESET)"; \
	fi

# ── Report generation ─────────────────────────────────────────────────────────

report: check-deps ## Generate consolidated Markdown report  [OUTPUT=./report.md]
	@echo "$(CYAN)=== Generating Security Report ===$(RESET)"
	@echo "  Target: $(TARGET)"
	@echo "  Output: $(OUTPUT)"
	@echo ""

	@mkdir -p $(REPORTS_DIR) $$(dirname $(OUTPUT))

	@# Run scans quietly if results don't exist
	@[ -f $(REPORTS_DIR)/grype-results.json ] || \
		grype dir:$(TARGET) --output json --file $(REPORTS_DIR)/grype-results.json > /dev/null 2>&1 || true
	@[ -f $(REPORTS_DIR)/semgrep-results.json ] || \
		semgrep scan --config auto --json --output $(REPORTS_DIR)/semgrep-results.json $(TARGET) > /dev/null 2>&1 || true
	@[ -f $(REPORTS_DIR)/gitleaks-results.json ] || \
		gitleaks detect --source $(TARGET) --report-format json \
		--report-path $(REPORTS_DIR)/gitleaks-results.json > /dev/null 2>&1 || true

	@# Generate report
	@CVE_CRITICAL=$$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' \
		$(REPORTS_DIR)/grype-results.json 2>/dev/null || echo 0); \
	CVE_HIGH=$$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' \
		$(REPORTS_DIR)/grype-results.json 2>/dev/null || echo 0); \
	SAST=$$(jq '.results | length' \
		$(REPORTS_DIR)/semgrep-results.json 2>/dev/null || echo 0); \
	SECRETS=$$(jq '. | length' \
		$(REPORTS_DIR)/gitleaks-results.json 2>/dev/null || echo 0); \
	STATUS="✅ PASSED"; \
	[ "$$CVE_CRITICAL" -gt "0" ] || [ "$$SECRETS" -gt "0" ] && STATUS="❌ FAILED"; \
	cat > $(OUTPUT) <<EOF
# Security Scan Report

**Date:** $$(date -u "+%Y-%m-%d %H:%M UTC")
**Target:** $(TARGET)
**Status:** $$STATUS

## Summary

| Check | Count | Status |
|-------|-------|--------|
| CVE Critical | $$CVE_CRITICAL | $$([ "$$CVE_CRITICAL" -gt 0 ] && echo "❌" || echo "✅") |
| CVE High | $$CVE_HIGH | $$([ "$$CVE_HIGH" -gt 0 ] && echo "⚠️" || echo "✅") |
| SAST Findings | $$SAST | $$([ "$$SAST" -gt 0 ] && echo "⚠️" || echo "✅") |
| Secrets | $$SECRETS | $$([ "$$SECRETS" -gt 0 ] && echo "❌" || echo "✅") |

## Critical CVEs

\`\`\`
$$(jq -r '.matches[] | select(.vulnerability.severity=="Critical") | 
    "[\(.vulnerability.id)] \(.artifact.name) \(.artifact.version) → fix: \(.vulnerability.fix.versions | join(", "))"' \
    $(REPORTS_DIR)/grype-results.json 2>/dev/null || echo "None")
\`\`\`

## High CVEs

\`\`\`
$$(jq -r '.matches[] | select(.vulnerability.severity=="High") | 
    "[\(.vulnerability.id)] \(.artifact.name) \(.artifact.version) → fix: \(.vulnerability.fix.versions | join(", "))"' \
    $(REPORTS_DIR)/grype-results.json 2>/dev/null || echo "None")
\`\`\`

## SAST Findings

\`\`\`
$$(jq -r '.results[] | "[\(.extra.severity)] \(.check_id)\n  \(.path):\(.start.line)\n  \(.extra.message)\n"' \
    $(REPORTS_DIR)/semgrep-results.json 2>/dev/null || echo "None")
\`\`\`

## Secrets

\`\`\`
$$(jq -r '.[] | "[\(.RuleID)] \(.File):\(.StartLine) — \(.Description)"' \
    $(REPORTS_DIR)/gitleaks-results.json 2>/dev/null || echo "None")
\`\`\`

---
*Generated by CyberStrikeAI DevSec | $$(date -u)*
EOF
	@echo "$(GREEN)✅ Report written to: $(OUTPUT)$(RESET)"

# ── Tool management ───────────────────────────────────────────────────────────

install-tools: ## Install all required security tools
	@echo "$(CYAN)=== Installing DevSec Tools ===$(RESET)"
	@echo ""

	@# System dependencies
	@echo "$(YELLOW)Installing system dependencies...$(RESET)"
	@sudo apt-get update -qq 2>/dev/null || true
	@sudo apt-get install -y -qq curl wget jq python3 python3-pip 2>/dev/null || \
		brew install curl wget jq python3 2>/dev/null || true

	@# Grype
	@echo "$(YELLOW)Installing Grype...$(RESET)"
	@curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
		| sudo sh -s -- -b /usr/local/bin
	@echo "  $$(grype version 2>&1 | head -1)"

	@# Trivy
	@echo "$(YELLOW)Installing Trivy...$(RESET)"
	@if command -v apt-get > /dev/null 2>&1; then \
		wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add - 2>/dev/null; \
		echo "deb https://aquasecurity.github.io/trivy-repo/deb $$(lsb_release -sc) main" \
			| sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null; \
		sudo apt-get update -qq && sudo apt-get install -y trivy; \
	elif command -v brew > /dev/null 2>&1; then \
		brew install aquasecurity/trivy/trivy; \
	fi
	@echo "  $$(trivy --version 2>&1 | head -1)"

	@# Semgrep
	@echo "$(YELLOW)Installing Semgrep...$(RESET)"
	@pip3 install --user --quiet semgrep || pip install --user --quiet semgrep
	@echo "  $$(semgrep --version 2>&1 | head -1)"

	@# Gitleaks
	@echo "$(YELLOW)Installing Gitleaks...$(RESET)"
	@GITLEAKS_VERSION=$$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
		| jq -r .tag_name); \
	curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/$${GITLEAKS_VERSION}/gitleaks_$${GITLEAKS_VERSION#v}_linux_x64.tar.gz" \
		| sudo tar -xz -C /usr/local/bin 2>/dev/null || \
	brew install gitleaks 2>/dev/null || true
	@echo "  $$(gitleaks version 2>&1 | head -1)"

	@# Syft
	@echo "$(YELLOW)Installing Syft...$(RESET)"
	@curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
		| sudo sh -s -- -b /usr/local/bin
	@echo "  $$(syft version 2>&1 | head -1)"

	@# OSV-Scanner
	@echo "$(YELLOW)Installing OSV-Scanner...$(RESET)"
	@if command -v go > /dev/null 2>&1; then \
		go install github.com/google/osv-scanner/cmd/osv-scanner@latest; \
		echo "  $$(osv-scanner --version 2>&1 | head -1)"; \
	elif command -v brew > /dev/null 2>&1; then \
		brew install osv-scanner; \
	else \
		echo "$(YELLOW)  Go not found — install Go 1.21+ to get osv-scanner$(RESET)"; \
	fi

	@echo ""
	@echo "$(GREEN)✅ All tools installed!$(RESET)"
	@$(MAKE) verify

verify: ## Verify all tools are installed and functional
	@echo "$(CYAN)=== Tool Verification ===$(RESET)"
	@echo ""
	@PASS=true; \
	check_tool() { \
		if command -v "$$1" > /dev/null 2>&1; then \
			printf "  $(GREEN)✅$(RESET)  %-15s %s\n" "$$1" "$$($$1 version 2>&1 | head -1)"; \
		else \
			printf "  $(RED)❌$(RESET)  %-15s NOT FOUND\n" "$$1"; \
			PASS=false; \
		fi; \
	}; \
	check_tool grype; \
	check_tool trivy; \
	check_tool semgrep; \
	check_tool gitleaks; \
	check_tool syft; \
	check_tool osv-scanner; \
	check_tool jq; \
	echo ""; \
	if [ -n "$(NVD_API_KEY)" ]; then \
		echo "  $(GREEN)✅$(RESET)  NVD_API_KEY    — configured"; \
	else \
		echo "  $(YELLOW)⚠️$(RESET)   NVD_API_KEY    — not set (rate-limited)"; \
	fi; \
	echo ""; \
	if [ "$$PASS" = "true" ]; then \
		echo "$(GREEN)All tools operational. CyberStrikeAI DevSec is ready.$(RESET)"; \
	else \
		echo "$(RED)Some tools are missing. Run: make install-tools$(RESET)"; \
		exit 1; \
	fi

update-dbs: ## Update vulnerability databases (Grype + Trivy)
	@echo "$(CYAN)=== Updating Vulnerability Databases ===$(RESET)"
	@echo ""
	@echo "$(YELLOW)Updating Grype DB...$(RESET)"
	@grype db update
	@echo "$(YELLOW)Updating Trivy DB...$(RESET)"
	@trivy image --download-db-only
	@echo ""
	@echo "$(GREEN)✅ Databases updated$(RESET)"

sbom: ## Generate SBOM for target project  [TARGET=./your-project]
	@echo "$(CYAN)=== Generating SBOM ===$(RESET)"
	@echo "  Target: $(TARGET)"
	@mkdir -p $(REPORTS_DIR)
	@syft dir:$(TARGET) \
		-o cyclonedx-json=$(REPORTS_DIR)/sbom.json \
		-o spdx-json=$(REPORTS_DIR)/sbom-spdx.json \
		-o table
	@echo ""
	@echo "$(GREEN)✅ SBOM written to:$(RESET)"
	@echo "   $(REPORTS_DIR)/sbom.json (CycloneDX)"
	@echo "   $(REPORTS_DIR)/sbom-spdx.json (SPDX)"

# ── Pipeline targets (Levels 2 & 3) ──────────────────────────────────────────

CONSENT        ?= ./consent/consent-signed.pdf
CONSENT_URL    ?=
TARGET_URL     ?= https://app.example.com
SCOPE          ?= "Specify scope here"
NOTIFY_EMAIL   ?=
AI_MODEL       ?= claude-sonnet-4-5
SCAN_LEVEL     ?= 1

scan-level2: ## Active light scan (requires consent) [TARGET_URL=... CONSENT=... NOTIFY_EMAIL=...]
	@echo "$(CYAN)=== Level 2 Active Light Scan ===$(RESET)"
	@echo "  Target  : $(TARGET_URL)"
	@echo "  Consent : $(CONSENT)"
	@python3 scripts/devsec-pipeline.py \
		--target "$(TARGET_URL)" \
		--level 2 \
		--lang auto \
		--consent "$(CONSENT)" \
		--output "$(REPORTS_DIR)/level2_$$(date +%Y%m%d_%H%M%S)" \
		--ai-model "$(AI_MODEL)" \
		$(if $(NOTIFY_EMAIL),--notify-email "$(NOTIFY_EMAIL)",)

scan-level3: ## Full pentest (requires signed consent + CONFIRM confirmation) [TARGET_URL=... CONSENT=...]
	@echo "$(RED)=== Level 3 Full Pentest ===$(RESET)"
	@echo "  $(RED)WARNING: This will perform active exploitation attempts$(RESET)"
	@echo "  Target  : $(TARGET_URL)"
	@echo "  Consent : $(CONSENT)"
	@python3 scripts/devsec-pipeline.py \
		--target "$(TARGET_URL)" \
		--level 3 \
		--lang auto \
		--consent "$(CONSENT)" \
		--output "$(REPORTS_DIR)/level3_$$(date +%Y%m%d_%H%M%S)" \
		--ai-model "$(AI_MODEL)" \
		$(if $(NOTIFY_EMAIL),--notify-email "$(NOTIFY_EMAIL)",)

generate-consent: ## Generate consent document PDF [TARGET_URL=... SCOPE=...]
	@echo "$(CYAN)=== Generating Consent Document ===$(RESET)"
	@mkdir -p consent
	@python3 scripts/consent/generate-consent.py \
		--target "$(TARGET_URL)" \
		--scope "$(SCOPE)" \
		--level "$(SCAN_LEVEL)" \
		--output consent/consent-draft.pdf || \
	( echo "$(YELLOW)⚠  generate-consent.py not found — creating basic template$(RESET)"; \
	  python3 -c "
import pathlib, datetime
consent_dir = pathlib.Path('consent')
consent_dir.mkdir(exist_ok=True)
template = (consent_dir / 'consent-template.md')
template.write_text(f'''# Consent for Security Testing\n\n**Target:** $(TARGET_URL)\n**Scope:** $(SCOPE)\n**Level:** $(SCAN_LEVEL)\n**Date:** {datetime.date.today()}\n\n## Authorization\nI, the undersigned, authorize CyberStrikeAI DevSec to perform security testing on the above target.\n\n**Signature:** ___________________________\n**Name:** ___________________________\n**Title:** ___________________________\n**Date:** ___________________________\n''')
print('Template written to consent/consent-template.md')
" )

verify-consent: ## Verify consent document [CONSENT=./consent/consent-signed.pdf]
	@echo "$(CYAN)=== Verifying Consent Document ===$(RESET)"
	@if [ ! -f "$(CONSENT)" ]; then \
		echo "$(RED)❌ Consent file not found: $(CONSENT)$(RESET)"; \
		exit 1; \
	fi
	@python3 scripts/consent/verify-consent.py \
		--consent "$(CONSENT)" \
		--level "$(SCAN_LEVEL)" || \
	( HASH=$$(sha256sum "$(CONSENT)" | cut -c1-12); \
	  echo "$(GREEN)✅ Basic check passed — consent_id=$$HASH$(RESET)" )

send-consent: ## Send consent for signature [CONSENT=... RECIPIENT=...]
	@echo "$(CYAN)=== Sending Consent for Signature ===$(RESET)"
	@python3 scripts/consent/generate-consent.py \
		--target "$(TARGET_URL)" \
		--scope "$(SCOPE)" \
		--level "$(SCAN_LEVEL)" \
		--send-to "$(RECIPIENT)" || \
	  echo "$(YELLOW)⚠  send-consent requires scripts/consent/generate-consent.py$(RESET)"

audit-trail: ## View audit trail [DATE=YYYY-MM-DD] [TAIL=20]
	@echo "$(CYAN)=== Audit Trail ===$(RESET)"
	@python3 scripts/audit-trail.py list \
		$(if $(DATE),--date "$(DATE)",) \
		$(if $(TAIL),--tail "$(TAIL)",)

audit-verify: ## Verify audit trail integrity [DATE=YYYY-MM-DD]
	@echo "$(CYAN)=== Verifying Audit Trail Integrity ===$(RESET)"
	@python3 scripts/audit-trail.py verify \
		$(if $(DATE),--date "$(DATE)",)

audit-export: ## Export audit trail to PDF [OUTPUT=audit.pdf] [DATE=YYYY-MM-DD]
	@echo "$(CYAN)=== Exporting Audit Trail ===$(RESET)"
	@python3 scripts/audit-trail.py export-pdf \
		--output "$(or $(OUTPUT),audit-trail.pdf)" \
		$(if $(DATE),--date "$(DATE)",)

pipeline-dry-run: ## Dry run pipeline (validate without scanning) [TARGET_URL=...]
	@python3 scripts/devsec-pipeline.py \
		--target "$(TARGET_URL)" \
		--level "$(SCAN_LEVEL)" \
		--consent "$(CONSENT)" \
		--dry-run

notify-test: ## Test notification channels [CHANNEL=email|slack|teams]
	@echo "$(CYAN)=== Testing Notification Channel: $(or $(CHANNEL),slack) ===$(RESET)"
	@echo '[{"tool":"test","severity":"high","id":"TEST-001","description":"Test finding"}]' > /tmp/test-findings.json
	@python3 scripts/notify.py \
		--channel "$(or $(CHANNEL),slack)" \
		--findings-json /tmp/test-findings.json \
		--target "$(TARGET_URL)"
	@rm -f /tmp/test-findings.json

# ── Dependency check ──────────────────────────────────────────────────────────

check-deps: ## Check that required tools are available (internal)
	@for tool in grype trivy semgrep gitleaks syft jq; do \
		if ! command -v $$tool > /dev/null 2>&1; then \
			echo "$(RED)❌ Required tool not found: $$tool$(RESET)"; \
			echo "   Run: make install-tools"; \
			exit 1; \
		fi; \
	done

clean: ## Remove scan results and reports
	@echo "$(YELLOW)Cleaning $(REPORTS_DIR)...$(RESET)"
	@rm -rf $(REPORTS_DIR)
	@echo "$(GREEN)✅ Done$(RESET)"

docker-scan: ## Run full scan using Docker (no local tool install needed)
	@echo "$(CYAN)=== Docker-based Full Scan ===$(RESET)"
	@echo "  Target: $(TARGET)"
	@mkdir -p $(REPORTS_DIR)

	@echo "$(YELLOW)Running Grype (Docker)...$(RESET)"
	@docker run --rm \
		-v "$$(realpath $(TARGET)):/workspace:ro" \
		-v "$$(realpath $(REPORTS_DIR)):/reports" \
		anchore/grype:latest \
		dir:/workspace \
		--output json \
		--file /reports/grype-results.json \
		--severity $(SEVERITY) || true

	@echo "$(YELLOW)Running Trivy (Docker)...$(RESET)"
	@docker run --rm \
		-v "$$(realpath $(TARGET)):/workspace:ro" \
		-v "$$(realpath $(REPORTS_DIR)):/reports" \
		aquasec/trivy:latest \
		fs /workspace \
		--format json \
		--output /reports/trivy-results.json \
		--severity $(SEVERITY),CRITICAL || true

	@echo "$(YELLOW)Running Semgrep (Docker)...$(RESET)"
	@docker run --rm \
		-v "$$(realpath $(TARGET)):/src:ro" \
		-v "$$(realpath $(REPORTS_DIR)):/reports" \
		semgrep/semgrep:latest \
		semgrep scan \
		--config auto \
		--json \
		--output /reports/semgrep-results.json \
		/src || true

	@echo "$(YELLOW)Running Gitleaks (Docker)...$(RESET)"
	@docker run --rm \
		-v "$$(realpath $(TARGET)):/path:ro" \
		-v "$$(realpath $(REPORTS_DIR)):/reports" \
		zricethezav/gitleaks:latest \
		detect \
		--source /path \
		--report-format json \
		--report-path /reports/gitleaks-results.json || true

	@echo ""
	@echo "$(GREEN)✅ Docker scan complete. Results in: $(REPORTS_DIR)$(RESET)"
	@$(MAKE) report TARGET=$(TARGET) OUTPUT=$(OUTPUT)
