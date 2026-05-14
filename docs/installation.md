# Installation & Configuration Guide — CyberStrikeAI DevSec

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installing Security Tools](#installing-security-tools)
   - [Linux (apt)](#linux-apt)
   - [macOS (Homebrew)](#macos-homebrew)
   - [Docker](#docker)
3. [Configuring CyberStrikeAI](#configuring-cyberstrikiai)
4. [Environment Variables](#environment-variables)
5. [Verifying the Installation](#verifying-the-installation)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| CyberStrikeAI | Latest | Must be installed and licensed |
| Go | 1.21+ | Required for osv-scanner and some tools |
| Python | 3.9+ | Required for Semgrep |
| Docker | 20.10+ | Optional, for containerized scans |
| curl / wget | Any | For tool installation scripts |
| jq | 1.6+ | For JSON parsing in scripts |

### Verify prerequisites

```bash
go version          # go1.21.x or higher
python3 --version   # Python 3.9.x or higher
docker --version    # Docker 20.10.x or higher
jq --version        # jq-1.6 or higher
```

---

## Installing Security Tools

### Linux (apt)

Run as root or with `sudo`:

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "=== Installing CyberStrikeAI DevSec tools (Linux/apt) ==="

# ── System dependencies ────────────────────────────────────────────────────
sudo apt-get update -y
sudo apt-get install -y \
    curl wget git jq unzip gnupg lsb-release \
    apt-transport-https ca-certificates \
    python3 python3-pip golang-go

# ── Grype (Anchore CVE scanner) ────────────────────────────────────────────
echo "Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
grype version

# ── Trivy (Aqua Security scanner) ─────────────────────────────────────────
echo "Installing Trivy..."
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
    | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update -y && sudo apt-get install -y trivy
trivy --version

# ── Semgrep (SAST) ─────────────────────────────────────────────────────────
echo "Installing Semgrep..."
pip3 install --user semgrep
semgrep --version

# ── Gitleaks (Secret detection) ───────────────────────────────────────────
echo "Installing Gitleaks..."
GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
    | jq -r .tag_name)
GITLEAKS_URL="https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz"
curl -sSfL "$GITLEAKS_URL" | sudo tar -xz -C /usr/local/bin
gitleaks version

# ── Syft (SBOM generator) ─────────────────────────────────────────────────
echo "Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sudo sh -s -- -b /usr/local/bin
syft version

# ── OSV-Scanner (Google Open Source Vulnerabilities) ──────────────────────
echo "Installing OSV-Scanner..."
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
# Add Go bin to PATH if not already there
export PATH="$PATH:$(go env GOPATH)/bin"
osv-scanner --version

echo ""
echo "✅ All tools installed successfully!"
```

Save as `install-tools.sh`, then run:

```bash
chmod +x install-tools.sh && ./install-tools.sh
```

---

### macOS (Homebrew)

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "=== Installing CyberStrikeAI DevSec tools (macOS/Homebrew) ==="

# Ensure Homebrew is installed
if ! command -v brew &>/dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

brew update

# ── Grype ──────────────────────────────────────────────────────────────────
echo "Installing Grype..."
brew install anchore/grype/grype
grype version

# ── Trivy ──────────────────────────────────────────────────────────────────
echo "Installing Trivy..."
brew install aquasecurity/trivy/trivy
trivy --version

# ── Semgrep ────────────────────────────────────────────────────────────────
echo "Installing Semgrep..."
brew install semgrep
semgrep --version

# ── Gitleaks ───────────────────────────────────────────────────────────────
echo "Installing Gitleaks..."
brew install gitleaks
gitleaks version

# ── Syft ───────────────────────────────────────────────────────────────────
echo "Installing Syft..."
brew install syft
syft version

# ── OSV-Scanner ────────────────────────────────────────────────────────────
echo "Installing OSV-Scanner..."
brew install osv-scanner
osv-scanner --version

# ── jq ─────────────────────────────────────────────────────────────────────
brew install jq

echo ""
echo "✅ All tools installed successfully!"
```

---

### Docker

All tools are available as official Docker images. Use for ephemeral CI scans or environments where you don't want to install binaries.

```bash
# ── Grype ──────────────────────────────────────────────────────────────────
# Scan current directory
docker run --rm \
    -v "$(pwd):/scan:ro" \
    anchore/grype:latest \
    dir:/scan \
    --output json

# ── Trivy ──────────────────────────────────────────────────────────────────
docker run --rm \
    -v "$(pwd):/scan:ro" \
    aquasec/trivy:latest \
    fs /scan \
    --format json \
    --severity HIGH,CRITICAL

# ── Semgrep ────────────────────────────────────────────────────────────────
docker run --rm \
    -v "$(pwd):/src:ro" \
    semgrep/semgrep:latest \
    semgrep scan --config auto --json /src

# ── Gitleaks ───────────────────────────────────────────────────────────────
docker run --rm \
    -v "$(pwd):/path:ro" \
    zricethezav/gitleaks:latest \
    detect \
    --source /path \
    --report-format json
```

---

## Configuring CyberStrikeAI

### Step 1 — Copy Tools Configuration

```bash
# From the cyberstrike-devsec workspace
WORKSPACE="/home/ubuntu/.openclaw/workspace/cyberstrike-devsec"
CYBERSTRIKE_HOME="$HOME/.cyberstrike"

mkdir -p "$CYBERSTRIKE_HOME/tools"

# Copy tool definitions
cp "$WORKSPACE/tools/"*.yaml "$CYBERSTRIKE_HOME/tools/"

echo "✅ Tool configs copied to $CYBERSTRIKE_HOME/tools/"
```

### Step 2 — Import Skills

```bash
# Import all DevSec skills into CyberStrikeAI
for skill in "$WORKSPACE/skills/"*.yaml; do
    echo "Importing skill: $skill"
    cyberstrike skill import "$skill"
done

# Verify skills are loaded
cyberstrike skill list
```

### Step 3 — Configure Roles

```bash
# Import role definitions
for role in "$WORKSPACE/roles/"*.yaml; do
    echo "Importing role: $role"
    cyberstrike role import "$role"
done

# Verify roles
cyberstrike role list
```

### Step 4 — Create Main Config File

Create `~/.cyberstrike/config.yaml`:

```yaml
# CyberStrikeAI DevSec Configuration
# ─────────────────────────────────────

# API Keys
nvd_api_key: "${NVD_API_KEY}"          # From environment variable

# Scanning behavior
severity_threshold: HIGH               # Minimum severity to report (INFO/LOW/MEDIUM/HIGH/CRITICAL)
fail_on_critical: true                 # Exit 1 when Critical CVEs found
fail_on_secrets: true                  # Exit 1 when secrets detected
fail_on_high: false                    # Set true for stricter pipelines
sast_fail_threshold: 0                 # Fail if SAST findings > threshold (0 = never fail on SAST alone)

# Output
output_format: json                    # json | text | markdown | sarif
report_dir: "./security-reports"       # Where to write reports
include_fix_versions: true             # Show recommended fix versions in CVE reports

# Tools paths (override if not in PATH)
tools:
  grype: grype
  trivy: trivy
  semgrep: semgrep
  gitleaks: gitleaks
  syft: syft
  osv_scanner: osv-scanner

# Scan exclusions
exclude_paths:
  - "**/.git/**"
  - "**/node_modules/**"
  - "**/vendor/**"
  - "**/*.test.*"
  - "**/test/**"
  - "**/tests/**"

# CVE suppression (known false positives)
# suppress:
#   - cve_id: CVE-2021-44228
#     reason: "Not exploitable in this context — log4j not used at runtime"
#     expires: "2026-12-31"
```

---

## Environment Variables

Set these in your shell profile (`~/.bashrc`, `~/.zshrc`) or CI/CD secret store:

```bash
# Required
export NVD_API_KEY="your-nvd-api-key-here"
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

# Optional — enhances scan accuracy
export CYBERSTRIKE_LICENSE="your-license-key"

# Semgrep Cloud (for dashboard and rule management)
export SEMGREP_APP_TOKEN="your-semgrep-token"

# Go path (for osv-scanner)
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Getting an NVD API Key

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Fill in the form (email required)
3. Check your email for the key (usually arrives within minutes)
4. Without an API key, NVD-based scans are rate-limited to 5 requests/30s

---

## Verifying the Installation

Run the built-in verification command:

```bash
cyberstrike verify-tools
```

Expected output:
```
CyberStrikeAI DevSec — Tool Verification
─────────────────────────────────────────
✅  grype       v0.78.0   — CVE filesystem scanner
✅  trivy       v0.50.0   — Multi-target vulnerability scanner
✅  semgrep     v1.60.0   — SAST / pattern matching
✅  gitleaks    v8.18.0   — Secret detection
✅  syft        v1.0.0    — SBOM generator
✅  osv-scanner v1.7.0    — OSV vulnerability database scanner
✅  NVD API key           — Configured and reachable

All tools operational. CyberStrikeAI DevSec is ready.
```

### Manual Verification

If `cyberstrike verify-tools` is not yet available, run manually:

```bash
#!/usr/bin/env bash
echo "Verifying DevSec tools..."

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo "✅  $1 — $($1 version 2>&1 | head -1)"
    else
        echo "❌  $1 — NOT FOUND"
    fi
}

check_tool grype
check_tool trivy
check_tool semgrep
check_tool gitleaks
check_tool syft
check_tool osv-scanner
check_tool jq

# Check NVD API key
if [ -n "$NVD_API_KEY" ]; then
    echo "✅  NVD_API_KEY — Set"
else
    echo "⚠️   NVD_API_KEY — Not set (scans will be rate-limited)"
fi
```

### Quick Smoke Test

```bash
# Create a test project
mkdir /tmp/test-project && cd /tmp/test-project

# Create a minimal package.json with a known vulnerable dependency
cat > package.json <<'EOF'
{
  "name": "test",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15"
  }
}
EOF

# Run a quick scan
grype dir:. --output table
trivy fs . --severity CRITICAL,HIGH

echo "Smoke test complete!"
cd - && rm -rf /tmp/test-project
```

---

## Windows Installation

### Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Windows | 10 / 11 or Server 2019+ | Windows 10 1803+ for built-in `tar.exe` |
| PowerShell | 5.1+ (7+ recommended) | Pre-installed on Windows 10+; download PS7 from [aka.ms/powershell](https://aka.ms/powershell) |
| Git for Windows | 2.x | Required for Gitleaks; download from [git-scm.com](https://git-scm.com/download/win) |
| winget | 1.4+ | Recommended; ships with Windows 11, installable via Microsoft Store on Win 10 |
| .NET SDK | 6.0+ | Required for C#/.NET project scanning |
| Go | 1.21+ | Optional; needed for `osv-scanner` if not using direct download |
| Python | 3.9+ | Optional; needed for Semgrep via `pip` if winget/choco unavailable |

### Option 1 — winget (recommended)

winget is the official Windows package manager, available on Windows 10/11:

```powershell
# Run as Administrator in PowerShell

# 1. Run the automated installer
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install.ps1

# Or install tools individually via winget:
winget install Anchore.Grype        --accept-source-agreements --accept-package-agreements
winget install AquaSecurity.Trivy   --accept-source-agreements --accept-package-agreements
winget install Semgrep.Semgrep      --accept-source-agreements --accept-package-agreements
winget install Gitleaks.Gitleaks    --accept-source-agreements --accept-package-agreements
winget install Anchore.Syft         --accept-source-agreements --accept-package-agreements
```

### Option 2 — Chocolatey

If winget is not available, use Chocolatey:

```powershell
# Install Chocolatey first (run as Administrator):
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Then install tools:
choco install grype trivy semgrep gitleaks syft -y

# Run the installer with Chocolatey mode:
.\scripts\install.ps1 -PackageManager choco
```

### Option 3 — Docker Desktop (cross-platform)

Use Docker Desktop on Windows to run tools in containers without native installation:

```powershell
# Grype
docker run --rm -v "${PWD}:/scan:ro" anchore/grype:latest dir:/scan --output json

# Trivy
docker run --rm -v "${PWD}:/scan:ro" aquasec/trivy:latest fs /scan --severity HIGH,CRITICAL

# Semgrep
docker run --rm -v "${PWD}:/src:ro" semgrep/semgrep:latest semgrep scan --config auto --json /src

# Gitleaks
docker run --rm -v "${PWD}:/path:ro" zricethezav/gitleaks:latest detect --source /path --report-format json
```

### Option 4 — WSL2 (advanced)

WSL2 (Windows Subsystem for Linux) provides a full Linux environment on Windows, enabling use of the native Linux install scripts:

```powershell
# Install WSL2 (requires Windows 10 version 2004+)
wsl --install

# After WSL setup, launch Ubuntu and run the Linux installer:
wsl bash -c "cd /mnt/c/path/to/cyberstrike-devsec && ./scripts/install.sh"

# Then scan from WSL:
wsl bash scripts/scan.sh --target /mnt/c/Projects/MyApp --mode full
```

### Using the Windows Scripts

After installation, use these Windows-native scripts:

```powershell
# Quick scan (secrets + critical CVEs, < 2 min)
.\scripts\scan.ps1 -Target . -Mode quick

# Full scan
.\scripts\scan.ps1 -Target "C:\Projects\MyApp" -Mode full -Lang csharp

# CI/CD mode (exits 1 on Critical)
.\scripts\scan.ps1 -Target . -Mode cicd

# Using make.bat (CMD-compatible)
.\scripts\make.bat scan-full TARGET=.\myproject
.\scripts\make.bat report TARGET=.\myproject OUTPUT=.\report.md
```

### COBOL on Windows

For COBOL project scanning on Windows:

- **GnuCOBOL for Windows** — [sourceforge.net/projects/gnucobol](https://sourceforge.net/projects/gnucobol/)
  ```powershell
  winget install GnuCOBOL.GnuCOBOL
  ```
- **IBM Developer for z/OS** — Full COBOL IDE from IBM; evaluation available at [ibm.com/products/developer-for-zos](https://www.ibm.com/products/developer-for-zos)
- **Micro Focus Visual COBOL** — Commercial IDE with Windows support

Scanning COBOL projects on Windows (no compiler required):

```powershell
# Secret and pattern scanning works on raw COBOL source
.\scripts\scan.ps1 -Target "C:\Projects\MyCOBOLApp" -Mode full -Lang cobol
```

### Verifying the Installation on Windows

```powershell
# Via make.bat
.\scripts\make.bat verify

# Or manually in PowerShell
@('grype','trivy','semgrep','gitleaks','syft','osv-scanner') | ForEach-Object {
    if (Get-Command $_ -ErrorAction SilentlyContinue) {
        Write-Host "  [OK] $_" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $_" -ForegroundColor Red
    }
}

# Check NVD API key
if ($env:NVD_API_KEY) {
    Write-Host "  [OK] NVD_API_KEY set" -ForegroundColor Green
} else {
    Write-Host "  [WARN] NVD_API_KEY not set — scans will be rate-limited" -ForegroundColor Yellow
}
```
