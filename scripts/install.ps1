#Requires -Version 5.1
<#
.SYNOPSIS
    CyberStrikeAI DevSec — Windows Installation Script
.DESCRIPTION
    Installs all required security tools (Grype, Trivy, Semgrep, Gitleaks, Syft,
    OSV-Scanner, TruffleHog) on Windows via winget, Chocolatey, or direct GitHub
    release download.
.PARAMETER PackageManager
    Force a specific package manager: 'winget', 'choco', or 'direct'.
    Default: auto-detect (winget preferred, then choco, then direct).
.PARAMETER InstallDir
    Directory where tools will be installed when using direct download.
    Default: C:\Tools\devsec
.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -PackageManager choco
.EXAMPLE
    .\install.ps1 -PackageManager direct -InstallDir "C:\MyTools"
#>
[CmdletBinding()]
param(
    [ValidateSet('winget', 'choco', 'direct', 'auto')]
    [string]$PackageManager = 'auto',

    [string]$InstallDir = 'C:\Tools\devsec'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Helper functions ───────────────────────────────────────────────────────

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "  ▶ $Text" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Text)
    Write-Host "  ✔ $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "  ⚠ $Text" -ForegroundColor Magenta
}

function Write-Fail {
    param([string]$Text)
    Write-Host "  ✖ $Text" -ForegroundColor Red
}

function Test-CommandExists {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

function Test-IsAdmin {
    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-ToPath {
    param([string]$Directory)
    $currentPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    if ($currentPath -notlike "*$Directory*") {
        Write-Step "Adding '$Directory' to system PATH..."
        [Environment]::SetEnvironmentVariable('PATH', "$currentPath;$Directory", 'Machine')
        $env:PATH = "$env:PATH;$Directory"
        Write-OK "Added to PATH"
    }
}

function Get-GitHubLatestVersion {
    param([string]$Repo)
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        return $response.tag_name
    }
    catch {
        throw "Failed to get latest version for $Repo`: $_"
    }
}

function Install-FromGitHub {
    param(
        [string]$ToolName,
        [string]$Repo,
        [string]$AssetPattern,   # Pattern to match the Windows asset filename
        [string]$ExtractedBinary  # Name of the .exe after extraction
    )

    Write-Step "Downloading $ToolName from GitHub Releases..."
    try {
        $version = Get-GitHubLatestVersion -Repo $Repo
        $cleanVersion = $version -replace '^v', ''

        # Get release assets
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $asset = $release.assets | Where-Object { $_.name -like $AssetPattern } | Select-Object -First 1

        if (-not $asset) {
            throw "No matching asset found for pattern '$AssetPattern' in $Repo $version"
        }

        $downloadUrl = $asset.browser_download_url
        $fileName = $asset.name
        $tempPath = Join-Path $env:TEMP $fileName

        Write-Step "Downloading $fileName..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempPath -UseBasicParsing

        # Ensure install directory exists
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        # Extract
        if ($fileName -like '*.zip') {
            $extractDir = Join-Path $env:TEMP "$ToolName-extract"
            if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
            Expand-Archive -Path $tempPath -DestinationPath $extractDir -Force

            # Find the binary
            $binaryPath = Get-ChildItem -Path $extractDir -Filter $ExtractedBinary -Recurse | Select-Object -First 1
            if ($binaryPath) {
                Copy-Item -Path $binaryPath.FullName -Destination (Join-Path $InstallDir $ExtractedBinary) -Force
            } else {
                throw "Binary '$ExtractedBinary' not found after extracting $fileName"
            }
            Remove-Item $extractDir -Recurse -Force
        }
        elseif ($fileName -like '*.tar.gz') {
            # PowerShell 5.1 does not natively handle tar.gz — use tar.exe (Windows 10 1803+)
            if (-not (Test-CommandExists 'tar')) {
                throw "tar.exe not found. Please install Windows 10 1803+ or use -PackageManager choco."
            }
            $extractDir = Join-Path $env:TEMP "$ToolName-extract"
            if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
            New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
            & tar -xzf $tempPath -C $extractDir
            $binaryPath = Get-ChildItem -Path $extractDir -Filter $ExtractedBinary -Recurse | Select-Object -First 1
            if ($binaryPath) {
                Copy-Item -Path $binaryPath.FullName -Destination (Join-Path $InstallDir $ExtractedBinary) -Force
            } else {
                throw "Binary '$ExtractedBinary' not found after extracting $fileName"
            }
            Remove-Item $extractDir -Recurse -Force
        }
        elseif ($fileName -like '*.exe') {
            Copy-Item -Path $tempPath -Destination (Join-Path $InstallDir $ExtractedBinary) -Force
        }

        Remove-Item $tempPath -Force -ErrorAction SilentlyContinue

        Add-ToPath -Directory $InstallDir
        Write-OK "$ToolName installed to $InstallDir\$ExtractedBinary"
        return $true
    }
    catch {
        Write-Fail "Direct install failed for ${ToolName}: $_"
        return $false
    }
}

# ── Prerequisite checks ────────────────────────────────────────────────────

Write-Header "CyberStrikeAI DevSec — Windows Installer"

Write-Step "Checking prerequisites..."

# PowerShell version
$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 5) {
    Write-Fail "PowerShell 5.1 or higher is required. Current: $($psVersion.ToString())"
    exit 1
}
Write-OK "PowerShell $($psVersion.ToString()) — OK"

# Admin rights
if (-not (Test-IsAdmin)) {
    Write-Warn "Not running as Administrator. Some install methods may fail."
    Write-Warn "Re-run as Administrator for best results:"
    Write-Warn "  Start-Process powershell -Verb RunAs -ArgumentList '-File `"$PSCommandPath`"'"
    $continue = Read-Host "Continue without admin rights? (y/N)"
    if ($continue -ne 'y' -and $continue -ne 'Y') {
        exit 1
    }
} else {
    Write-OK "Running as Administrator — OK"
}

# Git for Windows
if (Test-CommandExists 'git') {
    $gitVersion = & git --version 2>&1
    Write-OK "Git — $gitVersion"
} else {
    Write-Warn "Git for Windows not found. Please install from https://git-scm.com/download/win"
    Write-Warn "Continuing without Git (some tools may not work correctly)..."
}

# ── Package manager detection ──────────────────────────────────────────────

Write-Step "Detecting package manager..."

$useWinget = $false
$useChoco  = $false

if ($PackageManager -eq 'auto' -or $PackageManager -eq 'winget') {
    if (Test-CommandExists 'winget') {
        $wingetVersion = & winget --version 2>&1
        Write-OK "winget found: $wingetVersion"
        $useWinget = $true
    } elseif ($PackageManager -eq 'winget') {
        Write-Fail "winget not found. Install from the Microsoft Store (App Installer)."
        exit 1
    }
}

if (-not $useWinget -and ($PackageManager -eq 'auto' -or $PackageManager -eq 'choco')) {
    if (Test-CommandExists 'choco') {
        $chocoVersion = & choco --version 2>&1
        Write-OK "Chocolatey found: $chocoVersion"
        $useChoco = $true
    } elseif ($PackageManager -eq 'choco') {
        Write-Fail "Chocolatey not found."
        Write-Warn "Install Chocolatey: Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        exit 1
    }
}

if (-not $useWinget -and -not $useChoco) {
    if ($PackageManager -eq 'direct') {
        Write-Warn "Using direct GitHub download for all tools."
    } else {
        Write-Warn "Neither winget nor Chocolatey found. Falling back to direct GitHub downloads."
        Write-Warn "For a better experience, install either:"
        Write-Warn "  • winget: via Microsoft Store (App Installer)"
        Write-Warn "  • choco : Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
    }
}

# ── Tool installation ──────────────────────────────────────────────────────

Write-Header "Installing Security Tools"

$failedTools = @()

# ── Grype ──────────────────────────────────────────────────────────────────
Write-Step "Installing Grype (Anchore CVE scanner)..."
if ($useWinget) {
    try {
        & winget install --id Anchore.Grype --accept-source-agreements --accept-package-agreements --silent
        Write-OK "Grype installed via winget"
    } catch {
        Write-Warn "winget install failed for Grype, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'grype' -Repo 'anchore/grype' `
            -AssetPattern '*windows_amd64.zip' -ExtractedBinary 'grype.exe'
        if (-not $ok) { $failedTools += 'grype' }
    }
} elseif ($useChoco) {
    try {
        & choco install grype -y
        Write-OK "Grype installed via Chocolatey"
    } catch {
        Write-Warn "Chocolatey install failed for Grype, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'grype' -Repo 'anchore/grype' `
            -AssetPattern '*windows_amd64.zip' -ExtractedBinary 'grype.exe'
        if (-not $ok) { $failedTools += 'grype' }
    }
} else {
    $ok = Install-FromGitHub -ToolName 'grype' -Repo 'anchore/grype' `
        -AssetPattern '*windows_amd64.zip' -ExtractedBinary 'grype.exe'
    if (-not $ok) { $failedTools += 'grype' }
}

# ── Trivy ──────────────────────────────────────────────────────────────────
Write-Step "Installing Trivy (Aqua Security scanner)..."
if ($useWinget) {
    try {
        & winget install --id AquaSecurity.Trivy --accept-source-agreements --accept-package-agreements --silent
        Write-OK "Trivy installed via winget"
    } catch {
        Write-Warn "winget install failed for Trivy, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'trivy' -Repo 'aquasecurity/trivy' `
            -AssetPattern '*windows-64bit.zip' -ExtractedBinary 'trivy.exe'
        if (-not $ok) { $failedTools += 'trivy' }
    }
} elseif ($useChoco) {
    try {
        & choco install trivy -y
        Write-OK "Trivy installed via Chocolatey"
    } catch {
        Write-Warn "Chocolatey install failed for Trivy, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'trivy' -Repo 'aquasecurity/trivy' `
            -AssetPattern '*windows-64bit.zip' -ExtractedBinary 'trivy.exe'
        if (-not $ok) { $failedTools += 'trivy' }
    }
} else {
    $ok = Install-FromGitHub -ToolName 'trivy' -Repo 'aquasecurity/trivy' `
        -AssetPattern '*windows-64bit.zip' -ExtractedBinary 'trivy.exe'
    if (-not $ok) { $failedTools += 'trivy' }
}

# ── Semgrep ────────────────────────────────────────────────────────────────
Write-Step "Installing Semgrep (SAST)..."
# Semgrep on Windows is best installed via pip or winget
$semgrepInstalled = $false
if ($useWinget) {
    try {
        & winget install --id Semgrep.Semgrep --accept-source-agreements --accept-package-agreements --silent
        $semgrepInstalled = $true
        Write-OK "Semgrep installed via winget"
    } catch {
        Write-Warn "winget install failed for Semgrep"
    }
}
if (-not $semgrepInstalled -and $useChoco) {
    try {
        & choco install semgrep -y
        $semgrepInstalled = $true
        Write-OK "Semgrep installed via Chocolatey"
    } catch {
        Write-Warn "Chocolatey install failed for Semgrep"
    }
}
if (-not $semgrepInstalled) {
    # Try pip
    if (Test-CommandExists 'pip') {
        try {
            Write-Step "Trying pip install semgrep..."
            & pip install semgrep --quiet
            $semgrepInstalled = $true
            Write-OK "Semgrep installed via pip"
        } catch {
            Write-Fail "pip install failed for Semgrep: $_"
        }
    } elseif (Test-CommandExists 'pip3') {
        try {
            Write-Step "Trying pip3 install semgrep..."
            & pip3 install semgrep --quiet
            $semgrepInstalled = $true
            Write-OK "Semgrep installed via pip3"
        } catch {
            Write-Fail "pip3 install failed for Semgrep: $_"
        }
    }
}
if (-not $semgrepInstalled) {
    Write-Warn "Semgrep could not be installed automatically."
    Write-Warn "Manual install: pip install semgrep  OR  winget install Semgrep.Semgrep"
    $failedTools += 'semgrep'
}

# ── Gitleaks ───────────────────────────────────────────────────────────────
Write-Step "Installing Gitleaks (secret detection)..."
if ($useWinget) {
    try {
        & winget install --id Gitleaks.Gitleaks --accept-source-agreements --accept-package-agreements --silent
        Write-OK "Gitleaks installed via winget"
    } catch {
        Write-Warn "winget install failed for Gitleaks, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'gitleaks' -Repo 'gitleaks/gitleaks' `
            -AssetPattern '*windows_x64.zip' -ExtractedBinary 'gitleaks.exe'
        if (-not $ok) { $failedTools += 'gitleaks' }
    }
} elseif ($useChoco) {
    try {
        & choco install gitleaks -y
        Write-OK "Gitleaks installed via Chocolatey"
    } catch {
        Write-Warn "Chocolatey install failed for Gitleaks, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'gitleaks' -Repo 'gitleaks/gitleaks' `
            -AssetPattern '*windows_x64.zip' -ExtractedBinary 'gitleaks.exe'
        if (-not $ok) { $failedTools += 'gitleaks' }
    }
} else {
    $ok = Install-FromGitHub -ToolName 'gitleaks' -Repo 'gitleaks/gitleaks' `
        -AssetPattern '*windows_x64.zip' -ExtractedBinary 'gitleaks.exe'
    if (-not $ok) { $failedTools += 'gitleaks' }
}

# ── Syft ───────────────────────────────────────────────────────────────────
Write-Step "Installing Syft (SBOM generator)..."
if ($useWinget) {
    try {
        & winget install --id Anchore.Syft --accept-source-agreements --accept-package-agreements --silent
        Write-OK "Syft installed via winget"
    } catch {
        Write-Warn "winget install failed for Syft, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'syft' -Repo 'anchore/syft' `
            -AssetPattern '*windows_amd64.zip' -ExtractedBinary 'syft.exe'
        if (-not $ok) { $failedTools += 'syft' }
    }
} elseif ($useChoco) {
    try {
        & choco install syft -y
        Write-OK "Syft installed via Chocolatey"
    } catch {
        Write-Warn "Chocolatey install failed for Syft, trying direct download..."
        $ok = Install-FromGitHub -ToolName 'syft' -Repo 'anchore/syft' `
            -AssetPattern '*windows_amd64.zip' -ExtractedBinary 'syft.exe'
        if (-not $ok) { $failedTools += 'syft' }
    }
} else {
    $ok = Install-FromGitHub -ToolName 'syft' -Repo 'anchore/syft' `
        -AssetPattern '*windows_amd64.zip' -ExtractedBinary 'syft.exe'
    if (-not $ok) { $failedTools += 'syft' }
}

# ── OSV-Scanner ────────────────────────────────────────────────────────────
Write-Step "Installing OSV-Scanner (Google Open Source Vulnerabilities)..."
$osvInstalled = $false
# OSV-Scanner has no winget/choco package — direct download only
try {
    $ok = Install-FromGitHub -ToolName 'osv-scanner' -Repo 'google/osv-scanner' `
        -AssetPattern '*windows-amd64.exe' -ExtractedBinary 'osv-scanner.exe'
    if ($ok) { $osvInstalled = $true }
} catch {
    Write-Warn "Direct download failed for osv-scanner: $_"
}
if (-not $osvInstalled) {
    # Try Go install
    if (Test-CommandExists 'go') {
        try {
            Write-Step "Trying go install osv-scanner..."
            & go install github.com/google/osv-scanner/cmd/osv-scanner@latest
            $osvInstalled = $true
            Write-OK "OSV-Scanner installed via go install"
            # Ensure GOPATH/bin is in PATH
            $goPath = & go env GOPATH
            Add-ToPath -Directory (Join-Path $goPath 'bin')
        } catch {
            Write-Fail "go install failed for osv-scanner: $_"
            $failedTools += 'osv-scanner'
        }
    } else {
        Write-Warn "osv-scanner requires Go or a direct download. Install Go from https://golang.org/dl/"
        $failedTools += 'osv-scanner'
    }
}

# ── TruffleHog ─────────────────────────────────────────────────────────────
Write-Step "Installing TruffleHog (advanced secret scanning)..."
$ok = Install-FromGitHub -ToolName 'trufflehog' -Repo 'trufflesecurity/trufflehog' `
    -AssetPattern '*windows_amd64.tar.gz' -ExtractedBinary 'trufflehog.exe'
if (-not $ok) { $failedTools += 'trufflehog' }

# ── Post-install verification ──────────────────────────────────────────────

Write-Header "Post-Installation Verification"

$tools = @(
    @{ Name = 'grype';        VersionCmd = 'grype version' },
    @{ Name = 'trivy';        VersionCmd = 'trivy --version' },
    @{ Name = 'semgrep';      VersionCmd = 'semgrep --version' },
    @{ Name = 'gitleaks';     VersionCmd = 'gitleaks version' },
    @{ Name = 'syft';         VersionCmd = 'syft version' },
    @{ Name = 'osv-scanner';  VersionCmd = 'osv-scanner --version' },
    @{ Name = 'trufflehog';   VersionCmd = 'trufflehog --version' }
)

$allOk = $true
foreach ($tool in $tools) {
    $name = $tool.Name
    if (Test-CommandExists $name) {
        try {
            $versionOutput = Invoke-Expression $tool.VersionCmd 2>&1 | Select-Object -First 1
            Write-OK "$name — $versionOutput"
        } catch {
            Write-OK "$name — found (version check failed)"
        }
    } else {
        if ($failedTools -contains $name) {
            Write-Fail "$name — NOT FOUND (installation failed)"
        } else {
            Write-Warn "$name — not in current PATH (may require shell restart)"
        }
        $allOk = $false
    }
}

Write-Host ""
if ($failedTools.Count -gt 0) {
    Write-Warn "The following tools could not be installed automatically:"
    foreach ($t in $failedTools) {
        Write-Warn "  • $t"
    }
    Write-Host ""
    Write-Warn "Manual installation options:"
    Write-Warn "  • Restart this script with -PackageManager choco after installing Chocolatey"
    Write-Warn "  • Or use Docker Desktop for a container-based approach"
    Write-Host ""
}

if ($allOk) {
    Write-Host "  ✔ All tools installed and verified!" -ForegroundColor Green
    Write-Host "  ✔ You may need to restart your terminal for PATH changes to take effect." -ForegroundColor Green
} else {
    Write-Host "  ⚠ Installation completed with warnings. Check above for details." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Next step: run a quick scan:" -ForegroundColor Cyan
Write-Host "    .\scripts\scan.ps1 -Target . -Mode quick" -ForegroundColor White
Write-Host ""
