#Requires -Version 5.1
<#
.SYNOPSIS
    CyberStrikeAI DevSec — Windows Security Scanner
.DESCRIPTION
    Runs security scans (CVE, OWASP, secrets, supply chain) on a target project
    and generates a Markdown report.
.PARAMETER Target
    Path to the project directory to scan. Default: current directory.
.PARAMETER Mode
    Scan mode:
      quick  — Secrets (gitleaks) + Critical CVEs (grype) only. < 2 min.
      full   — All scanners: grype, trivy, semgrep, gitleaks, osv-scanner.
      cicd   — JSON output; exits with code 1 if Critical findings are found.
    Default: quick
.PARAMETER Output
    Path to the output Markdown report file.
    Default: .\security-reports\report-<timestamp>.md
.PARAMETER Lang
    Project language/type for SAST rule selection:
      auto   — detect from project files
      csharp — C# / .NET
      java   — Java / Maven / Gradle
      react  — React / TypeScript / JavaScript
      cobol  — COBOL
    Default: auto
.EXAMPLE
    .\scan.ps1
.EXAMPLE
    .\scan.ps1 -Target "C:\Projects\MyApp" -Mode full -Lang csharp
.EXAMPLE
    .\scan.ps1 -Target . -Mode cicd -Output ".\reports\scan.md"
#>
[CmdletBinding()]
param(
    [string]$Target  = '.',
    [ValidateSet('quick', 'full', 'cicd')]
    [string]$Mode    = 'quick',
    [string]$Output  = '',
    [ValidateSet('auto', 'csharp', 'java', 'react', 'cobol')]
    [string]$Lang    = 'auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # Don't stop on individual scan failures

# ── Resolve absolute paths ─────────────────────────────────────────────────

$TargetPath = [System.IO.Path]::GetFullPath($Target)
if (-not (Test-Path $TargetPath)) {
    Write-Host "ERROR: Target path not found: $TargetPath" -ForegroundColor Red
    exit 1
}

$Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportDir  = Join-Path $TargetPath 'security-reports'

if ($Output -eq '') {
    $ReportFile = Join-Path $ReportDir "report-$Timestamp.md"
} else {
    $ReportFile = [System.IO.Path]::GetFullPath($Output)
    $ReportDir  = Split-Path $ReportFile -Parent
}

if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

$JsonDir = Join-Path $ReportDir 'json'
if (-not (Test-Path $JsonDir)) {
    New-Item -ItemType Directory -Path $JsonDir -Force | Out-Null
}

# ── Helpers ────────────────────────────────────────────────────────────────

function Write-Banner {
    param([string]$Text)
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
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

function Invoke-ScanTool {
    param(
        [string]$ToolName,
        [string]$Description,
        [scriptblock]$ScriptBlock,
        [int]$StepNumber,
        [int]$TotalSteps
    )
    Write-Progress -Activity "CyberStrikeAI DevSec Scan" `
        -Status "Running $Description" `
        -PercentComplete ([int](($StepNumber / $TotalSteps) * 100))
    Write-Step "$Description..."
    if (-not (Test-CommandExists $ToolName)) {
        Write-Warn "$ToolName not found — skipping. Install with: .\scripts\install.ps1"
        return $false
    }
    try {
        & $ScriptBlock
        Write-OK "$Description completed"
        return $true
    }
    catch {
        Write-Fail "$Description failed: $_"
        return $false
    }
}

# ── Language auto-detection ────────────────────────────────────────────────

if ($Lang -eq 'auto') {
    Write-Step "Auto-detecting project type..."
    if (Get-ChildItem -Path $TargetPath -Filter '*.csproj' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $Lang = 'csharp'
    } elseif (Get-ChildItem -Path $TargetPath -Filter 'pom.xml' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $Lang = 'java'
    } elseif (Get-ChildItem -Path $TargetPath -Filter 'package.json' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $Lang = 'react'
    } elseif (Get-ChildItem -Path $TargetPath -Filter '*.cbl' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1) {
        $Lang = 'cobol'
    } else {
        $Lang = 'auto'  # Keep as auto — use generic rules
    }
    Write-OK "Detected project type: $Lang"
}

# ── Semgrep rule mapping ───────────────────────────────────────────────────

$SemgrepConfigs = switch ($Lang) {
    'csharp' { @('p/owasp-top-ten', 'p/csharp') }
    'java'   { @('p/owasp-top-ten', 'p/java') }
    'react'  { @('p/owasp-top-ten', 'p/javascript', 'p/typescript', 'p/react') }
    'cobol'  { @('p/owasp-top-ten') }
    default  { @('p/owasp-top-ten', 'p/csharp', 'p/java', 'p/javascript', 'p/typescript') }
}
$SemgrepConfigArgs = ($SemgrepConfigs | ForEach-Object { "--config", $_ })

# ── Scan execution ─────────────────────────────────────────────────────────

Write-Banner "CyberStrikeAI DevSec Scan — Mode: $Mode"
Write-Host "  Target : $TargetPath" -ForegroundColor White
Write-Host "  Mode   : $Mode" -ForegroundColor White
Write-Host "  Lang   : $Lang" -ForegroundColor White
Write-Host "  Report : $ReportFile" -ForegroundColor White
Write-Host "  Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

$scanResults = @{}
$criticalCount = 0
$secretCount   = 0
$totalSteps    = if ($Mode -eq 'quick') { 2 } elseif ($Mode -in 'full', 'cicd') { 5 } else { 2 }
$stepNum       = 0

# ── Gitleaks (all modes) ───────────────────────────────────────────────────
$stepNum++
$gitleaksJson = Join-Path $JsonDir 'gitleaks.json'
$ran = Invoke-ScanTool -ToolName 'gitleaks' -Description 'Secret Detection (Gitleaks)' `
    -StepNumber $stepNum -TotalSteps $totalSteps -ScriptBlock {
        & gitleaks detect `
            --source "$TargetPath" `
            --report-format json `
            --report-path "$gitleaksJson" `
            --no-banner `
            --exit-code 0
    }
if ($ran -and (Test-Path $gitleaksJson)) {
    try {
        $gitleaksData = Get-Content $gitleaksJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($gitleaksData -and $gitleaksData.Count -gt 0) {
            $secretCount = $gitleaksData.Count
            Write-Warn "Gitleaks found $secretCount potential secret(s)!"
        } else {
            Write-OK "No secrets detected"
        }
    } catch { }
}
$scanResults['gitleaks'] = @{ ran = $ran; secrets = $secretCount }

# ── Grype CVE (all modes) ──────────────────────────────────────────────────
$stepNum++
$grypeJson = Join-Path $JsonDir 'grype.json'
$ran = Invoke-ScanTool -ToolName 'grype' -Description 'CVE Dependency Scan (Grype)' `
    -StepNumber $stepNum -TotalSteps $totalSteps -ScriptBlock {
        & grype "dir:$TargetPath" `
            --output json `
            --file "$grypeJson" `
            --add-cpes-if-none `
            --quiet
    }
if ($ran -and (Test-Path $grypeJson)) {
    try {
        $grypeData    = Get-Content $grypeJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        $criticalCount = ($grypeData.matches | Where-Object { $_.vulnerability.severity -eq 'Critical' } | Measure-Object).Count
        $highCount     = ($grypeData.matches | Where-Object { $_.vulnerability.severity -eq 'High' }     | Measure-Object).Count
        if ($criticalCount -gt 0) {
            Write-Warn "Grype found $criticalCount Critical and $highCount High CVEs!"
        } else {
            Write-OK "No critical CVEs found ($highCount High)"
        }
    } catch { }
}
$scanResults['grype'] = @{ ran = $ran; critical = $criticalCount }

# ── Full / CI-CD mode only ─────────────────────────────────────────────────
if ($Mode -in 'full', 'cicd') {

    # ── Trivy ──────────────────────────────────────────────────────────────
    $stepNum++
    $trivyJson = Join-Path $JsonDir 'trivy.json'
    $ran = Invoke-ScanTool -ToolName 'trivy' -Description 'Trivy FS Scan' `
        -StepNumber $stepNum -TotalSteps $totalSteps -ScriptBlock {
            & trivy fs "$TargetPath" `
                --format json `
                --output "$trivyJson" `
                --severity HIGH,CRITICAL `
                --quiet
        }
    $scanResults['trivy'] = @{ ran = $ran }

    # ── Semgrep SAST ───────────────────────────────────────────────────────
    $stepNum++
    $semgrepJson = Join-Path $JsonDir 'semgrep.json'
    $ran = Invoke-ScanTool -ToolName 'semgrep' -Description "SAST Scan (Semgrep / $Lang)" `
        -StepNumber $stepNum -TotalSteps $totalSteps -ScriptBlock {
            $semgrepArgs = $SemgrepConfigArgs + @('--json', '--output', $semgrepJson, '--metrics', 'off', $TargetPath)
            & semgrep scan @semgrepArgs
        }
    $scanResults['semgrep'] = @{ ran = $ran }

    # ── OSV-Scanner ────────────────────────────────────────────────────────
    $stepNum++
    $osvJson = Join-Path $JsonDir 'osv.json'
    $ran = Invoke-ScanTool -ToolName 'osv-scanner' -Description 'OSV Dependency Scan' `
        -StepNumber $stepNum -TotalSteps $totalSteps -ScriptBlock {
            & osv-scanner --recursive "$TargetPath" --format json 2>$null |
                Set-Content -Path $osvJson -Encoding UTF8
        }
    $scanResults['osv'] = @{ ran = $ran }
}

Write-Progress -Activity "CyberStrikeAI DevSec Scan" -Completed

# ── Generate Markdown Report ───────────────────────────────────────────────

Write-Banner "Generating Report"

$reportLines = [System.Collections.Generic.List[string]]::new()
$reportLines.Add("# CyberStrikeAI DevSec Security Report")
$reportLines.Add("")
$reportLines.Add("| Field | Value |")
$reportLines.Add("|-------|-------|")
$reportLines.Add("| **Target** | $TargetPath |")
$reportLines.Add("| **Mode** | $Mode |")
$reportLines.Add("| **Language** | $Lang |")
$reportLines.Add("| **Date** | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC |")
$reportLines.Add("| **Platform** | Windows |")
$reportLines.Add("")
$reportLines.Add("---")
$reportLines.Add("")

# Gate summary
$gatePassed = ($criticalCount -eq 0 -and $secretCount -eq 0)
$gateEmoji  = if ($gatePassed) { "✅" } else { "❌" }
$gateLabel  = if ($gatePassed) { "PASSED" } else { "FAILED" }
$reportLines.Add("## Security Gate: $gateEmoji $gateLabel")
$reportLines.Add("")
$reportLines.Add("| Check | Count | Status |")
$reportLines.Add("|-------|-------|--------|")
$reportLines.Add("| Critical CVEs | $criticalCount | $(if ($criticalCount -gt 0) { '❌' } else { '✅' }) |")
$reportLines.Add("| Exposed Secrets | $secretCount | $(if ($secretCount -gt 0) { '❌' } else { '✅' }) |")
$reportLines.Add("")
$reportLines.Add("---")
$reportLines.Add("")

# Per-tool sections
if (Test-Path $gitleaksJson) {
    $reportLines.Add("## Secret Detection — Gitleaks")
    $reportLines.Add("")
    try {
        $data = Get-Content $gitleaksJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($data -and $data.Count -gt 0) {
            $reportLines.Add("⚠️ **$($data.Count) secret(s) found — rotate these credentials immediately!**")
            $reportLines.Add("")
            $reportLines.Add("| Rule | File | Line |")
            $reportLines.Add("|------|------|------|")
            foreach ($leak in $data | Select-Object -First 20) {
                $file  = $leak.File    -replace [regex]::Escape($TargetPath), '.'
                $rule  = $leak.RuleID
                $line  = $leak.StartLine
                $reportLines.Add("| $rule | $file | $line |")
            }
        } else {
            $reportLines.Add("✅ No secrets detected.")
        }
    } catch {
        $reportLines.Add("_Could not parse Gitleaks output._")
    }
    $reportLines.Add("")
    $reportLines.Add("---")
    $reportLines.Add("")
}

if (Test-Path $grypeJson) {
    $reportLines.Add("## CVE Dependency Scan — Grype")
    $reportLines.Add("")
    try {
        $data = Get-Content $grypeJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($data -and $data.matches) {
            $grouped = $data.matches | Group-Object { $_.vulnerability.severity }
            foreach ($g in $grouped | Sort-Object Name) {
                $reportLines.Add("### $($g.Name) ($($g.Count))")
                $reportLines.Add("")
                $reportLines.Add("| CVE | Package | Version | Fix |")
                $reportLines.Add("|-----|---------|---------|-----|")
                foreach ($m in $g.Group | Select-Object -First 25) {
                    $cve     = $m.vulnerability.id
                    $pkg     = $m.artifact.name
                    $ver     = $m.artifact.version
                    $fix     = if ($m.vulnerability.fix.versions) { $m.vulnerability.fix.versions -join ', ' } else { 'N/A' }
                    $reportLines.Add("| $cve | $pkg | $ver | $fix |")
                }
                $reportLines.Add("")
            }
        } else {
            $reportLines.Add("✅ No CVEs found.")
        }
    } catch {
        $reportLines.Add("_Could not parse Grype output._")
    }
    $reportLines.Add("")
    $reportLines.Add("---")
    $reportLines.Add("")
}

if ((Test-Path $semgrepJson) -and $Mode -in 'full', 'cicd') {
    $reportLines.Add("## SAST — Semgrep OWASP Top 10")
    $reportLines.Add("")
    try {
        $data = Get-Content $semgrepJson -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($data -and $data.results -and $data.results.Count -gt 0) {
            $reportLines.Add("Found **$($data.results.Count)** finding(s).")
            $reportLines.Add("")
            $reportLines.Add("| Rule | File | Line | Message |")
            $reportLines.Add("|------|------|------|---------|")
            foreach ($r in $data.results | Select-Object -First 30) {
                $rule = $r.check_id
                $file = $r.path -replace [regex]::Escape($TargetPath), '.'
                $line = $r.start.line
                $msg  = ($r.extra.message -replace '\|', '/' -replace '\r?\n', ' ') | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 80)) }
                $reportLines.Add("| $rule | $file | $line | $msg |")
            }
        } else {
            $reportLines.Add("✅ No SAST findings.")
        }
    } catch {
        $reportLines.Add("_Could not parse Semgrep output._")
    }
    $reportLines.Add("")
    $reportLines.Add("---")
    $reportLines.Add("")
}

$reportLines.Add("## Raw JSON Reports")
$reportLines.Add("")
$reportLines.Add("JSON scan outputs saved to: ``$JsonDir``")
$reportLines.Add("")
foreach ($jsonFile in Get-ChildItem $JsonDir -Filter '*.json' -ErrorAction SilentlyContinue) {
    $reportLines.Add("- ``$($jsonFile.FullName)``")
}
$reportLines.Add("")
$reportLines.Add("---")
$reportLines.Add("_Generated by CyberStrikeAI DevSec | scan.ps1 v1.0_")

# Write report
$reportLines | Set-Content -Path $ReportFile -Encoding UTF8
Write-OK "Report written to: $ReportFile"

# ── Final summary ──────────────────────────────────────────────────────────

Write-Banner "Scan Complete"
Write-Host "  Mode     : $Mode" -ForegroundColor White
Write-Host "  Target   : $TargetPath" -ForegroundColor White
Write-Host "  Report   : $ReportFile" -ForegroundColor White
Write-Host ""

if ($criticalCount -gt 0) {
    Write-Host "  ❌ Critical CVEs   : $criticalCount" -ForegroundColor Red
} else {
    Write-Host "  ✅ Critical CVEs   : 0" -ForegroundColor Green
}
if ($secretCount -gt 0) {
    Write-Host "  ❌ Secrets Found   : $secretCount" -ForegroundColor Red
} else {
    Write-Host "  ✅ Secrets Found   : 0" -ForegroundColor Green
}
Write-Host ""

# CI/CD mode: exit code 1 on critical findings
if ($Mode -eq 'cicd') {
    if ($criticalCount -gt 0 -or $secretCount -gt 0) {
        Write-Host "  ❌ Security gate FAILED — Critical findings detected." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "  ✅ Security gate PASSED." -ForegroundColor Green
        exit 0
    }
}
