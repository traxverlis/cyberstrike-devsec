@echo off
REM ============================================================
REM  CyberStrikeAI DevSec — Windows CMD Makefile equivalent
REM  Usage: make.bat <target> [TARGET=<path>] [OUTPUT=<path>]
REM
REM  Targets:
REM    install          Install all security tools (requires Admin)
REM    verify           Verify all tools are installed and in PATH
REM    scan-cve         Run CVE scan only (quick mode, Grype)
REM    scan-secrets     Run secret detection only (Gitleaks)
REM    scan-owasp       Run OWASP SAST scan (Semgrep)
REM    scan-quick       Quick scan: secrets + critical CVEs (< 2 min)
REM    scan-full        Full scan: all tools
REM    scan-cicd        CI/CD scan: JSON output, exit 1 on Critical
REM    report           Full scan + generate Markdown report
REM    help             Show this help message
REM
REM  Examples:
REM    make.bat install
REM    make.bat scan-cve TARGET=.\myproject
REM    make.bat scan-full TARGET=.\myproject
REM    make.bat report TARGET=.\myproject OUTPUT=.\report.md
REM    make.bat scan-cicd TARGET=.\myproject
REM ============================================================

setlocal EnableDelayedExpansion

REM Defaults
set "SCRIPT_DIR=%~dp0"
set "TARGET=."
set "OUTPUT="
set "LANG=auto"

REM Parse named arguments (KEY=VALUE pairs after the target)
:parse_args
if "%~2"=="" goto done_parse
set "arg=%~2"
for /f "tokens=1,2 delims==" %%a in ("%arg%") do (
    if /i "%%a"=="TARGET" set "TARGET=%%b"
    if /i "%%a"=="OUTPUT" set "OUTPUT=%%b"
    if /i "%%a"=="LANG"   set "LANG=%%b"
)
shift /2
goto parse_args
:done_parse

REM Resolve powershell executable (prefer pwsh / PowerShell 7)
set "PS_EXE=powershell"
where pwsh >nul 2>&1
if %errorlevel%==0 set "PS_EXE=pwsh"

set "PS_FLAGS=-ExecutionPolicy Bypass -NoProfile -NonInteractive"
set "INSTALL_SCRIPT=%SCRIPT_DIR%install.ps1"
set "SCAN_SCRIPT=%SCRIPT_DIR%scan.ps1"

REM ── Dispatch target ───────────────────────────────────────────────────────

if /i "%~1"=="install"      goto target_install
if /i "%~1"=="verify"       goto target_verify
if /i "%~1"=="scan-cve"     goto target_scan_cve
if /i "%~1"=="scan-secrets" goto target_scan_secrets
if /i "%~1"=="scan-owasp"   goto target_scan_owasp
if /i "%~1"=="scan-quick"   goto target_scan_quick
if /i "%~1"=="scan-full"    goto target_scan_full
if /i "%~1"=="scan-cicd"    goto target_scan_cicd
if /i "%~1"=="report"       goto target_report
if /i "%~1"=="help"         goto target_help
if "%~1"==""                goto target_help

echo [ERROR] Unknown target: %~1
echo Run  make.bat help  for available targets.
exit /b 1

REM ── install ───────────────────────────────────────────────────────────────
:target_install
echo [CyberStrikeAI DevSec] Installing tools...
%PS_EXE% %PS_FLAGS% -File "%INSTALL_SCRIPT%"
if %errorlevel% neq 0 (
    echo [ERROR] Installation failed with exit code %errorlevel%
    exit /b %errorlevel%
)
echo [OK] Installation complete.
exit /b 0

REM ── verify ────────────────────────────────────────────────────────────────
:target_verify
echo [CyberStrikeAI DevSec] Verifying installed tools...
%PS_EXE% %PS_FLAGS% -Command ^
    "$tools = @('grype','trivy','semgrep','gitleaks','syft','osv-scanner','trufflehog'); $ok=$true; foreach ($t in $tools) { if (Get-Command $t -ErrorAction SilentlyContinue) { Write-Host \"  [OK] $t\" -ForegroundColor Green } else { Write-Host \"  [MISSING] $t\" -ForegroundColor Red; $ok=$false } }; if ($ok) { Write-Host '' ; Write-Host '  All tools found.' -ForegroundColor Green } else { Write-Host '' ; Write-Host '  Some tools are missing. Run: make.bat install' -ForegroundColor Yellow }"
exit /b 0

REM ── scan-cve ──────────────────────────────────────────────────────────────
:target_scan_cve
echo [CyberStrikeAI DevSec] Running CVE scan on: %TARGET%
if "%OUTPUT%"=="" (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode quick -Lang %LANG%
) else (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode quick -Output "%OUTPUT%" -Lang %LANG%
)
exit /b %errorlevel%

REM ── scan-secrets ──────────────────────────────────────────────────────────
:target_scan_secrets
echo [CyberStrikeAI DevSec] Running secret detection on: %TARGET%
%PS_EXE% %PS_FLAGS% -Command ^
    "if (-not (Get-Command 'gitleaks' -ErrorAction SilentlyContinue)) { Write-Host 'gitleaks not found. Run: make.bat install' -ForegroundColor Red; exit 1 }; $reportDir = Join-Path '%TARGET%' 'security-reports'; New-Item -ItemType Directory -Path $reportDir -Force | Out-Null; $out = Join-Path $reportDir 'gitleaks.json'; gitleaks detect --source '%TARGET%' --report-format json --report-path $out --no-banner --exit-code 0; Write-Host 'Secrets report: ' $out -ForegroundColor Cyan"
exit /b %errorlevel%

REM ── scan-owasp ────────────────────────────────────────────────────────────
:target_scan_owasp
echo [CyberStrikeAI DevSec] Running OWASP SAST scan on: %TARGET%
%PS_EXE% %PS_FLAGS% -Command ^
    "if (-not (Get-Command 'semgrep' -ErrorAction SilentlyContinue)) { Write-Host 'semgrep not found. Run: make.bat install' -ForegroundColor Red; exit 1 }; $reportDir = Join-Path '%TARGET%' 'security-reports'; New-Item -ItemType Directory -Path $reportDir -Force | Out-Null; $out = Join-Path $reportDir 'semgrep.json'; semgrep scan --config 'p/owasp-top-ten' --config 'p/csharp' --config 'p/java' --config 'p/javascript' --json --output $out --metrics off '%TARGET%'; Write-Host 'SAST report: ' $out -ForegroundColor Cyan"
exit /b %errorlevel%

REM ── scan-quick ────────────────────────────────────────────────────────────
:target_scan_quick
echo [CyberStrikeAI DevSec] Running quick scan on: %TARGET%
if "%OUTPUT%"=="" (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode quick -Lang %LANG%
) else (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode quick -Output "%OUTPUT%" -Lang %LANG%
)
exit /b %errorlevel%

REM ── scan-full ─────────────────────────────────────────────────────────────
:target_scan_full
echo [CyberStrikeAI DevSec] Running full scan on: %TARGET%
if "%OUTPUT%"=="" (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode full -Lang %LANG%
) else (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode full -Output "%OUTPUT%" -Lang %LANG%
)
exit /b %errorlevel%

REM ── scan-cicd ─────────────────────────────────────────────────────────────
:target_scan_cicd
echo [CyberStrikeAI DevSec] Running CI/CD scan on: %TARGET%
if "%OUTPUT%"=="" (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode cicd -Lang %LANG%
) else (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode cicd -Output "%OUTPUT%" -Lang %LANG%
)
exit /b %errorlevel%

REM ── report ────────────────────────────────────────────────────────────────
:target_report
echo [CyberStrikeAI DevSec] Running full scan + report on: %TARGET%
if "%OUTPUT%"=="" (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode full -Lang %LANG%
) else (
    %PS_EXE% %PS_FLAGS% -File "%SCAN_SCRIPT%" -Target "%TARGET%" -Mode full -Output "%OUTPUT%" -Lang %LANG%
)
exit /b %errorlevel%

REM ── help ─────────────────────────────────────────────────────────────────
:target_help
echo.
echo  CyberStrikeAI DevSec — Windows make.bat
echo  =========================================
echo.
echo  Usage: make.bat ^<target^> [TARGET=^<path^>] [OUTPUT=^<path^>] [LANG=^<lang^>]
echo.
echo  Targets:
echo    install          Install all security tools (run as Administrator)
echo    verify           Check all tools are in PATH
echo    scan-cve         Quick CVE scan (Grype, ^< 2 min)
echo    scan-secrets     Secret detection only (Gitleaks)
echo    scan-owasp       OWASP SAST scan (Semgrep)
echo    scan-quick       Quick scan: secrets + critical CVEs
echo    scan-full        Full scan: Grype + Trivy + Semgrep + Gitleaks + OSV
echo    scan-cicd        CI/CD mode: exit code 1 on Critical findings
echo    report           Full scan with Markdown report
echo    help             Show this message
echo.
echo  Options:
echo    TARGET=^<path^>    Project directory to scan (default: .)
echo    OUTPUT=^<path^>    Output report file (default: auto-generated)
echo    LANG=^<lang^>      Language hint: auto^|csharp^|java^|react^|cobol
echo.
echo  Examples:
echo    make.bat install
echo    make.bat scan-cve TARGET=.\myproject
echo    make.bat scan-owasp TARGET=.\myproject LANG=csharp
echo    make.bat scan-full TARGET=.\myproject
echo    make.bat report TARGET=.\myproject OUTPUT=.\report.md
echo    make.bat scan-cicd TARGET=.\myproject
echo.
exit /b 0
