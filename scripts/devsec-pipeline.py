#!/usr/bin/env python3
"""
CyberStrikeAI DevSec Pipeline — Main Orchestrator
Usage: python devsec-pipeline.py --target https://app.company.com --level 1|2|3 ...
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich import print as rprint

# ── Dynamic loaders (Option C) ──────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
import shutil
try:
    from tool_loader import ToolLoader, PTESEngine
    from prompt_loader import PromptLoader
    _TOOLS_DIR  = Path(__file__).parent.parent / "tools"
    _AGENTS_DIR = Path(__file__).parent.parent / "agents"
    _SKILLS_DIR = Path(__file__).parent.parent / "skills"
    _ROLES_DIR  = Path(__file__).parent.parent / "roles"
    _tool_loader   = ToolLoader(_TOOLS_DIR) if _TOOLS_DIR.exists() else None
    _prompt_loader = PromptLoader(_AGENTS_DIR, _SKILLS_DIR, _ROLES_DIR) if _AGENTS_DIR.exists() else None
    _LOADERS_AVAILABLE = _tool_loader is not None
except ImportError as _e:
    _LOADERS_AVAILABLE = False
    _tool_loader = None
    _prompt_loader = None
    PTESEngine = None
    print(f"[yellow]⚠  Loaders non disponibles ({_e}) — fallback mode[/yellow]")
console = Console()

# ── Exit codes ────────────────────────────────────────────────────────────────
EXIT_PASS = 0
EXIT_CRITICAL = 1
EXIT_ERROR = 2
EXIT_CONSENT_INVALID = 3


# ── Argument parsing ──────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberStrikeAI DevSec Pipeline — Automated Security Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Level 1 — static analysis only
  python devsec-pipeline.py --target ./my-app --level 1

  # Level 2 — active light scan (requires consent)
  python devsec-pipeline.py \\
    --target https://app.company.com \\
    --level 2 \\
    --consent ./consent-signed.pdf \\
    --notify-email team@company.com

  # Level 3 — full pentest
  python devsec-pipeline.py \\
    --target https://app.company.com \\
    --level 3 \\
    --lang auto \\
    --source-dir ./monprojet \\
    --output ./reports/2024-01-15 \\
    --consent ./consent-signed.pdf \\
    --ai-model claude-sonnet-4-5 \\
    --notify-email team@company.com
""",
    )
    parser.add_argument("--target", required=True, help="Target URL or path to scan")
    parser.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3],
        required=True,
        help="Scan level: 1=static, 2=active light, 3=full pentest",
    )
    parser.add_argument(
        "--lang",
        default="auto",
        choices=["csharp", "java", "react", "cobol", "auto"],
        help="Source language (default: auto-detect)",
    )
    parser.add_argument("--source-dir", default=None, help="Path to source code directory")
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for reports (default: ./reports/<timestamp>)",
    )
    parser.add_argument("--consent", default=None, help="Path to signed consent PDF (required for level 2+)")
    parser.add_argument("--ai-model", default="claude-sonnet-4-5", help="AI model for analysis (default: claude-sonnet-4-5)")
    parser.add_argument("--ai", action="store_true", help="Enable AI-powered analysis (requires config.yaml or GITHUB_COPILOT_TOKEN env var)")
    parser.add_argument("--ai-config", default=None, type=Path, help="Path to config.yaml for AI provider (auto-detected if absent)")
    parser.add_argument("--notify-email", default=None, help="Email address for report notification")
    parser.add_argument("--operator", default=os.getenv("USER", "unknown"), help="Operator name for audit trail")
    parser.add_argument("--dry-run", action="store_true", help="Parse and validate without running scans")
    return parser.parse_args()


# ── Consent verification ──────────────────────────────────────────────────────

def verify_consent(consent_path: str | None, level: int) -> tuple[bool, str]:
    """Delegate to verify-consent.py and return (ok, consent_id)."""
    if consent_path is None:
        return False, ""

    consent_file = Path(consent_path)
    if not consent_file.exists():
        console.log(f"[red]❌ Consent file not found: {consent_path}[/red]")
        return False, ""

    verify_script = Path(__file__).parent / "consent" / "verify-consent.py"
    if not verify_script.exists():
        # Fallback: basic existence check
        console.log(f"[yellow]⚠  verify-consent.py not found — using basic check[/yellow]")
        import hashlib
        consent_id = hashlib.sha256(consent_file.read_bytes()).hexdigest()[:12]
        console.log(f"[green]✅ Consent document accepted (id={consent_id})[/green]")
        return True, consent_id

    result = subprocess.run(
        [sys.executable, str(verify_script), "--consent", consent_path],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        consent_id = result.stdout.strip().splitlines()[-1]  # Last line = consent_id
        console.log(f"[green]✅ Consent verified (id={consent_id})[/green]")
        return True, consent_id
    else:
        console.log(f"[red]❌ Consent verification failed:[/red] {result.stderr.strip()}")
        return False, ""


# ── Scan commands per level ───────────────────────────────────────────────────

def get_scan_commands(args: argparse.Namespace, output_dir: Path) -> list[dict[str, Any]]:
    """Return list of scan command definitions for the given level.
    
    Delègue à ToolLoader.build_scan_commands() si disponible (Option C),
    sinon fallback vers les commandes hardcodées.
    """
    source = args.source_dir or args.target

    if _LOADERS_AVAILABLE:
        tools_dir = Path(__file__).parent.parent / "tools"
        loader = ToolLoader(tools_dir=tools_dir)
        return loader.build_scan_commands(
            level=args.level,
            target=args.target,
            output_dir=output_dir,
            source=source,
        )

    # ── Fallback hardcodé (si tool_loader non disponible) ──────────────────
    console.log("[yellow]⚠  ToolLoader indisponible — utilisation des commandes hardcodées[/yellow]")
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    target = args.target
    scans: list[dict[str, Any]] = []

    if args.level >= 1:
        scans += [
            {
                "name": "grype-cve",
                "description": "CVE scan (Grype)",
                "cmd": [
                    "grype",
                    f"dir:{source}" if Path(source).exists() else source,
                    "--output", "json",
                    "--file", str(raw_dir / "grype-results.json"),
                    "--severity", "HIGH",
                ],
                "output_file": raw_dir / "grype-results.json",
            },
            {
                "name": "semgrep-sast",
                "description": "SAST analysis (Semgrep)",
                "cmd": [
                    "semgrep", "scan",
                    "--config", "auto",
                    "--json",
                    "--output", str(raw_dir / "semgrep-results.json"),
                    source if Path(source).exists() else ".",
                ],
                "output_file": raw_dir / "semgrep-results.json",
            },
            {
                "name": "gitleaks-secrets",
                "description": "Secret detection (Gitleaks)",
                "cmd": [
                    "gitleaks", "detect",
                    "--source", source if Path(source).exists() else ".",
                    "--report-format", "json",
                    "--report-path", str(raw_dir / "gitleaks-results.json"),
                    "--no-git",
                ],
                "output_file": raw_dir / "gitleaks-results.json",
            },
        ]
    if args.level >= 2:
        scans += [
            {
                "name": "nmap-portscan",
                "description": "Port scan (nmap)",
                "cmd": ["nmap", "-sV", "-sC", "-oX", str(raw_dir / "nmap-results.xml"), target],
                "output_file": raw_dir / "nmap-results.xml",
            },
            {
                "name": "nuclei-web",
                "description": "Web vulnerability scan (Nuclei)",
                "cmd": ["nuclei", "-u", target, "-j", "-o", str(raw_dir / "nuclei-results.json"), "-severity", "medium,high,critical"],
                "output_file": raw_dir / "nuclei-results.json",
            },
        ]
    if args.level >= 3:
        scans += [
            {
                "name": "zaproxy-active",
                "description": "Active web app scan (OWASP ZAP)",
                "cmd": ["zap-baseline.py", "-t", target, "-J", str(raw_dir / "zap-results.json"), "-l", "WARN"],
                "output_file": raw_dir / "zap-results.json",
            },
        ]
    return scans


# ── Async scan runner ─────────────────────────────────────────────────────────

async def run_scan(
    scan: dict[str, Any],
    progress: Progress,
    overall_task: Any,
    findings_collector: list[dict],
) -> dict[str, Any]:
    """Run a single scan subprocess asynchronously."""
    task_id = progress.add_task(f"[cyan]{scan['description']}[/cyan]", total=None)

    result: dict[str, Any] = {
        "name": scan["name"],
        "description": scan["description"],
        "status": "unknown",
        "returncode": -1,
        "output_file": str(scan.get("output_file", "")),
        "findings": [],
        "error": "",
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            *scan["cmd"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result["returncode"] = proc.returncode
        result["stdout"] = stdout.decode(errors="replace")
        result["stderr"] = stderr.decode(errors="replace")

        # Try to parse output file for findings
        output_file = Path(scan.get("output_file", ""))
        if output_file.exists() and output_file.suffix == ".json":
            try:
                data = json.loads(output_file.read_text())
                result["findings"] = _extract_findings(scan["name"], data)
                findings_collector.extend(result["findings"])
                if result["findings"]:
                    console.log(
                        f"[yellow]⚡ {scan['name']}[/yellow] — {len(result['findings'])} finding(s)"
                    )
            except json.JSONDecodeError:
                pass

        result["status"] = "success" if proc.returncode in (0, 1) else "error"

    except FileNotFoundError:
        result["status"] = "skipped"
        result["error"] = f"Tool not found: {scan['cmd'][0]}"
        console.log(f"[dim]⏭  {scan['description']} — tool not available, skipped[/dim]")
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        console.log(f"[red]❌ {scan['description']} failed: {exc}[/red]")
    finally:
        progress.update(task_id, completed=1, total=1)
        progress.advance(overall_task)

    return result


def _extract_findings(tool: str, data: Any) -> list[dict]:
    """Extract normalized findings from raw JSON output."""
    findings: list[dict] = []
    try:
        if tool == "grype-cve" and isinstance(data, dict):
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                findings.append({
                    "tool": tool,
                    "id": vuln.get("id", ""),
                    "severity": vuln.get("severity", "unknown"),
                    "description": vuln.get("description", ""),
                    "package": match.get("artifact", {}).get("name", ""),
                })
        elif tool == "semgrep-sast" and isinstance(data, dict):
            for r in data.get("results", []):
                findings.append({
                    "tool": tool,
                    "id": r.get("check_id", ""),
                    "severity": r.get("extra", {}).get("severity", "unknown"),
                    "description": r.get("extra", {}).get("message", ""),
                    "file": r.get("path", ""),
                    "line": r.get("start", {}).get("line"),
                })
        elif tool == "nuclei-web":
            items = data if isinstance(data, list) else []
            for item in items:
                findings.append({
                    "tool": tool,
                    "id": item.get("template-id", ""),
                    "severity": item.get("info", {}).get("severity", "unknown"),
                    "description": item.get("info", {}).get("name", ""),
                    "matched": item.get("matched-at", ""),
                })
        elif tool == "gitleaks-secrets" and isinstance(data, list):
            for secret in data:
                findings.append({
                    "tool": tool,
                    "id": secret.get("RuleID", ""),
                    "severity": "critical",
                    "description": secret.get("Description", ""),
                    "file": secret.get("File", ""),
                    "line": secret.get("StartLine"),
                })
    except Exception:
        pass
    return findings


# ── Score calculation ─────────────────────────────────────────────────────────

def calculate_score(all_findings: list[dict]) -> tuple[int, str]:
    """Return (score 0-100, grade)."""
    weights = {"critical": 20, "high": 10, "medium": 5, "low": 1, "info": 0}
    penalty = sum(weights.get(f.get("severity", "").lower(), 0) for f in all_findings)
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


# ── Report generation ─────────────────────────────────────────────────────────

def generate_report(
    args: argparse.Namespace,
    output_dir: Path,
    scan_results: list[dict],
    all_findings: list[dict],
    score: int,
    grade: str,
    consent_id: str,
    ai_section: str = "",
) -> Path:
    """Call generate-report.py or write basic JSON summary."""
    report_script = Path(__file__).parent / "generate-report.py"
    summary_data = {
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "target": args.target,
        "level": args.level,
        "operator": args.operator,
        "consent_id": consent_id,
        "ai_model": args.ai_model,
        "score": score,
        "grade": grade,
        "scan_results": scan_results,
        "total_findings": len(all_findings),
        "findings_by_severity": {
            sev: len([f for f in all_findings if f.get("severity", "").lower() == sev])
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "findings": all_findings,
    }

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary_data, indent=2))

    if report_script.exists():
        raw_dir = output_dir / "raw"
        html_path = output_dir / "report.html"
        pdf_path  = output_dir / "report.pdf"
        md_path   = output_dir / "report.md"

        # Step 1 — Markdown
        subprocess.run(
            [
                sys.executable, str(report_script),
                "--results-dir", str(raw_dir if raw_dir.exists() else output_dir),
                "--output", str(md_path),
                "--level", str(args.level),
                "--format", "md",
            ],
            check=False,
        )

        # Step 2 — HTML
        subprocess.run(
            [
                sys.executable, str(report_script),
                "--results-dir", str(raw_dir if raw_dir.exists() else output_dir),
                "--output", str(html_path),
                "--level", str(args.level),
                "--format", "html",
            ],
            check=False,
        )

        # Step 3 — PDF (weasyprint via HTML intermediate)
        subprocess.run(
            [
                sys.executable, str(report_script),
                "--results-dir", str(raw_dir if raw_dir.exists() else output_dir),
                "--output", str(pdf_path),
                "--level", str(args.level),
                "--format", "pdf",
            ],
            check=False,
        )

        if pdf_path.exists():
            console.log(f"[green]✅ PDF report generated → {pdf_path}[/green]")
        if html_path.exists():
            console.log(f"[green]✅ HTML report generated → {html_path}[/green]")
        if md_path.exists():
            console.log(f"[green]✅ Markdown report generated → {md_path}[/green]")

        # Injecter la section IA dans le rapport Markdown, puis regénérer PDF
        if ai_section and md_path.exists():
            md_content = md_path.read_text()
            md_path.write_text(md_content + "\n" + ai_section)
            console.log("[magenta]🤖 Section IA injectée dans le rapport[/magenta]")
            # Regénérer PDF avec la section IA
            subprocess.run(
                [
                    sys.executable, str(report_script),
                    "--results-dir", str(raw_dir if raw_dir.exists() else output_dir),
                    "--output", str(pdf_path),
                    "--level", str(args.level),
                    "--format", "pdf",
                ],
                check=False,
            )
            console.log(f"[green]✅ PDF final (avec analyse IA) → {pdf_path}[/green]")

        # Return PDF as primary deliverable (fallback to summary.json)
        return pdf_path if pdf_path.exists() else summary_path
    else:
        console.log(f"[dim]ℹ  generate-report.py not found — JSON summary written to {summary_path}[/dim]")

    return summary_path


# ── Audit trail ───────────────────────────────────────────────────────────────

def record_audit(
    action: str,
    target: str,
    tool: str,
    operator: str,
    consent_id: str,
    result_summary: str,
) -> None:
    """Append entry to audit trail via audit-trail.py if available."""
    audit_script = Path(__file__).parent / "audit-trail.py"
    if audit_script.exists():
        subprocess.run(
            [
                sys.executable,
                str(audit_script),
                "append",
                "--action", action,
                "--target", target,
                "--tool", tool,
                "--operator", operator,
                "--consent-id", consent_id,
                "--result", result_summary,
            ],
            check=False,
        )


# ── Notification ──────────────────────────────────────────────────────────────

def send_notification(args: argparse.Namespace, report_path: Path, all_findings: list[dict]) -> None:
    """Send email notification if notify-email is set."""
    notify_script = Path(__file__).parent / "notify.py"
    if not notify_script.exists():
        console.log("[dim]⚠  notify.py not found — skipping notification[/dim]")
        return

    findings_json = report_path.parent / "findings.json"
    findings_json.write_text(json.dumps(all_findings, indent=2))

    subprocess.run(
        [
            sys.executable,
            str(notify_script),
            "--channel", "email",
            "--findings-json", str(findings_json),
            "--report-pdf", str(report_path),
            "--recipient", args.notify_email,
        ],
        check=False,
    )
    console.log(f"[green]📧 Notification sent to {args.notify_email}[/green]")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main() -> int:
    args = parse_args()

    # Banner
    console.rule("[bold cyan]🔐 CyberStrikeAI DevSec Pipeline[/bold cyan]")
    console.print(f"  [bold]Target:[/bold]   {args.target}")
    console.print(f"  [bold]Level:[/bold]    {args.level}")
    console.print(f"  [bold]Operator:[/bold] {args.operator}")
    console.print(f"  [bold]Model:[/bold]    {args.ai_model}")
    console.print()

    # ── Consent verification (level 2+) ──────────────────────────────────────
    consent_id = ""
    if args.level >= 2:
        console.rule("[yellow]Step 1: Consent Verification[/yellow]")
        if not args.consent:
            console.print("[red]❌ --consent is required for level 2 and above.[/red]")
            return EXIT_CONSENT_INVALID

        ok, consent_id = verify_consent(args.consent, args.level)
        if not ok:
            console.print("[red]❌ Consent verification failed. Aborting.[/red]")
            return EXIT_CONSENT_INVALID

    # ── Level 3 double-verification + scope confirmation ──────────────────────
    if args.level == 3:
        console.rule("[bold red]Step 2: Level 3 — Full Pentest Confirmation[/bold red]")
        console.print(Panel(
            f"[bold yellow]⚠  WARNING: FULL PENTEST MODE[/bold yellow]\n\n"
            f"Target  : [cyan]{args.target}[/cyan]\n"
            f"Consent : [cyan]{args.consent}[/cyan] (id={consent_id})\n"
            f"Operator: [cyan]{args.operator}[/cyan]\n\n"
            "[red]This will perform active exploitation attempts, port scans, "
            "web fuzzing, and intrusive tests.[/red]\n\n"
            "Type [bold]CONFIRM[/bold] to proceed:",
            title="Level 3 Authorization Required",
            border_style="red",
        ))
        if not args.dry_run:
            confirmation = input("> ").strip()
            if confirmation != "CONFIRM":
                console.print("[red]❌ Confirmation not received. Aborting.[/red]")
                return EXIT_CONSENT_INVALID
        else:
            console.print("[dim](dry-run: skipping confirmation)[/dim]")

    # ── Output directory ──────────────────────────────────────────────────────
    if args.output:
        output_dir = Path(args.output)
    else:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_dir = Path("./reports") / f"level{args.level}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[dim]📁 Output directory: {output_dir}[/dim]\n")

    # ── Dry run exit ──────────────────────────────────────────────────────────
    if args.dry_run:
        scans = get_scan_commands(args, output_dir)
        console.print(f"[green]✅ Dry run complete. {len(scans)} scan(s) would be executed.[/green]")
        for s in scans:
            console.print(f"   • {s['description']}: [dim]{' '.join(s['cmd'][:3])}…[/dim]")
        return EXIT_PASS

    # ── Record audit trail start ──────────────────────────────────────────────
    record_audit("pipeline_start", args.target, "devsec-pipeline", args.operator, consent_id, f"level={args.level}")

    # ── Run scans in parallel ─────────────────────────────────────────────────
    console.rule(f"[cyan]Step {'3' if args.level == 3 else '2'}: Running Scans (Level {args.level}) — Phase 1[/cyan]")

    scans = get_scan_commands(args, output_dir)
    all_findings: list[dict] = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False,
    )

    with progress:
        overall_task = progress.add_task("[bold green]Overall progress", total=len(scans))
        tasks = [
            run_scan(scan, progress, overall_task, all_findings)
            for scan in scans
        ]
        scan_results = await asyncio.gather(*tasks)

    scan_results_list = list(scan_results)

    # ── Moteur PTES (phases 2→7) pour Level 2+ ──────────────────────────────────
    if args.level >= 2:
        console.rule("[bold cyan]Moteur PTES — Phases 2 à 6[/bold cyan]")
        try:
            if PTESEngine is None or _tool_loader is None:
                raise ImportError("PTESEngine ou ToolLoader non disponible")

            raw_dir = output_dir / "raw"
            ptes = PTESEngine(
                tool_loader=_tool_loader,
                raw_dir=raw_dir,
                target=args.target,
                level=args.level,
            )

            def run_ptes_scan(scan: dict, timeout: int = 120) -> None:
                """Callback PTES — exécute un scan et logue le résultat."""
                try:
                    cmd = [str(x) for x in scan["cmd"]]
                    if not shutil.which(cmd[0]):
                        console.log(f"[dim]⏭  {scan['description']} — outil absent[/dim]")
                        return
                    out_file = scan.get("output_file")
                    # Rediriger stdout vers out_file si l'outil ne gère pas lui-même le fichier
                    if out_file and not any(str(out_file) in str(c) for c in cmd):
                        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
                        if result.stdout:
                            Path(out_file).write_bytes(result.stdout)
                    else:
                        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
                    # Vérifier si une sortie a été produite
                    produced = out_file and Path(out_file).exists() and Path(out_file).stat().st_size > 0
                    if produced:
                        console.log(f"[green]✅ {scan['description']}[/green]")
                    elif result.returncode == 0:
                        console.log(f"[dim]✅ {scan['description']} (pas de finding)[/dim]")
                    else:
                        console.log(f"[yellow]⚠️  {scan['description']} (code {result.returncode})[/yellow]")
                except subprocess.TimeoutExpired:
                    console.log(f"[yellow]⏱  {scan['description']} — timeout ({timeout}s)[/yellow]")
                except Exception as e:
                    console.log(f"[red]❌ {scan['description']} — {e}[/red]")

            ptes_result = ptes.run(run_ptes_scan)

            # Intégrer les résultats PTES dans scan_results_list
            ptes_scans = ptes_result.get("scans", [])
            for s in ptes_scans:
                scan_results_list.append({
                    "name": s.get("name",""),
                    "description": s.get("description",""),
                    "status": "success",
                    "ptes": True,
                })

            # Sauvegarder le contexte PTES pour le rapport
            ptes_ctx_file = output_dir / "ptes_context.json"
            ptes_ctx_file.write_text(json.dumps(ptes_result.get("ptes_context", {}), indent=2, default=str))
            console.log(f"[green]✅ Moteur PTES terminé — {len(ptes_scans)} scan(s), "
                       f"{len(ptes.ctx.open_ports)} ports, "
                       f"{len(ptes.ctx.http_endpoints)} endpoints[/green]")

        except ImportError as e:
            console.log(f"[yellow]⚠️  PTESEngine non disponible: {e}[/yellow]")
        except Exception as e:
            console.log(f"[yellow]⚠️  Moteur PTES ignoré: {e}[/yellow]")

    # ── Analyse IA (optionnelle) ──────────────────────────────────────────────
    ai_section = ""
    if getattr(args, 'ai', False):
        console.rule("[bold magenta]🤖 AI Analysis[/bold magenta]")
        try:
            ai_script = Path(__file__).parent / "ai_analyzer.py"
            if ai_script.exists():
                sys.path.insert(0, str(Path(__file__).parent))
                import ai_analyzer
                cfg = ai_analyzer.load_config(getattr(args, 'ai_config', None))
                cfg["model"] = args.ai_model
                console.log(f"[magenta]🤖 Modèle : {cfg['model']} | Provider : {cfg['base_url']}[/magenta]")
                ai_result = ai_analyzer.analyze(
                    findings=all_findings,
                    target=args.target,
                    level=args.level,
                    cfg=cfg,
                    verbose=True,
                )
                ai_section = ai_analyzer.format_ai_section(ai_result)
                ai_out = output_dir / "ai_analysis.md"
                ai_out.write_text(ai_section)
                console.log(f"[green]✅ Analyse IA → {ai_out}[/green]")
            else:
                console.log("[yellow]⚠️  ai_analyzer.py introuvable[/yellow]")
        except Exception as exc:
            console.log(f"[red]❌ Analyse IA échouée : {exc}[/red]")
    else:
        console.log("[dim]ℹ  Mode sans IA — ajoutez --ai pour activer l'analyse GitHub Copilot[/dim]")

    # ── Generate report ───────────────────────────────────────────────────────
    console.rule("[cyan]Report Generation[/cyan]")
    score, grade = calculate_score(all_findings)
    report_path = generate_report(args, output_dir, scan_results_list, all_findings, score, grade, consent_id, ai_section=ai_section)

    # ── Send notification ─────────────────────────────────────────────────────
    if args.notify_email:
        console.rule("[cyan]Notification[/cyan]")
        send_notification(args, report_path, all_findings)

    # ── Record audit trail end ────────────────────────────────────────────────
    critical_count = len([f for f in all_findings if f.get("severity", "").lower() == "critical"])
    record_audit(
        "pipeline_complete",
        args.target,
        "devsec-pipeline",
        args.operator,
        consent_id,
        f"score={score} grade={grade} findings={len(all_findings)} critical={critical_count}",
    )

    # ── Final summary ─────────────────────────────────────────────────────────
    console.rule("[bold]Final Summary[/bold]")
    table = Table(title="Security Score", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Target", args.target)
    table.add_row("Level", str(args.level))
    table.add_row("Score", f"[{'green' if score >= 75 else 'yellow' if score >= 50 else 'red'}]{score}/100 ({grade})[/]")
    table.add_row("Total Findings", str(len(all_findings)))
    table.add_row("Critical", f"[red]{critical_count}[/red]")
    table.add_row(
        "High",
        str(len([f for f in all_findings if f.get("severity", "").lower() == "high"])),
    )
    table.add_row("Report", str(report_path))
    console.print(table)

    # ── Exit code ─────────────────────────────────────────────────────────────
    if critical_count > 0:
        console.print("\n[red bold]⚠  Critical findings detected — exit code 1[/red bold]")
        return EXIT_CRITICAL

    console.print("\n[green bold]✅ Pipeline complete — no critical findings[/green bold]")
    return EXIT_PASS


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠  Interrupted by user[/yellow]")
        sys.exit(EXIT_ERROR)
    except Exception as exc:
        console.print(f"\n[red]❌ Fatal error: {exc}[/red]")
        sys.exit(EXIT_ERROR)
