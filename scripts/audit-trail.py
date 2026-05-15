#!/usr/bin/env python3
"""
CyberStrikeAI DevSec — Audit Trail System
Immutable append-only log with chained integrity hashes.

Usage:
  python audit-trail.py append --action scan_start --target https://app.com ...
  python audit-trail.py verify [--date 2024-01-15]
  python audit-trail.py list [--date 2024-01-15] [--tail N]
  python audit-trail.py export-pdf --output audit.pdf [--date 2024-01-15]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()

AUDIT_BASE_DIR = Path(os.path.expanduser("~/.devsec/audit"))


# ── Entry model ───────────────────────────────────────────────────────────────

def make_entry(
    action: str,
    target: str,
    tool: str,
    operator: str,
    consent_id: str,
    result_summary: str,
    prev_hash: str = "",
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "action": action,
        "target": target,
        "tool": tool,
        "operator": operator,
        "consent_id": consent_id,
        "result": result_summary,
        "prev_hash": prev_hash,
        "hash": "",  # filled below
    }
    entry["hash"] = _hash_entry(entry)
    return entry


def _hash_entry(entry: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON (excluding the 'hash' field itself)."""
    data = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(data, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ── File helpers ──────────────────────────────────────────────────────────────

def _log_path(log_date: date | None = None) -> Path:
    d = log_date or date.today()
    AUDIT_BASE_DIR.mkdir(parents=True, exist_ok=True)
    return AUDIT_BASE_DIR / f"{d.isoformat()}.jsonl"


def _read_entries(log_date: date | None = None) -> list[dict[str, Any]]:
    path = _log_path(log_date)
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                console.log(f"[yellow]⚠  Malformed line in {path.name}[/yellow]")
    return entries


def _last_hash(log_date: date | None = None) -> str:
    entries = _read_entries(log_date)
    return entries[-1]["hash"] if entries else ""


def _append_entry(entry: dict[str, Any], log_date: date | None = None) -> None:
    path = _log_path(log_date)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_append(args: argparse.Namespace) -> int:
    prev_hash = _last_hash()
    entry = make_entry(
        action=args.action,
        target=args.target,
        tool=args.tool,
        operator=args.operator,
        consent_id=args.consent_id or "",
        result_summary=args.result or "",
        prev_hash=prev_hash,
    )
    _append_entry(entry)
    console.print(
        f"[green]✅ Audit entry recorded[/green] "
        f"[dim]{entry['timestamp']} | {entry['action']} | {entry['hash'][:12]}…[/dim]"
    )
    # Print consent_id on last line for pipeline to pick up
    print(entry["hash"][:12])
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify integrity of audit log using chained hashes."""
    log_date = date.fromisoformat(args.date) if args.date else None
    entries = _read_entries(log_date)

    if not entries:
        console.print("[yellow]No audit entries found for this date.[/yellow]")
        return 0

    errors = 0
    prev_hash = ""
    for i, entry in enumerate(entries):
        expected_hash = _hash_entry(entry)
        stored_hash = entry.get("hash", "")

        # 1. Hash integrity
        if stored_hash != expected_hash:
            console.print(f"[red]❌ Entry #{i} hash mismatch![/red]")
            console.print(f"   Expected : {expected_hash}")
            console.print(f"   Stored   : {stored_hash}")
            errors += 1

        # 2. Chain integrity
        if i > 0 and entry.get("prev_hash") != prev_hash:
            console.print(f"[red]❌ Entry #{i} chain broken![/red]")
            console.print(f"   Expected prev_hash : {prev_hash}")
            console.print(f"   Stored   prev_hash : {entry.get('prev_hash')}")
            errors += 1

        prev_hash = stored_hash

    if errors == 0:
        console.print(
            f"[green]✅ Audit trail verified — {len(entries)} entries, no tampering detected.[/green]"
        )
        return 0
    else:
        console.print(f"[red]❌ {errors} integrity error(s) detected.[/red]")
        return 1


def cmd_list(args: argparse.Namespace) -> int:
    log_date = date.fromisoformat(args.date) if getattr(args, "date", None) else None
    entries = _read_entries(log_date)

    if not entries:
        console.print("[dim]No audit entries found.[/dim]")
        return 0

    tail = getattr(args, "tail", None)
    if tail:
        entries = entries[-tail:]

    table = Table(title=f"Audit Trail — {(log_date or date.today()).isoformat()}", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Timestamp", style="cyan")
    table.add_column("Action")
    table.add_column("Target")
    table.add_column("Tool", style="yellow")
    table.add_column("Operator", style="magenta")
    table.add_column("Consent ID", style="dim")
    table.add_column("Result")
    table.add_column("Hash", style="dim")

    for i, e in enumerate(entries):
        table.add_row(
            str(i + 1),
            e.get("timestamp", "")[:19],
            e.get("action", ""),
            e.get("target", "")[:40],
            e.get("tool", ""),
            e.get("operator", ""),
            e.get("consent_id", "")[:12],
            (e.get("result", "") or "")[:40],
            (e.get("hash", "") or "")[:12] + "…",
        )

    console.print(table)
    return 0


def cmd_export_pdf(args: argparse.Namespace) -> int:
    """Export audit trail to PDF using weasyprint or fallback to HTML."""
    log_date = date.fromisoformat(args.date) if getattr(args, "date", None) else None
    entries = _read_entries(log_date)

    output_path = Path(args.output)

    html_rows = "\n".join(
        f"""<tr>
          <td>{e.get('timestamp','')[:19]}</td>
          <td>{e.get('action','')}</td>
          <td>{e.get('target','')}</td>
          <td>{e.get('tool','')}</td>
          <td>{e.get('operator','')}</td>
          <td>{e.get('consent_id','')[:12]}</td>
          <td>{(e.get('result','') or '')[:60]}</td>
          <td><code>{(e.get('hash','') or '')[:16]}…</code></td>
        </tr>"""
        for e in entries
    )

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>CyberStrikeAI Audit Trail — {(log_date or date.today()).isoformat()}</title>
  <style>
    body {{ font-family: Arial, sans-serif; font-size: 11px; margin: 20px; }}
    h1 {{ color: #1a1a2e; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th {{ background: #1a1a2e; color: white; padding: 6px; text-align: left; }}
    td {{ padding: 4px 6px; border-bottom: 1px solid #ddd; word-break: break-all; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    .footer {{ margin-top: 20px; color: #666; font-size: 10px; }}
  </style>
</head>
<body>
  <h1>🔒 CyberStrikeAI DevSec — Audit Trail</h1>
  <p><strong>Date:</strong> {(log_date or date.today()).isoformat()} &nbsp;
     <strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()[:19]}Z &nbsp;
     <strong>Entries:</strong> {len(entries)}</p>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th><th>Action</th><th>Target</th><th>Tool</th>
        <th>Operator</th><th>Consent ID</th><th>Result</th><th>Hash</th>
      </tr>
    </thead>
    <tbody>
      {html_rows}
    </tbody>
  </table>
  <div class="footer">Generated by CyberStrikeAI DevSec Pipeline — FOR COMPLIANCE USE ONLY</div>
</body>
</html>"""

    if output_path.suffix.lower() == ".pdf":
        try:
            from weasyprint import HTML  # type: ignore
            HTML(string=html_content).write_pdf(str(output_path))
            console.print(f"[green]✅ PDF audit trail written to {output_path}[/green]")
            return 0
        except ImportError:
            html_path = output_path.with_suffix(".html")
            html_path.write_text(html_content)
            console.print(
                f"[yellow]⚠  weasyprint not installed — HTML written to {html_path}[/yellow]"
            )
            console.print("   Install: pip install weasyprint")
            return 0
    else:
        output_path.write_text(html_content)
        console.print(f"[green]✅ HTML audit trail written to {output_path}[/green]")
        return 0


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberStrikeAI DevSec — Audit Trail")
    sub = parser.add_subparsers(dest="command", required=True)

    # append
    p_append = sub.add_parser("append", help="Append audit entry")
    p_append.add_argument("--action", required=True)
    p_append.add_argument("--target", required=True)
    p_append.add_argument("--tool", required=True)
    p_append.add_argument("--operator", default=os.getenv("USER", "unknown"))
    p_append.add_argument("--consent-id", default="")
    p_append.add_argument("--result", default="")

    # verify
    p_verify = sub.add_parser("verify", help="Verify audit trail integrity")
    p_verify.add_argument("--date", default=None, help="Date YYYY-MM-DD (default: today)")

    # list
    p_list = sub.add_parser("list", help="List audit entries")
    p_list.add_argument("--date", default=None)
    p_list.add_argument("--tail", type=int, default=None, help="Show last N entries")

    # export-pdf
    p_pdf = sub.add_parser("export-pdf", help="Export audit trail to PDF")
    p_pdf.add_argument("--output", required=True)
    p_pdf.add_argument("--date", default=None)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dispatch = {
        "append": cmd_append,
        "verify": cmd_verify,
        "list": cmd_list,
        "export-pdf": cmd_export_pdf,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
