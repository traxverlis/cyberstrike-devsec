#!/usr/bin/env python3
"""
CyberStrikeAI DevSec — Notification System
Supports: email (SMTP/SendGrid), Slack webhook, Teams webhook, GitHub Issues.

Usage:
  python notify.py --channel email --findings-json findings.json --report-pdf report.pdf --recipient team@company.com
  python notify.py --channel slack --findings-json findings.json
  python notify.py --channel teams --findings-json findings.json
  python notify.py --channel github --findings-json findings.json --repo owner/repo
"""
from __future__ import annotations

import argparse
import json
import os
import smtplib
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console()


# ── Finding helpers ───────────────────────────────────────────────────────────

def load_findings(path: str | None) -> list[dict]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        console.log(f"[yellow]⚠  Findings file not found: {path}[/yellow]")
        return []
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        console.log("[red]❌ Failed to parse findings JSON[/red]")
        return []


def summarize_findings(findings: list[dict]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "critical": by_severity.get("critical", 0),
        "high": by_severity.get("high", 0),
        "medium": by_severity.get("medium", 0),
        "low": by_severity.get("low", 0),
    }


def build_text_summary(findings: list[dict], target: str = "") -> str:
    s = summarize_findings(findings)
    lines = [
        "🔐 CyberStrikeAI DevSec — Scan Results",
        "",
        f"Target : {target or 'N/A'}",
        f"Total  : {s['total']} findings",
        f"Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}",
        "",
    ]
    if s["critical"] > 0:
        lines.append("⚠  CRITICAL FINDINGS:")
        for f in findings:
            if (f.get("severity") or "").lower() == "critical":
                lines.append(f"  • [{f.get('tool','')}] {f.get('id','')} — {f.get('description','')[:100]}")
        lines.append("")
    return "\n".join(lines)


def build_html_summary(findings: list[dict], target: str = "") -> str:
    s = summarize_findings(findings)
    color = "#dc3545" if s["critical"] > 0 else "#fd7e14" if s["high"] > 0 else "#28a745"
    critical_rows = "".join(
        f"<tr><td>{f.get('tool','')}</td><td>{f.get('id','')}</td>"
        f"<td style='color:#dc3545;font-weight:bold'>{f.get('severity','').upper()}</td>"
        f"<td>{(f.get('description','') or '')[:120]}</td></tr>"
        for f in findings
        if (f.get("severity") or "").lower() in ("critical", "high")
    )
    return f"""
<html><body style="font-family:Arial,sans-serif;max-width:700px;margin:auto">
<h2 style="color:#1a1a2e">🔐 CyberStrikeAI DevSec — Rapport de Sécurité</h2>
<p><strong>Cible:</strong> {target or 'N/A'}</p>
<div style="background:{color};color:white;padding:12px;border-radius:6px;margin:12px 0">
  <strong>{s['total']} findings</strong> —
  Critical: {s['critical']} | High: {s['high']} | Medium: {s['medium']} | Low: {s['low']}
</div>
{"<h3>Findings Critiques / High</h3><table style='width:100%;border-collapse:collapse'><thead><tr><th>Tool</th><th>ID</th><th>Severity</th><th>Description</th></tr></thead><tbody>" + critical_rows + "</tbody></table>" if critical_rows else "<p>✅ Aucun finding critique.</p>"}
<hr><p style="color:#666;font-size:11px">Généré par CyberStrikeAI DevSec Pipeline</p>
</body></html>"""


# ── Email channel ─────────────────────────────────────────────────────────────

def send_email(
    recipient: str,
    findings: list[dict],
    report_path: str | None,
    target: str = "",
) -> int:
    """Send email via SMTP or SendGrid REST API."""

    # Try SendGrid REST first
    sendgrid_key = os.getenv("SENDGRID_API_KEY")
    if sendgrid_key:
        return _send_via_sendgrid(sendgrid_key, recipient, findings, report_path, target)

    # Fallback: SMTP
    smtp_host = os.getenv("SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    smtp_from = os.getenv("SMTP_FROM", smtp_user or "devsec@localhost")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CyberStrikeAI] Security Report — {target or 'scan'}"
    msg["From"] = smtp_from
    msg["To"] = recipient

    msg.attach(MIMEText(build_text_summary(findings, target), "plain"))
    msg.attach(MIMEText(build_html_summary(findings, target), "html"))

    if report_path and Path(report_path).exists():
        with open(report_path, "rb") as f:
            attachment = MIMEApplication(f.read(), _subtype="pdf")
            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=Path(report_path).name,
            )
            msg.attach(attachment)

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            if smtp_port == 587:
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_from, [recipient], msg.as_string())
        console.print(f"[green]✅ Email sent to {recipient}[/green]")
        return 0
    except Exception as exc:
        console.print(f"[red]❌ Email failed: {exc}[/red]")
        return 1


def _send_via_sendgrid(
    api_key: str,
    recipient: str,
    findings: list[dict],
    report_path: str | None,
    target: str = "",
) -> int:
    import base64
    import urllib.request

    payload: dict[str, Any] = {
        "personalizations": [{"to": [{"email": recipient}]}],
        "from": {"email": os.getenv("SENDGRID_FROM", "devsec-noreply@yourdomain.com")},
        "subject": f"[CyberStrikeAI] Security Report — {target or 'scan'}",
        "content": [
            {"type": "text/plain", "value": build_text_summary(findings, target)},
            {"type": "text/html", "value": build_html_summary(findings, target)},
        ],
    }

    if report_path and Path(report_path).exists():
        encoded = base64.b64encode(Path(report_path).read_bytes()).decode()
        payload["attachments"] = [
            {
                "content": encoded,
                "type": "application/pdf",
                "filename": Path(report_path).name,
            }
        ]

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://api.sendgrid.com/v3/mail/send",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status in (200, 202):
                console.print(f"[green]✅ SendGrid email sent to {recipient}[/green]")
                return 0
            console.print(f"[red]❌ SendGrid returned {resp.status}[/red]")
            return 1
    except Exception as exc:
        console.print(f"[red]❌ SendGrid request failed: {exc}[/red]")
        return 1


# ── Slack channel ─────────────────────────────────────────────────────────────

def send_slack(findings: list[dict], target: str = "") -> int:
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        console.print("[red]❌ SLACK_WEBHOOK_URL environment variable not set[/red]")
        return 1

    s = summarize_findings(findings)
    color = "danger" if s["critical"] > 0 else "warning" if s["high"] > 0 else "good"
    text = (
        f"*🔐 CyberStrikeAI DevSec Scan Complete*\n"
        f"Target: `{target or 'N/A'}`\n"
        f"Total: *{s['total']}* | Critical: *{s['critical']}* | High: *{s['high']}* | Medium: *{s['medium']}*"
    )

    payload = {
        "attachments": [
            {
                "color": color,
                "text": text,
                "fallback": f"DevSec scan: {s['total']} findings ({s['critical']} critical)",
                "footer": "CyberStrikeAI DevSec",
            }
        ]
    }

    return _post_webhook(webhook_url, payload, "Slack")


# ── Teams channel ─────────────────────────────────────────────────────────────

def send_teams(findings: list[dict], target: str = "") -> int:
    webhook_url = os.getenv("TEAMS_WEBHOOK_URL")
    if not webhook_url:
        console.print("[red]❌ TEAMS_WEBHOOK_URL environment variable not set[/red]")
        return 1

    s = summarize_findings(findings)
    theme_color = "FF0000" if s["critical"] > 0 else "FFA500" if s["high"] > 0 else "00CC00"

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "summary": "CyberStrikeAI DevSec Scan Results",
        "sections": [
            {
                "activityTitle": "🔐 CyberStrikeAI DevSec — Scan Complete",
                "activitySubtitle": f"Target: {target or 'N/A'}",
                "facts": [
                    {"name": "Total Findings", "value": str(s["total"])},
                    {"name": "Critical", "value": str(s["critical"])},
                    {"name": "High", "value": str(s["high"])},
                    {"name": "Medium", "value": str(s["medium"])},
                    {"name": "Low", "value": str(s["low"])},
                ],
                "markdown": True,
            }
        ],
    }

    return _post_webhook(webhook_url, payload, "Teams")


# ── GitHub Issues channel ─────────────────────────────────────────────────────

def send_github(findings: list[dict], repo: str, target: str = "") -> int:
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        console.print("[red]❌ GITHUB_TOKEN environment variable not set[/red]")
        return 1

    import urllib.request

    critical_findings = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")]
    if not critical_findings:
        console.print("[dim]ℹ  No critical/high findings — skipping GitHub issue creation[/dim]")
        return 0

    errors = 0
    for finding in critical_findings[:10]:  # cap at 10 issues
        body = (
            f"## Security Finding\n\n"
            f"**Tool:** {finding.get('tool', 'unknown')}\n"
            f"**Severity:** {finding.get('severity', 'unknown').upper()}\n"
            f"**Target:** {target or 'N/A'}\n"
            f"**ID:** {finding.get('id', 'N/A')}\n\n"
            f"### Description\n{finding.get('description', 'No description available.')}\n\n"
            f"*Detected by CyberStrikeAI DevSec Pipeline*"
        )
        payload = {
            "title": f"[Security] {finding.get('id', 'Finding')} — {(finding.get('severity') or '').upper()}",
            "body": body,
            "labels": ["security", "devsec", (finding.get("severity") or "unknown").lower()],
        }
        url = f"https://api.github.com/repos/{repo}/issues"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"token {token}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.github.v3+json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if resp.status == 201:
                    data = json.loads(resp.read())
                    console.print(f"[green]✅ GitHub issue created: #{data['number']}[/green]")
                else:
                    console.print(f"[red]❌ GitHub API returned {resp.status}[/red]")
                    errors += 1
        except Exception as exc:
            console.print(f"[red]❌ GitHub issue creation failed: {exc}[/red]")
            errors += 1

    return 0 if errors == 0 else 1


# ── Webhook helper ────────────────────────────────────────────────────────────

def _post_webhook(url: str, payload: dict, label: str) -> int:
    import urllib.request

    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status in (200, 204):
                console.print(f"[green]✅ {label} notification sent[/green]")
                return 0
            console.print(f"[red]❌ {label} webhook returned {resp.status}[/red]")
            return 1
    except Exception as exc:
        console.print(f"[red]❌ {label} webhook failed: {exc}[/red]")
        return 1


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberStrikeAI DevSec — Notification System")
    parser.add_argument(
        "--channel",
        required=True,
        choices=["email", "slack", "teams", "github"],
        help="Notification channel",
    )
    parser.add_argument("--findings-json", default=None, help="Path to findings JSON file")
    parser.add_argument("--report-pdf", default=None, help="Path to PDF report to attach (email only)")
    parser.add_argument("--recipient", default=None, help="Email recipient")
    parser.add_argument("--target", default="", help="Scan target (for context in messages)")
    parser.add_argument("--repo", default=None, help="GitHub repo (owner/repo) for issue creation")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings_json)

    if args.channel == "email":
        if not args.recipient:
            console.print("[red]❌ --recipient is required for email channel[/red]")
            return 1
        return send_email(args.recipient, findings, args.report_pdf, args.target)

    elif args.channel == "slack":
        return send_slack(findings, args.target)

    elif args.channel == "teams":
        return send_teams(findings, args.target)

    elif args.channel == "github":
        if not args.repo:
            args.repo = os.getenv("GITHUB_REPOSITORY")
        if not args.repo:
            console.print("[red]❌ --repo or GITHUB_REPOSITORY env var required for github channel[/red]")
            return 1
        return send_github(findings, args.repo, args.target)

    return 0


if __name__ == "__main__":
    sys.exit(main())
