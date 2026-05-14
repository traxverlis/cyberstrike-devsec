#!/usr/bin/env python3
"""
send-consent.py — Send a penetration testing consent PDF by email for signature.

Supports:
  - SMTP (plain, STARTTLS, or SSL)
  - SendGrid API

Usage (SMTP):
    python send-consent.py \
        --pdf /tmp/consent-acme-2026.pdf \
        --to-email legal@acme.com \
        --to-name "Jane Smith" \
        --from-email pentest@redteam.io \
        --smtp-host mail.redteam.io \
        --smtp-port 587 \
        --smtp-user pentest@redteam.io \
        --smtp-pass "$SMTP_PASSWORD"

Usage (SendGrid):
    python send-consent.py \
        --pdf /tmp/consent-acme-2026.pdf \
        --to-email legal@acme.com \
        --to-name "Jane Smith" \
        --from-email pentest@redteam.io \
        --sendgrid-key "$SENDGRID_API_KEY"
"""

import argparse
import base64
import os
import smtplib
import sys
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


# ---------------------------------------------------------------------------
# Email content
# ---------------------------------------------------------------------------

def build_email_body(to_name: str, pdf_filename: str, return_email: str) -> tuple[str, str]:
    """Return (subject, html_body)."""
    subject = "ACTION REQUIRED: Penetration Testing Authorization — Signature Needed"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #222; max-width: 640px; margin: 0 auto; padding: 24px;">

  <div style="border-left: 4px solid #1a1a2e; padding-left: 16px; margin-bottom: 24px;">
    <h2 style="color: #1a1a2e; margin: 0 0 4px 0;">Penetration Testing Authorization Request</h2>
    <p style="color: #555; margin: 0; font-size: 13px;">Confidential — For Authorized Recipients Only</p>
  </div>

  <p>Dear {to_name},</p>

  <p>
    Please find attached a <strong>Penetration Testing Authorization document</strong>
    that requires your review and signature before security testing activities can commence.
  </p>

  <p>
    This document formally authorizes our security team to conduct the agreed penetration
    testing activities within the defined scope and timeframe. It is a legally binding
    agreement that protects both parties and ensures all testing is conducted lawfully.
  </p>

  <h3 style="color: #1a1a2e; border-bottom: 1px solid #ddd; padding-bottom: 6px;">What You Need to Do</h3>
  <ol>
    <li>Carefully <strong>review the attached PDF</strong> — especially the authorized scope and exclusions.</li>
    <li><strong>Print, sign, and date</strong> the document (all three signature blocks must be filled).</li>
    <li><strong>Scan and return</strong> the signed document to:
      <a href="mailto:{return_email}" style="color: #1a1a2e;">{return_email}</a>
    </li>
    <li>Or reply directly to this email with the signed PDF attached.</li>
  </ol>

  <div style="background: #fff8e1; border: 1px solid #f0c040; border-radius: 4px; padding: 12px; margin: 16px 0;">
    <strong>⚠ Important:</strong> Testing activities will <strong>not</strong> begin until
    a fully signed copy of this document has been received and verified. If you have
    any questions about the scope or terms, please reply before signing.
  </div>

  <h3 style="color: #1a1a2e; border-bottom: 1px solid #ddd; padding-bottom: 6px;">Document Details</h3>
  <p>The authorization document (<code>{pdf_filename}</code>) includes:</p>
  <ul>
    <li>Explicit scope and exclusions</li>
    <li>Authorization window (start and end dates)</li>
    <li>Authorized test types</li>
    <li>Legal clauses covering confidentiality, liability, and compliance (CFAA, GDPR, CMA)</li>
    <li>Unique document ID and SHA-256 integrity hash</li>
  </ul>

  <p>
    Please do not hesitate to contact us if you need clarification on any clause
    before signing.
  </p>

  <p style="margin-top: 24px;">
    Regards,<br>
    <strong>Security Testing Team</strong>
  </p>

  <hr style="border: none; border-top: 1px solid #ddd; margin: 24px 0;">
  <p style="font-size: 11px; color: #888;">
    This email and its attachments are intended solely for the named recipient.
    If you have received this in error, please notify the sender and delete this message immediately.
    The attached document contains confidential security information.
  </p>

</body>
</html>"""
    return subject, html


def build_text_body(to_name: str, pdf_filename: str, return_email: str) -> str:
    return f"""Dear {to_name},

Please find attached a Penetration Testing Authorization document that requires
your review and signature before security testing activities can commence.

WHAT YOU NEED TO DO:
1. Carefully review the attached PDF.
2. Print, sign, and date the document (all three signature blocks).
3. Scan and return the signed document to: {return_email}
   Or simply reply to this email with the signed PDF attached.

Testing activities will NOT begin until a fully signed copy has been received.

If you have questions about the scope or terms, please reply before signing.

Regards,
Security Testing Team

---
This email is confidential and intended solely for {to_name}.
"""


# ---------------------------------------------------------------------------
# Send via SMTP
# ---------------------------------------------------------------------------

def send_smtp(args, msg: MIMEMultipart) -> None:
    port = args.smtp_port or 587
    host = args.smtp_host

    password = args.smtp_pass or os.environ.get("SMTP_PASSWORD", "")

    print(f"[*] Connecting to SMTP {host}:{port} ...")

    if port == 465:
        with smtplib.SMTP_SSL(host, port) as server:
            if args.smtp_user:
                server.login(args.smtp_user, password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if args.smtp_user:
                server.login(args.smtp_user, password)
            server.send_message(msg)

    print(f"[+] Email sent via SMTP to {args.to_email}")


# ---------------------------------------------------------------------------
# Send via SendGrid
# ---------------------------------------------------------------------------

def send_sendgrid(args, subject: str, html_body: str, text_body: str, pdf_path: str) -> None:
    try:
        import requests  # type: ignore
    except ImportError:
        print("[ERROR] 'requests' library not found. Install it: pip install requests", file=sys.stderr)
        sys.exit(1)

    api_key = args.sendgrid_key or os.environ.get("SENDGRID_API_KEY", "")
    if not api_key:
        print("[ERROR] SendGrid API key not provided (--sendgrid-key or $SENDGRID_API_KEY)", file=sys.stderr)
        sys.exit(1)

    with open(pdf_path, "rb") as f:
        pdf_b64 = base64.b64encode(f.read()).decode("utf-8")

    pdf_filename = Path(pdf_path).name

    payload = {
        "personalizations": [
            {
                "to": [{"email": args.to_email, "name": args.to_name}],
                "subject": subject,
            }
        ],
        "from": {"email": args.from_email},
        "reply_to": {"email": args.reply_to or args.from_email},
        "content": [
            {"type": "text/plain", "value": text_body},
            {"type": "text/html", "value": html_body},
        ],
        "attachments": [
            {
                "content": pdf_b64,
                "type": "application/pdf",
                "filename": pdf_filename,
                "disposition": "attachment",
            }
        ],
    }

    print(f"[*] Sending via SendGrid to {args.to_email} ...")
    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )

    if resp.status_code in (200, 202):
        print(f"[+] Email sent via SendGrid to {args.to_email} (HTTP {resp.status_code})")
    else:
        print(f"[ERROR] SendGrid returned HTTP {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(args) -> None:
    pdf_path = args.pdf
    if not os.path.isfile(pdf_path):
        print(f"[ERROR] PDF not found: {pdf_path}", file=sys.stderr)
        sys.exit(1)

    pdf_filename = Path(pdf_path).name
    return_email = args.reply_to or args.from_email

    subject, html_body = build_email_body(args.to_name, pdf_filename, return_email)
    text_body = build_text_body(args.to_name, pdf_filename, return_email)

    if args.sendgrid_key or os.environ.get("SENDGRID_API_KEY"):
        send_sendgrid(args, subject, html_body, text_body, pdf_path)
        return

    if not args.smtp_host:
        print("[ERROR] Provide --smtp-host (SMTP) or --sendgrid-key (SendGrid)", file=sys.stderr)
        sys.exit(1)

    # Build MIME message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = args.from_email
    msg["To"] = f"{args.to_name} <{args.to_email}>"
    if args.reply_to:
        msg["Reply-To"] = args.reply_to

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    # Attach PDF
    with open(pdf_path, "rb") as f:
        pdf_part = MIMEApplication(f.read(), _subtype="pdf")
        pdf_part.add_header("Content-Disposition", "attachment", filename=pdf_filename)
        msg.attach(pdf_part)

    send_smtp(args, msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Send a penetration testing consent PDF by email for signature.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--pdf", required=True, help="Path to the consent PDF")
    p.add_argument("--to-email", required=True, dest="to_email", help="Recipient email address")
    p.add_argument("--to-name", required=True, dest="to_name", help="Recipient full name")
    p.add_argument("--from-email", required=True, dest="from_email", help="Sender email address")
    p.add_argument("--reply-to", dest="reply_to", help="Reply-To address (defaults to --from-email)")

    smtp_group = p.add_argument_group("SMTP options")
    smtp_group.add_argument("--smtp-host", dest="smtp_host", help="SMTP server hostname")
    smtp_group.add_argument("--smtp-port", dest="smtp_port", type=int, default=587, help="SMTP port (default: 587)")
    smtp_group.add_argument("--smtp-user", dest="smtp_user", help="SMTP username")
    smtp_group.add_argument("--smtp-pass", dest="smtp_pass", help="SMTP password (prefer $SMTP_PASSWORD env var)")

    sg_group = p.add_argument_group("SendGrid options")
    sg_group.add_argument("--sendgrid-key", dest="sendgrid_key", help="SendGrid API key (prefer $SENDGRID_API_KEY env var)")

    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    main(args)
