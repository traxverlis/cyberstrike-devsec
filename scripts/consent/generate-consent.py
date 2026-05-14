#!/usr/bin/env python3
"""
generate-consent.py — Generate a legally-binding penetration testing authorization PDF.

Usage:
    python generate-consent.py --target https://app.company.com \
        --scope "/*.api.company.com, /admin/*" \
        --requestor "John Smith" \
        --company "Acme Corp" \
        --tester "Red Team Alpha" \
        --duration "2026-05-14 to 2026-05-21" \
        --test-types "sqli,xss,auth,fuzzing" \
        --exclusions "production DB, payment endpoints" \
        --output /tmp/consent-acme-2026.pdf
"""

import argparse
import hashlib
import io
import uuid
from datetime import datetime, timezone

import qrcode
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontSize=16,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontSize=11,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            spaceAfter=2,
        ),
        "ref": ParagraphStyle(
            "ref",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            alignment=TA_CENTER,
            spaceAfter=12,
            textColor=colors.HexColor("#555555"),
        ),
        "section": ParagraphStyle(
            "section",
            parent=base["Normal"],
            fontSize=11,
            fontName="Helvetica-Bold",
            spaceAfter=4,
            spaceBefore=10,
            textColor=colors.HexColor("#1a1a2e"),
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            alignment=TA_JUSTIFY,
            spaceAfter=6,
            leading=14,
        ),
        "bullet": ParagraphStyle(
            "bullet",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            leftIndent=20,
            spaceAfter=3,
            leading=14,
        ),
        "label": ParagraphStyle(
            "label",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica-Bold",
            spaceAfter=2,
        ),
        "value": ParagraphStyle(
            "value",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica",
            spaceAfter=2,
        ),
        "warning": ParagraphStyle(
            "warning",
            parent=base["Normal"],
            fontSize=9,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            textColor=colors.HexColor("#cc0000"),
            spaceBefore=8,
            spaceAfter=8,
        ),
        "sig_label": ParagraphStyle(
            "sig_label",
            parent=base["Normal"],
            fontSize=8,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "sig_line": ParagraphStyle(
            "sig_line",
            parent=base["Normal"],
            fontSize=8,
            fontName="Helvetica",
            alignment=TA_CENTER,
            textColor=colors.HexColor("#555555"),
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# QR Code helper
# ---------------------------------------------------------------------------

def make_qr_image(data: str, size_cm: float = 3.0) -> Image:
    """Generate an in-memory QR code and return a ReportLab Image."""
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=6, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    rl_img = Image(buf, width=size_cm * cm, height=size_cm * cm)
    return rl_img


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------

def build_pdf(args) -> None:
    # Metadata
    doc_uuid = str(uuid.uuid4()).upper()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    test_types_list = [t.strip() for t in args.test_types.split(",")]

    # We compute the hash over the canonical document content (pre-signature).
    canonical = (
        f"UUID:{doc_uuid}|TARGET:{args.target}|SCOPE:{args.scope}|"
        f"REQUESTOR:{args.requestor}|COMPANY:{args.company}|TESTER:{args.tester}|"
        f"DURATION:{args.duration}|TEST_TYPES:{args.test_types}|"
        f"EXCLUSIONS:{args.exclusions}|GENERATED:{generated_at}"
    )
    doc_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    styles = build_styles()

    doc = SimpleDocTemplate(
        args.output,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="Authorization to Conduct Penetration Testing",
        author=args.tester,
        subject=f"Pentest Authorization — {args.company}",
    )

    story = []

    # -----------------------------------------------------------------------
    # Header
    # -----------------------------------------------------------------------
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 6))
    story.append(Paragraph("AUTHORIZATION TO CONDUCT PENETRATION TESTING", styles["title"]))
    story.append(Paragraph("Legally Binding Document — Read Carefully Before Signing", styles["subtitle"]))
    story.append(
        Paragraph(
            f"Reference: <b>{doc_uuid}</b> &nbsp;|&nbsp; Generated: {generated_at}",
            styles["ref"],
        )
    )
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 8))

    # -----------------------------------------------------------------------
    # Parties
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. PARTIES", styles["section"]))
    parties_data = [
        ["Client Organization:", args.company],
        ["Authorized Requestor:", args.requestor],
        ["Security Testing Team / Tester:", args.tester],
        ["Document Generated:", generated_at],
    ]
    parties_table = Table(parties_data, colWidths=[6 * cm, 11 * cm])
    parties_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(parties_table)
    story.append(Spacer(1, 6))

    # -----------------------------------------------------------------------
    # Explicit Authorization Declaration
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. EXPLICIT AUTHORIZATION DECLARATION", styles["section"]))
    story.append(
        Paragraph(
            f"The undersigned representatives of <b>{args.company}</b> (hereinafter &quot;the Client&quot;) "
            f"hereby expressly authorize <b>{args.tester}</b> (hereinafter &quot;the Tester&quot;) "
            "to perform security testing activities as described in this document. "
            "This authorization is voluntary, informed, and constitutes a lawful consent "
            "under applicable computer crime and cybersecurity legislation, including but not limited to "
            "the Computer Fraud and Abuse Act (CFAA, 18 U.S.C. § 1030), "
            "the Computer Misuse Act 1990 (UK), and equivalent national legislation. "
            "The Client confirms that it has full authority to grant access to all systems listed herein.",
            styles["body"],
        )
    )

    # -----------------------------------------------------------------------
    # Scope
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. AUTHORIZED SCOPE", styles["section"]))

    scope_data = [
        ["Target System(s) / IP Range:", args.target],
        ["In-Scope Paths / Resources:", args.scope],
        ["Authorization Window:", args.duration],
        ["Authorized Test Types:", ", ".join(test_types_list)],
        ["Explicitly Excluded:", args.exclusions],
    ]
    scope_table = Table(scope_data, colWidths=[6 * cm, 11 * cm])
    scope_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#fff0f0")),
                ("TEXTCOLOR", (0, 4), (-1, 4), colors.HexColor("#cc0000")),
            ]
        )
    )
    story.append(scope_table)
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            "⚠  Any testing activity outside the authorized scope listed above is strictly prohibited "
            "and may constitute a criminal offense.",
            styles["warning"],
        )
    )

    # -----------------------------------------------------------------------
    # Legal Clauses
    # -----------------------------------------------------------------------
    story.append(Paragraph("4. LEGAL CLAUSES", styles["section"]))

    clauses = [
        (
            "4.1 Authorized Testing Activities",
            f"The Tester is authorized to perform the following categories of security tests on the "
            f"in-scope systems during the specified authorization window: "
            f"{', '.join(test_types_list)}. "
            "Testing shall be conducted in a professional manner with the intent to identify "
            "vulnerabilities without causing unnecessary damage, data loss, or service disruption.",
        ),
        (
            "4.2 Prohibited Activities",
            f"The following activities are explicitly prohibited regardless of scope: "
            f"(a) testing systems not listed in Section 3; "
            f"(b) accessing, exfiltrating, or retaining Client data beyond what is strictly necessary "
            f"for proof-of-concept purposes; "
            f"(c) conducting tests outside the authorization window; "
            f"(d) sharing findings with third parties without written Client consent; "
            f"(e) any action targeting: {args.exclusions}.",
        ),
        (
            "4.3 Responsibilities — Client",
            "The Client shall: (a) ensure it has the legal right to authorize testing on all listed systems, "
            "including any third-party hosted infrastructure; "
            "(b) notify relevant cloud/hosting providers if required by their terms of service; "
            "(c) provide emergency contact information to the Tester; "
            "(d) ensure backups of critical systems are in place prior to testing; "
            "(e) accept responsibility for ensuring the authorization window is appropriate.",
        ),
        (
            "4.4 Responsibilities — Tester",
            "The Tester shall: (a) conduct all activities within the agreed scope; "
            "(b) immediately notify the Client upon discovery of critical vulnerabilities or evidence of "
            "active compromise by third parties; "
            "(c) cease testing upon Client request; "
            "(d) securely handle and destroy any data obtained during testing after report delivery; "
            "(e) maintain detailed activity logs for the duration of the engagement.",
        ),
        (
            "4.5 Confidentiality",
            "All information obtained during the engagement — including vulnerability details, system "
            "architecture, credentials, and data — is strictly confidential. The Tester agrees not to "
            "disclose, publish, or share any findings without the prior written consent of the Client, "
            "except where required by law. This obligation survives the termination of this agreement "
            "for a period of five (5) years.",
        ),
        (
            "4.6 Limitation of Liability",
            "The Tester shall exercise reasonable professional care to avoid service disruption or data "
            "loss. However, the Client acknowledges that security testing carries inherent risks. "
            "The Tester's liability for unintended damage shall be limited to direct damages up to the "
            "value of the engagement fee, except in cases of gross negligence or willful misconduct. "
            "The Client waives any claim for indirect, consequential, or punitive damages.",
        ),
        (
            "4.7 Legal Compliance",
            "This document constitutes lawful authorization under: "
            "(a) Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 — United States; "
            "(b) Computer Misuse Act 1990 — United Kingdom; "
            "(c) Directive 2013/40/EU on attacks against information systems — European Union; "
            "(d) General Data Protection Regulation (GDPR) — Regulation (EU) 2016/679, "
            "with respect to any personal data encountered during testing; "
            "(e) equivalent national cybercrime legislation in the jurisdiction(s) where systems reside. "
            "The Tester shall comply with GDPR obligations if personal data is incidentally accessed, "
            "including minimizing processing and notifying the Client promptly.",
        ),
        (
            "4.8 Governing Law & Dispute Resolution",
            "This agreement shall be governed by the laws of the jurisdiction agreed upon by both "
            "parties prior to signing. In the absence of explicit agreement, the laws of the Client's "
            "country of incorporation shall apply. Disputes shall be resolved through good-faith "
            "negotiation, and failing that, through binding arbitration.",
        ),
    ]

    for title, text in clauses:
        story.append(Paragraph(title, styles["label"]))
        story.append(Paragraph(text, styles["body"]))

    # -----------------------------------------------------------------------
    # Acknowledgment
    # -----------------------------------------------------------------------
    story.append(Paragraph("5. ACKNOWLEDGMENT", styles["section"]))
    story.append(
        Paragraph(
            "By signing below, each party confirms that they have read, understood, and agree to the "
            "terms of this Authorization. The signatories confirm they have the authority to bind "
            "their respective organizations to these terms.",
            styles["body"],
        )
    )

    # -----------------------------------------------------------------------
    # Signature blocks
    # -----------------------------------------------------------------------
    story.append(Paragraph("6. SIGNATURES", styles["section"]))

    def sig_block(role, name, title_hint=""):
        data = [
            [Paragraph(f"<b>{role}</b>", styles["sig_label"])],
            [Paragraph(f"Name: {name}", styles["sig_line"])],
            [Paragraph(f"Title: {title_hint if title_hint else '______________________________'}", styles["sig_line"])],
            [Paragraph("Signature: ______________________________", styles["sig_line"])],
            [Paragraph("Date: ______________________________", styles["sig_line"])],
        ]
        t = Table(data, colWidths=[5.5 * cm])
        t.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#aaaaaa")),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return t

    sig_row = [
        sig_block("Legal Representative\n(Client)", args.requestor, "Authorized Signatory"),
        sig_block("Technical Owner\n(Client)", "______________________________", ""),
        sig_block("Pentester / Team Lead", args.tester, "Security Tester"),
    ]
    sig_table = Table([sig_row], colWidths=[5.8 * cm, 5.8 * cm, 5.8 * cm], hAlign="CENTER")
    sig_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4)]))
    story.append(sig_table)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # Document integrity footer
    # -----------------------------------------------------------------------
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 6))

    qr_payload = f"PENTEST-AUTH|{doc_uuid}|{doc_hash[:16]}"
    qr_img = make_qr_image(qr_payload, size_cm=2.8)

    integrity_data = [
        [
            qr_img,
            Paragraph(
                f"<b>Document Integrity</b><br/>"
                f"UUID: {doc_uuid}<br/>"
                f"SHA-256: {doc_hash}<br/>"
                f"<font size='7' color='#555555'>"
                f"This hash covers all fields above (pre-signature). "
                f"Use verify-consent.py to validate integrity.</font>",
                styles["body"],
            ),
        ]
    ]
    integrity_table = Table(integrity_data, colWidths=[3.2 * cm, 13.8 * cm])
    integrity_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (1, 0), (1, 0), 10),
            ]
        )
    )
    story.append(integrity_table)

    # Build the PDF
    doc.build(story)
    print(f"[+] Consent document generated: {args.output}")
    print(f"[+] Document UUID : {doc_uuid}")
    print(f"[+] SHA-256 hash  : {doc_hash}")
    print(f"[+] QR payload    : {qr_payload}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate a penetration testing authorization PDF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", required=True, help="Target URL, IP, or CIDR range")
    p.add_argument("--scope", required=True, help='In-scope paths/resources (e.g. "/*.api.company.com")')
    p.add_argument("--requestor", required=True, help="Name of the authorized requestor (client side)")
    p.add_argument("--company", required=True, help="Client company name")
    p.add_argument("--tester", required=True, help="Pentester name or team name")
    p.add_argument("--duration", required=True, help='Authorization window (e.g. "2026-05-14 to 2026-05-21")')
    p.add_argument("--test-types", required=True, dest="test_types", help='Comma-separated test types (e.g. "sqli,xss,auth")')
    p.add_argument("--exclusions", required=True, help='Explicitly excluded targets (e.g. "production DB")')
    p.add_argument("--output", required=True, help="Output PDF file path")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    build_pdf(args)
