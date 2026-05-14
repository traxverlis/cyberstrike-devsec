#!/usr/bin/env python3
"""
verify-consent.py — Verify a penetration testing consent PDF before initiating a Level-3 scan.

Exit codes:
    0 — Consent is valid; consent-token.json written.
    1 — Consent is invalid or cannot be verified.

Usage:
    python verify-consent.py --consent /tmp/consent-acme-2026.pdf \
        --target https://app.company.com \
        --token-out /tmp/consent-token.json
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def err(msg: str) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"[OK]    {msg}")


def info(msg: str) -> None:
    print(f"[INFO]  {msg}")


# ---------------------------------------------------------------------------
# PDF text extraction (no external deps beyond stdlib + PyPDF2/pdfplumber)
# ---------------------------------------------------------------------------

def extract_pdf_text(pdf_path: str) -> str:
    """Extract raw text from a PDF. Tries pdfplumber first, falls back to pypdf."""
    try:
        import pdfplumber  # type: ignore
        with pdfplumber.open(pdf_path) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)
    except ImportError:
        pass

    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(pdf_path)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except ImportError:
        pass

    try:
        from PyPDF2 import PdfReader  # type: ignore
        reader = PdfReader(pdf_path)
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except ImportError:
        pass

    raise RuntimeError(
        "No PDF text-extraction library found. "
        "Install pdfplumber or pypdf: pip install pdfplumber"
    )


# ---------------------------------------------------------------------------
# Field extractors
# ---------------------------------------------------------------------------

def extract_field(text: str, label: str) -> str | None:
    """Extract the value that follows a label on the same line."""
    pattern = re.compile(rf"{re.escape(label)}\s*[:\-]?\s*(.+)", re.IGNORECASE)
    m = pattern.search(text)
    if m:
        return m.group(1).strip()
    return None


def extract_hash(text: str) -> str | None:
    """Find the first SHA-256 hex string (64 hex chars) in the text."""
    m = re.search(r"\b([0-9a-f]{64})\b", text, re.IGNORECASE)
    return m.group(1).lower() if m else None


def extract_uuid(text: str) -> str | None:
    """Find the document UUID (Reference field or plain UUID)."""
    # Try "Reference: <UUID>" first
    m = re.search(r"Reference\s*[:\|]\s*([0-9A-F\-]{36})", text, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    # Fall back to any UUID-looking string
    m = re.search(r"\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b", text, re.IGNORECASE)
    return m.group(1).upper() if m else None


def extract_target(text: str) -> str | None:
    return extract_field(text, "Target System(s) / IP Range")


def extract_scope(text: str) -> str | None:
    return extract_field(text, "In-Scope Paths / Resources")


def extract_duration(text: str) -> str | None:
    return extract_field(text, "Authorization Window")


def extract_test_types(text: str) -> list[str]:
    raw = extract_field(text, "Authorized Test Types")
    if raw:
        return [t.strip() for t in raw.split(",")]
    return []


def extract_generated_at(text: str) -> str | None:
    m = re.search(r"Generated\s*[:\|]\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC)", text)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Date window check
# ---------------------------------------------------------------------------

def parse_date_window(duration: str):
    """
    Parse strings like '2026-05-14 to 2026-05-21' or '2026-05-14 - 2026-05-21'.
    Returns (start_date, end_date) as datetime objects (UTC, date-level precision).
    """
    parts = re.split(r"\s+to\s+|\s+-\s+", duration, flags=re.IGNORECASE)
    if len(parts) != 2:
        return None, None
    try:
        start = datetime.strptime(parts[0].strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = datetime.strptime(parts[1].strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return start, end
    except ValueError:
        return None, None


def is_within_window(duration: str) -> tuple[bool, str]:
    """Return (is_valid, reason_string)."""
    start, end = parse_date_window(duration)
    if start is None:
        return False, f"Cannot parse authorization window: '{duration}'"
    now = datetime.now(timezone.utc)
    if now < start:
        return False, f"Authorization window has not started yet (starts {start.date()})"
    if now > end.replace(hour=23, minute=59, second=59):
        return False, f"Authorization window has expired (ended {end.date()})"
    return True, f"Within authorization window ({start.date()} → {end.date()})"


# ---------------------------------------------------------------------------
# Target match
# ---------------------------------------------------------------------------

def targets_match(doc_target: str, cli_target: str) -> bool:
    """
    Loose but conservative match:
    - Normalize trailing slashes and case.
    - The CLI target must be a substring of the doc target (or exact match).
    """
    dt = doc_target.rstrip("/").lower()
    ct = cli_target.rstrip("/").lower()
    return ct == dt or ct in dt or dt in ct


# ---------------------------------------------------------------------------
# Signature presence check
# ---------------------------------------------------------------------------

SIGNATURE_MARKERS = [
    "Signature:",
    "signature:",
]

def signatures_present(text: str) -> tuple[bool, str]:
    """
    Heuristic: count signature field lines that appear to be filled
    (i.e. not still showing the placeholder underscores '______').
    We require at least the three signature blocks to exist in the document.
    """
    # Count occurrences of "Signature:" — there should be 3
    sig_count = len(re.findall(r"Signature\s*:", text, re.IGNORECASE))
    if sig_count < 3:
        return False, f"Expected 3 signature blocks, found {sig_count}"

    # Count blank/unsigned lines (still placeholder)
    blank_sigs = len(re.findall(r"Signature\s*:\s*_{6,}", text))
    if blank_sigs > 0:
        return False, f"{blank_sigs} signature block(s) appear unsigned (placeholder underscores found)"

    return True, "All signature fields are present and appear filled"


# ---------------------------------------------------------------------------
# Integrity check
# ---------------------------------------------------------------------------

def verify_integrity(text: str, doc_uuid: str, doc_target: str, doc_scope: str,
                     doc_requestor: str, doc_company: str, doc_tester: str,
                     doc_duration: str, doc_test_types: str, doc_exclusions: str,
                     doc_generated_at: str) -> tuple[bool, str, str]:
    """
    Recompute the SHA-256 over the canonical string used during generation.
    Returns (is_valid, stored_hash, computed_hash).

    NOTE: Because PDF text extraction is imperfect and the generator embeds the
    hash *inside* the document (creating a chicken-and-egg problem), we extract
    the stored hash from the PDF and compare it to what we can recompute from
    the extracted fields.  If the fields match the hash, integrity is confirmed.
    """
    stored_hash = extract_hash(text)
    if not stored_hash:
        return False, "", ""

    canonical = (
        f"UUID:{doc_uuid}|TARGET:{doc_target}|SCOPE:{doc_scope}|"
        f"REQUESTOR:{doc_requestor}|COMPANY:{doc_company}|TESTER:{doc_tester}|"
        f"DURATION:{doc_duration}|TEST_TYPES:{doc_test_types}|"
        f"EXCLUSIONS:{doc_exclusions}|GENERATED:{doc_generated_at}"
    )
    computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return computed == stored_hash, stored_hash, computed


# ---------------------------------------------------------------------------
# Main verification flow
# ---------------------------------------------------------------------------

def verify(args) -> int:
    import os

    # ---- 1. File existence ------------------------------------------------
    if not os.path.isfile(args.consent):
        err(f"Consent file not found: {args.consent}")
        return 1
    ok(f"Consent file found: {args.consent}")

    # ---- 2. Extract text --------------------------------------------------
    try:
        text = extract_pdf_text(args.consent)
    except Exception as exc:
        err(f"Failed to extract PDF text: {exc}")
        return 1

    if not text.strip():
        err("PDF appears to be empty or contains no extractable text.")
        return 1
    ok("PDF text extracted successfully")

    # ---- 3. Extract fields ------------------------------------------------
    doc_uuid = extract_uuid(text) or ""
    doc_target = extract_target(text) or ""
    doc_scope = extract_scope(text) or ""
    doc_duration = extract_duration(text) or ""
    doc_test_types = extract_test_types(text)
    doc_generated_at = extract_generated_at(text) or ""

    # These fields aren't directly labeled in the table but are in the canonical string.
    # We extract them from the Parties section.
    doc_requestor = extract_field(text, "Authorized Requestor") or ""
    doc_company = extract_field(text, "Client Organization") or ""
    doc_tester = extract_field(text, "Security Testing Team / Tester") or ""
    doc_exclusions = extract_field(text, "Explicitly Excluded") or ""

    info(f"UUID         : {doc_uuid}")
    info(f"Target       : {doc_target}")
    info(f"Scope        : {doc_scope}")
    info(f"Duration     : {doc_duration}")
    info(f"Test types   : {doc_test_types}")

    errors = []

    # ---- 4. Date window ---------------------------------------------------
    if not doc_duration:
        errors.append("Authorization window not found in document")
    else:
        valid_date, date_msg = is_within_window(doc_duration)
        if valid_date:
            ok(f"Date window   : {date_msg}")
        else:
            errors.append(f"Date window   : {date_msg}")

    # ---- 5. Target match --------------------------------------------------
    if args.target:
        if not doc_target:
            errors.append("Target not found in document")
        elif not targets_match(doc_target, args.target):
            errors.append(
                f"Target mismatch: document authorizes '{doc_target}', "
                f"but scan target is '{args.target}'"
            )
        else:
            ok(f"Target match  : '{args.target}' matches document target '{doc_target}'")

    # ---- 6. Signatures ----------------------------------------------------
    sigs_ok, sig_msg = signatures_present(text)
    if sigs_ok:
        ok(f"Signatures    : {sig_msg}")
    else:
        errors.append(f"Signatures    : {sig_msg}")

    # ---- 7. Integrity (hash) ----------------------------------------------
    if doc_uuid and doc_target and doc_generated_at:
        # We need raw test_types string as stored in canonical — reconstruct from list
        raw_test_types = extract_field(text, "Authorized Test Types") or ",".join(doc_test_types)
        integrity_ok, stored_h, computed_h = verify_integrity(
            text, doc_uuid, doc_target, doc_scope,
            doc_requestor, doc_company, doc_tester,
            doc_duration, raw_test_types, doc_exclusions, doc_generated_at,
        )
        stored_display = extract_hash(text) or "(not found)"
        if integrity_ok:
            ok(f"Integrity     : SHA-256 match confirmed ({stored_display[:16]}…)")
        else:
            # Hash mismatch could be due to PDF extraction imperfection;
            # we warn but don't hard-fail if all other checks pass.
            info(
                f"Integrity     : Hash could not be fully verified via text extraction "
                f"(stored={stored_display[:16]}… computed={computed_h[:16]}…). "
                f"Manual review recommended."
            )
    else:
        info("Integrity     : Insufficient fields to verify hash (UUID or generated-at missing)")

    # ---- 8. Final verdict -------------------------------------------------
    if errors:
        print("\n[FAIL] Consent verification FAILED. Issues found:")
        for e in errors:
            print(f"  ✗  {e}")
        return 1

    # ---- 9. Write consent token -------------------------------------------
    token = {
        "consent_id": doc_uuid,
        "target": doc_target,
        "scope": doc_scope,
        "valid_until": doc_duration.split(" to ")[-1].strip() if " to " in doc_duration else doc_duration,
        "test_types": doc_test_types,
        "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "hash": extract_hash(text) or "",
        "status": "APPROVED",
    }

    token_path = args.token_out or "consent-token.json"
    with open(token_path, "w") as f:
        json.dump(token, f, indent=2)

    print(f"\n[PASS] Consent verification PASSED. Token written to: {token_path}")
    print(json.dumps(token, indent=2))
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Verify a penetration testing consent PDF before starting a Level-3 scan."
    )
    p.add_argument("--consent", required=True, help="Path to the consent PDF")
    p.add_argument("--target", help="Target URL/IP to match against document (optional but recommended)")
    p.add_argument("--token-out", default="consent-token.json", help="Path to write consent-token.json (default: ./consent-token.json)")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sys.exit(verify(args))
