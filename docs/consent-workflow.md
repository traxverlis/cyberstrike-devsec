# Consent Workflow — Level-3 Penetration Testing

> **Mandatory:** A signed and verified consent document is required before any Level-3
> (full pentest) scan can begin. This is non-negotiable and enforced programmatically.

---

## Flow Diagram

```
                       ┌─────────────────────────────────┐
                       │  Pentest Engagement Requested    │
                       └──────────────┬──────────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────────┐
                       │  1. Generate Consent Document    │
                       │     generate-consent.py          │
                       │  Output: consent-<ref>.pdf       │
                       └──────────────┬──────────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────────┐
                       │  2. Send for Signature           │
                       │     send-consent.py              │
                       │  → Email to client legal rep     │
                       └──────────────┬──────────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────────┐
                       │  3. Client Signs & Returns PDF   │
                       │     (all 3 signature blocks)     │
                       └──────────────┬──────────────────┘
                                      │
                                      ▼
                       ┌─────────────────────────────────┐
                       │  4. Verify Consent               │
                       │     verify-consent.py            │
                       │                                  │
                       │  Checks:                         │
                       │  ✓ File exists                   │
                       │  ✓ SHA-256 integrity             │
                       │  ✓ Date within window            │
                       │  ✓ Target matches                │
                       │  ✓ Signatures present            │
                       └──────────────┬──────────────────┘
                                      │
                       ┌─────────────┴──────────────────┐
                       │                                  │
                    exit 0                             exit 1
                  (APPROVED)                         (REJECTED)
                       │                                  │
                       ▼                                  ▼
        ┌──────────────────────────┐     ┌───────────────────────────┐
        │  consent-token.json      │     │  Error message displayed  │
        │  written to disk         │     │  Scan BLOCKED             │
        └──────────────┬───────────┘     │  Resolve issues & retry   │
                       │                 └───────────────────────────┘
                       ▼
        ┌──────────────────────────┐
        │  Level-3 Scan Proceeds   │
        │  (pipeline reads token)  │
        └──────────────────────────┘
```

---

## Step 1 — Generate the Consent Document

```bash
python scripts/consent/generate-consent.py \
  --target "https://app.company.com" \
  --scope "/*.api.company.com, /admin/*, /v2/api/*" \
  --requestor "Jane Smith" \
  --company "Acme Corporation" \
  --tester "Red Team Alpha" \
  --duration "2026-05-14 to 2026-05-21" \
  --test-types "sqli,xss,auth,fuzzing,recon" \
  --exclusions "production DB (db.acme.com), payment endpoints (/pay/*), /internal/hr/*" \
  --output reports/consent-acme-2026-05.pdf
```

**What this produces:**
- A multi-page PDF with all legal clauses
- Unique UUID and SHA-256 integrity hash embedded
- QR code linking to document identity
- Three signature blocks (legal rep, technical owner, tester)

**Dependencies:**
```bash
pip install -r scripts/consent/requirements.txt
```

---

## Step 2 — Send for Signature

### Option A: Via SMTP

```bash
python scripts/consent/send-consent.py \
  --pdf reports/consent-acme-2026-05.pdf \
  --to-email legal@acme.com \
  --to-name "Jane Smith" \
  --from-email pentest@yourteam.io \
  --reply-to pentest@yourteam.io \
  --smtp-host mail.yourteam.io \
  --smtp-port 587 \
  --smtp-user pentest@yourteam.io \
  --smtp-pass "$SMTP_PASSWORD"
```

### Option B: Via SendGrid

```bash
export SENDGRID_API_KEY="SG.xxxx"

python scripts/consent/send-consent.py \
  --pdf reports/consent-acme-2026-05.pdf \
  --to-email legal@acme.com \
  --to-name "Jane Smith" \
  --from-email pentest@yourteam.io
```

### Option C: Manual

If email delivery is not possible:
1. Use the Markdown template: `reports/templates/consent-form.md`
2. Send as Word/PDF through any channel
3. Collect signed scan or certified physical copy

---

## Step 3 — Receive Signed Document

The client should return:
- A **signed PDF** (scanned or digitally signed via DocuSign/Adobe Sign)
- All **three signature blocks** completed (legal rep, technical owner, tester)
- Within the stated authorization window

Store the signed PDF in a secure location (e.g., `reports/signed/`).

---

## Step 4 — Verify Consent Before Scanning

**Run this before every Level-3 scan:**

```bash
python scripts/consent/verify-consent.py \
  --consent reports/signed/consent-acme-2026-05-signed.pdf \
  --target "https://app.company.com" \
  --token-out /tmp/consent-token.json
```

**Exit codes:**
- `0` — All checks passed; `consent-token.json` written
- `1` — One or more checks failed; scan must not proceed

**Sample valid output:**
```
[OK]    Consent file found: reports/signed/consent-acme-2026-05-signed.pdf
[OK]    PDF text extracted successfully
[INFO]  UUID         : 4A3F2E1D-...
[INFO]  Target       : https://app.company.com
[INFO]  Duration     : 2026-05-14 to 2026-05-21
[OK]    Date window   : Within authorization window (2026-05-14 → 2026-05-21)
[OK]    Target match  : 'https://app.company.com' matches document target
[OK]    Signatures    : All signature fields are present and appear filled
[OK]    Integrity     : SHA-256 match confirmed (a3f2b1c9...)

[PASS] Consent verification PASSED. Token written to: /tmp/consent-token.json
```

**Sample consent-token.json:**
```json
{
  "consent_id": "4A3F2E1D-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
  "target": "https://app.company.com",
  "scope": "/*.api.company.com, /admin/*, /v2/api/*",
  "valid_until": "2026-05-21",
  "test_types": ["sqli", "xss", "auth", "fuzzing", "recon"],
  "verified_at": "2026-05-14 09:23:41 UTC",
  "hash": "a3f2b1c9...",
  "status": "APPROVED"
}
```

---

## Integration in the Automated Pipeline

Your scan orchestrator should check for the consent token before launching Level-3:

```bash
#!/usr/bin/env bash
# pre-scan-check.sh

CONSENT_PDF="${1:?Usage: pre-scan-check.sh <signed-consent.pdf> <target>}"
TARGET="${2:?Target required}"
TOKEN_FILE="/tmp/consent-token-$(date +%s).json"

python scripts/consent/verify-consent.py \
  --consent "$CONSENT_PDF" \
  --target "$TARGET" \
  --token-out "$TOKEN_FILE"

if [ $? -ne 0 ]; then
  echo "[ABORT] Consent verification failed. Level-3 scan cannot proceed."
  exit 1
fi

echo "[OK] Consent verified. Proceeding with scan."
# Pass $TOKEN_FILE to your scan scripts for audit trail
export CONSENT_TOKEN_FILE="$TOKEN_FILE"
```

In Python-based pipelines:

```python
import subprocess, sys

result = subprocess.run(
    ["python", "scripts/consent/verify-consent.py",
     "--consent", consent_pdf,
     "--target", target,
     "--token-out", token_path],
    capture_output=True
)

if result.returncode != 0:
    print(result.stderr.decode())
    sys.exit("CONSENT GATE: Scan blocked — consent not verified.")
```

---

## FAQ — Legal Coverage

### What does this document cover?

The authorization covers all explicitly listed test types on the in-scope systems
during the stated window. It provides legal protection for both the tester
(establishing authorized access) and the client (limiting unintended damage claims).

### Which jurisdictions does it cover?

The document references:
- **USA**: CFAA (18 U.S.C. § 1030) — authorizes access that would otherwise be unauthorized
- **UK**: Computer Misuse Act 1990 — provides explicit consent defense
- **EU**: Directive 2013/40/EU + GDPR — covers both access and any personal data encountered
- **Other**: The governing law clause allows parties to specify their jurisdiction

### Is this a substitute for a full legal contract?

No. This consent document is a **technical authorization** specific to the test.
It should be used alongside a master services agreement (MSA) or Statement of Work (SOW)
that covers billing, NDA, and broader engagement terms.

### What if the client uses cloud hosting (AWS, GCP, Azure)?

Cloud providers may require advance notification of penetration testing:
- **AWS**: Submit a Penetration Testing Request form
- **GCP**: No approval needed for most services (check policy)
- **Azure**: No approval needed for your own resources (check policy)

The client is responsible for complying with their provider's terms (Section 4.3).

### What about bug bounty programs?

This form is intended for **contracted pentests**, not bug bounties. Bug bounty
scopes are governed by the platform's own policies (HackerOne, Bugcrowd, etc.).

### Does digital signature (DocuSign/Adobe Sign) count?

Yes. Digital signatures from recognized platforms are legally valid in most jurisdictions
under eIDAS (EU), ESIGN Act (USA), and equivalent legislation. Include the certificate
or audit trail alongside the signed PDF.

### What happens if a critical vulnerability is found in out-of-scope systems?

The tester must immediately notify the client without exploiting the vulnerability
further, and document the discovery. Testing on out-of-scope systems must not proceed.
See Section 4.4 of the authorization document.

### How long should we keep consent records?

Minimum **5 years** (matching the confidentiality obligation). Some compliance frameworks
(PCI DSS, ISO 27001) may require longer retention. Store securely with restricted access.

---

## File Reference

| File | Purpose |
|---|---|
| `scripts/consent/generate-consent.py` | Generate authorization PDF |
| `scripts/consent/verify-consent.py` | Verify signed PDF before scan |
| `scripts/consent/send-consent.py` | Email PDF for signature |
| `scripts/consent/requirements.txt` | Python dependencies |
| `reports/templates/consent-form.md` | Manual fallback template |
| `reports/signed/` | Store signed consent PDFs here |
