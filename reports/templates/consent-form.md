# AUTHORIZATION TO CONDUCT PENETRATION TESTING
## Consent & Authorization Form — Manual Version

---

**REFERENCE NUMBER:** `[AUTO-GENERATED — leave blank if manual]`  
**DATE GENERATED:** `____________________________`

---

## 1. PARTIES

| Role | Details |
|---|---|
| **Client Organization** | `____________________________` |
| **Authorized Requestor (Legal Rep)** | `____________________________` |
| **Requestor Title** | `____________________________` |
| **Security Testing Team / Tester** | `____________________________` |
| **Engagement Reference** | `____________________________` |

---

## 2. EXPLICIT AUTHORIZATION DECLARATION

The undersigned representatives of **[CLIENT ORGANIZATION]** (hereinafter "the Client")
hereby **expressly authorize** **[TESTER/TEAM]** (hereinafter "the Tester") to perform
security testing activities as described in this document.

This authorization is:
- [ ] Voluntary and informed
- [ ] Granted by a party with full legal authority over the listed systems
- [ ] Limited strictly to the scope defined in Section 3

---

## 3. AUTHORIZED SCOPE

### 3.1 Target System(s) / IP Range(s)

```
[Enter target URL, IP address, CIDR range, or domain]

Example: https://app.company.com | 192.168.1.0/24
```

**TARGET:** `____________________________________________________________`

### 3.2 In-Scope Paths & Resources

```
List specific paths, endpoints, or services that are IN scope.
```

**SCOPE:**
```
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
```

### 3.3 Authorization Window

**START DATE:** `____________________________`  
**END DATE:** `____________________________`

> Testing activities are **only authorized** within this window.
> Any testing outside these dates is unauthorized.

### 3.4 Authorized Test Types

Check all that apply:

- [ ] **sqli** — SQL Injection
- [ ] **xss** — Cross-Site Scripting
- [ ] **auth** — Authentication & Authorization testing
- [ ] **fuzzing** — Input fuzzing / boundary testing
- [ ] **recon** — Passive and active reconnaissance
- [ ] **csrf** — Cross-Site Request Forgery
- [ ] **ssrf** — Server-Side Request Forgery
- [ ] **idor** — Insecure Direct Object Reference
- [ ] **rce** — Remote Code Execution (requires explicit approval)
- [ ] **dos** — Denial of Service simulation (requires explicit approval)
- [ ] **network** — Network-level scanning and enumeration
- [ ] **social** — Social engineering (requires explicit approval)
- [ ] **other:** `____________________________`

### 3.5 Explicitly Excluded (Out of Scope)

> **⚠ CRITICAL:** The following systems, endpoints, or data types are **EXCLUDED**
> and must NOT be tested under any circumstances:

```
_____________________________________________________________
_____________________________________________________________
_____________________________________________________________
```

---

## 4. LEGAL CLAUSES

### 4.1 Authorized Testing Activities

The Tester is authorized to perform only the test types checked in Section 3.4,
on the in-scope systems listed in Section 3.1–3.2, during the authorization window
defined in Section 3.3. Testing shall be conducted professionally with the intent
to identify vulnerabilities without causing unnecessary damage, data loss, or
service disruption.

### 4.2 Prohibited Activities

Regardless of scope, the following are **strictly prohibited**:

- Testing any system not explicitly listed in Section 3
- Accessing, retaining, or exfiltrating client data beyond proof-of-concept needs
- Conducting tests outside the authorization window
- Sharing findings with third parties without written Client consent
- Any action targeting the systems listed in Section 3.5 (exclusions)
- Destroying, modifying, or encrypting any data

### 4.3 Client Responsibilities

The Client shall:
- Confirm it holds legal authority to authorize testing on all listed systems
- Notify hosting/cloud providers if required by their terms of service
- Provide an emergency contact available during testing:
  **Emergency Contact:** `____________________________`
  **Phone/Signal:** `____________________________`
- Ensure backups of critical data exist prior to testing commencement
- Accept responsibility for scoping accuracy

### 4.4 Tester Responsibilities

The Tester shall:
- Conduct all activities strictly within the agreed scope
- Immediately notify the Client upon discovery of critical vulnerabilities or
  evidence of active third-party compromise
- Cease all testing immediately upon written Client request
- Securely destroy any data obtained during testing after final report delivery
- Maintain detailed timestamped activity logs throughout the engagement

### 4.5 Confidentiality

All information obtained during the engagement — including vulnerability details,
system architecture, credentials, and any data encountered — is **strictly confidential**.

The Tester agrees not to disclose, publish, or share any findings without prior
written consent from the Client, **except where required by applicable law**.

This obligation survives termination of this agreement for **five (5) years**.

### 4.6 Limitation of Liability

The Tester shall exercise reasonable professional care to avoid service disruption
or data loss. The Client acknowledges that security testing carries inherent risks.

The Tester's liability for unintended damage is limited to direct damages up to
the total value of the engagement fee, **except in cases of gross negligence or
willful misconduct**. The Client waives claims for indirect, consequential, or
punitive damages.

### 4.7 Legal Compliance & Jurisdiction

This document constitutes lawful authorization under:

| Jurisdiction | Legislation |
|---|---|
| United States | Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 |
| United Kingdom | Computer Misuse Act 1990 |
| European Union | Directive 2013/40/EU on attacks against information systems |
| EU (data protection) | General Data Protection Regulation (GDPR) — Regulation (EU) 2016/679 |
| Other national law | Equivalent cybercrime legislation in jurisdictions where systems reside |

The Tester shall comply with GDPR obligations if personal data is incidentally
accessed, including minimizing processing and notifying the Client promptly.

**Governing Law:** `____________________________`

### 4.8 Dispute Resolution

Disputes shall be resolved through good-faith negotiation. Failing resolution
within 30 days, disputes shall proceed to binding arbitration under the rules
of the jurisdiction's competent authority.

---

## 5. ACKNOWLEDGMENT

By signing below, each party confirms that they have **read, understood, and agree**
to all terms in this Authorization. Signatories confirm they have authority to bind
their respective organizations.

---

## 6. SIGNATURES

### 6.1 Legal Representative — Client Organization

```
Full Name:    ___________________________________________

Title:        ___________________________________________

Company:      ___________________________________________

Signature:    ___________________________________________

Date:         ___________________________________________
```

---

### 6.2 Technical Owner — Client Organization

```
Full Name:    ___________________________________________

Title:        ___________________________________________

Department:   ___________________________________________

Signature:    ___________________________________________

Date:         ___________________________________________
```

---

### 6.3 Penetration Tester / Team Lead

```
Full Name:    ___________________________________________

Title / Team: ___________________________________________

Organization: ___________________________________________

Signature:    ___________________________________________

Date:         ___________________________________________
```

---

## 7. DOCUMENT INTEGRITY

If this form was generated automatically, the original SHA-256 integrity hash is:

**SHA-256:** `________________________________________________________________`

**Document UUID:** `__________________________________________`

> This form must be returned to the testing team in signed form (PDF scan or
> certified physical copy) before any Level-3 testing activities commence.
> Digital signatures (e.g., DocuSign, Adobe Sign) are accepted.

---

*END OF DOCUMENT*

---

> **Instructions:**
> 1. Fill in all fields and check applicable test type boxes.
> 2. All three signature blocks must be signed and dated.
> 3. Return a signed copy (scanned PDF or original) to the testing team.
> 4. The testing team will verify the document using `verify-consent.py` before proceeding.
