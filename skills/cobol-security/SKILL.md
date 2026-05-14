---
name: cobol-security
description: Specialized COBOL security analysis — EXEC SQL injection, unbound buffers, hardcoded credentials, COPY book dependencies, floating-point financial risks, and concrete COBOL remediation examples
version: 1.0.0
author: DevSec Team
tags: [security, devsec, cobol, mainframe, sast, sql-injection, credentials, legacy]
---

# COBOL Security Analysis

## Objective

Perform targeted security analysis of COBOL programs and JCL job streams, covering the most critical vulnerability patterns in mainframe environments: SQL injection via dynamic EXEC SQL, unbound buffer operations, hardcoded credentials in WORKING-STORAGE, insecure COPY book dependencies, and precision risks from floating-point arithmetic in financial calculations.

## Prerequisites

### Required Tools

| Tool | Installation | Purpose |
|------|-------------|---------|
| `semgrep` | `pip install semgrep` | Pattern-based SAST (with generic rules) |
| `grep` / `ripgrep` | System or `apt install ripgrep` | Pattern detection in COBOL source |
| `jq` | Package manager | JSON parsing |
| `awk` / `sed` | System | Text processing for custom analysis |

> **Note:** COBOL has no dedicated mainstream SAST tool as of 2024. Analysis relies on custom Semgrep rules in `generic` language mode and targeted grep patterns. Complex semantic analysis (taint tracking, data flow) requires manual review or specialist tooling (Micro Focus DevPartner, IBM Application Discovery).

---

## Part 1: EXEC SQL Injection Detection

### Background

COBOL programs embedding DB2 (or CICS/VSAM SQL) via `EXEC SQL` are vulnerable to injection if they build SQL statements using string concatenation with host variables containing user input.

### Detection Strategy

#### Pattern 1 — Dynamic SQL via EXECUTE IMMEDIATE

```bash
# Find all EXECUTE IMMEDIATE with potentially tainted host variables
grep -rn "EXECUTE IMMEDIATE" \
  --include="*.cbl" --include="*.cob" --include="*.CBL" --include="*.COB" \
  . > /tmp/cobol-exec-immediate.txt

cat /tmp/cobol-exec-immediate.txt
```

**Vulnerable pattern:**
```cobol
*> DANGEROUS — User input concatenated into dynamic SQL
WORKING-STORAGE SECTION.
01 WS-SQL-STMT     PIC X(500).
01 WS-USER-INPUT   PIC X(50).

PROCEDURE DIVISION.
    MOVE 'SELECT * FROM ACCOUNT WHERE CUSTID = ' TO WS-SQL-STMT
    STRING WS-SQL-STMT DELIMITED SPACE
           WS-USER-INPUT DELIMITED SPACE   *> ← INJECTION POINT
           INTO WS-SQL-STMT
    EXEC SQL
        EXECUTE IMMEDIATE :WS-SQL-STMT
    END-EXEC
```

**Secure pattern — parameterized PREPARE/EXECUTE:**
```cobol
*> SECURE — Use PREPARE with host variable placeholder
WORKING-STORAGE SECTION.
01 WS-STMT-NAME    PIC X(18) VALUE 'CUST-LOOKUP       '.
01 WS-CUSTID       PIC X(20).   *> Validated input goes here

PROCEDURE DIVISION.
    *> Validate WS-CUSTID first (see Part 5)
    EXEC SQL
        PREPARE CUST-LOOKUP FROM
            'SELECT NAME, BALANCE FROM ACCOUNT WHERE CUSTID = ?'
    END-EXEC
    EXEC SQL
        EXECUTE CUST-LOOKUP USING :WS-CUSTID
    END-EXEC
```

#### Pattern 2 — STRING Concatenation Feeding EXEC SQL

```bash
# Find STRING operations that feed into variables used in EXEC SQL
grep -rn "STRING" --include="*.cbl" --include="*.cob" . | grep -v "^\*" > /tmp/cobol-string-ops.txt

# Cross-reference with EXEC SQL in same paragraph
awk '
  /EXEC SQL/ { in_sql = 1 }
  /END-EXEC/ { in_sql = 0 }
  in_sql && /:[A-Z]/ { print FILENAME ":" NR ": potential host var: " $0 }
' $(find . -name "*.cbl" -o -name "*.cob") > /tmp/cobol-host-vars.txt
```

#### Semgrep Custom Rule for COBOL SQL Injection

Create file `cobol-sqli-rules.yaml`:
```yaml
rules:
  - id: cobol-execute-immediate-injection
    patterns:
      - pattern: |
          STRING $USER_INPUT DELIMITED $DELIM
                 INTO $SQL_VAR
      - pattern: |
          EXECUTE IMMEDIATE :$SQL_VAR
    message: |
      Potential SQL injection: user input concatenated into SQL via STRING, then
      executed with EXECUTE IMMEDIATE. Use PREPARE/EXECUTE with host variable placeholders.
    severity: ERROR
    languages: [generic]
    metadata:
      owasp: "A03:2021 – Injection"
      cwe: "CWE-89"
    paths:
      include:
        - "*.cbl"
        - "*.cob"
        - "*.CBL"
        - "*.COB"

  - id: cobol-dynamic-sql-without-prepare
    pattern: |
      EXEC SQL
          EXECUTE IMMEDIATE $STMT
      END-EXEC
    pattern-not: |
      EXEC SQL PREPARE $NAME FROM $LITERAL
      ...
      EXEC SQL EXECUTE $NAME USING $PARAMS
      END-EXEC
    message: |
      EXECUTE IMMEDIATE found without corresponding PREPARE pattern.
      Verify that $STMT does not contain user-controlled input.
    severity: WARNING
    languages: [generic]
    paths:
      include: ["*.cbl", "*.cob"]
```

```bash
semgrep --config cobol-sqli-rules.yaml --lang generic . > /tmp/cobol-sqli-findings.json
```

---

## Part 2: Unbound Buffer Detection (PERFORM, MOVE, STRING)

### Background

COBOL does not have pointers or direct memory access, but numeric overflow, receiving field truncation, and STRING/UNSTRING without SIZE ERROR can corrupt data silently — or, in rare hybrid C/COBOL environments, lead to actual buffer overflows.

### Detection Patterns

#### 2a — MOVE without SIZE ERROR on numeric fields

```bash
# Find COMPUTE/ADD/SUBTRACT/MULTIPLY/DIVIDE without SIZE ERROR
grep -rn "COMPUTE\|ADD\|SUBTRACT\|MULTIPLY\|DIVIDE" \
  --include="*.cbl" --include="*.cob" . | \
  grep -v "SIZE ERROR\|ON SIZE\|^\*" > /tmp/cobol-no-size-error.txt

echo "Statements potentially missing SIZE ERROR:"
wc -l /tmp/cobol-no-size-error.txt
head -20 /tmp/cobol-no-size-error.txt
```

**Vulnerable:**
```cobol
*> No SIZE ERROR — silent overflow if result > PIC 9(5)
01 WS-TOTAL  PIC 9(5).
01 WS-A      PIC 9(4).
01 WS-B      PIC 9(4).

COMPUTE WS-TOTAL = WS-A * WS-B    *> 9999 * 9999 = 99980001 — truncated to 80001!
```

**Secure:**
```cobol
COMPUTE WS-TOTAL = WS-A * WS-B
    ON SIZE ERROR
        MOVE 'Y' TO WS-OVERFLOW-FLAG
        PERFORM HANDLE-OVERFLOW-ERROR
    NOT ON SIZE ERROR
        CONTINUE
END-COMPUTE
```

#### 2b — STRING/UNSTRING without OVERFLOW clause

```bash
grep -rn "STRING\|UNSTRING" --include="*.cbl" --include="*.cob" . | \
  grep -v "ON OVERFLOW\|OVERFLOW\|^\*" > /tmp/cobol-string-no-overflow.txt
```

**Vulnerable:**
```cobol
*> STRING without OVERFLOW — receiving field may be too small
01 WS-RESULT  PIC X(50).
01 WS-PART1   PIC X(30).
01 WS-PART2   PIC X(30).

STRING WS-PART1 DELIMITED SPACE
       WS-PART2 DELIMITED SPACE
       INTO WS-RESULT              *> Truncated silently if > 50 chars!
```

**Secure:**
```cobol
STRING WS-PART1 DELIMITED SPACE
       WS-PART2 DELIMITED SPACE
       INTO WS-RESULT
    ON OVERFLOW
        MOVE 'Y' TO WS-STRING-OVERFLOW
        PERFORM LOG-STRING-OVERFLOW-ERROR
END-STRING
```

#### 2c — PERFORM VARYING without bounds check

```bash
# Find PERFORM VARYING — verify loop bounds are validated
grep -rn "PERFORM.*VARYING\|PERFORM VARYING" --include="*.cbl" . | \
  grep -v "^\*" > /tmp/cobol-perform-varying.txt
```

**Risky pattern:**
```cobol
*> If WS-COUNT is tainted (from external input), loop could run excessively
PERFORM PROCESS-RECORD
    VARYING WS-IDX FROM 1 BY 1
    UNTIL WS-IDX > WS-COUNT       *> WS-COUNT must be validated!
```

**Secure:**
```cobol
*> Validate WS-COUNT before loop
IF WS-COUNT < 1 OR WS-COUNT > MAX-RECORDS
    MOVE 'Y' TO WS-INVALID-COUNT
    PERFORM HANDLE-INVALID-INPUT
    STOP RUN
END-IF

PERFORM PROCESS-RECORD
    VARYING WS-IDX FROM 1 BY 1
    UNTIL WS-IDX > WS-COUNT
```

---

## Part 3: Hardcoded Credentials in WORKING-STORAGE

### Background

Credentials (database passwords, MQ credentials, RACF user IDs) are often hardcoded in COBOL `WORKING-STORAGE SECTION` or `LINKAGE SECTION`, sometimes in `COPY` books shared across many programs.

### Detection

```bash
# Search for common credential patterns in WORKING-STORAGE
grep -rni \
  "PASSWORD\|PASSWD\|PWD\|SECRET\|TOKEN\|CREDENTIAL\|API-KEY\|APIKEY\|DB2-PASS\|DBPASS" \
  --include="*.cbl" --include="*.cob" --include="*.cpy" --include="*.CPY" \
  . > /tmp/cobol-credential-candidates.txt

# Look for VALUE clauses following password-like field names
grep -rn "PASSWORD.*VALUE\|PASSWD.*VALUE\|PWD.*VALUE\|PASSW.*VALUE" \
  --include="*.cbl" --include="*.cob" . | grep -v "SPACES\|LOW-VALUES\|HIGH-VALUES\|ZEROS\|^\*" \
  > /tmp/cobol-hardcoded-creds.txt

echo "=== Potential hardcoded credentials ==="
cat /tmp/cobol-hardcoded-creds.txt
```

**Vulnerable pattern:**
```cobol
WORKING-STORAGE SECTION.
*> DANGEROUS — hardcoded credentials
01 WS-DB2-CONNECT.
   05 WS-DB2-SUBSYS    PIC X(4)   VALUE 'DB2P'.
   05 WS-DB2-USER      PIC X(8)   VALUE 'SVCACCT '.  *> Hardcoded!
   05 WS-DB2-PASSWORD  PIC X(8)   VALUE 'Secr3t! '.  *> CRITICAL
   05 WS-MQ-PASSWORD   PIC X(32)  VALUE 'myMQpass123456  '.  *> CRITICAL
```

**Secure pattern — read from secured parameter file or encrypted dataset:**
```cobol
WORKING-STORAGE SECTION.
01 WS-DB2-CONNECT.
   05 WS-DB2-SUBSYS    PIC X(4).
   05 WS-DB2-USER      PIC X(8).
   05 WS-DB2-PASSWORD  PIC X(8).

PROCEDURE DIVISION.
    *> Read credentials from secured, encrypted parameter file
    PERFORM READ-SECURE-CONFIG

    *> Or: read from SYSIN DD (passed from JCL with encrypted value)
    *> Or: call external security API (e.g., CARLa, RACF RACDCERT)

READ-SECURE-CONFIG.
    OPEN INPUT CONFIG-FILE
    READ CONFIG-FILE INTO WS-DB2-CONNECT
    CLOSE CONFIG-FILE
    *> CONFIG-FILE should be a secured dataset (RACF-protected, encrypted at rest)
```

**JCL approach (no credentials in source):**
```jcl
//STEP01   EXEC PGM=MYCOBOLPGM
//SYSPRINT DD SYSOUT=*
//DBCONFIG  DD DSN=SYS1.SECURE.PARMS(DBCREDS),
//             DISP=SHR,LABEL=(,,,IN)
*> Dataset SYS1.SECURE.PARMS protected by RACF with READ access only to batch ID
```

---

## Part 4: COPY Book Dependency Analysis

### Background

COPY books (`.cpy`) are shared include files in COBOL. Vulnerable or outdated library interfaces embedded in widely-used COPY books can propagate security issues across hundreds of programs.

### Detection

```bash
# List all COPY statements and the books they reference
grep -rn "^[[:space:]]*COPY " --include="*.cbl" --include="*.cob" . | \
  awk '{print $2}' | sort | uniq -c | sort -rn > /tmp/cobol-copy-usage.txt

echo "Top 20 most-used COPY books:"
head -20 /tmp/cobol-copy-usage.txt

# Find COPY books that contain credential or security-sensitive fields
grep -rn "PASSWORD\|PASSWD\|TOKEN\|SECRET\|ENCRYPT" \
  --include="*.cpy" --include="*.CPY" . > /tmp/copybook-sensitive-fields.txt

# Find programs using deprecated or known-risky external CALL interfaces
grep -rn "CALL.*DB2\|CALL.*CICS\|CALL.*MQ\|CALL.*IMS" \
  --include="*.cbl" --include="*.cob" . > /tmp/cobol-external-calls.txt

# Check for obsolete COPY books (based on modified date)
find . -name "*.cpy" -o -name "*.CPY" | while read f; do
  days_old=$(( ($(date +%s) - $(date +%s -r "$f")) / 86400 ))
  if [ "$days_old" -gt 730 ]; then
    echo "STALE ($days_old days): $f"
  fi
done > /tmp/cobol-stale-copybooks.txt
```

**Security-sensitive COPY book example (flag for review):**
```cobol
*> BADCOPY.CPY — shared across 150 programs — contains hardcoded DB schema
01 WS-ACCT-RECORD.
   05 ACCT-ID         PIC 9(10).
   05 ACCT-BALANCE    PIC S9(13)V99 COMP-3.
   05 ACCT-PIN        PIC 9(4).      *> Storing PIN in clear — CRITICAL
   05 ACCT-SSN        PIC X(11).     *> PII — RGPD/GDPR concern
```

**Remediation approach:**
```cobol
*> SAFECOPY.CPY — remediated version
01 WS-ACCT-RECORD.
   05 ACCT-ID         PIC 9(10).
   05 ACCT-BALANCE    PIC S9(13)V99 COMP-3.
   05 ACCT-PIN-HASH   PIC X(64).    *> Store SHA-256 hash, never plain PIN
   05 ACCT-SSN-TOKEN  PIC X(16).    *> Tokenized SSN via vault — not raw value
```

---

## Part 5: COMP-1/COMP-2 Floating-Point in Financial Calculations

### Background

`COMP-1` (single-precision IEEE 754 float) and `COMP-2` (double-precision) are **not suitable for financial calculations** because they use binary floating-point arithmetic, which cannot represent decimal values like 0.1 exactly. This leads to rounding errors, audit discrepancies, and in worst cases, regulatory compliance failures.

### Detection

```bash
# Find COMP-1 and COMP-2 field definitions
grep -rn "COMP-1\|COMPUTATIONAL-1\|COMP-2\|COMPUTATIONAL-2" \
  --include="*.cbl" --include="*.cob" --include="*.cpy" . > /tmp/cobol-float-fields.txt

echo "=== COMP-1/COMP-2 fields found (review for financial use) ==="
cat /tmp/cobol-float-fields.txt

# Check if these fields appear in financial calculation paragraphs
FLOAT_FIELDS=$(grep -rn "COMP-1\|COMP-2" --include="*.cbl" . | \
  awk -F'[. ]' '{for(i=1;i<=NF;i++) if($i ~ /^[0-9][0-9]$/) print $(i+1)}' | sort -u)

for field in $FLOAT_FIELDS; do
  echo "=== Uses of $field ===" 
  grep -rn "$field" --include="*.cbl" . | grep -E "COMPUTE|ADD|SUBTRACT|MULTIPLY" | head -5
done
```

**Vulnerable — floating-point accumulator for balances:**
```cobol
WORKING-STORAGE SECTION.
*> DANGEROUS — COMP-2 for financial accumulation
01 WS-TOTAL-BALANCE    COMP-2.    *> Binary float — precision loss!
01 WS-INTEREST-RATE    COMP-2.
01 WS-TAX-AMOUNT       COMP-2.

PROCEDURE DIVISION.
    COMPUTE WS-TOTAL-BALANCE = WS-TOTAL-BALANCE + 0.10
    *> Binary: 0.1 cannot be represented exactly
    *> After 1000 iterations, accumulated error can be significant
```

**Secure — use COMP-3 (packed decimal) for financial arithmetic:**
```cobol
WORKING-STORAGE SECTION.
*> CORRECT — COMP-3 (packed decimal) preserves decimal precision
01 WS-TOTAL-BALANCE    PIC S9(13)V99 COMP-3.   *> ±9,999,999,999,999.99
01 WS-INTEREST-RATE    PIC S9(3)V9(6) COMP-3.  *> e.g. 0.045625
01 WS-TAX-AMOUNT       PIC S9(11)V99 COMP-3.
01 WS-WORK-AMOUNT      PIC S9(15)V9(4) COMP-3. *> Working field with extra digits

PROCEDURE DIVISION.
    *> Exact decimal arithmetic
    COMPUTE WS-TOTAL-BALANCE ROUNDED =
        WS-TOTAL-BALANCE + WS-INTEREST-RATE
    ON SIZE ERROR
        PERFORM HANDLE-BALANCE-OVERFLOW
    END-COMPUTE
```

**Detection rule (Semgrep):**
```yaml
rules:
  - id: cobol-float-in-financial-context
    patterns:
      - pattern: |
          $FIELD COMP-1
      - pattern-inside: |
          WORKING-STORAGE SECTION.
          ...
    pattern-regex: "(BALANCE|AMOUNT|TOTAL|INTEREST|RATE|PAYMENT|PREMIUM|PRICE|FEE|TAX|COST)"
    message: |
      COMP-1 (single-precision float) found in a field with a financial name.
      Use COMP-3 (packed decimal) or PIC 9(n)V9(m) for monetary calculations
      to avoid binary floating-point precision errors.
    severity: ERROR
    languages: [generic]
    metadata:
      cwe: "CWE-681"
    paths:
      include: ["*.cbl", "*.cob", "*.cpy"]
```

---

## Part 6: Input Validation Patterns

### External Input Sources in COBOL

| Source | COBOL Construct | Risk |
|--------|----------------|------|
| Batch file records | `READ ... INTO` | Data length, format |
| CICS screen maps | `EXEC CICS RECEIVE MAP` | All injection types |
| MQ messages | `MQGET` call | Content injection |
| DB2 query results | `EXEC SQL FETCH` | Trust boundary |
| SYSIN JCL parameters | `ACCEPT ... FROM SYSIN` | Length, format |

### Validation Template

```cobol
WORKING-STORAGE SECTION.
01 WS-VALIDATION-STATUS   PIC X(1).
   88 VALID-INPUT         VALUE 'Y'.
   88 INVALID-INPUT       VALUE 'N'.

01 WS-USER-ID             PIC X(20).
01 WS-USER-ID-LEN         PIC 99.

*> ─────────────────────────────────────────────────────
VALIDATE-USER-INPUT.
    MOVE 'Y' TO WS-VALIDATION-STATUS

    *> Check 1: Length validation
    MOVE FUNCTION LENGTH(FUNCTION TRIM(WS-USER-ID TRAILING))
        TO WS-USER-ID-LEN
    IF WS-USER-ID-LEN < 1 OR WS-USER-ID-LEN > 20
        MOVE 'N' TO WS-VALIDATION-STATUS
        MOVE 'INVALID LENGTH' TO WS-ERROR-MSG
        GO TO VALIDATE-USER-INPUT-EXIT
    END-IF

    *> Check 2: Allowed characters only (alphanumeric + hyphen)
    INSPECT WS-USER-ID
        TALLYING WS-INVALID-CHARS FOR ALL
            SPECIAL-NAMES  *> Customize with your allowlist
    IF WS-INVALID-CHARS > 0
        MOVE 'N' TO WS-VALIDATION-STATUS
        MOVE 'INVALID CHARS' TO WS-ERROR-MSG
        GO TO VALIDATE-USER-INPUT-EXIT
    END-IF

    *> Check 3: SQL metacharacter rejection
    IF WS-USER-ID(1:1) = ''''
        OR WS-USER-ID(1:2) = '--'
        OR WS-USER-ID(1:2) = '/*'
        MOVE 'N' TO WS-VALIDATION-STATUS
        MOVE 'SQL INJECTION ATTEMPT' TO WS-ERROR-MSG
    END-IF

    VALIDATE-USER-INPUT-EXIT.
        EXIT.
```

---

## Complete COBOL Security Scan Script

```bash
#!/bin/bash
# COBOL Security Scan — CyberStrikeAI DevSec
# Usage: ./cobol-scan.sh [project-dir] [output-dir]

PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./cobol-security-results}"
mkdir -p "$OUTPUT_DIR"

echo "=== CyberStrikeAI COBOL Security Scan ==="
echo "Target: $PROJECT_DIR"
echo ""

COBOL_FILES=$(find "$PROJECT_DIR" -name "*.cbl" -o -name "*.cob" -o \
              -name "*.CBL" -o -name "*.COB" 2>/dev/null | wc -l)
COPY_FILES=$(find "$PROJECT_DIR" -name "*.cpy" -o -name "*.CPY" 2>/dev/null | wc -l)

echo "Found: $COBOL_FILES COBOL source files, $COPY_FILES COPY books"
echo ""

if [ "$COBOL_FILES" -eq 0 ]; then
  echo "No COBOL files found in $PROJECT_DIR"
  exit 0
fi

echo "=== 1. SQL Injection (EXECUTE IMMEDIATE) ==="
grep -rn "EXECUTE IMMEDIATE" "$PROJECT_DIR" \
  --include="*.cbl" --include="*.cob" --include="*.CBL" --include="*.COB" \
  > "$OUTPUT_DIR/sqli-execute-immediate.txt" 2>/dev/null
echo "  Found: $(wc -l < "$OUTPUT_DIR/sqli-execute-immediate.txt") occurrences"

echo ""
echo "=== 2. Hardcoded Credentials ==="
grep -rni "PASSWORD.*VALUE\|PASSWD.*VALUE\|PWD.*VALUE" \
  --include="*.cbl" --include="*.cob" --include="*.cpy" "$PROJECT_DIR" | \
  grep -v "SPACES\|LOW-VALUES\|HIGH-VALUES\|ZEROS\|^\s*\*" \
  > "$OUTPUT_DIR/hardcoded-credentials.txt" 2>/dev/null
echo "  Found: $(wc -l < "$OUTPUT_DIR/hardcoded-credentials.txt") candidates"

echo ""
echo "=== 3. Missing SIZE ERROR ==="
grep -rn "COMPUTE\b" "$PROJECT_DIR" \
  --include="*.cbl" --include="*.cob" | \
  grep -v "SIZE ERROR\|^\s*\*" \
  > "$OUTPUT_DIR/missing-size-error.txt" 2>/dev/null
echo "  Found: $(wc -l < "$OUTPUT_DIR/missing-size-error.txt") COMPUTE without SIZE ERROR"

echo ""
echo "=== 4. COMP-1/COMP-2 Fields ==="
grep -rn "COMP-1\|COMPUTATIONAL-1\|COMP-2\|COMPUTATIONAL-2" \
  --include="*.cbl" --include="*.cob" --include="*.cpy" "$PROJECT_DIR" \
  > "$OUTPUT_DIR/float-fields.txt" 2>/dev/null
echo "  Found: $(wc -l < "$OUTPUT_DIR/float-fields.txt") floating-point fields"

echo ""
echo "=== 5. COPY Book Analysis ==="
grep -rni "PASSWORD\|PASSWD\|TOKEN\|SECRET" \
  --include="*.cpy" --include="*.CPY" "$PROJECT_DIR" \
  > "$OUTPUT_DIR/sensitive-copybooks.txt" 2>/dev/null
echo "  Found: $(wc -l < "$OUTPUT_DIR/sensitive-copybooks.txt") sensitive fields in COPY books"

echo ""
echo "=== 6. Semgrep SAST ==="
if command -v semgrep > /dev/null 2>&1; then
  semgrep \
    --lang generic \
    --pattern 'EXECUTE IMMEDIATE :$STMT' \
    --json \
    "$PROJECT_DIR" > "$OUTPUT_DIR/semgrep-cobol.json" 2>/dev/null
  echo "  Semgrep run complete"
else
  echo "  [WARN] semgrep not installed — skipping"
fi

echo ""
echo "=== SCAN COMPLETE ==="
echo "Results in: $OUTPUT_DIR/"
echo ""
echo "=== SUMMARY ==="
SQLI=$(wc -l < "$OUTPUT_DIR/sqli-execute-immediate.txt")
CREDS=$(wc -l < "$OUTPUT_DIR/hardcoded-credentials.txt")
NOSIZE=$(wc -l < "$OUTPUT_DIR/missing-size-error.txt")
FLOATS=$(wc -l < "$OUTPUT_DIR/float-fields.txt")

echo "  SQL Injection candidates     : $SQLI"
echo "  Hardcoded credential suspects: $CREDS"
echo "  COMPUTE without SIZE ERROR   : $NOSIZE"
echo "  Floating-point (COMP-1/2)    : $FLOATS"

if [ "$CREDS" -gt 0 ] || [ "$SQLI" -gt 0 ]; then
  echo ""
  echo "❌ CRITICAL findings require immediate review"
  exit 1
else
  echo ""
  echo "✅ No obvious critical issues — manual review still recommended for COBOL"
  exit 0
fi
```

---

## Severity Classification

| Pattern | Severity | OWASP | CWE |
|---------|----------|-------|-----|
| EXECUTE IMMEDIATE with concatenated input | CRITICAL | A03 Injection | CWE-89 |
| Hardcoded password in WORKING-STORAGE | CRITICAL | A07 Auth Failures | CWE-798 |
| Hardcoded password in COPY book | CRITICAL | A07 Auth Failures | CWE-798 |
| COMP-1/COMP-2 in financial fields | HIGH | A04 Insecure Design | CWE-681 |
| STRING/UNSTRING without OVERFLOW | MEDIUM | A04 Insecure Design | CWE-119 |
| COMPUTE without SIZE ERROR | MEDIUM | A04 Insecure Design | CWE-190 |
| PII in COPY book without tokenization | HIGH | RGPD Article 25 | CWE-312 |
| Stale COPY book (>2 years, no update) | LOW | A06 Outdated Components | — |

## Related Skills

- `cve-dependency-scan` — CVE scanning for COBOL hybrid projects with JAR/DLL dependencies
- `sast-devsec` — Broader SAST including gitleaks for COBOL credential detection
- `devsec-report` — Aggregate COBOL findings into the unified report
