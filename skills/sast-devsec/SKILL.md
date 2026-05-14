---
name: sast-devsec
description: Advanced SAST for DevSec teams — secret detection, hardcoded credentials, and language-specific dangerous patterns for C#, COBOL, Java, React, JavaScript, and TypeScript
version: 1.0.0
author: DevSec Team
tags: [security, devsec, sast, secrets, gitleaks, trufflehog, static-analysis, hardcoded-credentials]
---

# SAST DevSec

## Objective

Perform deep static analysis beyond OWASP coverage: detect hardcoded secrets and credentials, identify dangerous code patterns per language (unsafe code, deserialization, XSS, buffer overflows), and correlate findings with known CVE vulnerabilities when applicable.

## Prerequisites

### Required Tools

| Tool | Installation | Purpose |
|------|-------------|---------|
| `gitleaks` | `brew install gitleaks` or [GitHub releases](https://github.com/gitleaks/gitleaks/releases) | Secret/credential detection in git history and files |
| `trufflehog` | `pip install trufflehog` or [GitHub releases](https://github.com/trufflesecurity/trufflehog/releases) | Deep secret scanning with entropy analysis |
| `semgrep` | `pip install semgrep` | Pattern-based SAST |
| `jq` | Package manager | JSON parsing |

## Part 1: Secret and Credential Detection

### Tool 1A: Gitleaks

Gitleaks scans git history and working directory for secrets: API keys, passwords, tokens, private keys.

```bash
# Scan entire repo including git history
gitleaks detect --source . --report-format json --report-path gitleaks-report.json

# Scan only working directory (no git history)
gitleaks detect --source . --no-git --report-format json --report-path gitleaks-nowhistory.json

# Scan a specific branch
gitleaks detect --source . --log-opts="main..HEAD" --report-format json --report-path gitleaks-branch.json

# Use with CI (exit code 1 if secrets found)
gitleaks detect --source . --exit-code 1
```

**Gitleaks detects (partial list):**
- AWS Access Keys / Secret Keys
- Google API Keys / Service Account credentials
- GitHub / GitLab / Azure tokens
- Slack / Stripe / Twilio API keys
- SSH private keys (PEM)
- Database connection strings with passwords
- JWT secrets in config files
- `.env` file secrets

**Custom rules for enterprise patterns** (`gitleaks.toml`):
```toml
[[rules]]
id = "company-internal-token"
description = "Company internal API token"
regex = '''COMPANY_[A-Z0-9]{32}'''
tags = ["secret", "company"]

[[rules]]
id = "db-connection-string"
description = "Database connection string with embedded credentials"
regex = '''(Server|Data Source)=[^;]+;.{0,50}(Password|PWD)=[^;]+'''
tags = ["secret", "database"]
```

### Tool 1B: TruffleHog

TruffleHog performs entropy analysis and pattern matching to find high-entropy strings (likely secrets).

```bash
# Scan git repo with verification (checks if secrets are live)
trufflehog git file://. --json > trufflehog-report.json

# Scan without verification (faster)
trufflehog git file://. --no-verification --json > trufflehog-report.json

# Scan a specific GitHub repo
trufflehog github --repo=https://github.com/org/repo --json > trufflehog-github.json

# Scan filesystem
trufflehog filesystem /path/to/project --json > trufflehog-fs.json
```

### Combining Gitleaks + TruffleHog

```bash
#!/bin/bash
# Run both scanners and merge results

echo "=== Running Gitleaks ==="
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks.json 2>&1

echo "=== Running TruffleHog ==="
trufflehog git file://. --no-verification --json > /tmp/trufflehog.json 2>&1

# Combine into unified report
python3 - <<'EOF'
import json

findings = []

# Parse gitleaks
try:
    with open('/tmp/gitleaks.json') as f:
        gl = json.load(f)
        for item in gl:
            findings.append({
                "tool": "gitleaks",
                "rule": item.get("RuleID"),
                "description": item.get("Description"),
                "file": item.get("File"),
                "line": item.get("StartLine"),
                "secret_preview": item.get("Secret", "")[:20] + "...",
                "commit": item.get("Commit")
            })
except Exception as e:
    print(f"Gitleaks parse error: {e}")

# Parse trufflehog
try:
    with open('/tmp/trufflehog.json') as f:
        for line in f:
            th = json.loads(line)
            findings.append({
                "tool": "trufflehog",
                "rule": th.get("DetectorName"),
                "description": f"High-entropy secret: {th.get('DetectorName')}",
                "file": th.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file"),
                "line": None,
                "secret_preview": "[redacted]",
                "commit": th.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit")
            })
except Exception as e:
    print(f"TruffleHog parse error: {e}")

print(json.dumps({"secrets_found": len(findings), "findings": findings}, indent=2))
EOF
```

---

## Part 2: Language-Specific Dangerous Patterns

### C# — Unsafe Code & Dangerous APIs

```bash
# Semgrep rules for C# dangerous patterns
semgrep --config 'r/csharp.dotnet.security' \
        --config 'r/csharp.dotnet.correctness' \
        --json --output csharp-sast.json .
```

**Patterns detected:**

#### Unsafe Code / P/Invoke
```csharp
// DANGEROUS — unsafe block with pointer manipulation
unsafe {
    int* ptr = &value;
    *(ptr + offset) = data; // Buffer overflow risk
}

// DANGEROUS — P/Invoke with unvalidated input
[DllImport("kernel32.dll")]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);
// Input size not validated before passing to native call
```

**Semgrep rule (custom):**
```yaml
rules:
  - id: csharp-unsafe-pinvoke-size
    patterns:
      - pattern: |
          [DllImport(...)]
          static extern $RET $FUNC($PARAMS);
    message: "P/Invoke declaration found — verify all size parameters are validated"
    severity: WARNING
    languages: [csharp]
```

#### XML External Entity (XXE)
```csharp
// VULNERABLE — XmlDocument with DTD processing enabled
var doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver(); // Allows external DTD
doc.Load(xmlInput);

// SECURE
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
var reader = XmlReader.Create(xmlInput, settings);
```

#### Insecure Deserialization
```csharp
// DANGEROUS — BinaryFormatter (deprecated in .NET 5+, removed in .NET 9)
var formatter = new BinaryFormatter();
var obj = (MyClass)formatter.Deserialize(stream); // RCE risk

// DANGEROUS — TypeNameHandling in Newtonsoft
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All // NEVER use All or Auto with untrusted input
};

// SAFE alternatives
var obj = JsonSerializer.Deserialize<MyClass>(json); // System.Text.Json
var obj = MessagePackSerializer.Deserialize<MyClass>(bytes); // MessagePack
```

---

### COBOL — EXEC SQL Injection & Buffer Overflow Patterns

```bash
# COBOL has limited automated SAST tooling; use custom Semgrep + grep patterns
semgrep --lang generic --config custom-cobol-rules.yaml .

# Grep-based detection for common issues
grep -rn "EXEC SQL" --include="*.cbl" --include="*.cob" . | grep -v "PREPARE\|?" > cobol-sqli-candidates.txt
grep -rn "STRING\|UNSTRING\|MOVE" --include="*.cbl" | grep -v "SIZE ERROR" > cobol-buffer-candidates.txt
```

**Custom Semgrep rules for COBOL** (`custom-cobol-rules.yaml`):
```yaml
rules:
  - id: cobol-dynamic-sql-injection
    pattern: |
      EXEC SQL
          $SQL-STMT
      END-EXEC
    pattern-not: |
      EXEC SQL PREPARE $STMT-NAME FROM $HOST-VAR
      ...
      EXEC SQL EXECUTE $STMT-NAME USING $PARAMS
      END-EXEC
    message: "Potential SQL injection in COBOL EXEC SQL — verify statement uses PREPARE/EXECUTE with host variables"
    severity: WARNING
    languages: [generic]
    paths:
      include:
        - "*.cbl"
        - "*.cob"

  - id: cobol-missing-size-error
    pattern: |
      MOVE $SRC TO $DEST
    pattern-not: |
      MOVE $SRC TO $DEST
          ON SIZE ERROR
              $HANDLER
      END-MOVE
    message: "MOVE statement without SIZE ERROR clause — potential buffer overflow for numeric fields"
    severity: INFO
    languages: [generic]
    paths:
      include:
        - "*.cbl"
```

**COBOL dangerous patterns to look for:**

```cobol
*> VULNERABLE — Dynamic SQL built with string concatenation
MOVE 'SELECT * FROM USER WHERE ID = ' TO WS-SQL-STMT
STRING WS-SQL-STMT DELIMITED SPACE
       WS-USER-INPUT DELIMITED SPACE  *> User input directly concatenated!
       INTO WS-DYNAMIC-SQL
EXEC SQL EXECUTE IMMEDIATE :WS-DYNAMIC-SQL END-EXEC

*> SECURE — Use parameterized query
EXEC SQL
    SELECT NAME INTO :WS-NAME
    FROM USER
    WHERE ID = :WS-USER-ID  *> Host variable, not string concat
END-EXEC

*> VULNERABLE — No SIZE ERROR on arithmetic
COMPUTE WS-RESULT = WS-VALUE1 * WS-VALUE2  *> Overflow possible

*> SECURE
COMPUTE WS-RESULT = WS-VALUE1 * WS-VALUE2
    ON SIZE ERROR
        MOVE 'OVERFLOW' TO WS-ERROR-FLAG
END-COMPUTE
```

---

### Java — Deserialization, XXE, Path Traversal

```bash
semgrep --config 'r/java.lang.security.audit' \
        --config 'r/java.spring.security' \
        --json --output java-sast.json .
```

**Deserialization:**
```java
// VULNERABLE — Java native deserialization
ObjectInputStream ois = new ObjectInputStream(userInputStream);
Object obj = ois.readObject(); // RCE if gadget chain available

// VULNERABLE — XStream without security
XStream xstream = new XStream();
Object obj = xstream.fromXML(userXml); // CVE-2021-39144

// SECURE — Jackson with type restrictions
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    LaissezFaireSubTypeValidator.instance,
    ObjectMapper.DefaultTyping.NON_FINAL,
    JsonTypeInfo.As.PROPERTY  // Only for trusted sources
);
// Better: use @JsonTypeInfo only on specific classes
```

**XXE:**
```java
// VULNERABLE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(xmlInput); // XXE possible

// SECURE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**Path Traversal:**
```java
// VULNERABLE
String filename = request.getParameter("file");
File f = new File("/app/uploads/" + filename); // ../../etc/passwd possible
Files.readAllBytes(f.toPath());

// SECURE
Path base = Paths.get("/app/uploads/").toRealPath();
Path file = base.resolve(filename).normalize();
if (!file.startsWith(base)) throw new SecurityException("Path traversal detected");
Files.readAllBytes(file);
```

---

### React / JavaScript / TypeScript — XSS, eval, dangerouslySetInnerHTML

```bash
semgrep --config 'r/javascript.react.security' \
        --config 'r/typescript.react.security' \
        --config 'r/javascript.lang.security.audit' \
        --json --output react-sast.json .
```

**XSS and dangerouslySetInnerHTML:**
```jsx
// VULNERABLE — Direct HTML injection
function UserProfile({ bio }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />; // XSS if bio is user-controlled
}

// SECURE — Sanitize before rendering
import DOMPurify from 'dompurify';
function UserProfile({ bio }) {
  const cleanBio = DOMPurify.sanitize(bio);
  return <div dangerouslySetInnerHTML={{ __html: cleanBio }} />;
}

// EVEN BETTER — Avoid dangerouslySetInnerHTML entirely
function UserProfile({ bio }) {
  return <div>{bio}</div>; // React auto-escapes text content
}
```

**eval() and dynamic code:**
```javascript
// DANGEROUS — eval with user input
eval(userInput);                    // RCE risk in Node.js
new Function(userInput)();          // Same risk
setTimeout(userInput, 1000);        // If userInput is a string

// DANGEROUS — document.write
document.write('<script>' + userInput + '</script>');

// SECURE — Use safe alternatives
const fn = safePrecompiledFunction;  // Never build from strings
setTimeout(() => myFunction(safeArg), 1000);  // Pass function reference
```

**Prototype pollution:**
```javascript
// VULNERABLE
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key]; // __proto__ can be overwritten
  }
}

// SECURE
function safeMerge(target, source) {
  const safeKeys = Object.keys(source).filter(k => k !== '__proto__' && k !== 'constructor');
  safeKeys.forEach(k => { target[k] = source[k]; });
}
// Or use: Object.assign({}, source) with Object.create(null) as base
```

---

## Part 3: CVE Correlation

When a dangerous pattern is found involving a third-party dependency, correlate with CVE data:

```bash
#!/bin/bash
# After SAST scan, check if affected packages have known CVEs

# Extract package references from SAST findings
jq -r '.results[] | .extra.metadata.dependency // empty' semgrep-results.json | sort -u > affected-packages.txt

# Cross-reference with Grype CVE database
while IFS= read -r pkg; do
  echo "Checking CVEs for: $pkg"
  grype "$pkg" -o json >> cve-correlation.json
done < affected-packages.txt

echo "CVE correlation complete: cve-correlation.json"
```

---

## Full SAST Scan Script

```bash
#!/bin/bash
# Full SAST scan pipeline

PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./sast-results}"
mkdir -p "$OUTPUT_DIR"

echo "=== Phase 1: Secret Detection ==="
gitleaks detect --source "$PROJECT_DIR" --report-format json \
  --report-path "$OUTPUT_DIR/gitleaks.json" || true
trufflehog git "file://$PROJECT_DIR" --no-verification --json \
  > "$OUTPUT_DIR/trufflehog.json" 2>&1 || true

echo "=== Phase 2: Language-Specific SAST ==="
semgrep \
  --config "p/csharp" \
  --config "p/java" \
  --config "p/javascript" \
  --config "p/typescript" \
  --config "p/react" \
  --config "p/secrets" \
  --json \
  --output "$OUTPUT_DIR/semgrep-sast.json" \
  "$PROJECT_DIR"

echo "=== Phase 3: COBOL-specific grep patterns ==="
if find "$PROJECT_DIR" -name "*.cbl" -o -name "*.cob" | grep -q .; then
  grep -rn "EXEC SQL EXECUTE IMMEDIATE" "$PROJECT_DIR" \
    --include="*.cbl" --include="*.cob" > "$OUTPUT_DIR/cobol-sqli.txt" || true
  grep -rn "STRING.*DELIMITED" "$PROJECT_DIR" \
    --include="*.cbl" --include="*.cob" > "$OUTPUT_DIR/cobol-string-ops.txt" || true
fi

echo "Scan complete. Results in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
```

## Interpreting Results

| Category | Severity | Action |
|----------|----------|--------|
| Hardcoded secret (live/verified) | CRITICAL | Rotate immediately, remove from code and git history |
| Hardcoded secret (unverified) | HIGH | Investigate and rotate |
| Insecure deserialization | HIGH | Replace with safe library/pattern |
| eval() with user input | HIGH | Refactor immediately |
| SQL injection pattern | HIGH | Use parameterized queries |
| XXE without protection | MEDIUM | Add DTD/entity restrictions |
| `dangerouslySetInnerHTML` | MEDIUM | Add DOMPurify or remove |
| Unsafe COBOL MOVE | LOW | Add SIZE ERROR clause |

## Related Skills

- `cve-dependency-scan` — Dependency vulnerability scanning
- `owasp-code-review` — OWASP Top 10 static analysis
- `devsec-report` — Aggregate all findings into a report
