---
name: owasp-code-review
description: Static source code analysis aligned to OWASP Top 10 (2021) using Semgrep with language-specific rulesets for C#, Java, JavaScript, TypeScript, and React
version: 1.0.0
author: DevSec Team
tags: [security, devsec, owasp, sast, semgrep, code-review, static-analysis]
---

# OWASP Code Review

## Objective

Perform automated static code analysis against the OWASP Top 10 (2021) vulnerabilities across C#, Java, JavaScript, TypeScript, and React codebases using Semgrep with curated, language-specific rulesets.

## Prerequisites

### Required Tools

| Tool | Installation | Purpose |
|------|-------------|---------|
| `semgrep` | `pip install semgrep` or [semgrep.dev](https://semgrep.dev/docs/getting-started/) | Primary SAST engine |
| `jq` | Package manager | JSON result parsing |

### Semgrep Rulesets Used

```bash
# Install and verify Semgrep
semgrep --version

# Available registry rulesets
# p/owasp-top-ten        — Generic OWASP Top 10 rules
# p/csharp               — C# specific rules
# p/java                 — Java specific rules
# p/javascript           — JavaScript rules
# p/typescript           — TypeScript rules
# p/react                — React-specific rules
# p/secrets              — Secret/credential detection
```

## OWASP Top 10 Coverage

### A01 — Broken Access Control

**Risk:** Functions or resources accessible without proper authorization.

**Semgrep rules:**

```bash
# C# — Missing authorization attributes
semgrep --config 'r/csharp.dotnet.security.missing-authorization' .

# Java — Missing Spring Security annotations
semgrep --config 'r/java.spring.security.missing-spring-security-annotation' .

# JavaScript/TypeScript — Insecure direct object reference patterns
semgrep --config 'r/javascript.express.security.express-path-traversal' .
```

**Patterns to detect:**
```csharp
// C# — Controller action without [Authorize]
[HttpGet("{id}")]
public IActionResult GetUser(int id) { /* No [Authorize] */ }

// Secure version:
[Authorize(Roles = "Admin,User")]
[HttpGet("{id}")]
public IActionResult GetUser(int id) { ... }
```

```java
// Java Spring — Missing @PreAuthorize
@GetMapping("/admin/users")
public List<User> getAllUsers() { /* Missing @PreAuthorize */ }
```

---

### A02 — Cryptographic Failures

**Risk:** Sensitive data exposed due to weak or missing encryption.

```bash
# C# — Weak crypto algorithms
semgrep --config 'r/csharp.dotnet.security.weak-crypto' .
semgrep --config 'r/csharp.dotnet.security.use-des' .
semgrep --config 'r/csharp.dotnet.security.use-md5' .

# Java — Weak hash / cipher usage
semgrep --config 'r/java.lang.security.audit.crypto.weak-hash' .
semgrep --config 'r/java.lang.security.audit.crypto.des-is-deprecated' .

# JS/TS — Crypto issues
semgrep --config 'r/javascript.lang.security.audit.md5-used-as-password' .
```

**Patterns to detect:**
```csharp
// WEAK — MD5 / DES usage
using var md5 = MD5.Create();         // CVE risk
using var des = DES.Create();          // CVE risk
var rng = new Random();                // Not cryptographically secure

// SECURE
using var sha256 = SHA256.Create();
using var aes = Aes.Create();
using var rng = RandomNumberGenerator.Create();
```

---

### A03 — Injection (SQL, Command, LDAP)

**Risk:** Untrusted data sent to an interpreter as part of a command or query.

```bash
# C# SQL injection
semgrep --config 'r/csharp.dotnet.security.sqli.raw-sql-concatenation' .
semgrep --config 'r/csharp.dotnet.security.sqli.string-format-sqli' .

# Java SQL injection
semgrep --config 'r/java.lang.security.audit.sqli.jdbc-sqli' .
semgrep --config 'r/java.spring.security.injection.tainted-sql-from-http-request' .

# Command injection
semgrep --config 'r/csharp.dotnet.security.process-start-injection' .
semgrep --config 'r/java.lang.security.audit.command-injection-formatted-runtime-call' .
semgrep --config 'r/javascript.lang.security.audit.dangerous-spawn-shell' .

# LDAP injection
semgrep --config 'r/java.lang.security.audit.ldap-injection' .
```

**Patterns to detect:**
```csharp
// VULNERABLE — String concatenation in SQL
string query = "SELECT * FROM Users WHERE Name = '" + username + "'";
var cmd = new SqlCommand(query, conn);

// SECURE — Parameterized query
string query = "SELECT * FROM Users WHERE Name = @username";
var cmd = new SqlCommand(query, conn);
cmd.Parameters.AddWithValue("@username", username);
```

```java
// VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();

// SECURE
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
```

```javascript
// VULNERABLE — Command injection
const { exec } = require('child_process');
exec('ls ' + userInput);

// SECURE
const { execFile } = require('child_process');
execFile('ls', [sanitizedInput]);
```

---

### A04 — Insecure Design

**Risk:** Missing or ineffective security controls at design level.

```bash
# Detect missing rate limiting patterns (Express.js)
semgrep --config 'r/javascript.express.security.express-missing-rate-limit' .

# Detect mass assignment vulnerabilities
semgrep --config 'r/csharp.dotnet.security.mass-assignment' .
semgrep --config 'r/java.spring.security.spring-mass-assignment' .
```

**Patterns:**
```csharp
// INSECURE — No input size limits, mass assignment
public IActionResult Create([FromBody] UserModel user) { /* All fields accepted */ }

// SECURE — Use DTOs with explicit binding
public IActionResult Create([FromBody] CreateUserDto dto) { /* Only required fields */ }
```

---

### A05 — Security Misconfiguration

**Risk:** Insecure default settings, error messages exposing details, unnecessary features enabled.

```bash
# C# — Debug mode / detailed error pages in production
semgrep --config 'r/csharp.dotnet.security.developer-exception-page-in-production' .

# Java — Spring Boot actuator exposure
semgrep --config 'r/java.spring.security.spring-actuator-fully-exposed' .

# General — CORS misconfiguration
semgrep --config 'r/javascript.express.security.express-cors-misconfiguration' .
semgrep --config 'r/csharp.dotnet.security.cors-wildcard' .
```

**Patterns:**
```csharp
// MISCONFIGURED — Wildcard CORS
services.AddCors(options => options.AddPolicy("AllowAll",
    builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

// SECURE
services.AddCors(options => options.AddPolicy("Restricted",
    builder => builder.WithOrigins("https://trusted-domain.com")
                      .WithMethods("GET", "POST")));
```

---

### A06 — Vulnerable and Outdated Components

**Risk:** Using components with known vulnerabilities.

This category is primarily covered by the `cve-dependency-scan` skill. However, SAST can detect:

```bash
# Detect use of known-vulnerable function patterns
semgrep --config 'r/java.lang.security.audit.crypto.ssl.avoid-insecure-ssl-protocols' .
semgrep --config 'r/javascript.lang.security.audit.node-curl-unsafe-ssrf' .
```

**Cross-reference:** Run `cve-dependency-scan` skill alongside this analysis.

---

### A07 — Identification and Authentication Failures

**Risk:** Weak authentication mechanisms, credential exposure.

```bash
# C# — Hardcoded credentials, weak password policy
semgrep --config 'r/csharp.dotnet.security.hardcoded-credentials' .
semgrep --config 'r/generic.secrets.security.detected-generic-secret' .

# Java — Hardcoded passwords
semgrep --config 'r/java.lang.security.audit.hardcoded-credentials-in-properties' .

# JWT issues
semgrep --config 'r/javascript.jsonwebtoken.security.jwt-none-alg' .
semgrep --config 'r/java.lang.security.audit.crypto.jwt.jwt-none-alg' .
```

**Patterns:**
```csharp
// INSECURE
string password = "Admin1234!";  // Hardcoded
if (token == null) token = "none"; // JWT none algorithm

// INSECURE — JWT with no expiry
var token = new JwtSecurityToken(claims: claims); // No expiry set

// SECURE
var token = new JwtSecurityToken(
    claims: claims,
    expires: DateTime.UtcNow.AddHours(1),
    signingCredentials: creds);
```

---

### A08 — Software and Data Integrity Failures

**Risk:** Code and infrastructure not protected against integrity violations; insecure deserialization.

```bash
# C# — Insecure deserialization
semgrep --config 'r/csharp.dotnet.security.insecure-deserialization-newtonsoft' .
semgrep --config 'r/csharp.dotnet.security.binaryformatter-deserialization' .

# Java — Insecure deserialization
semgrep --config 'r/java.lang.security.audit.object-deserialization' .

# JavaScript — eval / unsafe dynamic code
semgrep --config 'r/javascript.lang.security.audit.unsafe-dynamic-method-access' .
```

**Patterns:**
```csharp
// INSECURE — BinaryFormatter is vulnerable and deprecated
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream); // CVE risk

// INSECURE — Newtonsoft TypeNameHandling
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All // Dangerous!
});

// SECURE
var obj = JsonSerializer.Deserialize<MyClass>(json); // System.Text.Json
```

---

### A09 — Security Logging and Monitoring Failures

**Risk:** Insufficient logging; failure to detect attacks.

```bash
# Detect logging of sensitive data
semgrep --config 'r/csharp.dotnet.security.sensitive-data-logging' .
semgrep --config 'r/java.lang.security.audit.log-injection' .
semgrep --config 'r/javascript.lang.security.audit.logging.winston-security-issue' .
```

**Patterns:**
```csharp
// INSECURE — Logging sensitive data
_logger.LogInformation($"User login: {username} with password {password}");

// INSECURE — Log injection
_logger.LogInformation(userControlledInput); // Could inject fake log entries

// SECURE
_logger.LogInformation("User login attempt for user ID: {UserId}", userId);
// Never log passwords, tokens, PII
```

---

### A10 — Server-Side Request Forgery (SSRF)

**Risk:** Server fetches remote resources based on user-supplied URL without validation.

```bash
# C# — SSRF patterns
semgrep --config 'r/csharp.dotnet.security.ssrf.httpclient-taint' .

# Java — SSRF
semgrep --config 'r/java.lang.security.audit.url-rewrite.url-rewrite' .
semgrep --config 'r/java.spring.security.injection.tainted-url-from-http-request' .

# JavaScript — SSRF via axios/fetch
semgrep --config 'r/javascript.lang.security.audit.ssrf.node-request-taint-ssrf' .
```

**Patterns:**
```csharp
// VULNERABLE
string url = Request.Query["url"];
var response = await httpClient.GetAsync(url); // SSRF risk!

// SECURE
var allowedDomains = new[] { "api.trusted.com", "cdn.trusted.com" };
var uri = new Uri(url);
if (!allowedDomains.Contains(uri.Host)) throw new SecurityException("SSRF blocked");
var response = await httpClient.GetAsync(uri);
```

## Full Scan Command

```bash
#!/bin/bash
# Run complete OWASP Top 10 scan

PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./owasp-results}"
mkdir -p "$OUTPUT_DIR"

echo "Detecting project type..."
# Run all applicable rulesets
semgrep \
  --config "p/owasp-top-ten" \
  --config "p/csharp" \
  --config "p/java" \
  --config "p/javascript" \
  --config "p/typescript" \
  --config "p/react" \
  --json \
  --output "$OUTPUT_DIR/semgrep-owasp-raw.json" \
  "$PROJECT_DIR"

echo "Scan complete. Results: $OUTPUT_DIR/semgrep-owasp-raw.json"

# Summary
jq '{
  total: (.results | length),
  by_severity: (.results | group_by(.extra.severity) | map({key: .[0].extra.severity, value: length}) | from_entries),
  by_owasp_category: (.results | group_by(.extra.metadata."owasp") | map({key: .[0].extra.metadata."owasp"[0], value: length}) | from_entries)
}' "$OUTPUT_DIR/semgrep-owasp-raw.json"
```

## Interpreting Results

Each Semgrep finding includes:

| Field | Description |
|-------|-------------|
| `check_id` | Rule identifier (e.g., `java.spring.sqli`) |
| `path` | File path |
| `start.line` | Line number |
| `extra.severity` | ERROR / WARNING / INFO |
| `extra.message` | Human-readable description |
| `extra.metadata.owasp` | OWASP category (e.g., `A03:2021`) |
| `extra.metadata.cwe` | CWE identifier |
| `extra.fix` | Suggested fix (when available) |

## Severity to Priority Mapping

| Semgrep Severity | DevSec Priority | SLA |
|-----------------|-----------------|-----|
| ERROR | CRITICAL/HIGH | Fix immediately / 7 days |
| WARNING | MEDIUM | Fix within 30 days |
| INFO | LOW | Fix in next sprint |

## CI/CD Integration

```yaml
# GitLab CI example
owasp-scan:
  stage: security
  image: semgrep/semgrep:latest
  script:
    - semgrep --config "p/owasp-top-ten" --json --output semgrep-results.json .
    - |
      ERRORS=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' semgrep-results.json)
      if [ "$ERRORS" -gt 0 ]; then
        echo "HIGH/CRITICAL findings: $ERRORS — pipeline blocked"
        exit 1
      fi
  artifacts:
    paths:
      - semgrep-results.json
```

## Related Skills

- `cve-dependency-scan` — CVE scanning for dependencies (A06 coverage)
- `sast-devsec` — Secrets detection and advanced language-specific patterns
- `devsec-report` — Aggregate and format scan results
