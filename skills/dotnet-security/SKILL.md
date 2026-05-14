---
name: dotnet-security
description: Specialized .NET/C# security analysis — NuGet vulnerability scanning, unsafe code detection, XXE, insecure deserialization, weak crypto, hardcoded connection strings, and missing security headers
version: 1.0.0
author: DevSec Team
tags: [security, devsec, dotnet, csharp, aspnetcore, nuget, sast, owasp]
---

# .NET / C# Security Analysis

## Objective

Perform comprehensive security analysis of .NET/C# applications: NuGet vulnerability scanning, detection of unsafe code blocks, XXE via insecure XML parsers, insecure deserialization, weak cryptographic algorithms, hardcoded connection strings, and missing ASP.NET Core security middleware.

## Prerequisites

### Required Tools

| Tool | Installation | Purpose |
|------|-------------|---------|
| `dotnet` CLI | [.NET SDK](https://dotnet.microsoft.com/download) | NuGet vulnerability audit |
| `semgrep` | `pip install semgrep` | C# pattern-based SAST |
| `grype` | [install script](https://github.com/anchore/grype) | CVE scan of NuGet packages |
| `gitleaks` | [GitHub releases](https://github.com/gitleaks/gitleaks) | Connection string / secret detection |
| `jq` | Package manager | JSON parsing |

---

## Part 1: NuGet Vulnerability Scanning

### 1a — dotnet list package --vulnerable

The native .NET CLI checks all packages against GitHub Advisory Database and NuGet.org advisories.

```bash
# Ensure packages are restored first
dotnet restore

# Check direct dependencies only
dotnet list package --vulnerable

# Include transitive dependencies (recommended)
dotnet list package --vulnerable --include-transitive

# JSON output for CI parsing
dotnet list package --vulnerable --include-transitive --format json \
  > dotnet-vuln-report.json 2>&1

# Check specific project or solution
dotnet list ./MyApp/MyApp.csproj package --vulnerable --include-transitive
dotnet list ./MySolution.sln package --vulnerable --include-transitive
```

**Sample output interpretation:**
```
Project `MyApp` has the following vulnerable packages
   [net8.0]:
   Top-level Package           Requested   Resolved    Severity   Advisory URL
   > Newtonsoft.Json           12.0.3      12.0.3      High       https://github.com/advisories/GHSA-5crp-9r3c-p9vr
   > System.Net.Http           4.3.0       4.3.0       High       https://github.com/advisories/GHSA-7jgj-8wvc-jh57
```

**Remediation for each finding:**
```xml
<!-- In your .csproj — update to safe version -->
<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
<PackageReference Include="System.Net.Http" Version="4.3.4" />
```

### 1b — Grype on NuGet Packages

```bash
# Generate SBOM with CycloneDX then scan with Grype
dotnet tool install --global CycloneDX
dotnet CycloneDX . -o ./sbom -j
grype sbom:./sbom/bom.json -o json > grype-nuget-results.json

# Or directly scan directory
grype dir:. -o json > grype-dotnet-results.json

# Fail on Critical
grype dir:. --fail-on critical
```

### 1c — NuGet Lock File Integrity

```bash
# Enable lock file (add to .csproj)
# <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>

# Verify existing lock file is consistent
dotnet restore --locked-mode 2>&1

# Check for unsigned packages
dotnet nuget verify --all 2>&1 | grep -E "warning|error|unsigned"
```

---

## Part 2: Unsafe Code Blocks

### Background

The `unsafe` keyword in C# bypasses CLR memory safety guarantees and allows pointer arithmetic, which can lead to buffer overflows, memory corruption, and information disclosure.

### Detection

```bash
# Find all unsafe blocks and P/Invoke declarations
grep -rn "unsafe\s*{" --include="*.cs" . > /tmp/unsafe-blocks.txt
grep -rn "DllImport\|P/Invoke\|\[DllImport" --include="*.cs" . > /tmp/pinvoke-declarations.txt

# Count unsafe files
echo "Files with unsafe code:"
grep -rl "unsafe" --include="*.cs" . | wc -l
```

**Semgrep rules:**
```bash
semgrep --config 'r/csharp.lang.security.unsafe' --json --output unsafe-findings.json .
```

**Patterns to flag:**

```csharp
// ❌ DANGEROUS — pointer arithmetic without bounds check
unsafe {
    byte* ptr = stackalloc byte[bufSize];
    // If offset is user-controlled:
    *(ptr + userControlledOffset) = value; // Buffer overflow!
}

// ❌ DANGEROUS — fixed pointer to managed array with no length check
unsafe {
    fixed (byte* pBuffer = buffer) {
        CopyMemory(pBuffer + offset, source, userLength); // Check userLength!
    }
}

// ❌ DANGEROUS — P/Invoke passing unsanitized size
[DllImport("kernel32.dll")]
static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
    byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

// User controls dwSize without validation — potential overflow
WriteProcessMemory(handle, address, data, data.Length, out _); // OK if data.Length is checked
WriteProcessMemory(handle, address, data, userSize, out _);    // ❌ userSize must be validated
```

**Secure pattern:**
```csharp
// ✅ SAFE — bounds validated before unsafe operations
unsafe {
    if (offset < 0 || offset >= buffer.Length || length <= 0 || offset + length > buffer.Length)
        throw new ArgumentOutOfRangeException("Buffer bounds exceeded");

    fixed (byte* pBuf = buffer) {
        // Operate within validated bounds
        Buffer.MemoryCopy(source, pBuf + offset, buffer.Length - offset, length);
    }
}
```

---

## Part 3: XXE via XmlDocument / XmlReader

### Background

XML External Entity (XXE) attacks allow reading arbitrary files or performing SSRF when an XML parser processes external entity references. In .NET, `XmlDocument` and `XmlReader` are vulnerable by default in older .NET Framework versions.

### Detection

```bash
# Find XML parser usage without security settings
grep -rn "XmlDocument\|XmlReader\|XmlTextReader\|XPathDocument\|XmlSerializer" \
  --include="*.cs" . > /tmp/xml-parsers.txt

# Flag parsers without DtdProcessing.Prohibit or XmlResolver = null
grep -rn "new XmlDocument()\|new XmlTextReader\|XmlReader.Create" \
  --include="*.cs" . > /tmp/xml-create-patterns.txt
```

```bash
semgrep --config 'r/csharp.dotnet.security.xxe' --json --output xxe-findings.json .
```

**Vulnerable patterns:**
```csharp
// ❌ VULNERABLE — XmlDocument with default settings (.NET Framework)
var doc = new XmlDocument();
doc.Load(userXmlInput); // XXE if input contains <!DOCTYPE> with external entity

// ❌ VULNERABLE — XmlReader without DTD prohibition
var reader = XmlReader.Create(stream); // Default: DtdProcessing.Prohibit in .NET Core
                                        // But: DtdProcessing.Parse in .NET Framework!

// ❌ VULNERABLE — Explicit XmlResolver enables network access
var doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver(); // Allows external DTD loading
doc.Load(untrustedXml);

// ❌ VULNERABLE — XmlTextReader
var reader = new XmlTextReader(stream); // Always DTD-enabled
```

**Secure patterns:**
```csharp
// ✅ SAFE — XmlDocument with resolver disabled
var doc = new XmlDocument();
doc.XmlResolver = null;         // Disables external entity resolution
doc.LoadXml(xmlContent);

// ✅ SAFE — XmlReader with explicit DTD prohibition
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersFromEntities = 1024
};
using var reader = XmlReader.Create(stream, settings);

// ✅ SAFE — Use System.Text.Json when possible (no XML = no XXE)
var obj = JsonSerializer.Deserialize<MyClass>(jsonContent);
```

---

## Part 4: Insecure Deserialization

### Background

Deserialization of untrusted data can lead to Remote Code Execution (RCE) when the deserializer allows arbitrary type instantiation. `BinaryFormatter` has been deprecated and removed in modern .NET; `Newtonsoft.Json` with `TypeNameHandling.All` is still commonly misused.

### Detection

```bash
# Find BinaryFormatter usage (deprecated since .NET 5, removed .NET 9)
grep -rn "BinaryFormatter\|SoapFormatter\|LosFormatter\|NetDataContractSerializer" \
  --include="*.cs" . > /tmp/dangerous-deserializers.txt

# Find Newtonsoft.Json TypeNameHandling
grep -rn "TypeNameHandling" --include="*.cs" . > /tmp/json-typename.txt

# Find JavaScriptSerializer (legacy ASP.NET)
grep -rn "JavaScriptSerializer" --include="*.cs" . > /tmp/js-serializer.txt
```

```bash
semgrep --config 'r/csharp.dotnet.security.insecure-deserialization-newtonsoft' \
        --config 'r/csharp.dotnet.security.binaryformatter-deserialization' \
        --json --output deser-findings.json .
```

**Vulnerable patterns:**
```csharp
// ❌ CRITICAL — BinaryFormatter: RCE via gadget chains
#pragma warning disable SYSLIB0011
var formatter = new BinaryFormatter();
var obj = (MyClass)formatter.Deserialize(untrustedStream); // RCE risk!

// ❌ CRITICAL — TypeNameHandling.All with untrusted input
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All   // Allows instantiation of ANY type
};
var obj = JsonConvert.DeserializeObject(untrustedJson, settings);

// ❌ HIGH — TypeNameHandling.Auto (same risk for polymorphic types)
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Auto
};

// ❌ HIGH — JavaScriptSerializer (obsolete, no type safety)
var serializer = new JavaScriptSerializer();
var obj = serializer.Deserialize<object>(untrustedJson); // Type confusion possible
```

**Secure patterns:**
```csharp
// ✅ SAFE — System.Text.Json (no TypeNameHandling, safe by default)
var obj = JsonSerializer.Deserialize<MySpecificClass>(json);

// ✅ SAFE — Newtonsoft.Json with TypeNameHandling.None
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None  // Default — safe
};
var obj = JsonConvert.DeserializeObject<MyClass>(json, settings);

// ✅ SAFE — For polymorphic types, use a custom ISerializationBinder
var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.Objects,
    SerializationBinder = new SafeTypesBinder(allowedTypes) // Allowlist approach
};

// ✅ SAFE — MessagePack for binary serialization
var obj = MessagePackSerializer.Deserialize<MyClass>(bytes);

// ✅ SAFE — Protobuf (no arbitrary type instantiation)
var obj = Serializer.Deserialize<MyClass>(stream);
```

---

## Part 5: Weak Cryptography

### Detection

```bash
# Find weak hash and cipher usage
grep -rn "MD5\|SHA1\b\|DES\b\|TripleDES\|RC2\|RC4\|new Random()" \
  --include="*.cs" . | grep -v "^\s*//" > /tmp/weak-crypto.txt

# Find hardcoded IV / salt
grep -rn "new byte\[\].*{.*}\|Convert.FromBase64String" \
  --include="*.cs" . | grep -i "iv\|salt\|key" > /tmp/hardcoded-iv.txt
```

```bash
semgrep \
  --config 'r/csharp.dotnet.security.weak-crypto' \
  --config 'r/csharp.dotnet.security.use-des' \
  --config 'r/csharp.dotnet.security.use-md5' \
  --json --output weak-crypto-findings.json .
```

**Vulnerable patterns:**
```csharp
// ❌ WEAK — MD5 for password hashing (collision attacks, no salting)
using var md5 = MD5.Create();
byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));

// ❌ WEAK — SHA1 for integrity (collision attacks since 2017)
using var sha1 = SHA1.Create();
byte[] hash = sha1.ComputeHash(data);

// ❌ WEAK — DES/TripleDES (56-bit key, deprecated)
using var des = DES.Create();
des.Key = hardcodedKey;

// ❌ WEAK — Random for security purposes (not cryptographically secure)
var random = new Random();
string token = random.Next().ToString(); // Predictable!

// ❌ WEAK — ECB mode (deterministic, pattern-leaking)
using var aes = Aes.Create();
aes.Mode = CipherMode.ECB; // Never for encryption!

// ❌ WEAK — Short RSA key
RSA.Create(1024); // Minimum 2048 bits required
```

**Secure patterns:**
```csharp
// ✅ STRONG — bcrypt for passwords (use BCrypt.Net-Next or ASP.NET Identity)
using BCrypt.Net;
string hash = BCrypt.HashPassword(password, workFactor: 12);
bool valid = BCrypt.Verify(password, hash);

// ✅ STRONG — SHA256/SHA384/SHA512 for integrity
using var sha256 = SHA256.Create();
byte[] hash = sha256.ComputeHash(data);

// ✅ STRONG — AES-256-GCM (authenticated encryption)
using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
aes.Encrypt(nonce, plaintext, ciphertext, tag);

// ✅ STRONG — Cryptographically secure random
using var rng = RandomNumberGenerator.Create();
byte[] token = new byte[32];
rng.GetBytes(token);
string tokenStr = Convert.ToBase64String(token);

// ✅ STRONG — RSA 2048+ with OAEP padding
using var rsa = RSA.Create(2048);
var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

// ✅ STRONG — Argon2 via Konscious.Security.Cryptography
var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password)) {
    Salt = salt, MemorySize = 65536, Iterations = 3, DegreeOfParallelism = 4
};
byte[] hash = argon2.GetBytes(32);
```

---

## Part 6: Hardcoded Connection Strings

### Detection

```bash
# Find hardcoded connection strings in source code
grep -rn "ConnectionString\|Data Source=\|Server=.*Password=\|mongodb://\|redis://" \
  --include="*.cs" --include="*.csproj" . | grep -v "^\s*//" > /tmp/connection-strings.txt

# Check appsettings.json for sensitive data
find . -name "appsettings*.json" ! -name "appsettings.Development.json" | \
  xargs grep -l "Password\|Secret\|Key\|ConnectionString" 2>/dev/null > /tmp/appsettings-sensitive.txt

# Check web.config (legacy ASP.NET)
find . -name "web.config" -o -name "Web.config" | \
  xargs grep -l "password=\|Password=" 2>/dev/null > /tmp/webconfig-sensitive.txt
```

```bash
gitleaks detect --source . --report-format json --report-path gitleaks-report.json
```

**Vulnerable patterns:**
```csharp
// ❌ CRITICAL — Hardcoded connection string in source
private const string ConnString = 
    "Server=prod-db.corp.com;Database=AppDB;User=sa;Password=Sup3rS3cr3t!;";

// ❌ CRITICAL — Hardcoded in appsettings.json (committed to git)
// appsettings.json:
// "ConnectionStrings": {
//   "Default": "Server=prod;Database=App;Password=P@ssw0rd"
// }
```

**Secure patterns:**
```csharp
// ✅ SAFE — Read from environment variable
var connString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING")
    ?? throw new InvalidOperationException("DB_CONNECTION_STRING not configured");
builder.Services.AddDbContext<AppDbContext>(opts => opts.UseSqlServer(connString));

// ✅ SAFE — ASP.NET Core configuration (set via env vars, Azure Key Vault, etc.)
// Program.cs:
builder.Configuration.AddEnvironmentVariables();
// appsettings.json: use placeholder — actual value from env:
// ConnectionStrings__Default=... (set in deployment environment)

// ✅ SAFE — Azure Key Vault integration
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{vaultName}.vault.azure.net/"),
    new DefaultAzureCredential());

// ✅ SAFE — HashiCorp Vault (via VaultSharp)
var vaultClient = new VaultClient(new VaultClientSettings(vaultAddr, authMethod));
var secret = await vaultClient.V1.Secrets.KeyValue.V2
    .ReadSecretAsync("database/credentials");
var password = secret.Data.Data["password"].ToString();
```

---

## Part 7: Missing Security Headers (ASP.NET Core Middleware)

### Detection

```bash
# Check for security middleware configuration in Program.cs / Startup.cs
find . -name "Program.cs" -o -name "Startup.cs" | \
  xargs grep -l "UseHsts\|UseXXX\|helmet\|SecurityHeaders" 2>/dev/null

# Flag missing security headers
grep -rn "app\.Use\|app\.Run\|Configure(" \
  --include="*.cs" . | grep -v "Hsts\|Https\|SecurityHeaders\|CSP\|^\s*//"
```

**Missing security middleware (flag these):**
```csharp
// ❌ INCOMPLETE — Missing critical security middleware
var app = builder.Build();
app.UseRouting();
app.UseAuthorization();
app.MapControllers();
app.Run();
// Missing: HSTS, HTTPS redirect, security headers, anti-forgery, CSP
```

**Complete secure ASP.NET Core middleware pipeline:**
```csharp
var app = builder.Build();

// ✅ Force HTTPS and HSTS (in production)
if (!app.Environment.IsDevelopment()) {
    app.UseExceptionHandler("/Error");
    app.UseHsts(); // HTTP Strict Transport Security
}
app.UseHttpsRedirection();

// ✅ Custom security headers middleware
app.Use(async (context, next) => {
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    context.Response.Headers.Append(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
    );
    await next();
});

// ✅ Or use NWebsec package for cleaner header management:
// app.UseNoCacheHttpHeaders();
// app.UseXContentTypeOptions();
// app.UseXfo(options => options.Deny());
// app.UseReferrerPolicy(opts => opts.StrictOriginWhenCrossOrigin());
// app.UseCsp(opts => opts.DefaultSources(s => s.Self()));

// ✅ Rate limiting (ASP.NET Core 7+)
app.UseRateLimiter();

// ✅ Anti-CSRF token validation
builder.Services.AddAntiforgery(options => {
    options.HeaderName = "X-CSRF-TOKEN";
    options.SuppressXFrameOptionsHeader = false;
});

app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapControllers();
app.Run();
```

**Required NuGet packages:**
```xml
<!-- For enhanced security headers -->
<PackageReference Include="NWebsec.AspNetCore.Middleware" Version="3.0.0" />
<!-- For rate limiting (built-in .NET 7+, no package needed) -->
<!-- For CORS control -->
<PackageReference Include="Microsoft.AspNetCore.Cors" Version="2.2.0" />
```

---

## Full .NET Security Scan Script

```bash
#!/bin/bash
# .NET Security Scan — CyberStrikeAI DevSec
# Usage: ./dotnet-scan.sh [project-dir] [output-dir]

PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./dotnet-security-results}"
mkdir -p "$OUTPUT_DIR"

echo "=== CyberStrikeAI .NET Security Scan ==="
echo "Target: $PROJECT_DIR"

# Check for .NET projects
if ! find "$PROJECT_DIR" -name "*.csproj" -o -name "*.sln" | grep -q .; then
  echo "[WARN] No .csproj or .sln files found in $PROJECT_DIR"
  exit 0
fi

echo ""
echo "=== 1. NuGet Vulnerability Scan ==="
if command -v dotnet > /dev/null 2>&1; then
  cd "$PROJECT_DIR"
  dotnet restore --verbosity quiet 2>&1 | tail -3
  dotnet list package --vulnerable --include-transitive \
    > "$OUTPUT_DIR/dotnet-vuln.txt" 2>&1
  cd -
  VULN_COUNT=$(grep -c ">" "$OUTPUT_DIR/dotnet-vuln.txt" 2>/dev/null || echo 0)
  echo "  Vulnerable packages: $VULN_COUNT"
else
  echo "  [SKIP] dotnet CLI not found"
fi

echo ""
echo "=== 2. SAST (Semgrep) ==="
if command -v semgrep > /dev/null 2>&1; then
  semgrep \
    --config "p/csharp" \
    --config "p/owasp-top-ten" \
    --config "p/dotnet" \
    --json \
    --output "$OUTPUT_DIR/semgrep-dotnet.json" \
    "$PROJECT_DIR" 2>/dev/null
  SAST_COUNT=$(jq '.results | length' "$OUTPUT_DIR/semgrep-dotnet.json" 2>/dev/null || echo 0)
  echo "  SAST findings: $SAST_COUNT"
else
  echo "  [SKIP] semgrep not found"
fi

echo ""
echo "=== 3. Secret Detection ==="
if command -v gitleaks > /dev/null 2>&1; then
  gitleaks detect --source "$PROJECT_DIR" \
    --report-format json \
    --report-path "$OUTPUT_DIR/gitleaks.json" \
    --no-banner 2>/dev/null || true
  SECRET_COUNT=$(jq '. | length' "$OUTPUT_DIR/gitleaks.json" 2>/dev/null || echo 0)
  echo "  Secrets found: $SECRET_COUNT"
else
  echo "  [SKIP] gitleaks not found"
fi

echo ""
echo "=== 4. Dangerous Patterns Check ==="
grep -rn "BinaryFormatter\|TypeNameHandling.All\|TypeNameHandling.Auto" \
  --include="*.cs" "$PROJECT_DIR" > "$OUTPUT_DIR/dangerous-patterns.txt" 2>/dev/null
grep -rn "MD5.Create\|SHA1.Create\|DES.Create\|new Random()" \
  --include="*.cs" "$PROJECT_DIR" >> "$OUTPUT_DIR/dangerous-patterns.txt" 2>/dev/null
DANGER_COUNT=$(wc -l < "$OUTPUT_DIR/dangerous-patterns.txt")
echo "  Dangerous patterns: $DANGER_COUNT"

echo ""
echo "=== 5. Grype CVE Scan ==="
if command -v grype > /dev/null 2>&1; then
  grype dir:"$PROJECT_DIR" -o json > "$OUTPUT_DIR/grype.json" 2>/dev/null
  CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' \
    "$OUTPUT_DIR/grype.json" 2>/dev/null || echo 0)
  HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' \
    "$OUTPUT_DIR/grype.json" 2>/dev/null || echo 0)
  echo "  Critical CVEs: $CRITICAL | High CVEs: $HIGH"
else
  echo "  [SKIP] grype not found"
fi

echo ""
echo "=== SCAN COMPLETE ==="
echo "Results in: $OUTPUT_DIR/"

# Summary
SECRETS=${SECRET_COUNT:-0}
CRITICALS=${CRITICAL:-0}
if [ "$SECRETS" -gt 0 ] || [ "$CRITICALS" -gt 0 ]; then
  echo "❌ Critical findings require immediate action"
  exit 1
else
  echo "✅ No critical blockers found (review full results for medium/low)"
  exit 0
fi
```

---

## Severity Reference

| Pattern | Severity | OWASP | CWE |
|---------|----------|-------|-----|
| Hardcoded connection string / password | CRITICAL | A07 Auth Failures | CWE-798 |
| BinaryFormatter deserialization | CRITICAL | A08 Integrity Failures | CWE-502 |
| TypeNameHandling.All/Auto | CRITICAL | A08 Integrity Failures | CWE-502 |
| XXE via XmlDocument without null resolver | HIGH | A05 Misconfiguration | CWE-611 |
| unsafe block without bounds validation | HIGH | A04 Insecure Design | CWE-119 |
| MD5/SHA1 for passwords | HIGH | A02 Crypto Failures | CWE-327 |
| DES/TripleDES/RC2 ciphers | HIGH | A02 Crypto Failures | CWE-327 |
| ECB cipher mode | HIGH | A02 Crypto Failures | CWE-327 |
| Missing HSTS / HTTPS redirect | MEDIUM | A05 Misconfiguration | CWE-319 |
| Missing CSP header | MEDIUM | A05 Misconfiguration | CWE-1021 |
| Missing X-Frame-Options | MEDIUM | A05 Misconfiguration | CWE-1021 |
| Random() for tokens | MEDIUM | A02 Crypto Failures | CWE-338 |
| SHA256 for passwords (no KDF) | MEDIUM | A02 Crypto Failures | CWE-916 |

## Related Skills

- `cve-dependency-scan` — Full NuGet CVE scanning with SBOM generation
- `owasp-code-review` — Complete OWASP Top 10 analysis for C#
- `sast-devsec` — Advanced secret detection and dangerous patterns
- `devsec-report` — Aggregate all findings into unified report
