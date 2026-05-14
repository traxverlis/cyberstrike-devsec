# Remediation Guide — CyberStrikeAI DevSec

Concrete, copy-paste-ready fixes for the most common vulnerability patterns by language.

---

## Table of Contents

1. [C# / .NET](#c--net)
2. [Java](#java)
3. [JavaScript / TypeScript / React](#javascript--typescript--react)
4. [COBOL](#cobol)

---

## C# / .NET

### SQL Injection → Parameterized Queries (Entity Framework)

**❌ Vulnerable:**
```csharp
// Direct string concatenation — SQL injection risk
public User GetUser(string username)
{
    var query = $"SELECT * FROM Users WHERE Username = '{username}'";
    return _context.Users.FromSqlRaw(query).FirstOrDefault();
}
```

**✅ Fixed — Raw SQL with parameters:**
```csharp
// Use parameterized SQL
public User GetUser(string username)
{
    return _context.Users
        .FromSqlRaw("SELECT * FROM Users WHERE Username = {0}", username)
        .FirstOrDefault();
}
```

**✅ Fixed — LINQ (preferred, no SQL at all):**
```csharp
public User GetUser(string username)
{
    return _context.Users
        .Where(u => u.Username == username)
        .FirstOrDefault();
}
```

**✅ Fixed — Dapper with parameters:**
```csharp
public User GetUser(string username)
{
    using var connection = new SqlConnection(_connectionString);
    return connection.QueryFirstOrDefault<User>(
        "SELECT * FROM Users WHERE Username = @Username",
        new { Username = username }
    );
}
```

---

### Insecure Deserialization → Json.NET Secure Settings

**❌ Vulnerable:**
```csharp
// TypeNameHandling.All allows arbitrary type instantiation
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All
};
var obj = JsonConvert.DeserializeObject(userInput, settings);
```

**✅ Fixed:**
```csharp
// Never use TypeNameHandling.All or TypeNameHandling.Auto with untrusted input
var settings = new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.None,   // Default, safest
    SerializationBinder = new KnownTypesBinder() // If you need type discrimination
};
var obj = JsonConvert.DeserializeObject<MyKnownType>(userInput, settings);
```

**✅ Implement a KnownTypesBinder:**
```csharp
public class KnownTypesBinder : ISerializationBinder
{
    private static readonly HashSet<string> AllowedTypes = new()
    {
        typeof(MyDto).FullName!,
        typeof(AnotherDto).FullName!
    };

    public Type BindToType(string assemblyName, string typeName)
    {
        if (!AllowedTypes.Contains(typeName))
            throw new JsonSerializationException($"Unexpected type: {typeName}");

        return Type.GetType($"{typeName}, {assemblyName}")
            ?? throw new JsonSerializationException($"Type not found: {typeName}");
    }

    public void BindToName(Type serializedType, out string assemblyName, out string typeName)
    {
        assemblyName = serializedType.Assembly.FullName!;
        typeName = serializedType.FullName!;
    }
}
```

**✅ Prefer System.Text.Json (built-in, safer):**
```csharp
// System.Text.Json doesn't support TypeNameHandling by design
var obj = System.Text.Json.JsonSerializer.Deserialize<MyDto>(userInput);
```

---

### XXE (XML External Entity) → XmlReaderSettings

**❌ Vulnerable:**
```csharp
// Default XmlDocument is vulnerable to XXE
var doc = new XmlDocument();
doc.Load(userXmlInput);  // Can be exploited to read local files
```

**✅ Fixed:**
```csharp
// Disable DTD processing and external entity resolution
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,        // Disable external entity resolution
    MaxCharactersFromEntities = 1024,  // Limit entity expansion (billion laughs)
    MaxCharactersInDocument = 1024 * 1024 * 10  // 10MB limit
};

using var reader = XmlReader.Create(userXmlInput, settings);
var doc = new XmlDocument { XmlResolver = null };
doc.Load(reader);
```

**✅ For LINQ to XML (XDocument):**
```csharp
// XDocument is NOT vulnerable to XXE by default in .NET Core/.NET 5+
// But still set resolver explicitly for clarity:
var doc = XDocument.Load(
    XmlReader.Create(userXmlInput, new XmlReaderSettings
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null
    })
);
```

---

### Hardcoded Secrets → Azure Key Vault / Secret Manager

**❌ Vulnerable:**
```csharp
// Hardcoded credentials
private const string ConnectionString = "Server=prod-db;User Id=admin;Password=SuperSecret123;";
private const string ApiKey = "sk-1234abcd...";
```

**✅ Fixed — Azure Key Vault:**
```csharp
// Program.cs / Startup.cs
using Azure.Identity;
using Azure.Extensions.AspNetCore.Configuration.Secrets;

var builder = WebApplication.CreateBuilder(args);

// Add Azure Key Vault to configuration
var keyVaultUri = new Uri($"https://{builder.Configuration["KeyVaultName"]}.vault.azure.net/");
builder.Configuration.AddAzureKeyVault(keyVaultUri, new DefaultAzureCredential());

// Access secrets through IConfiguration (automatically injected)
// Secret named "ConnectionString--Database" in Key Vault
// is accessed as Configuration["ConnectionString:Database"]
```

**✅ Inject in service:**
```csharp
public class MyService
{
    private readonly string _connectionString;

    public MyService(IConfiguration configuration)
    {
        // Retrieved from Key Vault at startup
        _connectionString = configuration["ConnectionString:Database"]
            ?? throw new InvalidOperationException("Database connection string not configured.");
    }
}
```

**✅ For local development (.NET User Secrets):**
```bash
# Never commit — stored in ~/.microsoft/usersecrets/
dotnet user-secrets init
dotnet user-secrets set "ConnectionString:Database" "Server=localhost;..."
dotnet user-secrets set "ApiKeys:ThirdParty" "dev-key-here"
```

---

### Weak Cryptography → System.Security.Cryptography

**❌ Vulnerable:**
```csharp
// MD5 is broken — don't use for passwords or integrity
using var md5 = MD5.Create();
var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));

// DES is broken — 56-bit key
using var des = DES.Create();
```

**✅ Fixed — Password hashing:**
```csharp
// Use BCrypt.Net-Next NuGet package
using BCrypt.Net;

// Hash
string hashedPassword = BCrypt.HashPassword(plainPassword, workFactor: 12);

// Verify
bool isValid = BCrypt.Verify(plainPassword, hashedPassword);
```

**✅ Fixed — Data encryption (AES-256-GCM):**
```csharp
using System.Security.Cryptography;

public static (byte[] ciphertext, byte[] nonce, byte[] tag) Encrypt(byte[] plaintext, byte[] key)
{
    var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];   // 12 bytes
    var tag   = new byte[AesGcm.TagByteSizes.MaxSize];      // 16 bytes
    var ciphertext = new byte[plaintext.Length];

    RandomNumberGenerator.Fill(nonce);

    using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
    aes.Encrypt(nonce, plaintext, ciphertext, tag);

    return (ciphertext, nonce, tag);
}

// Generate a secure key (store in Key Vault!)
var key = new byte[32]; // 256 bits
RandomNumberGenerator.Fill(key);
```

**✅ Fixed — Integrity hashing (SHA-256):**
```csharp
using var sha256 = SHA256.Create();
byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
string hexHash = Convert.ToHexString(hash);
```

---

## Java

### SQL Injection → PreparedStatement / JPA

**❌ Vulnerable:**
```java
// String concatenation — SQL injection
public User findUser(String username) throws SQLException {
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(
        "SELECT * FROM users WHERE username = '" + username + "'"
    );
    // ...
}
```

**✅ Fixed — PreparedStatement:**
```java
public User findUser(String username) throws SQLException {
    String sql = "SELECT * FROM users WHERE username = ?";
    try (PreparedStatement stmt = connection.prepareStatement(sql)) {
        stmt.setString(1, username);  // Parameterized — safe
        ResultSet rs = stmt.executeQuery();
        // ...
    }
}
```

**✅ Fixed — JPA / Spring Data:**
```java
// Repository interface — JPQL with named parameters
public interface UserRepository extends JpaRepository<User, Long> {

    // Safe: Spring Data generates parameterized query
    Optional<User> findByUsername(String username);

    // Safe: Named parameter in JPQL
    @Query("SELECT u FROM User u WHERE u.username = :username")
    Optional<User> findByUsernameQuery(@Param("username") String username);

    // ❌ DON'T DO THIS — native query with concatenation
    // @Query(value = "SELECT * FROM users WHERE username = '" + username + "'", nativeQuery = true)
}
```

**✅ Fixed — Criteria API:**
```java
public User findUser(String username) {
    CriteriaBuilder cb = entityManager.getCriteriaBuilder();
    CriteriaQuery<User> query = cb.createQuery(User.class);
    Root<User> root = query.from(User.class);
    query.where(cb.equal(root.get("username"), username));  // Parameterized
    return entityManager.createQuery(query).getSingleResult();
}
```

---

### XXE → DocumentBuilderFactory

**❌ Vulnerable:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userXmlInput);  // XXE vulnerable
```

**✅ Fixed:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable DTD and external entities
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(userXmlInput);
```

**✅ Fixed — SAX Parser:**
```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
SAXParser parser = spf.newSAXParser();
```

---

### Deserialization → Whitelisting / ObjectInputFilter

**❌ Vulnerable:**
```java
// Deserializing untrusted data
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);
Object obj = ois.readObject();  // Can execute arbitrary code
```

**✅ Fixed — ObjectInputFilter (Java 9+):**
```java
ObjectInputStream ois = new ObjectInputStream(untrustedInputStream);

// Allow only specific classes
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.yourcompany.dto.*;!*"  // Allow your DTOs, block everything else
);
ois.setObjectInputFilter(filter);

Object obj = ois.readObject();
```

**✅ Fixed — Global filter (application startup):**
```java
// Set in main() or @PostConstruct
ObjectInputFilter.Config.setSerialFilter(
    ObjectInputFilter.Config.createFilter(
        "com.yourcompany.dto.**;" +
        "java.util.ArrayList;" +
        "java.lang.String;" +
        "!*"
    )
);
```

**✅ Preferred — Use JSON instead of Java serialization:**
```java
// Replace ObjectInputStream with Jackson
ObjectMapper mapper = new ObjectMapper();
// Disable dangerous features
mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES); // doesn't affect safety but good practice
mapper.activateDefaultTyping(
    mapper.getPolymorphicTypeValidator(),
    ObjectMapper.DefaultTyping.NON_FINAL
); // Only if needed, use allowlist validator

MyDto dto = mapper.readValue(jsonString, MyDto.class);
```

---

### Path Traversal → Path.normalize() + Validation

**❌ Vulnerable:**
```java
// User-controlled filename — path traversal risk
public byte[] downloadFile(String filename) throws IOException {
    File file = new File("/uploads/" + filename);  // "../../etc/passwd" works
    return Files.readAllBytes(file.toPath());
}
```

**✅ Fixed:**
```java
public byte[] downloadFile(String filename) throws IOException {
    Path uploadDir = Paths.get("/uploads").toAbsolutePath().normalize();
    Path requestedFile = uploadDir.resolve(filename).normalize();

    // Verify the resolved path is still within the upload directory
    if (!requestedFile.startsWith(uploadDir)) {
        throw new SecurityException("Path traversal attempt detected: " + filename);
    }

    // Verify the file actually exists and is a regular file
    if (!Files.isRegularFile(requestedFile)) {
        throw new FileNotFoundException("File not found: " + filename);
    }

    return Files.readAllBytes(requestedFile);
}
```

---

## JavaScript / TypeScript / React

### XSS → DOMPurify + CSP Headers

**❌ Vulnerable:**
```tsx
// dangerouslySetInnerHTML with unsanitized content
function Comment({ content }: { content: string }) {
    return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// Direct DOM manipulation
document.getElementById('output')!.innerHTML = userInput;
```

**✅ Fixed — DOMPurify:**
```bash
npm install dompurify
npm install --save-dev @types/dompurify
```

```tsx
import DOMPurify from 'dompurify';

function Comment({ content }: { content: string }) {
    const sanitized = DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
        ALLOWED_ATTR: ['href', 'title', 'target']
    });

    return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// Or avoid HTML entirely — prefer text rendering
function SafeComment({ content }: { content: string }) {
    return <p>{content}</p>;  // React escapes automatically
}
```

**✅ Fixed — CSP Headers (Express.js example):**
```typescript
import helmet from 'helmet';

app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'nonce-{NONCE}'"],  // Use nonces for inline scripts
        styleSrc: ["'self'", "'unsafe-inline'"],   // Tighten if possible
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", "https://api.yourapp.com"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
    }
}));
```

---

### Prototype Pollution → Object.create(null) + Validation

**❌ Vulnerable:**
```typescript
// Deep merge without protection
function mergeOptions(defaults: object, userOptions: object) {
    for (const key in userOptions) {
        if (typeof userOptions[key] === 'object') {
            defaults[key] = mergeOptions(defaults[key] || {}, userOptions[key]);
        } else {
            defaults[key] = userOptions[key];  // __proto__ can be set here
        }
    }
    return defaults;
}

// Exploit: {"__proto__": {"isAdmin": true}}
```

**✅ Fixed:**
```typescript
import lodash from 'lodash';

// Option 1: Use lodash.merge (prototype pollution safe in recent versions)
const merged = lodash.merge({}, defaults, userOptions);

// Option 2: Use Object.create(null) for config objects
function safeOptions(userOptions: Record<string, unknown>) {
    const safe = Object.create(null) as Record<string, unknown>;
    for (const [key, value] of Object.entries(userOptions)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Reject dangerous keys
        }
        safe[key] = value;
    }
    return safe;
}

// Option 3: JSON round-trip (nukes prototype chain)
const sanitized = JSON.parse(JSON.stringify(userOptions));
```

**✅ Validate with Zod (recommended):**
```typescript
import { z } from 'zod';

const OptionsSchema = z.object({
    theme: z.enum(['light', 'dark']),
    language: z.string().max(10),
    pageSize: z.number().int().min(10).max(100),
    // Only allowed fields — __proto__ will be rejected
});

const options = OptionsSchema.parse(userInput);  // Throws on invalid input
```

---

### Dependency Confusion → npm audit + package-lock.json

**Best practices:**

```bash
# Audit dependencies
npm audit
npm audit --audit-level=high  # Fail on high+

# Fix automatically where possible
npm audit fix

# Lock your registry to prevent dependency confusion
cat > .npmrc <<'EOF'
registry=https://registry.npmjs.org/
# Or your private registry:
# registry=https://your-registry.company.com/
@yourcompany:registry=https://your-private-registry.company.com/
EOF

# Always commit package-lock.json
git add package-lock.json
```

**In CI, always use `npm ci` (not `npm install`):**
```bash
# npm ci: uses package-lock.json exactly, fails if lock doesn't match
npm ci --audit
```

---

### Secrets in Frontend → Environment Variables

**❌ Vulnerable:**
```typescript
// Hardcoded API key in source code
const API_KEY = "sk-prod-1234abcdef...";

// In .env committed to git
// REACT_APP_SECRET_KEY=my-secret-key  <- Never commit!
```

**✅ Fixed — React (Create React App / Vite):**
```bash
# .env.local — NEVER commit this file
REACT_APP_API_URL=https://api.example.com
VITE_API_URL=https://api.example.com

# Add to .gitignore
echo ".env.local" >> .gitignore
echo ".env.production.local" >> .gitignore
echo ".env.development.local" >> .gitignore
```

```typescript
// Only expose non-sensitive config to frontend
// NEVER put API keys, secrets, or credentials in REACT_APP_ variables
// They will be visible in the browser bundle!

const API_URL = process.env.REACT_APP_API_URL ?? 'http://localhost:3000';

// Secrets belong on the server, not in the browser
// Use a backend API proxy instead of calling external APIs directly from frontend
```

**✅ Server-side proxy pattern:**
```typescript
// Backend: /api/external-data (server keeps the API key)
app.get('/api/external-data', authenticate, async (req, res) => {
    const response = await fetch('https://external-api.com/data', {
        headers: { 'Authorization': `Bearer ${process.env.EXTERNAL_API_KEY}` }
    });
    res.json(await response.json());
});

// Frontend: calls your backend, not the external API directly
const data = await fetch('/api/external-data');
```

---

## COBOL

### EXEC SQL Injection → Parameterized COBOL SQL

**❌ Vulnerable:**
```cobol
WORKING-STORAGE SECTION.
    01  WS-USER-ID         PIC X(20).
    01  WS-SQL-STMT        PIC X(200).

PROCEDURE DIVISION.
    MOVE FUNCTION CONCATENATE(
        "SELECT * FROM USERS WHERE ID = '",
        WS-USER-ID,
        "'")
    TO WS-SQL-STMT
    EXEC SQL
        EXECUTE IMMEDIATE :WS-SQL-STMT
    END-EXEC.
```

**✅ Fixed — Use host variables (parameterized):**
```cobol
WORKING-STORAGE SECTION.
    01  WS-USER-ID         PIC X(20).
    01  WS-USER-NAME       PIC X(50).

PROCEDURE DIVISION.
*   Use host variable :WS-USER-ID — never concatenated into SQL
    EXEC SQL
        SELECT USER_NAME
        INTO   :WS-USER-NAME
        FROM   USERS
        WHERE  USER_ID = :WS-USER-ID
    END-EXEC

    EVALUATE SQLCODE
        WHEN 0
            DISPLAY "Found: " WS-USER-NAME
        WHEN 100
            DISPLAY "Not found"
        WHEN OTHER
            DISPLAY "SQL error: " SQLCODE
    END-EVALUATE.
```

---

### Buffer Overflow → OCCURS DEPENDING ON with Validation

**❌ Vulnerable:**
```cobol
WORKING-STORAGE SECTION.
    01  WS-ITEMS.
        05  WS-ITEM        PIC X(100)
                           OCCURS 100 TIMES.
    01  WS-COUNT           PIC 9(3).

PROCEDURE DIVISION.
*   No bounds check — WS-COUNT could be > 100
    PERFORM VARYING WS-IDX FROM 1 BY 1
        UNTIL WS-IDX > WS-COUNT
        MOVE WS-SOURCE(WS-IDX) TO WS-ITEM(WS-IDX)
    END-PERFORM.
```

**✅ Fixed — Validate before use:**
```cobol
WORKING-STORAGE SECTION.
    01  WS-MAX-ITEMS       PIC 9(3) VALUE 100.
    01  WS-ITEMS.
        05  WS-ITEM        PIC X(100)
                           OCCURS 1 TO 100 TIMES
                           DEPENDING ON WS-MAX-ITEMS.
    01  WS-COUNT           PIC 9(3).
    01  WS-IDX             PIC 9(3).

PROCEDURE DIVISION.
*   Validate count before loop
    IF WS-COUNT > WS-MAX-ITEMS
        DISPLAY "ERROR: Count " WS-COUNT " exceeds maximum " WS-MAX-ITEMS
        MOVE 16 TO RETURN-CODE
        STOP RUN
    END-IF

    IF WS-COUNT <= ZERO
        DISPLAY "ERROR: Count must be positive"
        MOVE 12 TO RETURN-CODE
        STOP RUN
    END-IF

    PERFORM VARYING WS-IDX FROM 1 BY 1
        UNTIL WS-IDX > WS-COUNT
        MOVE WS-SOURCE(WS-IDX) TO WS-ITEM(WS-IDX)
    END-PERFORM.
```

---

### Hardcoded Credentials → EXTERNAL Data Items

**❌ Vulnerable:**
```cobol
WORKING-STORAGE SECTION.
    01  DB-USERID          PIC X(20) VALUE "PRODUSER".
    01  DB-PASSWORD        PIC X(20) VALUE "SuperSecret123".

PROCEDURE DIVISION.
    EXEC SQL
        CONNECT :DB-USERID IDENTIFIED BY :DB-PASSWORD
    END-EXEC.
```

**✅ Fixed — EXTERNAL data items (set by environment):**
```cobol
WORKING-STORAGE SECTION.
*   EXTERNAL items are provided by the runtime environment
*   Set via environment variables or JCL SYSIN
    01  DB-CREDENTIALS     EXTERNAL.
        05  DB-USERID      PIC X(20).
        05  DB-PASSWORD    PIC X(20).

PROCEDURE DIVISION.
*   Credentials are injected at runtime — never hardcoded
    EXEC SQL
        CONNECT :DB-USERID IDENTIFIED BY :DB-PASSWORD
    END-EXEC

    EVALUATE SQLCODE
        WHEN 0
            DISPLAY "Connected successfully"
        WHEN OTHER
            DISPLAY "Connection failed: " SQLCODE
            MOVE 8 TO RETURN-CODE
            STOP RUN
    END-EVALUATE.
```

**Setting EXTERNAL data at runtime (z/OS JCL):**
```jcl
//MYJOB   JOB  ...
//STEP1   EXEC PGM=MYCOBOL
//SYSOUT  DD   SYSOUT=*
//SYSIN   DD   *
DB-CREDENTIALS DBUSER001           MyRuntimePwd!
/*
```

**Setting via environment variable (Linux/OpenCOBOL):**
```bash
# For GnuCOBOL EXTERNAL variables
export COB_PRE_LOAD="DB-CREDENTIALS"
# Or use a secure vault integration
```

**✅ Better — Use a Secrets Manager integration:**
```cobol
*   Call a utility program to fetch credentials from vault
    CALL "VAULTCRED" USING
        BY CONTENT "database/prod"
        BY REFERENCE DB-USERID
        BY REFERENCE DB-PASSWORD
    END-CALL

    IF RETURN-CODE NOT = 0
        DISPLAY "Failed to retrieve credentials from vault"
        STOP RUN
    END-IF.
```

---

## Quick Reference — Fix Checklist

| Vulnerability | Language | Fix |
|--------------|----------|-----|
| SQL Injection | C# | `FromSqlRaw` with params or LINQ |
| SQL Injection | Java | `PreparedStatement` / JPA `@Query` |
| SQL Injection | COBOL | Host variables in EXEC SQL |
| XXE | C# | `DtdProcessing.Prohibit` |
| XXE | Java | Disable DTD features on factory |
| XSS | React/JS | DOMPurify + CSP headers |
| Deserialization | C# | `TypeNameHandling.None` |
| Deserialization | Java | `ObjectInputFilter` allowlist |
| Path Traversal | Java | `Path.normalize()` + prefix check |
| Hardcoded Secrets | C# | Azure Key Vault / User Secrets |
| Hardcoded Secrets | Java | Spring Vault / Environment |
| Hardcoded Secrets | JS/TS | `.env.local` (gitignored) + server proxy |
| Hardcoded Secrets | COBOL | EXTERNAL data items |
| Weak Crypto | C# | `AesGcm` / `BCrypt` |
| Prototype Pollution | JS/TS | Zod validation / `Object.create(null)` |
| Buffer Overflow | COBOL | Bounds check before OCCURS loop |
| Dependency issues | JS | `npm audit fix` + `npm ci` |
