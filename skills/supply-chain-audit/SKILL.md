---
name: supply-chain-audit
description: Software supply chain security audit — package integrity verification, typosquatting detection, license compliance, abandoned dependency detection, and transitive dependency analysis
version: 1.0.0
author: DevSec Team
tags: [security, devsec, supply-chain, sbom, integrity, license, typosquatting, dependencies]
---

# Supply Chain Audit

## Objective

Audit the software supply chain for security and compliance risks: verify package integrity (checksums, signatures), detect typosquatting attacks, assess license compliance (GPL, LGPL, MIT, Apache), flag abandoned dependencies, and analyze transitive dependency trees.

## Prerequisites

### Required Tools

| Tool | Installation | Purpose |
|------|-------------|---------|
| `grype` | See cve-dependency-scan skill | Vulnerability + integrity scanning |
| `syft` | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh -s -- -b /usr/local/bin` | SBOM generation |
| `pip-licenses` | `pip install pip-licenses` | Python license detection |
| `license-checker` | `npm install -g license-checker` | Node.js license detection |
| `dotnet-project-licenses` | `dotnet tool install -g dotnet-project-licenses` | .NET license detection |
| `cosign` | [sigstore/cosign](https://github.com/sigstore/cosign) | Container/artifact signature verification |
| `jq` | Package manager | JSON processing |
| `python3` | System | Custom analysis scripts |

## Part 1: Package Integrity Verification

### Generate and Verify SBOM

An SBOM (Software Bill of Materials) provides a complete inventory of components with their versions and checksums.

```bash
# Generate SBOM for any project type
syft dir:. -o cyclonedx-json > sbom.json       # CycloneDX format (recommended)
syft dir:. -o spdx-json > sbom-spdx.json       # SPDX format
syft dir:. -o table                             # Human-readable summary

# Verify SBOM with Grype (vulnerability check on SBOM)
grype sbom:./sbom.json -o json > sbom-vulns.json
```

### npm / yarn — Lockfile Integrity

```bash
# Verify package-lock.json integrity hashes
node -e "
const lock = require('./package-lock.json');
const deps = lock.packages || lock.dependencies || {};
let issues = 0;
for (const [name, info] of Object.entries(deps)) {
  if (info.integrity && !info.integrity.startsWith('sha512-') && !info.integrity.startsWith('sha1-')) {
    console.log('WEAK HASH:', name, info.integrity);
    issues++;
  }
  if (!info.integrity && name !== '') {
    console.log('MISSING INTEGRITY:', name);
    issues++;
  }
}
console.log('Issues found:', issues);
"

# Check for integrity mismatches
npm ci --dry-run 2>&1 | grep -i "integrity\|tamper\|mismatch" || echo "npm integrity OK"

# Yarn integrity check
yarn check --integrity 2>&1 | grep -v "^$" | head -50
```

### NuGet — Package Signature Verification

```bash
# Verify NuGet package signatures
dotnet nuget verify --all 2>&1 | tee nuget-verify.txt

# Check for unsigned packages
grep -i "unsigned\|not signed\|warning" nuget-verify.txt > nuget-unsigned.txt

# List all packages with their hashes
dotnet list package --format json > nuget-packages.json

# Check NuGet.lock.json exists (enables reproducible builds)
if [ ! -f "packages.lock.json" ]; then
  echo "WARNING: packages.lock.json not found — enable with <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>"
fi
```

### Maven — Checksum Verification

```bash
# Maven enforces checksums by default; verify settings
grep -r "checksumPolicy" ~/.m2/settings.xml . 2>/dev/null | head

# Check for 'warn' or 'ignore' checksum policies (should be 'fail')
if grep -q "checksumPolicy>warn\|checksumPolicy>ignore" ~/.m2/settings.xml 2>/dev/null; then
  echo "INSECURE: Maven checksumPolicy is not set to 'fail'"
fi

# Generate dependency tree for audit
mvn dependency:tree -DoutputFile=dep-tree.txt -DoutputType=text

# Check for SNAPSHOT dependencies in production
grep "SNAPSHOT" dep-tree.txt && echo "WARNING: SNAPSHOT dependencies found — not suitable for production"
```

---

## Part 2: Typosquatting Detection

Typosquatting attacks use packages with names similar to legitimate popular packages to trick developers into installing malicious code.

### npm Typosquatting Check

```python
#!/usr/bin/env python3
"""
check-typosquatting.py — Detect potential typosquatting in package.json
"""
import json
import re
import sys
from itertools import product

# Popular npm packages that are frequent typosquatting targets
POPULAR_PACKAGES = {
    "react", "react-dom", "lodash", "express", "axios", "webpack",
    "babel-core", "typescript", "jest", "eslint", "prettier",
    "vue", "angular", "next", "nuxt", "gatsby", "redux",
    "moment", "dayjs", "uuid", "chalk", "dotenv", "cors",
    "mongoose", "sequelize", "knex", "prisma", "typeorm",
    "jsonwebtoken", "bcrypt", "passport", "helmet", "morgan"
}

def levenshtein(s1, s2):
    m, n = len(s1), len(s2)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1): dp[i][0] = i
    for j in range(n+1): dp[0][j] = j
    for i in range(1, m+1):
        for j in range(1, n+1):
            if s1[i-1] == s2[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]

def check_typosquatting(pkg_name):
    suspicious = []
    clean_name = pkg_name.lstrip("@").split("/")[-1]  # Handle scoped packages
    for popular in POPULAR_PACKAGES:
        dist = levenshtein(clean_name.lower(), popular.lower())
        if 0 < dist <= 2 and clean_name.lower() != popular.lower():
            suspicious.append({
                "package": pkg_name,
                "similar_to": popular,
                "edit_distance": dist
            })
    return suspicious

# Load package.json
with open("package.json") as f:
    pkg = json.load(f)

all_deps = {}
for section in ["dependencies", "devDependencies", "peerDependencies"]:
    all_deps.update(pkg.get(section, {}))

print(f"Checking {len(all_deps)} packages for typosquatting...\n")
findings = []
for name in all_deps:
    matches = check_typosquatting(name)
    findings.extend(matches)

if findings:
    print("⚠️  POTENTIAL TYPOSQUATTING DETECTED:")
    for f in findings:
        print(f"  Package '{f['package']}' is similar to '{f['similar_to']}' (edit distance: {f['edit_distance']})")
    print("\nManually verify these packages are legitimate before using in production.")
else:
    print("✅ No obvious typosquatting detected in direct dependencies.")
    print("Note: Transitive dependencies are not checked here. Use 'npm audit' for broader coverage.")
```

### NuGet Typosquatting Check

```python
#!/usr/bin/env python3
"""Check NuGet packages for typosquatting"""
import xml.etree.ElementTree as ET
import subprocess
import json

POPULAR_NUGET = {
    "Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection",
    "Microsoft.EntityFrameworkCore", "AutoMapper", "Serilog",
    "FluentValidation", "MediatR", "StackExchange.Redis",
    "Dapper", "NLog", "log4net", "Polly", "RestSharp",
    "Bogus", "xunit", "NUnit", "Moq", "FluentAssertions"
}

# Parse .csproj files
import glob
packages = []
for csproj in glob.glob("**/*.csproj", recursive=True):
    tree = ET.parse(csproj)
    root = tree.getroot()
    for ref in root.iter("PackageReference"):
        include = ref.get("Include")
        if include:
            packages.append(include)

print(f"Found {len(packages)} package references")
# Apply levenshtein check (same as npm version above)
```

### PyPI Typosquatting Check

```bash
# Use pip-audit which includes some typosquatting detection
pip-audit --output-format json > pip-audit-full.json

# Additional check with custom script or OSV scanner
osv-scanner --lockfile requirements.txt

# Check against known typosquatting database
curl -s "https://api.osv.dev/v1/query" \
  -d '{"package": {"name": "colourama", "ecosystem": "PyPI"}}' | jq '.vulns'
# "colourama" is a known typosquat of "colorama"
```

---

## Part 3: License Compliance

### License Classification

| License | Type | Risk for Commercial Use |
|---------|------|------------------------|
| MIT | Permissive | ✅ Low — attribution required |
| Apache 2.0 | Permissive | ✅ Low — attribution + patent notice |
| BSD 2/3-Clause | Permissive | ✅ Low |
| LGPL v2.1/v3 | Weak Copyleft | ⚠️ Medium — linking restrictions |
| GPL v2 | Strong Copyleft | 🔴 High — requires open-sourcing your code |
| GPL v3 | Strong Copyleft | 🔴 High |
| AGPL v3 | Network Copyleft | 🔴 Critical — applies to SaaS |
| CC BY-NC | Non-Commercial | 🔴 Critical — no commercial use |
| Proprietary | Commercial | ❓ Review license terms |

### npm License Check

```bash
# Install and run license-checker
npm install -g license-checker
license-checker --json --out licenses-npm.json

# Check for problematic licenses
license-checker --failOn "GPL;AGPL;CC-BY-NC" --json --out licenses-npm.json

# Summary by license type
license-checker --summary

# List only packages with copyleft licenses
license-checker --onlyAllow "MIT;Apache-2.0;BSD-2-Clause;BSD-3-Clause;ISC;0BSD;CC0-1.0;Unlicense"
```

### .NET License Check

```bash
# Install dotnet-project-licenses
dotnet tool install -g dotnet-project-licenses

# Generate license report
dotnet-project-licenses --input . --output-format json --output-file licenses-dotnet.json

# Check for GPL/LGPL packages
cat licenses-dotnet.json | jq '.[] | select(.LicenseType | test("GPL|LGPL|AGPL"))'
```

### Maven License Check

```bash
# OWASP License Check Plugin
mvn license:aggregate-add-third-party

# Generate license report
mvn license:aggregate-download-licenses

# Check report
cat target/generated-sources/license/THIRD-PARTY.txt | grep -i "GPL\|AGPL\|LGPL"
```

### Python License Check

```bash
# pip-licenses: comprehensive Python license analysis
pip-licenses --format json --output-file licenses-python.json

# Flag problematic licenses
pip-licenses --fail-on "GPL;AGPL" --format markdown

# Summary
pip-licenses --format markdown | head -50
```

---

## Part 4: Abandoned Dependency Detection

A dependency is considered abandoned if it has not had a release in 2+ years.

### npm Abandoned Check

```bash
#!/bin/bash
# Check last publish date for all npm dependencies

node -e "
const pkg = require('./package.json');
const deps = {...(pkg.dependencies||{}), ...(pkg.devDependencies||{})};
const pkgs = Object.keys(deps);

(async () => {
  const https = require('https');
  const TWO_YEARS_AGO = Date.now() - (2 * 365 * 24 * 60 * 60 * 1000);

  for (const name of pkgs) {
    await new Promise((resolve) => {
      const url = \`https://registry.npmjs.org/\${name}/latest\`;
      https.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const info = JSON.parse(data);
            const published = new Date(info.time || info._time).getTime();
            if (published < TWO_YEARS_AGO) {
              const years = ((Date.now() - published) / (365*24*60*60*1000)).toFixed(1);
              console.log(\`ABANDONED (\${years}y): \${name} — last release: \${info.time}\`);
            }
          } catch(e) {}
          resolve();
        });
      }).on('error', resolve);
    });
  }
})();
" 2>/dev/null
```

### NuGet Abandoned Check

```python
#!/usr/bin/env python3
"""Check NuGet packages for last publish date"""
import subprocess
import json
import datetime
import urllib.request
import xml.etree.ElementTree as ET
import glob

TWO_YEARS_AGO = datetime.datetime.now() - datetime.timedelta(days=730)

packages = []
for csproj in glob.glob("**/*.csproj", recursive=True):
    tree = ET.parse(csproj)
    root = tree.getroot()
    for ref in root.iter("PackageReference"):
        name = ref.get("Include")
        version = ref.get("Version", "")
        if name:
            packages.append((name, version))

for name, version in packages:
    try:
        url = f"https://api.nuget.org/v3/registration5-gz-semver2/{name.lower()}/index.json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        items = data.get("items", [])
        if items:
            latest_entry = items[-1]
            latest_items = latest_entry.get("items", [])
            if latest_items:
                last_entry = latest_items[-1]
                published = last_entry.get("catalogEntry", {}).get("published", "")
                if published:
                    pub_date = datetime.datetime.fromisoformat(published.replace("Z", "+00:00")).replace(tzinfo=None)
                    if pub_date < TWO_YEARS_AGO:
                        age = (datetime.datetime.now() - pub_date).days // 365
                        print(f"ABANDONED ({age}+ years): {name} — last release: {published[:10]}")
    except Exception as e:
        pass  # Skip packages with registry errors
```

---

## Part 5: Transitive Dependency Analysis

### npm Transitive Dependencies

```bash
# Full dependency tree
npm ls --all --json > npm-dep-tree.json

# Count total transitive deps
node -e "
const tree = require('./npm-dep-tree.json');
const all = new Set();
function walk(deps) {
  if (!deps) return;
  for (const [name, info] of Object.entries(deps)) {
    all.add(name);
    walk(info.dependencies);
  }
}
walk(tree.dependencies);
console.log('Total unique transitive dependencies:', all.size);
"

# Find deeply nested packages (potential risk)
npm ls --all 2>&1 | awk '{print NF, $0}' | sort -rn | head -20
```

### Maven Transitive Dependencies

```bash
# Full dependency tree
mvn dependency:tree -DoutputFile=maven-dep-tree.txt

# Count unique transitive deps
grep -v "^\\[INFO\\]" maven-dep-tree.txt | grep ":" | sed 's/.*://; s/:.*//' | sort -u | wc -l

# Find highest risk transitive deps (check against CVE db)
mvn dependency:tree -DoutputFile=/tmp/tree.txt && \
  grep -oP '([a-zA-Z0-9.-]+):([a-zA-Z0-9.-]+):jar:([0-9.]+)' /tmp/tree.txt | \
  awk -F: '{print $1":"$2"@"$3}' | sort -u > transitive-pkgs.txt

# Scan transitives with Grype
grype dir:. --scope all-layers -o json > grype-transitives.json
```

### .NET Transitive Dependencies

```bash
# List all packages including transitive
dotnet list package --include-transitive --format json > dotnet-all-deps.json

# Count transitive packages
jq '[.projects[].frameworks[].transitivePackages[]?.id] | length' dotnet-all-deps.json

# Find transitive packages with vulnerabilities
dotnet list package --include-transitive --vulnerable 2>&1
```

---

## Complete Supply Chain Audit Script

```bash
#!/bin/bash
# Full supply chain audit

PROJECT_DIR="${1:-.}"
OUTPUT_DIR="${2:-./supply-chain-audit}"
mkdir -p "$OUTPUT_DIR"

echo "=== 1. SBOM Generation ==="
syft dir:"$PROJECT_DIR" -o cyclonedx-json > "$OUTPUT_DIR/sbom.json"
echo "SBOM saved: $OUTPUT_DIR/sbom.json"

echo "=== 2. Package Integrity ==="
if [ -f "$PROJECT_DIR/package.json" ]; then
  cd "$PROJECT_DIR" && npm ci --dry-run 2>&1 > "$OUTPUT_DIR/npm-integrity.txt" && cd -
fi
if [ -f "$PROJECT_DIR/packages.lock.json" ]; then
  dotnet nuget verify --all > "$OUTPUT_DIR/nuget-verify.txt" 2>&1 || true
fi

echo "=== 3. Typosquatting Check ==="
if [ -f "$PROJECT_DIR/package.json" ]; then
  python3 check-typosquatting.py > "$OUTPUT_DIR/typosquatting.txt"
fi

echo "=== 4. License Compliance ==="
if [ -f "$PROJECT_DIR/package.json" ]; then
  license-checker --json --out "$OUTPUT_DIR/licenses-npm.json" 2>/dev/null || true
fi
if find "$PROJECT_DIR" -name "*.csproj" | grep -q .; then
  dotnet-project-licenses --input "$PROJECT_DIR" \
    --output-format json \
    --output-file "$OUTPUT_DIR/licenses-dotnet.json" 2>/dev/null || true
fi
if [ -f "$PROJECT_DIR/requirements.txt" ]; then
  pip-licenses --format json --output-file "$OUTPUT_DIR/licenses-python.json" 2>/dev/null || true
fi

echo "=== 5. Abandoned Dependency Check ==="
if [ -f "$PROJECT_DIR/package.json" ]; then
  node check-abandoned-npm.js > "$OUTPUT_DIR/abandoned-npm.txt" 2>/dev/null || true
fi

echo "=== 6. Transitive Dependency Analysis ==="
grype sbom:"$OUTPUT_DIR/sbom.json" -o json > "$OUTPUT_DIR/grype-sbom.json" 2>/dev/null || true

echo ""
echo "=== SUPPLY CHAIN AUDIT COMPLETE ==="
echo "Results in: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"

# Quick summary
echo ""
echo "=== SUMMARY ==="
if [ -f "$OUTPUT_DIR/grype-sbom.json" ]; then
  echo -n "CVE findings in dependencies: "
  jq '.matches | length' "$OUTPUT_DIR/grype-sbom.json" 2>/dev/null || echo "N/A"
fi
if [ -f "$OUTPUT_DIR/typosquatting.txt" ]; then
  TYPO_COUNT=$(grep -c "POTENTIAL" "$OUTPUT_DIR/typosquatting.txt" 2>/dev/null || echo 0)
  echo "Potential typosquatting: $TYPO_COUNT"
fi
if [ -f "$OUTPUT_DIR/abandoned-npm.txt" ]; then
  ABN_COUNT=$(grep -c "ABANDONED" "$OUTPUT_DIR/abandoned-npm.txt" 2>/dev/null || echo 0)
  echo "Abandoned npm packages: $ABN_COUNT"
fi
```

## Interpreting Results

### Risk Matrix

| Finding Type | Risk Level | Action |
|-------------|-----------|--------|
| Package with known CVE | Per CVSS | See CVE scan skill |
| Integrity mismatch / unsigned | CRITICAL | Do not use — potential supply chain attack |
| Typosquatting candidate | HIGH | Verify package name is correct, check publisher |
| GPL/AGPL in commercial product | HIGH | Legal review required — may require open-sourcing |
| Abandoned dependency (>2 years) | MEDIUM | Find maintained fork or alternative |
| LGPL in commercial product | MEDIUM | Legal review — dynamic linking may be acceptable |
| SNAPSHOT/pre-release in production | MEDIUM | Pin to stable release |
| Missing lockfile | LOW | Add lockfile for reproducible builds |

### Supply Chain Attack Indicators

Watch for these red flags:
- Package recently uploaded with no version history
- Package name extremely similar to popular package (edit distance 1-2)
- Author/maintainer account recently created
- Unexpected network calls in package install scripts (`preinstall`, `postinstall`)
- Package size dramatically different from similar packages
- No source code repository linked

```bash
# Check for suspicious install scripts
cat node_modules/*/package.json | jq 'select(.scripts.preinstall or .scripts.postinstall) | {name: .name, preinstall: .scripts.preinstall, postinstall: .scripts.postinstall}'
```

## Related Skills

- `cve-dependency-scan` — Detailed CVE scanning
- `owasp-code-review` — OWASP A06 vulnerable components
- `sast-devsec` — Secret detection in code
- `devsec-report` — Aggregate all findings into a report
