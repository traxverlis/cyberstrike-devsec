# Security Report — Level 1

Generated: 2026-05-15 11:26 UTC



---

## Resultats des scans

*Genere automatiquement - a valider avant livraison au client.*

### Distribution des severites

```
Severity Distribution
──────────────────────────────────────────────────
🔴 Critical   █████████                      (5)
🟠 High       █████                          (3)
🟡 Medium     ██████████████████████████████ (16)
🟢 Low                                       (0)
ℹ️ Info                                      (0)
──────────────────────────────────────────────────
Total: 24
```

### 🔴 Secrets exposes (5 findings)

| # | Outil | Regle | Fichier:Ligne | Description |
|---|-------|-------|---------------|-------------|
| 1 | gitleaks | `generic-api-key` | `tools/jwt-tool.yaml:164` | Detected a Generic API Key, potentially exposing access to various services and  |
| 2 | gitleaks | `generic-api-key` | `tools/jwt-tool.yaml:171` | Detected a Generic API Key, potentially exposing access to various services and  |
| 3 | gitleaks | `generic-api-key` | `agents/devsec-quick-scan.md:289` | Detected a Generic API Key, potentially exposing access to various services and  |
| 4 | gitleaks | `generic-api-key` | `reports/templates/devsec-full-report.md:214` | Detected a Generic API Key, potentially exposing access to various services and  |
| 5 | gitleaks | `generic-api-key` | `docs/remediation-guide.md:603` | Detected a Generic API Key, potentially exposing access to various services and  |

### 🟡 Vulnerabilites code - SAST (19 findings)

| # | Regle | Fichier:Ligne | Severite | Description |
|---|-------|---------------|----------|-------------|
| 1 | `tainted-sql-string` | `vuln-target/app2.py:74` | 🟠 High | Detected user input used to manually construct a SQL string. This is usually bad practice because ma |
| 2 | `tainted-sql-string` | `vuln-target/app2.py:95` | 🟠 High | Detected user input used to manually construct a SQL string. This is usually bad practice because ma |
| 3 | `tainted-sql-string` | `vuln-target/app2.py:130` | 🟠 High | Detected user input used to manually construct a SQL string. This is usually bad practice because ma |
| 4 | `sql-injection-db-cursor-execute` | `vuln-target/app2.py:70` | 🟡 Medium | User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and |
| 5 | `sql-injection-db-cursor-execute` | `vuln-target/app2.py:71` | 🟡 Medium | User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and |
| 6 | `raw-html-format` | `vuln-target/app2.py:80` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 7 | `directly-returned-format-string` | `vuln-target/app2.py:81` | 🟡 Medium | Detected Flask route directly returning a formatted string. This is subject to cross-site scripting  |
| 8 | `raw-html-format` | `vuln-target/app2.py:81` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 9 | `sql-injection-db-cursor-execute` | `vuln-target/app2.py:93` | 🟡 Medium | User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and |
| 10 | `raw-html-format` | `vuln-target/app2.py:97` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 11 | `directly-returned-format-string` | `vuln-target/app2.py:98` | 🟡 Medium | Detected Flask route directly returning a formatted string. This is subject to cross-site scripting  |
| 12 | `raw-html-format` | `vuln-target/app2.py:98` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 13 | `sql-injection-db-cursor-execute` | `vuln-target/app2.py:127` | 🟡 Medium | User-controlled data from a request is passed to 'execute()'. This could lead to a SQL injection and |
| 14 | `raw-html-format` | `vuln-target/app2.py:133` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 15 | `raw-html-format` | `vuln-target/app2.py:134` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 16 | `raw-html-format` | `vuln-target/app2.py:136` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 17 | `directly-returned-format-string` | `vuln-target/app2.py:138` | 🟡 Medium | Detected Flask route directly returning a formatted string. This is subject to cross-site scripting  |
| 18 | `raw-html-format` | `vuln-target/app2.py:138` | 🟡 Medium | Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassi |
| 19 | `avoid_app_run_with_bad_host` | `vuln-target/app2.py:163` | 🟡 Medium | Running flask app with host 0.0.0.0 could expose the server publicly. |

