# CI/CD Security Gate Report
<!-- CyberStrikeAI DevSec CI/CD Pipeline Role | Template Version: 1.0 -->

---

## Build Security Status

```
┌─────────────────────────────────────────────┐
│  PROJECT : {{project_name}}                 │
│  COMMIT  : {{commit_sha}}                   │
│  BRANCH  : {{branch_name}}                  │
│  DATE    : {{scan_date}}                    │
│                                             │
│  SECURITY GATE : [ {{PASS_OR_FAIL}} ]       │
│  BLOCKERS      : {{blocker_count}}          │
└─────────────────────────────────────────────┘
```

> **Result:** {{result_one_liner}}

---

## Blockers (Critical Only)

> Pipeline fails if any blocker is present.

| # | ID | Type | Package / File | Severity | CVSS | Quick Fix |
|---|----|------|----------------|----------|------|-----------|
| 1 | {{b1_id}} | {{b1_type}} | {{b1_location}} | 🔴 Critical | {{b1_cvss}} | {{b1_fix}} |
| 2 | {{b2_id}} | {{b2_type}} | {{b2_location}} | 🔴 Critical | {{b2_cvss}} | {{b2_fix}} |
| *(add rows...)* | | | | | | |

*No rows = no blockers = PASS.*

---

## Quick Fix Suggestions

{{#each blockers}}
### {{id}} — {{type}}

- **Location:** `{{location}}`
- **Fix:** {{quick_fix}}
- **Docs:** {{reference_url}}

{{/each}}

---

## README Badge

Copy into your project `README.md`:

```markdown
![Security Gate](https://img.shields.io/badge/Security%20Gate-{{PASS_OR_FAIL}}-{{badge_color}}?style=flat-square&logo=shield)
```

**Rendered:**

![Security Gate](https://img.shields.io/badge/Security%20Gate-{{PASS_OR_FAIL}}-{{badge_color}}?style=flat-square&logo=shield)

> Badge color: `brightgreen` for PASS · `red` for FAIL

---

*CyberStrikeAI CI/CD Pipeline | {{scan_date}} | Auto-generated — do not edit manually*
