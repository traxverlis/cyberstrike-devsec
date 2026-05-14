# Security Executive Summary
<!-- CyberStrikeAI DevSec | Template Version: 1.0 | For Management & Stakeholders -->

---

## {{project_name}} — Security Assessment Overview

**Date:** {{report_date}}
**Prepared by:** {{analyst_name}}, {{analyst_role}}
**Audience:** {{audience}} (Executive / CISO / Board)

---

## Overall Risk Level

```
┌──────────────────────────────────────────────┐
│                                              │
│   RISK LEVEL :  🔴 HIGH  /  🟠 MEDIUM  /  🟢 LOW   │
│   (circle one)                               │
│                                              │
│   Current:  [ {{risk_level_label}} ]         │
│                                              │
└──────────────────────────────────────────────┘
```

| Level | Criteria |
|-------|----------|
| 🔴 HIGH | Active exploitable vulnerabilities or exposed secrets |
| 🟠 MEDIUM | Known vulnerabilities without immediate exploitability |
| 🟢 LOW | Minor issues only, good security posture |

---

## What We Found — In Plain Terms

> *This section avoids technical jargon. Security issues are explained as business risks.*

### Key Findings

1. **{{finding_1_title}}**
   {{finding_1_business_impact}}
   *Example: "An attacker could access customer data without authentication."*

2. **{{finding_2_title}}**
   {{finding_2_business_impact}}
   *Example: "An outdated library could allow ransomware-style file encryption."*

3. **{{finding_3_title}}**
   {{finding_3_business_impact}}

---

## Potential Business Impact

| Risk Area                  | Potential Impact                            | Likelihood     |
|----------------------------|---------------------------------------------|----------------|
| **Data Breach**            | {{data_breach_impact}}                      | {{data_breach_likelihood}} |
| **Service Disruption**     | {{disruption_impact}}                       | {{disruption_likelihood}}  |
| **Regulatory / Compliance**| {{compliance_impact}}                       | {{compliance_likelihood}}  |
| **Reputation**             | {{reputation_impact}}                       | {{reputation_likelihood}}  |
| **Financial**              | Estimated exposure: {{financial_exposure}}  | {{financial_likelihood}}   |

> **Regulatory context:** {{regulatory_notes}}
> *(e.g., GDPR fines up to 4% of annual turnover; PCI-DSS non-compliance penalties, etc.)*

---

## Remediation Investment

| Priority | Work Required                          | Estimated Effort | Estimated Cost  |
|----------|----------------------------------------|------------------|-----------------|
| Immediate (Sprint 1) | {{sprint1_summary}}        | {{sprint1_effort}} | {{sprint1_cost}} |
| Short-term (Sprint 2) | {{sprint2_summary}}       | {{sprint2_effort}} | {{sprint2_cost}} |
| Medium-term (Sprint 3) | {{sprint3_summary}}      | {{sprint3_effort}} | {{sprint3_cost}} |
| **Total**            |                                        | **{{total_effort}}** | **{{total_cost}}** |

> **Cost of inaction estimate:** {{inaction_cost_estimate}}
> *(e.g., average cost of a data breach in {{industry}}: ${{avg_breach_cost}}M — IBM Cost of a Data Breach Report {{year}})*

---

## Comparison with Industry Benchmarks

| Metric                        | This Project        | Industry Average    | Best Practice Target |
|-------------------------------|---------------------|---------------------|----------------------|
| Critical CVEs                 | {{our_critical}}    | {{industry_critical}} | 0                  |
| Mean Time to Remediate (MTTR) | {{our_mttr}}        | {{industry_mttr}}   | < 7 days (Critical) |
| Secrets in Code               | {{our_secrets}}     | —                   | 0                  |
| Dependency Freshness          | {{our_freshness}}   | {{industry_freshness}} | > 90%            |
| OWASP Top 10 Coverage         | {{our_owasp}}       | —                   | 100%               |

> Source: {{benchmark_source}} | {{benchmark_date}}

---

## Recommended Actions

### Immediate (This Week)
- [ ] {{immediate_1}}
- [ ] {{immediate_2}}
- [ ] {{immediate_3}}

### Short-Term (Next 30 Days)
- [ ] {{shortterm_1}}
- [ ] {{shortterm_2}}

### Strategic (Next Quarter)
- [ ] Integrate automated security scanning into CI/CD pipeline
- [ ] Conduct developer security awareness training
- [ ] {{strategic_3}}

---

## Conclusion

{{conclusion_paragraph}}

> *"{{closing_quote}}"*
> — {{analyst_name}}, {{analyst_role}}

---

*This document is confidential and intended for executive audiences. A full technical report is available upon request.*
*CyberStrikeAI DevSec | {{report_date}}*
