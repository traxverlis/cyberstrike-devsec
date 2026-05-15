#!/usr/bin/env python3
"""
generate-report.py — CyberStrike DevSec Automated Report Generator
====================================================================
Aggregates JSON results from security tools, deduplicates findings,
scores them with CVSS, and fills a Markdown report template.
Optionally converts to PDF or HTML via pandoc.

Usage:
    python generate-report.py \
        --level 2 \
        --results-dir ./results/ \
        --template ./reports/templates/level2-active-scan-report.md \
        --output ./reports/output/report-2024-01-15.md \
        --format md

    python generate-report.py \
        --level 3 \
        --results-dir ./results/ \
        --output ./reports/output/pentest-report.pdf \
        --format pdf
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# CVSS SEVERITY MAPPING
# ─────────────────────────────────────────────────────────────────

def cvss_to_severity(score: float) -> str:
    """Map a CVSS v3.1 base score to a severity label."""
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    else:
        return "Info"


def severity_emoji(severity: str) -> str:
    mapping = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🟢",
        "Info":     "ℹ️",
    }
    return mapping.get(severity, "⚪")


# ─────────────────────────────────────────────────────────────────
# RESULT LOADERS
# ─────────────────────────────────────────────────────────────────

def load_json_file(path: Path) -> Optional[dict]:
    """Load a JSON file, return None on failure."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"  [WARN] Could not load {path}: {e}", file=sys.stderr)
        return None


def load_nmap_results(results_dir: Path) -> list[dict]:
    """Parse nmap XML or JSON results into a list of port findings."""
    findings = []

    # Try nmap JSON (nmap -oJ)
    for fname in ["nmap.json", "nmap_results.json", "nmap-results.json"]:
        fpath = results_dir / fname
        if fpath.exists():
            data = load_json_file(fpath)
            if data:
                # nmap JSON structure: nmaprun.host[].ports.port[]
                hosts = data.get("nmaprun", {}).get("host", [])
                if isinstance(hosts, dict):
                    hosts = [hosts]
                for host in hosts:
                    addr = host.get("address", {})
                    if isinstance(addr, list):
                        addr = addr[0]
                    hostname = addr.get("addr", "unknown")
                    ports = host.get("ports", {}).get("port", [])
                    if isinstance(ports, dict):
                        ports = [ports]
                    for port in ports:
                        findings.append({
                            "host": hostname,
                            "port": port.get("@portid", ""),
                            "protocol": port.get("@protocol", "tcp"),
                            "state": port.get("state", {}).get("@state", ""),
                            "service": port.get("service", {}).get("@name", ""),
                            "version": port.get("service", {}).get("@version", ""),
                            "product": port.get("service", {}).get("@product", ""),
                        })
            return findings

    # Fallback: try .txt summary
    for fname in ["nmap.txt", "nmap_results.txt", "nmap-results.xml"]:
        fpath = results_dir / fname
        if fpath.exists():
            try:
                with open(fpath, "r") as f:
                    content = f.read()
                # Simple regex parse for open ports
                for match in re.finditer(
                    r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", content
                ):
                    findings.append({
                        "host": "target",
                        "port": match.group(1),
                        "protocol": match.group(2),
                        "state": "open",
                        "service": match.group(3),
                        "version": match.group(4).strip(),
                        "product": "",
                    })
            except Exception as e:
                print(f"  [WARN] nmap txt parse error: {e}", file=sys.stderr)

    return findings


def load_nuclei_results(results_dir: Path) -> list[dict]:
    """Parse nuclei JSONL output."""
    findings = []
    for fname in ["nuclei.json", "nuclei_results.json", "nuclei.jsonl"]:
        fpath = results_dir / fname
        if fpath.exists():
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            findings.append({
                                "tool": "nuclei",
                                "id": item.get("template-id", ""),
                                "name": item.get("info", {}).get("name", ""),
                                "severity": item.get("info", {}).get("severity", "info").capitalize(),
                                "cvss": item.get("info", {}).get("classification", {}).get("cvss-score", 0.0),
                                "url": item.get("matched-at", ""),
                                "description": item.get("info", {}).get("description", ""),
                                "tags": item.get("info", {}).get("tags", []),
                                "cve": item.get("info", {}).get("classification", {}).get("cve-id", []),
                            })
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"  [WARN] nuclei parse error: {e}", file=sys.stderr)
            break
    return findings


def load_testssl_results(results_dir: Path) -> list[dict]:
    """Parse testssl.sh JSON output."""
    findings = []
    for fname in ["testssl.json", "testssl_results.json"]:
        fpath = results_dir / fname
        if fpath.exists():
            data = load_json_file(fpath)
            if data:
                # testssl JSON structure: {"scanResult": [{"findings": [...]}]}
                scan_results = data.get("scanResult", [])
                for result in scan_results:
                    for finding in result.get("findings", []):
                        severity_raw = finding.get("severity", "INFO").capitalize()
                        if severity_raw.lower() in ("ok", "not tested"):
                            continue
                        findings.append({
                            "tool": "testssl",
                            "id": finding.get("id", ""),
                            "name": finding.get("id", ""),
                            "finding": finding.get("finding", ""),
                            "severity": severity_raw if severity_raw in (
                                "Critical", "High", "Medium", "Low", "Info"
                            ) else "Info",
                            "cvss": 0.0,
                        })
            break
    return findings


def load_nikto_results(results_dir: Path) -> list[dict]:
    """Parse nikto JSON ou texte output."""
    findings = []
    for fname in ["nikto.json", "nikto_results.json", "nikto-results.json"]:
        fpath = results_dir / fname
        if fpath.exists():
            data = load_json_file(fpath)
            if data:
                vulnerabilities = data.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    vulnerabilities = []
                for vuln in vulnerabilities:
                    findings.append({
                        "tool": "nikto",
                        "id": vuln.get("id", ""),
                        "name": vuln.get("msg", ""),
                        "url": vuln.get("url", ""),
                        "method": vuln.get("method", "GET"),
                        "severity": "Medium",
                        "cvss": 0.0,
                        "description": vuln.get("msg", ""),
                    })
                return findings
    # Fallback : parser nikto texte brut
    for fname in ["nikto-results.txt", "nikto.txt", "nikto_results.txt"]:
        fpath = results_dir / fname
        if fpath.exists():
            try:
                import re as _re
                for line in fpath.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("+ ") and len(line) > 5:
                        msg = line[2:].strip()
                        findings.append({
                            "tool": "nikto",
                            "id": "nikto-finding",
                            "name": msg[:80],
                            "url": "",
                            "method": "GET",
                            "severity": "Medium",
                            "cvss": 5.0,
                            "description": msg,
                        })
            except Exception as e:
                print(f"  [WARN] nikto txt parse: {e}", file=sys.stderr)
            if findings:
                return findings
    return findings


# ─────────────────────────────────────────────────────────────────
# DEDUPLICATION
# ─────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
# ADDITIONAL TOOL LOADERS (semgrep, gitleaks, grype, trivy, checkov, trufflehog)
# ─────────────────────────────────────────────────────────────────

SEVERITY_DEFAULT_CVSS = {
    "Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.0, "Info": 0.0,
}


def find_results_file(results_dir: Path, *names) -> Optional[Path]:
    """Cherche un fichier de résultats dans results_dir et ses sous-répertoires phase*."""
    for name in names:
        # Chercher d'abord à la racine
        for candidate in [results_dir / name, results_dir / "raw" / name]:
            if candidate.exists():
                return candidate
        # Chercher dans les sous-répertoires phase*/
        for phase_dir in sorted(results_dir.glob("phase*")):
            candidate = phase_dir / name
            if candidate.exists():
                return candidate
        # Chercher dans raw/phase*/
        for phase_dir in sorted((results_dir / "raw").glob("phase*") if (results_dir / "raw").exists() else []):
            candidate = phase_dir / name
            if candidate.exists():
                return candidate
    return None

def load_semgrep_results(results_dir):
    findings = []
    for candidate in [results_dir/"semgrep.json", results_dir/"semgrep-results.json", results_dir/"raw"/"semgrep-results.json"]:
        if not candidate.exists(): continue
        try:
            data = json.loads(candidate.read_text())
            sev_map = {"ERROR":"High","WARNING":"Medium","INFO":"Low","error":"High","warning":"Medium","info":"Low"}
            for r in data.get("results",[]):
                sev = sev_map.get(r.get("extra",{}).get("severity","WARNING"),"Medium")
                findings.append({"tool":"semgrep","id":r.get("check_id",""),"name":r.get("check_id","").split(".")[-1].replace("-"," ").title(),"severity":sev,"cvss":SEVERITY_DEFAULT_CVSS.get(sev,5.0),"description":r.get("extra",{}).get("message","")[:200],"url":f"{r.get('path','')}:{r.get('start',{}).get('line','')}","file":r.get("path",""),"line":r.get("start",{}).get("line")})
        except Exception as e: print(f"  [WARN] semgrep: {e}", file=sys.stderr)
        break
    return findings

def load_gitleaks_results(results_dir):
    findings = []
    for candidate in [results_dir/"gitleaks.json", results_dir/"gitleaks-results.json", results_dir/"raw"/"gitleaks-results.json"]:
        if not candidate.exists(): continue
        try:
            data = json.loads(candidate.read_text())
            if isinstance(data, list):
                for s in data:
                    findings.append({"tool":"gitleaks","id":s.get("RuleID","?"),"name":s.get("Description",s.get("RuleID","Secret")),"severity":"Critical","cvss":9.0,"description":s.get("Description",""),"url":f"{s.get('File','')}:{s.get('StartLine','')}","file":s.get("File",""),"line":s.get("StartLine")})
        except Exception as e: print(f"  [WARN] gitleaks: {e}", file=sys.stderr)
        break
    return findings

def load_grype_results(results_dir):
    findings = []
    for candidate in [results_dir/"grype.json", results_dir/"grype-results.json", results_dir/"raw"/"grype-results.json"]:
        if not candidate.exists(): continue
        try:
            data = json.loads(candidate.read_text())
            for match in data.get("matches",[]):
                vuln = match.get("vulnerability",{}); art = match.get("artifact",{})
                sev = vuln.get("severity","Unknown").capitalize()
                if sev not in ("Critical","High","Medium","Low","Info"): sev = "Medium"
                cvss_list = vuln.get("cvss",[])
                cvss_score = float(cvss_list[-1].get("metrics",{}).get("baseScore",SEVERITY_DEFAULT_CVSS.get(sev,0))) if cvss_list else SEVERITY_DEFAULT_CVSS.get(sev,0)
                findings.append({"tool":"grype","id":vuln.get("id",""),"name":f"{vuln.get('id','')} — {art.get('name','')} {art.get('version','')}","severity":sev,"cvss":cvss_score,"description":vuln.get("description","")[:200],"url":art.get("name",""),"package":art.get("name",""),"version":art.get("version",""),"fix":", ".join(vuln.get("fix",{}).get("versions",[])) or "no fix"})
        except Exception as e: print(f"  [WARN] grype: {e}", file=sys.stderr)
        break
    return findings

def load_trivy_results(results_dir):
    findings = []
    for candidate in [results_dir/"trivy.json", results_dir/"trivy-results.json", results_dir/"raw"/"trivy-results.json"]:
        if not candidate.exists(): continue
        try:
            data = json.loads(candidate.read_text())
            for result in data.get("Results",[]):
                for vuln in result.get("Vulnerabilities",[]):
                    sev = vuln.get("Severity","UNKNOWN").capitalize()
                    if sev not in ("Critical","High","Medium","Low","Info"): sev = "Medium"
                    findings.append({"tool":"trivy","id":vuln.get("VulnerabilityID",""),"name":f"{vuln.get('VulnerabilityID','')} — {vuln.get('PkgName','')}","severity":sev,"cvss":float(vuln.get("CVSS",{}).get("nvd",{}).get("V3Score",SEVERITY_DEFAULT_CVSS.get(sev,0))),"description":vuln.get("Description","")[:200],"url":vuln.get("PkgName",""),"package":vuln.get("PkgName",""),"fix":vuln.get("FixedVersion","no fix")})
        except Exception as e: print(f"  [WARN] trivy: {e}", file=sys.stderr)
        break
    return findings

def load_checkov_results(results_dir):
    findings = []
    for candidate in [results_dir/"checkov.json", results_dir/"checkov-results.json", results_dir/"raw"/"checkov-results.json"]:
        if not candidate.exists(): continue
        try:
            data = json.loads(candidate.read_text())
            if isinstance(data, dict): data = [data]
            for d in data:
                for check in d.get("results",{}).get("failed_checks",[]):
                    findings.append({"tool":"checkov","id":check.get("check_id",""),"name":check.get("check_name",""),"severity":"Medium","cvss":5.0,"description":check.get("check_name",""),"url":check.get("file_path",""),"file":check.get("file_path","")})
        except Exception as e: print(f"  [WARN] checkov: {e}", file=sys.stderr)
        break
    return findings

def load_trufflehog_results(results_dir):
    findings = []
    for candidate in [results_dir/"trufflehog.json", results_dir/"trufflehog-results.json", results_dir/"raw"/"trufflehog-results.json"]:
        if not candidate.exists(): continue
        try:
            for line in candidate.read_text().splitlines():
                line = line.strip()
                if not line: continue
                item = json.loads(line)
                det = item.get("DetectorName","?"); src_meta = item.get("SourceMetadata",{}).get("Data",{})
                loc = next(iter(src_meta.values()),{}) if src_meta else {}
                findings.append({"tool":"trufflehog","id":det,"name":f"Secret: {det}","severity":"Critical","cvss":9.0,"description":f"Potential secret ({det})","url":loc.get("file",loc.get("link",""))})
        except Exception as e: print(f"  [WARN] trufflehog: {e}", file=sys.stderr)
        break
    return findings


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings based on tool + name + URL."""
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get("tool", ""),
            f.get("name", "").lower().strip(),
            f.get("url", ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ─────────────────────────────────────────────────────────────────
# CVSS AUTO-SCORING (heuristic for tools without CVSS)
# ─────────────────────────────────────────────────────────────────

SEVERITY_DEFAULT_CVSS = {
    "Critical": 9.5,
    "High":     7.5,
    "Medium":   5.0,
    "Low":      2.0,
    "Info":     0.0,
}


def ensure_cvss_scores(findings: list[dict]) -> list[dict]:
    """Fill in default CVSS scores where not provided."""
    for f in findings:
        if not f.get("cvss") or f["cvss"] == 0.0:
            severity = f.get("severity", "Info")
            f["cvss"] = SEVERITY_DEFAULT_CVSS.get(severity, 0.0)
        # Ensure severity is set from CVSS if missing
        if not f.get("severity"):
            f["severity"] = cvss_to_severity(f["cvss"])
    return findings


# ─────────────────────────────────────────────────────────────────
# STATISTICS GENERATION
# ─────────────────────────────────────────────────────────────────

def generate_stats(findings: list[dict]) -> dict:
    """Generate summary statistics from findings."""
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "total": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        if sev in stats:
            stats[sev] += 1
        stats["total"] += 1
    return stats


def render_stats_ascii(stats: dict) -> str:
    """Render a simple ASCII bar chart of finding distribution."""
    lines = ["```", "Severity Distribution", "─" * 50]
    max_count = max((stats[s] for s in ("Critical", "High", "Medium", "Low", "Info")), default=1)
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = stats[sev]
        bar_len = int((count / max(max_count, 1)) * 30)
        bar = "█" * bar_len
        emoji = severity_emoji(sev)
        lines.append(f"{emoji} {sev:<10} {bar:<30} ({count})")
    lines.append("─" * 50)
    lines.append(f"Total: {stats['total']}")
    lines.append("```")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# TEMPLATE FILLING
# ─────────────────────────────────────────────────────────────────

def build_findings_table(findings: list[dict]) -> str:
    """Build a Markdown findings summary table."""
    lines = [
        "| ID | Tool | Title | Severity | CVSS | URL |",
        "|----|------|-------|----------|------|-----|",
    ]
    for i, f in enumerate(findings, start=1):
        fid = f"F-{i:03d}"
        emoji = severity_emoji(f.get("severity", "Info"))
        lines.append(
            f"| {fid} | {f.get('tool', '')} | {f.get('name', '')[:60]} | "
            f"{emoji} {f.get('severity', 'Info')} | {f.get('cvss', 0.0):.1f} | "
            f"`{f.get('url', f.get('host', ''))[:60]}` |"
        )
    return "\n".join(lines)


def build_ports_table(port_findings: list[dict]) -> str:
    """Build a Markdown ports/services table."""
    lines = [
        "| Port | Protocol | Service | Version | State |",
        "|------|----------|---------|---------|-------|",
    ]
    for p in port_findings:
        version = f"{p.get('product', '')} {p.get('version', '')}".strip()
        lines.append(
            f"| {p.get('port', '')} | {p.get('protocol', 'tcp')} | "
            f"{p.get('service', '')} | {version} | {p.get('state', '')} |"
        )
    return "\n".join(lines)


def fill_template(template_content: str, replacements: dict) -> str:
    """Fill placeholder tokens in a template with actual values."""
    result = template_content
    for key, value in replacements.items():
        placeholder = f"<!-- {key} -->"
        result = result.replace(placeholder, str(value))
    return result


# ─────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────

def generate_report(
    level: int,
    results_dir: Path,
    template_path: Optional[Path],
    output_path: Path,
    output_format: str,
) -> None:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")

    print(f"[*] CyberStrike DevSec — Report Generator")
    print(f"[*] Level: {level} | Results: {results_dir} | Output: {output_path}")
    print(f"[*] Timestamp: {timestamp}")
    print()

    # ── Load results ──────────────────────────────────────────────
    print("[*] Loading tool results...")
    port_findings = load_nmap_results(results_dir)
    print(f"    nmap: {len(port_findings)} ports loaded")

    nuclei_findings = load_nuclei_results(results_dir)
    print(f"    nuclei: {len(nuclei_findings)} findings loaded")

    testssl_findings = load_testssl_results(results_dir)
    print(f"    testssl: {len(testssl_findings)} findings loaded")

    nikto_findings = load_nikto_results(results_dir)
    print(f"    nikto: {len(nikto_findings)} findings loaded")

    semgrep_findings = load_semgrep_results(results_dir)
    print(f"    semgrep: {len(semgrep_findings)} findings loaded")
    gitleaks_findings = load_gitleaks_results(results_dir)
    print(f"    gitleaks: {len(gitleaks_findings)} findings loaded")
    grype_findings = load_grype_results(results_dir)
    print(f"    grype: {len(grype_findings)} findings loaded")
    trivy_findings = load_trivy_results(results_dir)
    print(f"    trivy: {len(trivy_findings)} findings loaded")
    checkov_findings = load_checkov_results(results_dir)
    print(f"    checkov: {len(checkov_findings)} findings loaded")
    trufflehog_findings = load_trufflehog_results(results_dir)
    print(f"    trufflehog: {len(trufflehog_findings)} findings loaded")
    all_findings = (nuclei_findings + testssl_findings + nikto_findings
        + semgrep_findings + gitleaks_findings + grype_findings
        + trivy_findings + checkov_findings + trufflehog_findings)

    # ── Deduplicate & score ───────────────────────────────────────
    print("[*] Deduplicating findings...")
    all_findings = deduplicate_findings(all_findings)
    all_findings = ensure_cvss_scores(all_findings)
    all_findings.sort(key=lambda f: f.get("cvss", 0.0), reverse=True)
    print(f"    {len(all_findings)} unique findings after deduplication")

    stats = generate_stats(all_findings)
    print(f"[*] Stats: Critical={stats['Critical']} High={stats['High']} "
          f"Medium={stats['Medium']} Low={stats['Low']} Info={stats['Info']}")

    # ── Resolve template ──────────────────────────────────────────
    if template_path is None:
        default_templates = {
            1: "reports/templates/level1-static-report.md",
            2: "reports/templates/level2-active-scan-report.md",
            3: "reports/templates/level3-pentest-report.md",
        }
        template_path = Path(default_templates.get(level, default_templates[2]))

    if not template_path.exists():
        print(f"[WARN] Template not found: {template_path}. Generating minimal report.")
        template_content = f"# Security Report — Level {level}\n\nGenerated: {timestamp}\n\n"
    else:
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()

    # ── Build replacement values ──────────────────────────────────
    replacements = {
        "SCAN_DATE":          timestamp,
        "REPORT_DATE":        timestamp,
        "OPEN_PORT_COUNT":    str(len(port_findings)),
        "VULN_COUNT":         str(stats["total"]),
        "C":                  str(stats["Critical"]),
        "H":                  str(stats["High"]),
        "M":                  str(stats["Medium"]),
        "L":                  str(stats["Low"]),
        "TOTAL_FINDINGS":     str(stats["total"]),
    }

    # ── Fill template ─────────────────────────────────────────────
    print("[*] Filling report template...")
    report_content = fill_template(template_content, replacements)

    # ── Build report sections ────────────────────────────────────────────────────
    def row(f):
        return {"tool": f.get("tool",""), "id": f.get("id",""), "url": f.get("url",""), "description": f.get("description",""), "severity": f.get("severity",""), "cvss": f.get("cvss",0), "fix": f.get("fix","?"), "package": f.get("package", f.get("url",""))}

    report_content += "\n\n---\n\n## Resultats des scans\n\n"
    report_content += "*Genere automatiquement - a valider avant livraison au client.*\n\n"
    report_content += "### Distribution des severites\n\n"
    report_content += render_stats_ascii(stats)
    report_content += "\n\n"

    if port_findings:
        n = len(port_findings)
        report_content += "### Ports & Services ouverts (" + str(n) + " trouves)\n\n"
        report_content += build_ports_table(port_findings)
        report_content += "\n\n"

    secret_findings = [f for f in all_findings if f.get("tool") in ("gitleaks","trufflehog")]
    if secret_findings:
        n = len(secret_findings)
        report_content += "### 🔴 Secrets exposes (" + str(n) + " findings)\n\n"
        report_content += "| # | Outil | Regle | Fichier:Ligne | Description |\n"
        report_content += "|---|-------|-------|---------------|-------------|\n"
        for i, f in enumerate(secret_findings, 1):
            r = row(f)
            report_content += "| " + str(i) + " | " + r["tool"] + " | `" + r["id"] + "` | `" + r["url"][:60] + "` | " + r["description"][:80] + " |\n"
        report_content += "\n"

    cve_findings = [f for f in all_findings if f.get("tool") in ("grype","trivy")]
    if cve_findings:
        n = len(cve_findings)
        report_content += "### 🟠 CVE / Dependances vulnerables (" + str(n) + " findings)\n\n"
        report_content += "| # | Outil | CVE | Package | Fix | Severite |\n"
        report_content += "|---|-------|-----|---------|-----|----------|\n"
        for i, f in enumerate(sorted(cve_findings, key=lambda x: x.get("cvss", 0), reverse=True), 1):
            r = row(f)
            report_content += "| " + str(i) + " | " + r["tool"] + " | `" + r["id"] + "` | `" + r["package"][:40] + "` | " + r["fix"] + " | " + severity_emoji(r["severity"]) + " " + r["severity"] + " |\n"
        report_content += "\n"

    sast_findings = [f for f in all_findings if f.get("tool") == "semgrep"]
    if sast_findings:
        n = len(sast_findings)
        report_content += "### 🟡 Vulnerabilites code - SAST (" + str(n) + " findings)\n\n"
        report_content += "| # | Regle | Fichier:Ligne | Severite | Description |\n"
        report_content += "|---|-------|---------------|----------|-------------|\n"
        for i, f in enumerate(sorted(sast_findings, key=lambda x: x.get("cvss", 0), reverse=True), 1):
            r = row(f)
            rule = r["id"].split(".")[-1][:40]
            report_content += "| " + str(i) + " | `" + rule + "` | `" + r["url"][:60] + "` | " + severity_emoji(r["severity"]) + " " + r["severity"] + " | " + r["description"][:100] + " |\n"
        report_content += "\n"

    iac_findings = [f for f in all_findings if f.get("tool") == "checkov"]
    if iac_findings:
        n = len(iac_findings)
        report_content += "### 🔵 IaC / Configuration (" + str(n) + " findings)\n\n"
        report_content += "| # | Check ID | Fichier | Description |\n"
        report_content += "|---|----------|---------|-------------|\n"
        for i, f in enumerate(iac_findings, 1):
            r = row(f)
            report_content += "| " + str(i) + " | `" + r["id"] + "` | `" + r["url"][:60] + "` | " + r["description"][:80] + " |\n"
        report_content += "\n"

    web_findings = [f for f in all_findings if f.get("tool") in ("nuclei","nikto","testssl")]
    if web_findings:
        n = len(web_findings)
        report_content += "### 🟡 Vulnerabilites Web (" + str(n) + " findings)\n\n"
        report_content += build_findings_table(web_findings)
        report_content += "\n\n"

        # ── Write markdown output ─────────────────────────────────────
    output_path.parent.mkdir(parents=True, exist_ok=True)
    md_path = output_path.with_suffix(".md") if output_format != "md" else output_path

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"[+] Markdown report written: {md_path}")

    # ── Convert format ────────────────────────────────────────────
    if output_format in ("pdf", "html"):
        _convert_with_pandoc(md_path, output_path, output_format)

    print(f"\n[+] Done. Report: {output_path}")


def _convert_with_pandoc(md_path, output_path, fmt):
    if fmt == "html":
        _pandoc_html(md_path, output_path)
        return
    if fmt == "pdf":
        if _weasyprint_available():
            html_path = md_path.with_suffix(".html")
            _pandoc_html(md_path, html_path)
            _weasyprint_pdf(html_path, output_path)
        else:
            _pandoc_pdf_latex(md_path, output_path)

def _weasyprint_available():
    try:
        r = subprocess.run(["weasyprint","--version"], capture_output=True, text=True)
        return r.returncode == 0
    except FileNotFoundError:
        return False

def _pandoc_html(md_path, output_path):
    css = "body{font-family:Arial,sans-serif;max-width:960px;margin:2em auto;padding:0 2em;color:#1a1a2e;line-height:1.6}h1{color:#e94560;border-bottom:3px solid #e94560;padding-bottom:.3em}h2{color:#0f3460;border-bottom:1px solid #0f3460;margin-top:2em}table{border-collapse:collapse;width:100%;margin:1em 0}th{background:#0f3460;color:#fff;padding:.5em 1em;text-align:left}td{border:1px solid #ccc;padding:.5em 1em}tr:nth-child(even){background:#f5f7fa}code,pre{background:#f0f0f0;border-radius:4px;font-family:monospace;font-size:.9em}pre{padding:1em;overflow-x:auto}"
    css_path = md_path.parent / "_style.css"
    css_path.write_text(css)
    try:
        r = subprocess.run(["pandoc", str(md_path), "-o", str(output_path), "--standalone","--toc","--self-contained","--css",str(css_path),"--metadata","title=CyberStrikeAI DevSec Report"], capture_output=True, text=True)
        css_path.unlink(missing_ok=True)
        if r.returncode == 0: print(f"[+] HTML report written: {output_path}")
        else: print(f"[ERROR] pandoc HTML: {r.stderr}", file=sys.stderr)
    except FileNotFoundError:
        css_path.unlink(missing_ok=True)
        print("[WARN] pandoc not found")

def _weasyprint_pdf(html_path, output_path):
    print("[*] Generating PDF via weasyprint...")
    try:
        r = subprocess.run(["weasyprint", str(html_path), str(output_path)], capture_output=True, text=True)
        if r.returncode == 0: print(f"[+] PDF report written: {output_path}")
        else: print(f"[ERROR] weasyprint: {r.stderr}", file=sys.stderr)
    except FileNotFoundError:
        print("[WARN] weasyprint not found")

def _pandoc_pdf_latex(md_path, output_path):
    print("[*] PDF via pandoc+xelatex (fallback)...")
    try:
        r = subprocess.run(["pandoc", str(md_path), "-o", str(output_path), "--pdf-engine=xelatex","--variable","geometry:margin=2cm","--toc"], capture_output=True, text=True)
        if r.returncode == 0: print(f"[+] PDF written: {output_path}")
        else: print(f"[ERROR] xelatex: {r.stderr}", file=sys.stderr)
    except FileNotFoundError:
        print("[WARN] pandoc not found")


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CyberStrike DevSec — Automated Security Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate Level 2 Markdown report
  python generate-report.py --level 2 --results-dir ./results/ --output ./reports/output/report.md

  # Generate Level 3 PDF report
  python generate-report.py --level 3 --results-dir ./results/ --output ./reports/output/pentest.pdf --format pdf

  # Generate Level 2 HTML with custom template
  python generate-report.py --level 2 --results-dir ./results/ \\
      --template ./reports/templates/level2-active-scan-report.md \\
      --output ./reports/output/report.html --format html
        """
    )
    parser.add_argument(
        "--level", type=int, choices=[1, 2, 3], default=2,
        help="Scan/pentest level (1=passive, 2=active scan, 3=full pentest)"
    )
    parser.add_argument(
        "--results-dir", type=Path, default=Path("./results/"),
        help="Directory containing tool JSON/text output files"
    )
    parser.add_argument(
        "--template", type=Path, default=None,
        help="Path to report Markdown template (auto-selected by level if omitted)"
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Output file path (e.g., ./reports/output/report.md)"
    )
    parser.add_argument(
        "--format", choices=["md", "pdf", "html"], default="md",
        help="Output format: md (Markdown), pdf (weasyprint via HTML, fallback xelatex), html (pandoc)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.results_dir.exists():
        print(f"[ERROR] Results directory not found: {args.results_dir}", file=sys.stderr)
        sys.exit(1)

    generate_report(
        level=args.level,
        results_dir=args.results_dir,
        template_path=args.template,
        output_path=args.output,
        output_format=args.format,
    )


if __name__ == "__main__":
    main()
