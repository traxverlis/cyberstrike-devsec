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
    """Génère un rapport de sécurité professionnel, lisible et 100% auto-rempli."""
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M UTC")

    print(f"[*] CyberStrike DevSec — Report Generator")
    print(f"[*] Level: {level} | Results: {results_dir} | Output: {output_path}")
    print(f"[*] Timestamp: {timestamp}")
    print()

    print("[*] Loading tool results...")
    port_findings    = load_nmap_results(results_dir)
    nuclei_findings  = load_nuclei_results(results_dir)
    testssl_findings = load_testssl_results(results_dir)
    nikto_findings   = load_nikto_results(results_dir)
    semgrep_findings = load_semgrep_results(results_dir)
    gitleaks_findings= load_gitleaks_results(results_dir)
    grype_findings   = load_grype_results(results_dir)
    trivy_findings   = load_trivy_results(results_dir)
    checkov_findings = load_checkov_results(results_dir)
    trufflehog_findings = load_trufflehog_results(results_dir)

    print(f"    nmap:{len(port_findings)} nuclei:{len(nuclei_findings)} nikto:{len(nikto_findings)}")
    print(f"    semgrep:{len(semgrep_findings)} gitleaks:{len(gitleaks_findings)} grype:{len(grype_findings)}")

    # Charger contexte
    target = "N/A"
    ptes_ctx = {}
    scan_summary = {}
    for c in [results_dir/"summary.json", results_dir.parent/"summary.json"]:
        if c.exists():
            try: scan_summary = json.load(open(c)); target = scan_summary.get("target","N/A")
            except: pass
            break
    for c in [results_dir/"ptes_context.json", results_dir.parent/"ptes_context.json"]:
        if c.exists():
            try: ptes_ctx = json.load(open(c))
            except: pass
            break

    # Charger analyse IA
    ai_content = ""
    for c in [results_dir.parent/"ai_analysis.md", results_dir/"ai_analysis.md"]:
        if c.exists():
            try: ai_content = c.read_text()
            except: pass
            break

    # Agréger findings
    all_findings = (nuclei_findings + testssl_findings + nikto_findings +
                    semgrep_findings + gitleaks_findings + grype_findings +
                    trivy_findings + checkov_findings + trufflehog_findings)
    all_findings = deduplicate_findings(all_findings)
    all_findings = ensure_cvss_scores(all_findings)
    all_findings.sort(key=lambda f: f.get("cvss", 0.0), reverse=True)
    stats = generate_stats(all_findings)
    print(f"[*] Total: {stats['total']} findings C:{stats['Critical']} H:{stats['High']} M:{stats['Medium']}")

    # Calculer score
    score = max(0, min(100, 100 - stats["Critical"]*20 - stats["High"]*10 - stats["Medium"]*5))
    grade = "A" if score>=85 else "B" if score>=70 else "C" if score>=50 else "D" if score>=30 else "F"

    # Catégories
    technologies   = ptes_ctx.get("technologies", [])
    open_ports     = ptes_ctx.get("open_ports", [])
    http_endpoints = ptes_ctx.get("http_endpoints", [])
    secrets        = [f for f in all_findings if f.get("tool") in ("gitleaks","trufflehog")]
    cves           = [f for f in all_findings if f.get("tool") in ("grype","trivy")]
    sast           = [f for f in all_findings if f.get("tool") == "semgrep"]
    web_vulns      = [f for f in all_findings if f.get("tool") in ("nuclei","nikto","testssl","wapiti")]
    iac            = [f for f in all_findings if f.get("tool") == "checkov"]
    top5           = [f for f in all_findings if f.get("severity","").lower() in ("critical","high")][:5]

    BADGES = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"ℹ️"}
    def badge(sev): return BADGES.get(str(sev).lower(),"⚪")

    LEVEL_NAMES = {1:"Static Code Analysis", 2:"Active Web Scan", 3:"Full Penetration Test"}
    risk = "CRITICAL" if stats["Critical"]>0 else "HIGH" if stats["High"]>0 else "MEDIUM" if stats["Medium"]>0 else "LOW"
    risk_b = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}[risk]

    print("[*] Building professional report...")

    lines_out = []

    # === COVER PAGE ===
    lines_out.append("# Security Assessment Report")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")
    lines_out.append("| | |")
    lines_out.append("|---|---|")
    lines_out.append(f"| **Report Type** | {LEVEL_NAMES.get(level, f'Level {level}')} |")
    lines_out.append(f"| **Target** | `{target}` |")
    lines_out.append(f"| **Date** | {timestamp} |")
    lines_out.append("| **Conducted by** | CyberStrikeAI DevSec |")
    lines_out.append("| **Classification** | CONFIDENTIAL |")
    lines_out.append(f"| **Security Score** | **{score}/100 ({grade})** |")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")

    # === EXECUTIVE SUMMARY ===
    lines_out.append("## 1. Executive Summary")
    lines_out.append("")
    lines_out.append(f"{risk_b} **Overall Risk Level: {risk}**")
    lines_out.append("")
    lines_out.append(f"A security assessment was conducted against `{target}`. "
                     f"The assessment identified **{stats['total']} security findings**, "
                     f"including **{stats['Critical']} critical** and **{stats['High']} high** severity issues.")
    lines_out.append("")
    lines_out.append("### Findings Summary")
    lines_out.append("")
    lines_out.append("| Severity | Count | Action |")
    lines_out.append("|----------|-------|--------|")
    lines_out.append(f"| 🔴 Critical | **{stats['Critical']}** | Immediate — do not deploy |")
    lines_out.append(f"| 🟠 High     | **{stats['High']}** | Fix within 7 days |")
    lines_out.append(f"| 🟡 Medium   | **{stats['Medium']}** | Fix within 30 days |")
    lines_out.append(f"| 🟢 Low      | **{stats['Low']}** | Fix in next sprint |")
    lines_out.append(f"| **Total**   | **{stats['total']}** | |")
    lines_out.append("")
    if technologies:
        techs_str = ", ".join(technologies[:8])
        lines_out.append(f"**Technologies detected:** {techs_str}")
        lines_out.append("")
    if open_ports:
        http_p = [p for p in open_ports if p.get("is_http") or p.get("is_tls")]
        lines_out.append(f"**Network:** {len(open_ports)} open ports, {len(http_p)} HTTP/HTTPS services")
        lines_out.append("")
    if http_endpoints:
        lines_out.append(f"**HTTP endpoints analyzed:** {len(http_endpoints)}")
        lines_out.append("")
    lines_out.append("---")
    lines_out.append("")

    # === AI ANALYSIS ===
    sec = 2
    if ai_content:
        lines_out.append(f"## {sec}. AI-Powered Analysis")
        lines_out.append("")
        lines_out.append("> *Powered by GitHub Copilot — automated triage and prioritization*")
        lines_out.append("")
        lines_out.append(ai_content.strip())
        lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === TOP FINDINGS ===
    if top5:
        lines_out.append(f"## {sec}. Top Critical Findings")
        lines_out.append("")
        for idx_f, f in enumerate(top5, 1):
            sev = f.get("severity","?").upper()
            b = badge(f.get("severity",""))
            tool = f.get("tool","?")
            fid  = f.get("id","?")
            desc = f.get("description","")[:300]
            loc  = f.get("url") or f.get("file","") or f.get("package","")
            cvss = f.get("cvss",0.0)
            fix  = f.get("fix","")

            lines_out.append(f"### {b} Finding #{idx_f} — {fid}")
            lines_out.append("")
            lines_out.append(f"| Field | Value |")
            lines_out.append(f"|-------|-------|")
            lines_out.append(f"| **Severity** | {sev} |")
            lines_out.append(f"| **Tool** | {tool} |")
            lines_out.append(f"| **Location** | `{loc}` |")
            lines_out.append(f"| **CVSS** | {cvss:.1f} |")
            if fix and fix != "no fix":
                lines_out.append(f"| **Fix** | `{fix}` |")
            lines_out.append("")
            lines_out.append(f"**Description:** {desc}")
            lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === SECRETS ===
    if secrets:
        lines_out.append(f"## {sec}. Exposed Secrets")
        lines_out.append("")
        lines_out.append(f"> ⚠️ **{len(secrets)} secret(s) detected** — rotate immediately")
        lines_out.append("")
        lines_out.append("| # | Rule | Location | Description |")
        lines_out.append("|---|------|----------|-------------|")
        for idx_s, s in enumerate(secrets[:20], 1):
            loc = s.get("url","") or f"{s.get('file','')}:{s.get('line','')}"
            desc = s.get("description","")[:80]
            rule = s.get("id","?")
            lines_out.append(f"| {idx_s} | `{rule}` | `{loc[:60]}` | {desc} |")
        if len(secrets) > 20:
            lines_out.append(f"")
            lines_out.append(f"*... and {len(secrets)-20} more secrets.*")
        lines_out.append("")
        lines_out.append("**Immediate actions:**")
        lines_out.append("1. Invalidate and rotate all exposed credentials")
        lines_out.append("2. Add `gitleaks` pre-commit hook to prevent future leaks")
        lines_out.append("3. Move secrets to a secrets manager (Vault, AWS SSM, etc.)")
        lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === CVE ===
    if cves:
        crit_h = [c for c in cves if c.get("severity","").lower() in ("critical","high")]
        lines_out.append(f"## {sec}. Vulnerable Dependencies (CVE)")
        lines_out.append("")
        lines_out.append(f"> {len(cves)} CVE(s) found — {len(crit_h)} critical/high severity")
        lines_out.append("")
        lines_out.append("| # | CVE ID | Package | Fix Version | Severity |")
        lines_out.append("|---|--------|---------|-------------|----------|")
        for idx_c, c in enumerate(sorted(cves, key=lambda x:x.get("cvss",0), reverse=True)[:20], 1):
            pkg  = (c.get("package") or c.get("url",""))[:30]
            fix  = c.get("fix","no fix available")
            sev  = c.get("severity","?")
            cid  = c.get("id","?")
            lines_out.append(f"| {idx_c} | `{cid}` | `{pkg}` | {fix} | {badge(sev)} {sev} |")
        if len(cves) > 20:
            lines_out.append(f"")
            lines_out.append(f"*... and {len(cves)-20} more CVEs in full scan data.*")
        lines_out.append("")
        lines_out.append("**Recommendation:** Update all flagged dependencies to their patched versions.")
        lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === SAST ===
    if sast:
        high_s = [f for f in sast if f.get("severity","").lower() in ("high","error")]
        lines_out.append(f"## {sec}. Code Vulnerabilities (SAST)")
        lines_out.append("")
        lines_out.append(f"> Semgrep OWASP analysis — {len(sast)} total, {len(high_s)} high/critical")
        lines_out.append("")
        if high_s:
            lines_out.append("### High / Critical")
            lines_out.append("")
            lines_out.append("| # | Rule | File:Line | Description |")
            lines_out.append("|---|------|-----------|-------------|")
            for idx_s, f in enumerate(high_s[:15], 1):
                rule = f.get("id","").split(".")[-1][:40]
                url  = f.get("url","")[:50]
                desc = f.get("description","")[:80]
                lines_out.append(f"| {idx_s} | `{rule}` | `{url}` | {desc} |")
            lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === PORTS ===
    if port_findings:
        lines_out.append(f"## {sec}. Network — Open Ports")
        lines_out.append("")
        lines_out.append(build_ports_table(port_findings))
        lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === WEB VULNS ===
    if web_vulns:
        lines_out.append(f"## {sec}. Web Vulnerabilities")
        lines_out.append("")
        lines_out.append(f"> {len(web_vulns)} web vulnerabilities identified")
        lines_out.append("")
        lines_out.append("| # | Tool | Finding | URL | Severity |")
        lines_out.append("|---|------|---------|-----|----------|")
        for idx_w, f in enumerate(sorted(web_vulns, key=lambda x:x.get("cvss",0), reverse=True)[:20], 1):
            tool = f.get("tool","")
            name = f.get("name","")[:50]
            url  = f.get("url","")[:40]
            sev  = f.get("severity","")
            lines_out.append(f"| {idx_w} | {tool} | {name} | `{url}` | {badge(sev)} |")
        lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === IAC ===
    if iac:
        lines_out.append(f"## {sec}. Infrastructure Misconfigurations")
        lines_out.append("")
        lines_out.append(f"> Checkov — {len(iac)} IaC misconfiguration(s)")
        lines_out.append("")
        for f in iac[:10]:
            lines_out.append(f"- **{f.get('id','')}** `{f.get('file','')}` — {f.get('description','')[:80]}")
        lines_out.append("")
        lines_out.append("---")
        lines_out.append("")
        sec += 1

    # === REMEDIATION PLAN ===
    lines_out.append(f"## {sec}. Remediation Roadmap")
    lines_out.append("")

    if stats["Critical"] > 0:
        lines_out.append("### 🔴 Immediate (before next deployment)")
        lines_out.append("")
        if secrets:
            lines_out.append(f"- [ ] Rotate all {len(secrets)} exposed credentials")
        crit_cves = [c for c in cves if c.get("severity","").lower()=="critical"]
        if crit_cves:
            lines_out.append(f"- [ ] Patch {len(crit_cves)} critical CVE(s)")
        crit_sast = [f for f in sast if f.get("severity","").lower() in ("high","error")][:3]
        for f in crit_sast:
            rule = f.get("id","").split(".")[-1]
            loc  = f.get("url","")
            lines_out.append(f"- [ ] Fix `{rule}` in `{loc}`")
        lines_out.append("")

    if stats["High"] > 0:
        lines_out.append("### 🟠 Short-term (within 7 days)")
        lines_out.append("")
        high_cves = [c for c in cves if c.get("severity","").lower()=="high"]
        if high_cves:
            lines_out.append(f"- [ ] Update {len(high_cves)} high-severity dependencies")
        high_web = [f for f in web_vulns if f.get("severity","").lower() in ("high","critical")]
        if high_web:
            lines_out.append(f"- [ ] Fix {len(high_web)} high-severity web vulnerabilities")
        lines_out.append("")

    if stats["Medium"] > 0:
        lines_out.append("### 🟡 Medium-term (within 30 days)")
        lines_out.append("")
        lines_out.append(f"- [ ] Address {stats['Medium']} medium-severity findings")
        if iac:
            lines_out.append(f"- [ ] Fix {len(iac)} IaC misconfiguration(s)")
        lines_out.append("")

    lines_out.append("### Prevention")
    lines_out.append("")
    lines_out.append("- [ ] Add `gitleaks` pre-commit hook: `gitleaks detect --staged`")
    lines_out.append("- [ ] Integrate in CI/CD: `./scripts/scan.sh --mode cicd`")
    lines_out.append("- [ ] Schedule weekly dependency scans")
    lines_out.append("- [ ] Add SAST to PR checks")
    lines_out.append("")
    lines_out.append("---")
    lines_out.append("")
    sec += 1

    # === APPENDIX ===
    lines_out.append(f"## Appendix — Tools & Coverage")
    lines_out.append("")
    lines_out.append("| Tool | Findings | Category |")
    lines_out.append("|------|----------|----------|")
    lines_out.append(f"| Gitleaks | {len(gitleaks_findings)} | Secrets |")
    lines_out.append(f"| TruffleHog | {len(trufflehog_findings)} | Secrets |")
    lines_out.append(f"| Grype | {len(grype_findings)} | CVE |")
    lines_out.append(f"| Trivy | {len(trivy_findings)} | CVE |")
    lines_out.append(f"| Semgrep | {len(sast)} | SAST |")
    lines_out.append(f"| Nuclei | {len(nuclei_findings)} | Web |")
    lines_out.append(f"| Nikto | {len(nikto_findings)} | Web |")
    lines_out.append(f"| Nmap | {len(port_findings)} ports | Network |")
    lines_out.append(f"| Checkov | {len(iac)} | IaC |")
    lines_out.append("")
    lines_out.append(f"---")
    lines_out.append("")
    lines_out.append(f"*Report generated by CyberStrikeAI DevSec v3.3.0 — {timestamp}*")

    report_content = "\n".join(lines_out)

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    md_path = output_path.with_suffix(".md") if output_format != "md" else output_path

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"[+] Markdown report written: {md_path}")

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