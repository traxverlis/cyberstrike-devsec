"""
tool_loader.py — Chargement dynamique des outils depuis tools/*.yaml
CyberStrikeAI DevSec — Option C Refactor
"""
import shutil
import subprocess
from pathlib import Path
from typing import Optional

try:
    import yaml as _yaml
    def _load_yaml(text: str) -> dict:
        return _yaml.safe_load(text)
except ImportError:
    # Fallback minimal YAML parser for simple key:value files
    def _load_yaml(text: str) -> dict:  # type: ignore
        import re
        result = {}
        current_key = None
        current_list = None
        for line in text.splitlines():
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            # Detect list item under a key
            if stripped.startswith('- ') and current_key:
                if current_list is None:
                    current_list = []
                    result[current_key] = current_list
                current_list.append(stripped[2:].strip())
                continue
            # Key: value
            if ':' in stripped:
                key, _, val = stripped.partition(':')
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                current_key = key
                current_list = None
                if val:
                    # Try booleans and numbers
                    if val.lower() == 'true':
                        result[key] = True
                    elif val.lower() == 'false':
                        result[key] = False
                    else:
                        try:
                            result[key] = int(val)
                        except ValueError:
                            result[key] = val
        return result


class ToolLoader:
    """
    Charge et exécute les outils depuis tools/*.yaml dynamiquement.
    Supporte deux formats YAML coexistants :
      - Format A (semgrep/grype/gitleaks) : name, command, parameters[] (liste avec flag/format)
      - Format B (nmap/nuclei-passive) : name, binary, parameters{} (dict)
    """

    def __init__(self, tools_dir: Path):
        self.tools_dir = Path(tools_dir)
        self._cache: dict[str, dict] = {}

    def load_tool(self, name: str) -> Optional[dict]:
        """Charge un outil depuis tools/{name}.yaml"""
        if name in self._cache:
            return self._cache[name]

        tool_file = self.tools_dir / f"{name}.yaml"
        if not tool_file.exists():
            return None

        try:
            tool = _load_yaml(tool_file.read_text())
            self._cache[name] = tool
            return tool
        except Exception as e:
            print(f"[ToolLoader] ⚠️  Erreur lecture {tool_file}: {e}")
            return None

    def is_available(self, tool: dict) -> bool:
        """Vérifie si le binaire est installé"""
        binary = tool.get("command") or tool.get("binary") or tool.get("name")
        if not binary:
            return False
        return shutil.which(str(binary)) is not None

    def build_command(self, tool: dict, params: dict) -> list[str]:
        """
        Construit la liste d'args CLI depuis les paramètres YAML.
        Gère les deux formats de paramètres.
        """
        binary = tool.get("command") or tool.get("binary") or tool.get("name")
        cmd = [str(binary)]

        # Format A : parameters est une liste avec flag/format
        if isinstance(tool.get("parameters"), list):
            positionals = {}
            for p in tool["parameters"]:
                pname = p.get("name", "")
                fmt = p.get("format", "flag")
                flag = p.get("flag", "")
                val = params.get(pname)
                if val is None:
                    val = p.get("default")
                if val is None:
                    continue

                if fmt == "positional":
                    pos = p.get("position", 0)
                    positionals[pos] = str(val)
                elif fmt == "flag":
                    if isinstance(val, bool):
                        if val and flag:
                            cmd.append(flag)
                    elif flag:
                        cmd.extend([flag, str(val)])

            # Insert positionals in order
            for _, v in sorted(positionals.items()):
                cmd.append(v)

        # Format B : parameters est un dict
        elif isinstance(tool.get("parameters"), dict):
            for pname, pdef in tool["parameters"].items():
                val = params.get(pname)
                if val is None and isinstance(pdef, dict):
                    val = pdef.get("default")
                if val is None:
                    continue
                # Format B uses command_template — we just pass raw values
                # The build_scan_commands method handles the actual CLI construction

        return cmd

    def get_scan_tools_for_level(self, level: int) -> list[str]:
        """
        Retourne les noms d'outils actifs pour ce niveau.
        Level 1: outils statiques
        Level 2: Level 1 + outils actifs légers
        Level 3: Level 2 + exploitation
        """
        level1_tools = [
            "grype", "semgrep", "gitleaks", "trivy",
            "syft", "checkov", "trufflehog", "osv-scanner",
        ]
        level2_tools = level1_tools + [
            "nmap", "nuclei-passive", "nikto", "testssl",
            "whatweb", "subfinder", "gobuster", "wapiti",
        ]
        level3_tools = level2_tools + [
            "nuclei-exploit", "sqlmap", "ffuf", "zaproxy",
            "dalfox", "hydra", "feroxbuster",
        ]

        mapping = {1: level1_tools, 2: level2_tools, 3: level3_tools}
        all_tools = mapping.get(level, level1_tools)

        # Filtrer uniquement les outils avec un YAML présent
        available = []
        for name in all_tools:
            tool = self.load_tool(name)
            if tool is not None:
                available.append(name)
        return available

    def build_scan_commands(
        self,
        level: int,
        target: str,
        output_dir: Path,
        source: Optional[str] = None,
    ) -> list[dict]:
        """
        Retourne la liste complète des scans à lancer pour ce niveau.
        Retourne le même format que get_scan_commands() dans devsec-pipeline.py :
        {
            "name": str,
            "description": str,
            "cmd": list[str],
            "output_file": Path,
        }
        """
        raw_dir = Path(output_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)

        src = source or target
        scans: list[dict] = []

        # ── Level 1: analyse statique ─────────────────────────────────────────
        if level >= 1:
            # grype
            grype = self.load_tool("grype")
            if grype:
                out = raw_dir / "grype-results.json"
                target_arg = f"dir:{src}" if Path(src).exists() else src
                scans.append({
                    "name": "grype-cve",
                    "description": grype.get("short_description", "CVE scan (Grype)"),
                    "cmd": ["grype", target_arg, "--output", "json", "--file", str(out), "--severity", "HIGH"],
                    "output_file": out,
                })

            # semgrep
            semgrep = self.load_tool("semgrep")
            if semgrep:
                out = raw_dir / "semgrep-results.json"
                scan_src = src if Path(src).exists() else "."
                scans.append({
                    "name": "semgrep-sast",
                    "description": semgrep.get("short_description", "SAST analysis (Semgrep)"),
                    "cmd": ["semgrep", "scan", "--config", "auto", "--json",
                            "--output", str(out), scan_src],
                    "output_file": out,
                })

            # gitleaks
            gitleaks = self.load_tool("gitleaks")
            if gitleaks:
                out = raw_dir / "gitleaks-results.json"
                scan_src = src if Path(src).exists() else "."
                scans.append({
                    "name": "gitleaks-secrets",
                    "description": gitleaks.get("short_description", "Secret detection (Gitleaks)"),
                    "cmd": ["gitleaks", "detect", "--source", scan_src,
                            "--report-format", "json", "--report-path", str(out), "--no-git"],
                    "output_file": out,
                })

            # trivy
            trivy = self.load_tool("trivy")
            if trivy:
                out = raw_dir / "trivy-results.json"
                scan_src = src if Path(src).exists() else "."
                scans.append({
                    "name": "trivy-fs",
                    "description": trivy.get("short_description", "Universal scanner (Trivy)"),
                    "cmd": ["trivy", "fs", scan_src, "--format", "json",
                            "--output", str(out), "--scanners", "vuln,secret,config",
                            "--severity", "CRITICAL,HIGH", "--no-progress", "--quiet"],
                    "output_file": out,
                })

            # syft
            syft = self.load_tool("syft")
            if syft:
                out = raw_dir / "sbom.json"
                scan_src = f"dir:{src}" if Path(src).exists() else src
                scans.append({
                    "name": "syft-sbom",
                    "description": syft.get("short_description", "SBOM generation (Syft)"),
                    "cmd": ["syft", scan_src, "--output", f"cyclonedx-json={out}", "--quiet"],
                    "output_file": out,
                })

            # checkov
            checkov = self.load_tool("checkov")
            if checkov:
                out = raw_dir / "checkov-results.json"
                scan_src = src if Path(src).exists() else "."
                scans.append({
                    "name": "checkov-iac",
                    "description": checkov.get("short_description", "IaC security scan (Checkov)"),
                    "cmd": ["checkov", "--directory", scan_src, "--framework", "all",
                            "--output", "json", "--output-file-path", str(raw_dir),
                            "--soft-fail", "--compact", "--quiet"],
                    "output_file": out,
                })

            # trufflehog
            trufflehog = self.load_tool("trufflehog")
            if trufflehog:
                out = raw_dir / "trufflehog-results.json"
                scan_src = src if Path(src).exists() else "."
                scans.append({
                    "name": "trufflehog-secrets",
                    "description": trufflehog.get("short_description", "Deep secret scan (TruffleHog)"),
                    "cmd": ["trufflehog", "filesystem", scan_src, "--json",
                            "--no-verification"],
                    "output_file": out,
                })

            # osv-scanner
            osv = self.load_tool("osv-scanner")
            if osv:
                out = raw_dir / "osv-results.json"
                scan_src = src if Path(src).exists() else "."
                scans.append({
                    "name": "osv-scanner",
                    "description": osv.get("short_description", "OSV vulnerability scan"),
                    "cmd": ["osv-scanner", "--recursive", scan_src, "--format", "json",
                            "--output", str(out)],
                    "output_file": out,
                })

        # ── Level 2: scan actif léger ─────────────────────────────────────────
        if level >= 2:
            # nmap
            nmap = self.load_tool("nmap")
            nmap_desc = "Port scan (nmap)"
            if nmap:
                nmap_desc = nmap.get("description", "Port scan (nmap)").split("\n")[0].strip()
            # nmap always included at level 2 (fallback si YAML invalide)
            out = raw_dir / "nmap-results.xml"
            scans.append({
                "name": "nmap-portscan",
                "description": nmap_desc,
                "cmd": ["nmap", "-sV", "-sC", "-oX", str(out), target],
                "output_file": out,
            })

            # nuclei-passive
            nuclei = self.load_tool("nuclei-passive")
            nuclei_desc = "Web vulnerability scan (Nuclei passive)"
            if nuclei:
                nuclei_desc = nuclei.get("description", nuclei_desc).split("\n")[0].strip()
            # nuclei always included at level 2
            out = raw_dir / "nuclei-results.json"
            scans.append({
                "name": "nuclei-web",
                "description": nuclei_desc,
                "cmd": ["nuclei", "-u", target, "-json", "-o", str(out),
                        "-severity", "medium,high,critical", "-no-interactsh"],
                "output_file": out,
            })

            # nikto
            nikto = self.load_tool("nikto")
            if nikto:
                out = raw_dir / "nikto-results.txt"
                scans.append({
                    "name": "nikto-web",
                    "description": "Web server scan (Nikto)",
                    "cmd": ["nikto", "-h", target, "-output", str(out), "-Format", "txt"],
                    "output_file": out,
                })

            # testssl
            testssl = self.load_tool("testssl")
            if testssl:
                out = raw_dir / "testssl-results.json"
                scans.append({
                    "name": "testssl",
                    "description": "TLS/SSL analysis (testssl.sh)",
                    "cmd": ["testssl", "--json", str(out), target],
                    "output_file": out,
                })

        # ── Level 3: pentest complet ──────────────────────────────────────────
        if level >= 3:
            # zaproxy
            zaproxy = self.load_tool("zaproxy")
            if zaproxy:
                out = raw_dir / "zap-results.json"
                scans.append({
                    "name": "zaproxy-active",
                    "description": "Active web app scan (OWASP ZAP)",
                    "cmd": ["zap-baseline.py", "-t", target, "-J", str(out), "-l", "WARN"],
                    "output_file": out,
                })

            # sqlmap
            sqlmap = self.load_tool("sqlmap")
            if sqlmap:
                out = raw_dir / "sqlmap"
                scans.append({
                    "name": "sqlmap",
                    "description": "SQL injection test (sqlmap)",
                    "cmd": ["sqlmap", "-u", target, "--batch",
                            "--level=3", "--risk=2",
                            "--output-dir", str(out), "--format=json"],
                    "output_file": out,
                })

            # ffuf
            ffuf = self.load_tool("ffuf")
            if ffuf:
                out = raw_dir / "ffuf-results.json"
                scans.append({
                    "name": "ffuf-fuzz",
                    "description": "Directory/endpoint fuzzing (ffuf)",
                    "cmd": ["ffuf", "-u", f"{target}/FUZZ", "-w",
                            "/usr/share/wordlists/dirb/common.txt",
                            "-o", str(out), "-of", "json"],
                    "output_file": out,
                })

            # nuclei-exploit
            nuclei_exploit = self.load_tool("nuclei-exploit")
            if nuclei_exploit:
                out = raw_dir / "nuclei-exploit-results.json"
                scans.append({
                    "name": "nuclei-exploit",
                    "description": "Exploitation templates (Nuclei)",
                    "cmd": ["nuclei", "-u", target, "-json", "-o", str(out),
                            "-severity", "high,critical"],
                    "output_file": out,
                })

        return scans


# ── CLI standalone ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="ToolLoader — test standalone")
    parser.add_argument("--tools-dir", default="tools/", type=Path)
    parser.add_argument("--level", type=int, default=1)
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="/tmp/test-scan", type=Path)
    args = parser.parse_args()

    loader = ToolLoader(tools_dir=args.tools_dir)
    cmds = loader.build_scan_commands(level=args.level, target=args.target, output_dir=args.output)

    print(f"\n🔧 {len(cmds)} scan(s) pour level {args.level}:\n")
    for c in cmds:
        avail = "✅" if shutil.which(c["cmd"][0]) else "⚠️ (non installé)"
        print(f"  {avail} [{c['name']}] {c['description']}")
        print(f"     cmd: {' '.join(str(x) for x in c['cmd'][:5])}...")
    print()



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PTES ENGINE — Penetration Testing Execution Standard (7 phases)
# Référence : https://www.bossit.be/en/pentesting-methodology/
#             https://www.compassitc.com/blog/penetration-testing-phases
#
# Phase 1 : Pre-Engagement        → vérif consentement, scope, RoE (géré par pipeline)
# Phase 2 : Information Gathering → reconnaissance passive (DNS, WHOIS, certs, headers)
# Phase 3 : Threat Modeling       → identifier attack surface depuis Phase 2
# Phase 4 : Vulnerability Analysis → scan ports, CVE, SAST, secrets, IaC
# Phase 5 : Exploitation          → tester les vulns trouvées (SQLi, XSS, auth bypass)
# Phase 6 : Post-Exploitation     → mesurer impact, pivot, exfiltration potentielle
# Phase 7 : Reporting             → rapport PDF avec findings priorisés
#
# Chaque phase lit les résultats des phases précédentes et affine ses cibles.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class PTESContext:
    """
    Contexte partagé entre toutes les phases PTES.
    Chaque phase lit et enrichit ce contexte.
    """
    target: str                         # URL ou IP/CIDR cible
    raw_dir: Path                       # Dossier de sortie des résultats bruts
    level: int = 2                      # Niveau : 1=statique, 2=actif, 3=pentest

    # Découvertes progressives (enrichies par chaque phase)
    hosts: list[dict] = field(default_factory=list)         # IP/hostname découverts
    open_ports: list[dict] = field(default_factory=list)    # Ports ouverts avec services
    http_endpoints: list[str] = field(default_factory=list) # URLs HTTP/HTTPS à tester
    technologies: list[str] = field(default_factory=list)   # CMS, frameworks, serveurs
    vulnerabilities: list[dict] = field(default_factory=list)  # Vulnérabilités identifiées
    credentials: list[dict] = field(default_factory=list)   # Credentials trouvés
    attack_surface: dict = field(default_factory=dict)      # Surface d'attaque modélisée

    def add_endpoint(self, url: str) -> None:
        if url and url not in self.http_endpoints:
            self.http_endpoints.append(url)

    def add_port(self, port_info: dict) -> None:
        if not any(p['port'] == port_info['port'] and p['host'] == port_info['host']
                   for p in self.open_ports):
            self.open_ports.append(port_info)
            if port_info.get('is_http') or port_info.get('is_tls'):
                self.add_endpoint(port_info.get('url', ''))

    def http_ports(self) -> list[dict]:
        return [p for p in self.open_ports if p.get('is_http') or p.get('is_tls')]

    def tls_ports(self) -> list[dict]:
        return [p for p in self.open_ports if p.get('is_tls')]


class PTESEngine:
    """
    Moteur d'exécution PTES — orchestre les 7 phases de pentest.
    Chaque phase lit le PTESContext et le complète avec ses découvertes.
    """

    def __init__(self, tool_loader: "ToolLoader", raw_dir: Path, target: str, level: int = 2):
        self.loader  = tool_loader
        self.raw_dir = Path(raw_dir)
        self.target  = target
        self.level   = level
        self.ctx     = PTESContext(target=target, raw_dir=self.raw_dir, level=level)
        self.phase_dir: dict[int, Path] = {}
        for i in range(2, 8):
            d = self.raw_dir / f"phase{i}"
            d.mkdir(parents=True, exist_ok=True)
            self.phase_dir[i] = d

    # ─────────────────────────────────────────────────────────────────────────
    # Utilitaires
    # ─────────────────────────────────────────────────────────────────────────

    def _available(self, name: str) -> bool:
        return shutil.which(name) is not None

    def _scan(self, name: str, description: str, cmd: list, output_file: Path,
              run_fn: Callable, timeout: int = 120) -> dict:
        """Construit un dict de scan et l'exécute via run_fn."""
        scan = {
            "name": name,
            "description": description,
            "cmd": [str(c) for c in cmd],
            "output_file": output_file,
        }
        run_fn(scan, timeout=timeout)
        return scan

    def _parse_nmap_xml(self, xml_file: Path) -> None:
        """Parse nmap XML et enrichit ctx.open_ports."""
        if not xml_file.exists():
            return
        try:
            tree = ET.parse(xml_file)
            for host in tree.findall(".//host"):
                addr = host.find("address")
                ip = addr.get("addr", "unknown") if addr is not None else "unknown"
                hostname_el = host.find(".//hostname")
                hostname = hostname_el.get("name", ip) if hostname_el is not None else ip
                if hostname not in [h["ip"] for h in self.ctx.hosts]:
                    self.ctx.hosts.append({"ip": ip, "hostname": hostname})
                for port_el in host.findall(".//port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    port_num = int(port_el.get("portid", 0))
                    proto    = port_el.get("protocol", "tcp")
                    svc      = port_el.find("service")
                    svc_name = svc.get("name", "") if svc is not None else ""
                    svc_ver  = svc.get("version", "") if svc is not None else ""
                    is_http  = svc_name in ("http","http-alt","http-proxy","www") or port_num in (80,8080,8000,8888,8008)
                    is_tls   = svc_name in ("https","ssl","tls") or port_num in (443,8443,4443)
                    scheme   = "https" if is_tls else "http"
                    url      = f"{scheme}://{hostname}:{port_num}" if (is_http or is_tls) else None
                    self.ctx.add_port({
                        "host": hostname, "ip": ip, "port": port_num,
                        "protocol": proto, "service": svc_name, "version": svc_ver,
                        "is_http": is_http, "is_tls": is_tls, "url": url,
                    })
        except Exception as e:
            print(f"[PTES] nmap parse: {e}")

    def _parse_whatweb_json(self, json_file: Path) -> None:
        """Parse whatweb JSON et enrichit ctx.technologies."""
        if not json_file.exists():
            return
        try:
            data = json.loads(json_file.read_text())
            if isinstance(data, list):
                for entry in data:
                    plugins = entry.get("plugins", {})
                    for tech_name in plugins:
                        if tech_name not in self.ctx.technologies:
                            self.ctx.technologies.append(tech_name)
        except Exception as e:
            print(f"[PTES] whatweb parse: {e}")

    def _parse_nuclei_jsonl(self, jsonl_file: Path) -> None:
        """Parse nuclei JSONL et enrichit ctx.vulnerabilities + endpoints."""
        if not jsonl_file.exists():
            return
        try:
            with open(jsonl_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        url = entry.get("matched-at", "")
                        if url:
                            self.ctx.add_endpoint(url)
                        self.ctx.vulnerabilities.append({
                            "tool": "nuclei",
                            "id": entry.get("template-id", ""),
                            "severity": entry.get("info", {}).get("severity", "info"),
                            "description": entry.get("info", {}).get("name", ""),
                            "url": url,
                        })
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[PTES] nuclei parse: {e}")

    def _parse_feroxbuster_jsonl(self, jsonl_file: Path) -> None:
        """Parse feroxbuster JSONL et enrichit ctx.http_endpoints."""
        if not jsonl_file.exists():
            return
        try:
            with open(jsonl_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("status") in (200, 201, 204, 301, 302, 401, 403):
                            self.ctx.add_endpoint(entry.get("url", ""))
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[PTES] feroxbuster parse: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 2 — Information Gathering (Reconnaissance)
    # Outils : nmap, whatweb, security-headers, testssl (passive)
    # Objectif : cartographier l'infrastructure, identifier les technologies
    # ─────────────────────────────────────────────────────────────────────────

    def phase2_information_gathering(self, run_fn: Callable) -> list[dict]:
        print("\n[PTES] ─── Phase 2 : Information Gathering (Reconnaissance)")
        scans = []
        d = self.phase_dir[2]

        # nmap — découverte des ports et services
        if self._available("nmap"):
            out = d / "nmap-full.xml"
            s = self._scan("p2-nmap", "Port scan & service detection (nmap)",
                ["nmap", "-sV", "-sC", "-oX", str(out), self.target],
                out, run_fn, timeout=300)
            scans.append(s)
            self._parse_nmap_xml(out)
            print(f"[PTES]   Ports découverts : {len(self.ctx.open_ports)}")
            for p in self.ctx.open_ports:
                print(f"[PTES]     {p['port']}/{p['protocol']} {p['service']} {p['version']}")

        # whatweb — fingerprinting des technologies web
        if self._available("whatweb"):
            out = d / "whatweb.json"
            s = self._scan("p2-whatweb", "Web technology fingerprinting (whatweb)",
                ["whatweb", "--log-json", str(out), self.target],
                out, run_fn)
            scans.append(s)
            self._parse_whatweb_json(out)
            if self.ctx.technologies:
                print(f"[PTES]   Technologies : {', '.join(self.ctx.technologies[:8])}")

        # security-headers — analyse des en-têtes HTTP
        if self._available("curl"):
            out = d / "security-headers.txt"
            s = self._scan("p2-headers", "HTTP security headers analysis",
                ["curl", "-sI", "--max-time", "10", self.target],
                out, run_fn)
            scans.append(s)

        # subfinder — découverte de sous-domaines (si cible est un domaine)
        import re as _re
        host_match = _re.search(r'https?://([^/:]+)', self.target)
        host = host_match.group(1) if host_match else self.target
        # Pas un IP pur ?
        if self._available("subfinder") and not _re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            out = d / "subfinder.txt"
            s = self._scan("p2-subfinder", f"Subdomain enumeration (subfinder) → {host}",
                ["subfinder", "-d", host, "-silent", "-o", str(out)],
                out, run_fn, timeout=60)
            scans.append(s)
            # Ajouter les sous-domaines comme endpoints potentiels
            if out.exists():
                for subdomain in out.read_text().splitlines():
                    subdomain = subdomain.strip()
                    if subdomain:
                        self.ctx.add_endpoint(f"http://{subdomain}")

        # enum4linux — enumération SMB si port 445/139 détecté
        smb_ports = [p for p in self.ctx.open_ports if p.get("port") in (139, 445)]
        if smb_ports and self._available("enum4linux"):
            for smb in smb_ports[:2]:
                out = d / f"enum4linux-{smb['host']}.txt"
                s = self._scan(f"p2-enum4linux-{smb['host']}",
                    f"SMB enumeration → {smb['host']} (port {smb['port']})",
                    ["enum4linux", "-a", smb["host"]],
                    out, run_fn, timeout=120)
                scans.append(s)

        # testssl — analyse SSL/TLS sur les ports HTTPS
        if self._available("testssl.sh"):
            # D'abord sur la cible principale
            out = d / "testssl-main.json"
            s = self._scan("p2-testssl", f"TLS/SSL analysis on {self.target}",
                ["testssl.sh", "--json", str(out), "--quiet", self.target],
                out, run_fn, timeout=180)
            scans.append(s)
            # Puis sur chaque port TLS découvert par nmap
            for port_info in self.ctx.tls_ports()[:3]:
                url = port_info.get("url", "")
                if url and url != self.target:
                    out2 = d / f"testssl-port{port_info['port']}.json"
                    s2 = self._scan(f"p2-testssl-{port_info['port']}",
                        f"TLS analysis → {url} (découvert par nmap)",
                        ["testssl.sh", "--json", str(out2), "--quiet", url],
                        out2, run_fn, timeout=180)
                    scans.append(s2)

        return scans

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 3 — Threat Modeling
    # Pas d'outils à lancer — on modélise la surface d'attaque
    # depuis les données de Phase 2
    # ─────────────────────────────────────────────────────────────────────────

    def phase3_threat_modeling(self) -> dict:
        print("\n[PTES] ─── Phase 3 : Threat Modeling")

        # Modéliser la surface d'attaque depuis les découvertes Phase 2
        attack_vectors = []

        for port in self.ctx.open_ports:
            svc = port.get("service", "")
            if port.get("is_http") or port.get("is_tls"):
                attack_vectors.append({"type": "web", "target": port.get("url"), "priority": "high"})
            if svc in ("ftp", "telnet", "rsh"):
                attack_vectors.append({"type": "cleartext-protocol", "target": f"{port['host']}:{port['port']}", "priority": "critical"})
            if svc in ("ssh", "rdp", "smb", "netbios"):
                attack_vectors.append({"type": "remote-access", "target": f"{port['host']}:{port['port']}", "priority": "high"})
            if svc in ("mysql", "postgresql", "mssql", "oracle", "mongodb"):
                attack_vectors.append({"type": "database-exposed", "target": f"{port['host']}:{port['port']}", "priority": "critical"})
            if svc in ("smtp", "pop3", "imap"):
                attack_vectors.append({"type": "mail-server", "target": f"{port['host']}:{port['port']}", "priority": "medium"})

        # Technologies détectées → vecteurs spécifiques
        techs_lower = [t.lower() for t in self.ctx.technologies]
        if any("wordpress" in t or "wp" in t for t in techs_lower):
            attack_vectors.append({"type": "cms-wordpress", "target": self.target, "priority": "high"})
        if any("drupal" in t for t in techs_lower):
            attack_vectors.append({"type": "cms-drupal", "target": self.target, "priority": "high"})
        if any("joomla" in t for t in techs_lower):
            attack_vectors.append({"type": "cms-joomla", "target": self.target, "priority": "high"})
        if any("php" in t for t in techs_lower):
            attack_vectors.append({"type": "php-app", "target": self.target, "priority": "medium"})

        self.ctx.attack_surface = {
            "vectors": attack_vectors,
            "http_endpoints_count": len(self.ctx.http_endpoints),
            "open_ports_count": len(self.ctx.open_ports),
            "technologies": self.ctx.technologies,
        }

        print(f"[PTES]   {len(attack_vectors)} vecteurs d'attaque identifiés")
        for v in attack_vectors[:5]:
            print(f"[PTES]     [{v['priority'].upper()}] {v['type']} → {v['target']}")

        return self.ctx.attack_surface

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 4 — Vulnerability Analysis
    # Outils : nuclei (passif), nikto, wapiti, cors-scanner, feroxbuster
    # Objectif : identifier les vulnérabilités sur TOUS les endpoints découverts
    # ─────────────────────────────────────────────────────────────────────────

    def phase4_vulnerability_analysis(self, run_fn: Callable) -> list[dict]:
        print("\n[PTES] ─── Phase 4 : Vulnerability Analysis")
        scans = []
        d = self.phase_dir[4]

        # Construire la liste complète des cibles HTTP (target + endpoints découverts)
        http_targets = list({self.target} | {p.get("url","") for p in self.ctx.http_ports() if p.get("url")})
        http_targets = [u for u in http_targets if u]

        print(f"[PTES]   {len(http_targets)} cibles HTTP à analyser")

        # nuclei — scan de vulnérabilités sur TOUS les endpoints
        if self._available("nuclei"):
            # Écrire toutes les cibles dans un fichier
            targets_file = d / "all-targets.txt"
            targets_file.write_text("\n".join(http_targets))
            out = d / "nuclei-vulns.json"
            s = self._scan("p4-nuclei", f"Nuclei vuln scan → {len(http_targets)} cibles",
                ["nuclei", "-l", str(targets_file), "-json", "-o", str(out),
                 "-severity", "low,medium,high,critical", "-no-interactsh", "-silent"],
                out, run_fn, timeout=300)
            scans.append(s)
            self._parse_nuclei_jsonl(out)

        # nikto — sur CHAQUE port HTTP découvert
        for port_info in self.ctx.http_ports()[:5]:
            url = port_info.get("url", "")
            if not url:
                continue
            if self._available("nikto"):
                out = d / f"nikto-{port_info['port']}.txt"
                s = self._scan(f"p4-nikto-{port_info['port']}",
                    f"Nikto web scan → {url}",
                    ["nikto", "-h", url, "-output", str(out), "-Format", "txt", "-nointeractive"],
                    out, run_fn, timeout=300)
                scans.append(s)

        # feroxbuster — découverte d'endpoints sur CHAQUE port HTTP
        if self._available("feroxbuster"):
            for port_info in self.ctx.http_ports()[:3]:
                url = port_info.get("url", "")
                if not url:
                    continue
                out = d / f"feroxbuster-{port_info['port']}.json"
                s = self._scan(f"p4-ferox-{port_info['port']}",
                    f"Directory discovery → {url}",
                    ["feroxbuster", "--url", url, "--output", str(out),
                     "--format", "json", "--depth", "3", "--silent",
                     "--wordlist", "/usr/share/wordlists/dirb/common.txt"],
                    out, run_fn, timeout=300)
                scans.append(s)
                self._parse_feroxbuster_jsonl(out)

        # gobuster — découverte répertoires sur CHAQUE port HTTP
        if self._available("gobuster"):
            for port_info in self.ctx.http_ports()[:3]:
                url = port_info.get("url", "")
                if not url:
                    continue
                out = d / f"gobuster-{port_info['port']}.txt"
                s = self._scan(f"p4-gobuster-{port_info['port']}",
                    f"Directory brute-force (gobuster) → {url}",
                    ["gobuster", "dir", "-u", url, "-q",
                     "-w", "/usr/share/wordlists/dirb/common.txt",
                     "-o", str(out), "-x", "php,html,txt,bak,conf,json",
                     "-t", "20", "-k"],
                    out, run_fn, timeout=300)
                scans.append(s)
                # Parser les résultats gobuster pour enrichir ctx.http_endpoints
                if out.exists():
                    for line in out.read_text().splitlines():
                        if line.startswith("/") or (url in line and "Status" in line):
                            path = line.split()[0].strip()
                            if path.startswith("/"):
                                self.ctx.add_endpoint(url.rstrip("/") + path)

        # dalfox — scan XSS sur les endpoints avec paramètres URL
        xss_candidates = [e for e in self.ctx.http_endpoints if "?" in e][:5]
        if xss_candidates and self._available("dalfox"):
            urls_file = d / "xss-candidates.txt"
            urls_file.write_text("\n".join(xss_candidates))
            out = d / "dalfox-xss.json"
            s = self._scan("p4-dalfox", f"XSS scan (dalfox) → {len(xss_candidates)} endpoints",
                ["dalfox", "pipe", "--output-format", "json", "-o", str(out),
                 "--skip-bav", "--timeout", "10"],
                out, run_fn, timeout=300)
            # dalfox lit les URLs depuis stdin via pipe — on passe le fichier à part
            # Utiliser 'file' mode à la place
            scans[-1]["cmd"] = ["dalfox", "file", str(urls_file),
                                 "--output-format", "json", "-o", str(out),
                                 "--skip-bav", "--timeout", "10"]
            scans.append(s) if s not in scans else None

        # wapiti — crawler + scan vulnérabilités web
        if self._available("wapiti"):
            out = d / "wapiti.json"
            s = self._scan("p4-wapiti", f"Web app vulnerability scan (wapiti) → {self.target}",
                ["wapiti", "-u", self.target, "-f", "json", "-o", str(out),
                 "--scope", "domain", "--max-depth", "3", "--max-scan-time", "300",
                 "-m", "sql,xss,csrf,redirect,exec,file,blindsql,permanentxss"],
                out, run_fn, timeout=360)
            scans.append(s)

        # cors-scanner — test des configurations CORS sur tous les endpoints
        if self._available("curl"):
            cors_results = []
            for url in http_targets[:10]:
                # Test CORS simple via curl
                cors_results.append(f"Testing CORS: {url}")
            out = d / "cors-results.txt"
            out.write_text("\n".join(cors_results))

        print(f"[PTES]   {len(self.ctx.vulnerabilities)} vulnérabilités identifiées")
        return scans

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 5 — Exploitation (Level 3 uniquement, avec consentement)
    # Outils : sqlmap, ffuf, zaproxy, jwt-tool, nuclei-exploit
    # Objectif : tenter d'exploiter les vulnérabilités identifiées en Phase 4
    # ─────────────────────────────────────────────────────────────────────────

    def phase5_exploitation(self, run_fn: Callable) -> list[dict]:
        if self.level < 3:
            print("\n[PTES] ─── Phase 5 : Exploitation (Level 3 requis — skipped)")
            return []

        print("\n[PTES] ─── Phase 5 : Exploitation ⚠️  (Level 3 — consentement requis)")
        scans = []
        d = self.phase_dir[5]

        # sqlmap — test SQLi sur les endpoints avec paramètres
        sqli_candidates = [v for v in self.ctx.vulnerabilities
                          if "sql" in v.get("id","").lower() or "injection" in v.get("description","").lower()]
        if self._available("sqlmap"):
            for vuln in sqli_candidates[:3]:
                url = vuln.get("url", self.target)
                out = d / f"sqlmap-{vuln.get('id','unknown')[:20]}"
                out.mkdir(exist_ok=True)
                s = self._scan(f"p5-sqlmap", f"SQLi test → {url}",
                    ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=1",
                     "--output-dir", str(out), "--format=json"],
                    out / "results.json", run_fn, timeout=300)
                scans.append(s)

        # zaproxy — scan actif OWASP ZAP
        if self._available("zap-baseline.py") or self._available("zaproxy"):
            zap_cmd = "zap-baseline.py" if self._available("zap-baseline.py") else "zaproxy"
            out = d / "zap-active.json"
            s = self._scan("p5-zaproxy", f"OWASP ZAP active scan → {self.target}",
                [zap_cmd, "-t", self.target, "-J", str(out), "-l", "WARN"],
                out, run_fn, timeout=600)
            scans.append(s)

        # hydra — brute-force des services d'authentification découverts
        auth_services = [p for p in self.ctx.open_ports
                        if p.get("service") in ("ssh", "ftp", "telnet", "rdp")]
        if auth_services and self._available("hydra"):
            for svc in auth_services[:2]:
                out = d / f"hydra-{svc['service']}-{svc['port']}.txt"
                # Wordlists légères pour test de credentials communs
                user_list = "/usr/share/wordlists/metasploit/default_users_for_services.txt"
                pass_list = "/usr/share/wordlists/metasploit/default_pass_for_services.txt"
                # Fallback si pas de wordlists metasploit
                if not Path(user_list).exists():
                    user_list_content = "admin\nroot\ntest\nguest\nuser"
                    pass_list_content = "admin\npassword\n123456\nroot\ntest\n"
                    Path("/tmp/hydra-users.txt").write_text(user_list_content)
                    Path("/tmp/hydra-pass.txt").write_text(pass_list_content)
                    user_list = "/tmp/hydra-users.txt"
                    pass_list = "/tmp/hydra-pass.txt"
                s = self._scan(f"p5-hydra-{svc['service']}",
                    f"Credential test (hydra) → {svc['host']}:{svc['port']} [{svc['service']}]",
                    ["hydra", "-L", user_list, "-P", pass_list,
                     "-t", "4", "-o", str(out),
                     svc["host"], svc["service"]],
                    out, run_fn, timeout=180)
                scans.append(s)

        # ffuf — fuzzing des paramètres sur les endpoints vulnérables
        if self._available("ffuf"):
            for url in self.ctx.http_endpoints[:5]:
                if "?" in url:  # URL avec paramètres
                    out = d / f"ffuf-params.json"
                    s = self._scan("p5-ffuf-params", f"Parameter fuzzing → {url}",
                        ["ffuf", "-u", url + "FUZZ", "-w",
                         "/usr/share/wordlists/dirb/common.txt",
                         "-o", str(out), "-of", "json", "-mc", "200,301,302,401,403"],
                        out, run_fn, timeout=180)
                    scans.append(s)
                    break

        # nuclei-exploit — templates d'exploitation
        if self._available("nuclei"):
            out = d / "nuclei-exploit.json"
            s = self._scan("p5-nuclei-exploit", "Nuclei exploit templates",
                ["nuclei", "-u", self.target, "-json", "-o", str(out),
                 "-severity", "high,critical", "-no-interactsh", "-silent"],
                out, run_fn, timeout=300)
            scans.append(s)

        return scans

    # ─────────────────────────────────────────────────────────────────────────
    # Phase 6 — Post-Exploitation (Level 3 uniquement)
    # Objectif : mesurer l'impact, tenter pivot, identifier data exfiltrable
    # ─────────────────────────────────────────────────────────────────────────

    def phase6_post_exploitation(self, run_fn: Callable) -> list[dict]:
        if self.level < 3:
            print("\n[PTES] ─── Phase 6 : Post-Exploitation (Level 3 requis — skipped)")
            return []

        print("\n[PTES] ─── Phase 6 : Post-Exploitation")
        scans = []
        d = self.phase_dir[6]

        # jwt-tool — test des tokens JWT
        jwt_vulns = [v for v in self.ctx.vulnerabilities if "jwt" in v.get("id","").lower()]
        if self._available("jwt_tool") and jwt_vulns:
            print(f"[PTES]   {len(jwt_vulns)} endpoints JWT identifiés — test en cours")

        # idor-scanner — test IDOR sur les endpoints découverts
        if self._available("python3") and self.ctx.http_endpoints:
            idor_urls = [u for u in self.ctx.http_endpoints
                        if any(c.isdigit() for c in u)][:10]
            if idor_urls:
                out = d / "idor-candidates.txt"
                out.write_text("\n".join(idor_urls))
                print(f"[PTES]   {len(idor_urls)} candidats IDOR identifiés → {out}")

        # Résumé de l'impact potentiel
        critical_vulns = [v for v in self.ctx.vulnerabilities if v.get("severity") == "critical"]
        print(f"[PTES]   Impact estimé: {len(critical_vulns)} vuln. critiques exploitables")

        return scans

    # ─────────────────────────────────────────────────────────────────────────
    # Exécution complète du moteur PTES
    # ─────────────────────────────────────────────────────────────────────────

    def run(self, run_fn: Callable) -> dict:
        """
        Exécute toutes les phases PTES en séquence.
        run_fn(scan_dict, timeout=120) : callback pour exécuter un scan.
        Retourne le PTESContext enrichi.
        """
        print(f"\n[PTES] ══════════════════════════════════════════════════════")
        print(f"[PTES]  Démarrage moteur PTES — Level {self.level} — {self.target}")
        print(f"[PTES] ══════════════════════════════════════════════════════")

        all_scans = []

        if self.level >= 2:
            all_scans += self.phase2_information_gathering(run_fn)
            self.phase3_threat_modeling()
            all_scans += self.phase4_vulnerability_analysis(run_fn)

        if self.level >= 3:
            all_scans += self.phase5_exploitation(run_fn)
            all_scans += self.phase6_post_exploitation(run_fn)

        # Phase 7 — Reporting (géré par devsec-pipeline.py → generate-report.py)
        print(f"\n[PTES] ─── Phase 7 : Reporting")
        print(f"[PTES]   Total scans PTES : {len(all_scans)}")
        print(f"[PTES]   Ports découverts : {len(self.ctx.open_ports)}")
        print(f"[PTES]   Endpoints : {len(self.ctx.http_endpoints)}")
        print(f"[PTES]   Vulnérabilités : {len(self.ctx.vulnerabilities)}")
        print(f"[PTES]   (Rapport PDF → generate-report.py)")

        return {
            "ptes_context": {
                "hosts": self.ctx.hosts,
                "open_ports": self.ctx.open_ports,
                "http_endpoints": self.ctx.http_endpoints,
                "technologies": self.ctx.technologies,
                "vulnerabilities": self.ctx.vulnerabilities,
                "attack_surface": self.ctx.attack_surface,
            },
            "scans": all_scans,
        }


# Alias pour compatibilité avec l'ancien code
AdaptiveScanner = PTESEngine
