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
        level2_tools = level1_tools + ["nmap", "nuclei-passive", "nikto", "testssl"]
        level3_tools = level2_tools + ["nuclei-exploit", "sqlmap", "ffuf", "zaproxy"]

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


# ─────────────────────────────────────────────────────────────────────────────
class AdaptiveScanner:
    """
    Moteur de scan adaptatif (Phase 1 → Phase 2).

    Phase 1 : scans de découverte (nmap, feroxbuster, nuclei passif)
              → découverte de ports ouverts, URLs et endpoints
    Phase 2 : scans ciblés sur les découvertes de la Phase 1
              → nikto sur chaque port HTTP trouvé, nuclei sur chaque URL,
                semgrep ciblé, testssl sur chaque port TLS
    """

    def __init__(self, tool_loader: ToolLoader, raw_dir: Path):
        self.loader = tool_loader
        self.raw_dir = Path(raw_dir)

    # ── Extraction des découvertes ──────────────────────────────────────────

    def extract_nmap_discoveries(self) -> list[dict]:
        """
        Lit nmap-results.xml et extrait les ports ouverts.
        Retourne : [{host, port, protocol, service, version, is_http, is_tls}]
        """
        discoveries = []
        nmap_xml = self.raw_dir / "nmap-results.xml"
        if not nmap_xml.exists():
            return discoveries
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(nmap_xml)
            for host in tree.findall(".//host"):
                addr = host.find("address")
                ip = addr.get("addr", "unknown") if addr is not None else "unknown"
                hostname_el = host.find(".//hostname")
                hostname = hostname_el.get("name", ip) if hostname_el is not None else ip
                for port_el in host.findall(".//port"):
                    state = port_el.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    port_num = int(port_el.get("portid", 0))
                    proto = port_el.get("protocol", "tcp")
                    svc = port_el.find("service")
                    svc_name = svc.get("name", "") if svc is not None else ""
                    svc_ver = svc.get("version", "") if svc is not None else ""
                    is_http = svc_name in ("http", "http-alt", "http-proxy") or port_num in (80, 8080, 8000, 8888)
                    is_tls  = svc_name in ("https", "ssl", "tls") or port_num in (443, 8443)
                    discoveries.append({
                        "host": hostname, "ip": ip, "port": port_num, "protocol": proto,
                        "service": svc_name, "version": svc_ver,
                        "is_http": is_http, "is_tls": is_tls,
                        "url": f"{'https' if is_tls else 'http'}://{hostname}:{port_num}"
                              if (is_http or is_tls) else None,
                    })
        except Exception as e:
            print(f"[AdaptiveScanner] nmap parse error: {e}")
        return discoveries

    def extract_feroxbuster_discoveries(self) -> list[str]:
        """
        Lit feroxbuster-results.json et extrait les URLs découvertes (status 200/301/302).
        Retourne : [url1, url2, ...]
        """
        import json
        urls = []
        ferox_file = self.raw_dir / "feroxbuster-results.json"
        if not ferox_file.exists():
            return urls
        try:
            with open(ferox_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        status = entry.get("status", 0)
                        url = entry.get("url", "")
                        if url and status in (200, 201, 301, 302, 403):
                            urls.append(url)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[AdaptiveScanner] feroxbuster parse error: {e}")
        return list(set(urls))  # dédupliquer

    def extract_nuclei_discoveries(self) -> list[dict]:
        """
        Lit nuclei-results.json et extrait les endpoints vulnérables.
        Retourne : [{url, template_id, severity}]
        """
        import json
        endpoints = []
        nuclei_file = self.raw_dir / "nuclei-results.json"
        if not nuclei_file.exists():
            return endpoints
        try:
            with open(nuclei_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        url = entry.get("matched-at", "")
                        if url:
                            endpoints.append({
                                "url": url,
                                "template_id": entry.get("template-id", ""),
                                "severity": entry.get("info", {}).get("severity", "info"),
                            })
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[AdaptiveScanner] nuclei parse error: {e}")
        return endpoints

    def extract_all_discoveries(self) -> dict:
        """
        Agrège toutes les découvertes de Phase 1.
        Retourne un dict avec : ports, urls, vulnerable_endpoints
        """
        ports = self.extract_nmap_discoveries()
        urls_ferox = self.extract_feroxbuster_discoveries()
        vuln_endpoints = self.extract_nuclei_discoveries()

        # Construire la liste d'URLs HTTP complète
        all_urls = set(urls_ferox)
        for p in ports:
            if p.get("url"):
                all_urls.add(p["url"])
        for e in vuln_endpoints:
            if e.get("url"):
                all_urls.add(e["url"])

        return {
            "ports": ports,
            "urls": list(all_urls),
            "vulnerable_endpoints": vuln_endpoints,
            "http_ports": [p for p in ports if p.get("is_http") or p.get("is_tls")],
        }

    # ── Construction des scans Phase 2 (adaptatifs) ──────────────────────────

    def build_phase2_commands(self, discoveries: dict) -> list[dict]:
        """
        Construit les scans ciblés basés sur les découvertes de Phase 1.
        Chaque URL/port découvert est soumis aux outils pertinents.
        """
        scans = []
        phase2_dir = self.raw_dir / "phase2"
        phase2_dir.mkdir(parents=True, exist_ok=True)

        http_ports = discoveries.get("http_ports", [])
        all_urls   = discoveries.get("urls", [])
        vuln_eps   = discoveries.get("vulnerable_endpoints", [])

        if not http_ports and not all_urls:
            print("[AdaptiveScanner] Phase 1 : aucune découverte HTTP — Phase 2 ignorée")
            return []

        n = len(http_ports) + len(all_urls)
        print(f"[AdaptiveScanner] Phase 2 : {n} cibles découvertes → scans ciblés")

        # 1. nikto sur chaque port HTTP découvert
        if self.loader.is_available(self.loader.load_tool("nikto") or {"command": "nikto"}):
            for i, port_info in enumerate(http_ports[:5]):  # max 5 ports
                url = port_info.get("url", "")
                if not url:
                    continue
                out = phase2_dir / f"nikto-port{port_info['port']}.txt"
                scans.append({
                    "name": f"nikto-adaptive-{port_info['port']}",
                    "description": f"Nikto scan → {url} (découvert par nmap)",
                    "cmd": ["nikto", "-h", url, "-output", str(out), "-Format", "txt"],
                    "output_file": out,
                    "adaptive": True,
                    "source": "nmap",
                })

        # 2. nuclei sur les URLs découvertes par feroxbuster
        if all_urls:
            # Écrire la liste d'URLs dans un fichier cible
            urls_file = phase2_dir / "discovered-urls.txt"
            urls_file.write_text("\n".join(all_urls[:50]))  # max 50 URLs
            out = phase2_dir / "nuclei-urls.json"
            scans.append({
                "name": "nuclei-adaptive-urls",
                "description": f"Nuclei sur {min(len(all_urls),50)} URLs découvertes",
                "cmd": ["nuclei", "-l", str(urls_file), "-json", "-o", str(out),
                        "-severity", "medium,high,critical", "-no-interactsh"],
                "output_file": out,
                "adaptive": True,
                "source": "feroxbuster+nmap",
            })

        # 3. testssl sur chaque port TLS découvert
        tls_ports = [p for p in discoveries.get("ports", []) if p.get("is_tls")]
        for port_info in tls_ports[:3]:  # max 3 ports TLS
            url = port_info.get("url", "")
            if not url:
                continue
            out = phase2_dir / f"testssl-port{port_info['port']}.json"
            scans.append({
                "name": f"testssl-adaptive-{port_info['port']}",
                "description": f"testssl → {url} (port TLS découvert par nmap)",
                "cmd": ["testssl.sh", "--json", str(out), url],
                "output_file": out,
                "adaptive": True,
                "source": "nmap",
            })

        # 4. feroxbuster sur les ports HTTP non-standards découverts
        non_standard = [p for p in http_ports if p["port"] not in (80, 443, 8080, 8443)]
        for port_info in non_standard[:3]:  # max 3
            url = port_info.get("url", "")
            if not url:
                continue
            out = phase2_dir / f"feroxbuster-port{port_info['port']}.json"
            scans.append({
                "name": f"feroxbuster-adaptive-{port_info['port']}",
                "description": f"Feroxbuster → {url} (port non-standard découvert)",
                "cmd": ["feroxbuster", "--url", url, "--output", str(out),
                        "--format", "json", "--depth", "3",
                        "--wordlist", "/usr/share/wordlists/dirb/common.txt",
                        "--silent"],
                "output_file": out,
                "adaptive": True,
                "source": "nmap",
            })

        # 5. Endpoints vulnérables : scan SAST ciblé sur les chemins associés
        if vuln_eps:
            print(f"[AdaptiveScanner]   → {len(vuln_eps)} endpoints vulnérables à investiguer")
            for ep in vuln_eps[:10]:
                print(f"     - [{ep['severity'].upper()}] {ep['template_id']} → {ep['url']}")

        return scans

    def run_phase2(self, run_cmd_fn) -> list[dict]:
        """
        Extrait les découvertes de Phase 1, construit et exécute les scans Phase 2.
        run_cmd_fn : callable(scan_dict) → bool (ex: la fonction run_scan du pipeline)
        Retourne la liste des scans Phase 2 lancés.
        """
        print("\n[AdaptiveScanner] ── Phase 2 : analyse des découvertes ──")
        discoveries = self.extract_all_discoveries()

        ports_found = len(discoveries["ports"])
        urls_found  = len(discoveries["urls"])
        print(f"[AdaptiveScanner]   Ports découverts : {ports_found}")
        print(f"[AdaptiveScanner]   URLs découvertes : {urls_found}")
        print(f"[AdaptiveScanner]   Endpoints vuln. : {len(discoveries['vulnerable_endpoints'])}")

        phase2_scans = self.build_phase2_commands(discoveries)
        if not phase2_scans:
            print("[AdaptiveScanner]   Aucun scan Phase 2 généré")
            return []

        print(f"[AdaptiveScanner]   {len(phase2_scans)} scans ciblés générés")
        results = []
        for scan in phase2_scans:
            print(f"[AdaptiveScanner]   ► {scan['description']}")
            run_cmd_fn(scan)
            results.append(scan)

        return results
