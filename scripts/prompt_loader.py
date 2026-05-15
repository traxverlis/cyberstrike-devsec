"""
prompt_loader.py — Chargement dynamique des agents, skills et roles
CyberStrikeAI DevSec — Option C Refactor
"""
from pathlib import Path
from typing import Optional

try:
    import yaml as _yaml
    def _load_yaml(text: str) -> dict:
        return _yaml.safe_load(text) or {}
except ImportError:
    def _load_yaml(text: str) -> dict:  # type: ignore
        result = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if ':' in stripped:
                key, _, val = stripped.partition(':')
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if val:
                    result[key] = val
        return result


class PromptLoader:
    """
    Charge dynamiquement les agents/*.md, skills/*/SKILL.md et roles/*.yaml.
    Assemble les prompts système IA à partir de ces sources.
    """

    # Mapping niveau → agent
    AGENT_MAP = {
        1: "devsec-orchestrator",
        2: "active-scan-orchestrator",
        3: "pentest-orchestrator",
    }

    # Mapping niveau → role
    ROLE_MAP = {
        1: "devsec-team",
        2: "pentest-level2",
        3: "pentest-level3",
    }

    # Mapping niveau → skills (cumulatifs)
    SKILLS_MAP = {
        1: [
            "cve-dependency-scan",
            "owasp-code-review",
            "sast-devsec",
            "supply-chain-audit",
            "devsec-report",
        ],
        2: [
            "cve-dependency-scan",
            "owasp-code-review",
            "sast-devsec",
            "supply-chain-audit",
            "devsec-report",
            "active-recon",
            "web-vulnerability-scan",
        ],
        3: [
            "cve-dependency-scan",
            "owasp-code-review",
            "sast-devsec",
            "supply-chain-audit",
            "devsec-report",
            "active-recon",
            "web-vulnerability-scan",
            "pentest-full",
            "api-pentest",
            "auth-bypass",
        ],
    }

    def __init__(
        self,
        agents_dir: Path,
        skills_dir: Path,
        roles_dir: Path,
    ):
        self.agents_dir = Path(agents_dir)
        self.skills_dir = Path(skills_dir)
        self.roles_dir = Path(roles_dir)
        self._agent_cache: dict[str, str] = {}
        self._skill_cache: dict[str, str] = {}
        self._role_cache: dict[str, dict] = {}

    # ── Loaders ───────────────────────────────────────────────────────────────

    def load_agent(self, name: str) -> str:
        """Charge agents/{name}.md — retourne le contenu brut."""
        if name in self._agent_cache:
            return self._agent_cache[name]

        path = self.agents_dir / f"{name}.md"
        if not path.exists():
            return f"<!-- Agent '{name}' not found at {path} -->"

        content = path.read_text(encoding="utf-8")
        self._agent_cache[name] = content
        return content

    def load_skill(self, name: str) -> str:
        """Charge skills/{name}/SKILL.md — retourne les sections pertinentes."""
        if name in self._skill_cache:
            return self._skill_cache[name]

        path = self.skills_dir / name / "SKILL.md"
        if not path.exists():
            return f"<!-- Skill '{name}' not found at {path} -->"

        content = path.read_text(encoding="utf-8")
        # Extraire les sections pertinentes (sauter le header YAML frontmatter si présent)
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                content = parts[2].strip()

        self._skill_cache[name] = content
        return content

    def load_role(self, name: str) -> dict:
        """Charge roles/{name}.yaml — retourne dict avec system_prompt et allowed_tools."""
        if name in self._role_cache:
            return self._role_cache[name]

        path = self.roles_dir / f"{name}.yaml"
        if not path.exists():
            return {"system_prompt": "", "allowed_tools": [], "name": name}

        try:
            data = _load_yaml(path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[PromptLoader] ⚠️  Erreur lecture role {name}: {e}")
            data = {}

        result = {
            "name": data.get("name", name),
            "system_prompt": data.get("system_prompt", ""),
            "allowed_tools": data.get("allowed_tools", []),
            "description": data.get("description", ""),
        }
        self._role_cache[name] = result
        return result

    # ── Helpers niveau ─────────────────────────────────────────────────────────

    def get_agent_for_level(self, level: int) -> str:
        """Retourne le nom de l'agent approprié pour le niveau."""
        return self.AGENT_MAP.get(level, "devsec-orchestrator")

    def get_skills_for_level(self, level: int) -> list[str]:
        """Retourne les skills pertinents pour ce niveau."""
        return self.SKILLS_MAP.get(level, self.SKILLS_MAP[1])

    def get_role_for_level(self, level: int) -> str:
        """Retourne le nom du role approprié."""
        return self.ROLE_MAP.get(level, "devsec-team")

    # ── Assemblage du prompt système ──────────────────────────────────────────

    def build_system_prompt(self, level: int) -> str:
        """
        Assemble : role.system_prompt + agent context + skills pertinents.
        """
        parts = []

        # 1. Prompt système du rôle
        role_name = self.get_role_for_level(level)
        role = self.load_role(role_name)
        if role.get("system_prompt"):
            parts.append(f"# Rôle : {role.get('name', role_name)}\n\n{role['system_prompt']}")

        # 2. Contexte de l'agent
        agent_name = self.get_agent_for_level(level)
        agent_content = self.load_agent(agent_name)
        if agent_content and not agent_content.startswith("<!--"):
            parts.append(f"\n---\n# Agent : {agent_name}\n\n{agent_content}")

        # 3. Skills pertinents
        skills = self.get_skills_for_level(level)
        loaded_skills = []
        for skill_name in skills:
            skill_content = self.load_skill(skill_name)
            if skill_content and not skill_content.startswith("<!--"):
                loaded_skills.append(f"\n## Skill : {skill_name}\n\n{skill_content}")

        if loaded_skills:
            parts.append("\n---\n# Instructions spécialisées par domaine\n" + "\n".join(loaded_skills))

        return "\n\n".join(parts)

    # ── Prompts de triage et analyse ──────────────────────────────────────────

    def build_triage_prompt(self, findings: list[dict], target: str, level: int) -> str:
        """
        Construit le prompt de triage en utilisant le skill devsec-report.
        Remplace le prompt hardcodé dans ai_analyzer.py.
        """
        # Charger le skill devsec-report pour les instructions de format
        report_skill = self.load_skill("devsec-report")
        skill_context = ""
        if report_skill and not report_skill.startswith("<!--"):
            # Extraire juste les premières lignes pertinentes (max 500 chars)
            skill_lines = report_skill.strip().splitlines()[:20]
            skill_context = "\n".join(skill_lines)

        # Dédupliquer et résumer les findings par sévérité
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in by_severity:
                by_severity[sev].append(f)

        summary_lines = []
        for sev, items in by_severity.items():
            if items:
                summary_lines.append(f"\n### {sev.upper()} ({len(items)} findings)")
                for item in items[:5]:
                    tool = item.get("tool", "?")
                    fid = item.get("id", "?")
                    desc = item.get("description", "")[:120]
                    loc = item.get("file", item.get("package", item.get("matched", "")))
                    line = item.get("line", "")
                    loc_str = f" — `{loc}:{line}`" if line else (f" — `{loc}`" if loc else "")
                    summary_lines.append(f"- **[{tool}]** `{fid}`{loc_str}: {desc}")
                if len(items) > 5:
                    summary_lines.append(f"  *(+ {len(items) - 5} autres)*")

        findings_text = "\n".join(summary_lines) if summary_lines else "Aucun finding détecté."
        level_desc = {1: "analyse statique", 2: "scan actif web", 3: "pentest complet"}

        prompt = f"""## Contexte du scan

- **Cible :** `{target}`
- **Niveau :** {level} ({level_desc.get(level, 'inconnu')})
- **Total findings :** {len(findings)}

## Findings détectés
{findings_text}

---

## Ta mission

1. **Triage & Priorisation** — Classe les findings par risque réel (pas juste la sévérité brute). \
Identifie les faux positifs probables.

2. **Top 5 vulnérabilités critiques** — Pour chacune : description du risque, impact métier, \
vecteur d'exploitation, et fix recommandé avec exemple de code si applicable.

3. **Synthèse exécutive** (5 lignes max) — Pour un RSSI ou un CTO non-technique.

4. **Plan de remédiation** — Actions prioritaires classées par effort/impact.

Réponds en Markdown structuré."""

        if skill_context:
            prompt = f"<!-- Instructions de reporting :\n{skill_context}\n-->\n\n{prompt}"

        return prompt

    def build_cve_prompt(self, findings: list[dict], target: str) -> str:
        """Construit le prompt CVE en utilisant cve-dependency-scan skill."""
        skill_content = self.load_skill("cve-dependency-scan")
        cves = [
            f for f in findings
            if f.get("tool", "").startswith("grype") or "CVE" in f.get("id", "")
        ]
        if not cves:
            return ""

        cve_list = "\n".join(
            f"- `{f.get('id')}` ({f.get('severity', '?')}) — "
            f"{f.get('package', '?')} — {f.get('description', '')[:100]}"
            for f in cves[:20]
        )

        skill_ctx = ""
        if skill_content and not skill_content.startswith("<!--"):
            lines = skill_content.strip().splitlines()[:15]
            skill_ctx = "\n".join(lines)

        prompt = f"""## CVE détectées sur `{target}`

{cve_list}

Pour chaque CVE critique ou high :
1. Est-elle exploitable dans ce contexte ? (score CVSS, vecteur d'attaque)
2. Quelle version corrige la faille ?
3. Y a-t-il un workaround si la mise à jour n'est pas possible immédiatement ?

Réponds en Markdown."""

        if skill_ctx:
            prompt = f"<!-- Contexte CVE :\n{skill_ctx}\n-->\n\n{prompt}"

        return prompt

    def build_secrets_prompt(self, findings: list[dict], target: str) -> str:
        """Construit le prompt secrets en utilisant sast-devsec skill."""
        skill_content = self.load_skill("sast-devsec")
        secrets = [
            f for f in findings
            if f.get("tool", "") in ("gitleaks-secrets", "trufflehog-secrets")
        ]
        if not secrets:
            return ""

        secret_list = "\n".join(
            f"- `{f.get('id')}` dans `{f.get('file', '?')}:{f.get('line', '?')}` — "
            f"{f.get('description', '')[:80]}"
            for f in secrets[:20]
        )

        skill_ctx = ""
        if skill_content and not skill_content.startswith("<!--"):
            lines = skill_content.strip().splitlines()[:15]
            skill_ctx = "\n".join(lines)

        prompt = f"""## Secrets détectés dans `{target}`

{secret_list}

Pour chaque secret :
1. Est-ce un vrai secret ou un faux positif ?
2. Si vrai positif : procédure de rotation urgente recommandée.
3. Comment éviter ce type de fuite à l'avenir (pre-commit hooks, vault, etc.) ?

Réponds en Markdown."""

        if skill_ctx:
            prompt = f"<!-- Contexte SAST/secrets :\n{skill_ctx}\n-->\n\n{prompt}"

        return prompt


# ── CLI standalone ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PromptLoader — test standalone")
    parser.add_argument("--agents-dir", default="agents/", type=Path)
    parser.add_argument("--skills-dir", default="skills/", type=Path)
    parser.add_argument("--roles-dir", default="roles/", type=Path)
    parser.add_argument("--level", type=int, default=1)
    args = parser.parse_args()

    loader = PromptLoader(
        agents_dir=args.agents_dir,
        skills_dir=args.skills_dir,
        roles_dir=args.roles_dir,
    )

    print(f"\n📋 System prompt pour level {args.level}:\n")
    prompt = loader.build_system_prompt(args.level)
    # Afficher juste les 1000 premiers chars
    print(prompt[:1000])
    print(f"\n... ({len(prompt)} caractères total)\n")
