"""
ai_analyzer.py — CyberStrikeAI DevSec × IA
============================================
Module d'analyse IA des findings de sécurité.
Compatible avec tout provider OpenAI-compatible :
  - GitHub Copilot (recommandé — 0 coût supplémentaire)
  - OpenAI (GPT-4o, GPT-4-turbo)
  - Anthropic (Claude via proxy)
  - Ollama (local, 0 internet)
  - DeepSeek, Azure OpenAI

Usage standalone :
    python3 scripts/ai_analyzer.py --findings summary.json --config config.yaml

Usage depuis le pipeline :
    Importé par devsec-pipeline.py quand --ai est activé.
"""

import json
import os
import sys
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

# ── Shared YAML loading ──────────────────────────────────────────────────────
from yaml_utils import load_config_yaml

# ── PromptLoader dynamique (Option C) ────────────────────────────────────────
try:
    from prompt_loader import PromptLoader
    _PROJECT_ROOT = Path(__file__).parent.parent
    _PROMPT_LOADER = PromptLoader(
        agents_dir=_PROJECT_ROOT / "agents",
        skills_dir=_PROJECT_ROOT / "skills",
        roles_dir=_PROJECT_ROOT / "roles",
    )
    _PROMPT_LOADER_AVAILABLE = True
except ImportError:
    _PROMPT_LOADER_AVAILABLE = False
    _PROMPT_LOADER = None  # type: ignore


# ── Chargement de la config ───────────────────────────────────────────────────

def load_config(config_path: Optional[Path] = None) -> dict:
    """Charge config.yaml via yaml_utils. Fallback sur variables d'environnement."""
    return load_config_yaml(config_path)


# ── Appel au LLM ─────────────────────────────────────────────────────────────

def call_llm(prompt: str, system: str, cfg: dict) -> str:
    """Appel HTTP vers un provider OpenAI-compatible. Retourne le texte de la réponse."""
    base_url = cfg["base_url"].rstrip("/")
    api_key  = cfg["api_key"]
    model    = cfg["model"]

    if not api_key:
        return "[AI] ⚠️  Pas de clé API configurée — mode IA désactivé. Voir config.yaml"

    payload = json.dumps({
        "model": model,
        "temperature": float(cfg.get("temperature", 0.1)),
        "max_tokens": int(cfg.get("max_tokens", 4096)),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
        "Editor-Version": "vscode/1.85.0",
        "Copilot-Integration-Id": "vscode-chat",
        "X-Request-Id": os.urandom(8).hex(),
    }

    endpoint = f"{base_url}/chat/completions"

    try:
        req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        return f"[AI] ❌ HTTP {e.code} — {body}"
    except Exception as e:
        return f"[AI] ❌ Erreur: {e}"


# ── Prompts spécialisés ───────────────────────────────────────────────────────

SYSTEM_SECURITY_ANALYST = """Tu es un expert en cybersécurité senior. Tu analyses les résultats \
de scans de sécurité (CVE, SAST, secrets, IaC) et produis des rapports clairs, \
priorisés et actionnables pour des équipes de développement.

Règles :
- Réponds toujours en français
- Sois concis mais précis
- Priorise par criticité réelle (exploitabilité × impact business)
- Pour chaque finding critique, donne un exemple de fix concret
- Distingue les vrais positifs des faux positifs probables
- Format : Markdown structuré"""


def _get_system_prompt(level: int = 1) -> str:
    """Retourne le prompt système : depuis PromptLoader si dispo, sinon fallback."""
    if _PROMPT_LOADER_AVAILABLE and _PROMPT_LOADER is not None:
        try:
            return _PROMPT_LOADER.build_system_prompt(level)
        except Exception:
            pass
    return SYSTEM_SECURITY_ANALYST


def build_triage_prompt(findings: list[dict], target: str, level: int) -> str:
    """Construit le prompt de triage — délègue à PromptLoader si disponible."""
    if _PROMPT_LOADER_AVAILABLE and _PROMPT_LOADER is not None:
        try:
            return _PROMPT_LOADER.build_triage_prompt(findings, target, level)
        except Exception:
            pass
    # Fallback hardcodé

    # Dédupliquer et résumer les findings
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in by_severity:
            by_severity[sev].append(f)

    summary_lines = []
    for sev, items in by_severity.items():
        if items:
            summary_lines.append(f"\n### {sev.upper()} ({len(items)} findings)")
            # Max 5 examples par sévérité pour ne pas dépasser le contexte
            for item in items[:5]:
                tool = item.get("tool", "?")
                fid  = item.get("id", "?")
                desc = item.get("description", "")[:120]
                loc  = item.get("file", item.get("package", item.get("matched", "")))
                line = item.get("line", "")
                loc_str = f" — `{loc}:{line}`" if line else (f" — `{loc}`" if loc else "")
                summary_lines.append(f"- **[{tool}]** `{fid}`{loc_str}: {desc}")
            if len(items) > 5:
                summary_lines.append(f"  *(+ {len(items)-5} autres)*")

    findings_text = "\n".join(summary_lines) if summary_lines else "Aucun finding détecté."

    return f"""## Contexte du scan

- **Cible :** `{target}`
- **Niveau :** {level} ({'analyse statique' if level == 1 else 'scan actif web' if level == 2 else 'pentest complet'})
- **Total findings :** {len(findings)}

## Findings détectés
{findings_text}

---

## Ta mission

1. **Triage & Priorisation** — Classe les findings par risque réel (pas juste la sévérité brute). \
Identifie les faux positifs probables (ex: clés API dans des fichiers de documentation/templates).

2. **Top 5 vulnérabilités critiques** — Pour chacune : description du risque, impact métier, \
vecteur d'exploitation, et fix recommandé avec exemple de code si applicable.

3. **Synthèse exécutive** (5 lignes max) — Pour un RSSI ou un CTO non-technique.

4. **Plan de remédiation** — Actions prioritaires classées par effort/impact.

Réponds en Markdown structuré."""


def build_cve_analysis_prompt(findings: list[dict], target: str) -> str:
    """Prompt CVE — délègue à PromptLoader si disponible."""
    if _PROMPT_LOADER_AVAILABLE and _PROMPT_LOADER is not None:
        try:
            result = _PROMPT_LOADER.build_cve_prompt(findings, target)
            if result:
                return result
        except Exception:
            pass
    # Fallback hardcodé
    cves = [f for f in findings if f.get("tool", "").startswith("grype") or "CVE" in f.get("id", "")]
    if not cves:
        return None

    cve_list = "\n".join(
        f"- `{f.get('id')}` ({f.get('severity','?')}) — {f.get('package','?')} — {f.get('description','')[:100]}"
        for f in cves[:20]
    )

    return f"""## CVE détectées sur `{target}`

{cve_list}

Pour chaque CVE critique ou high :
1. Est-elle exploitable dans ce contexte ? (score CVSS, vecteur d'attaque)
2. Quelle version corrige la faille ?
3. Y a-t-il un workaround si la mise à jour n'est pas possible immédiatement ?

Réponds en Markdown."""


def build_secrets_analysis_prompt(findings: list[dict], target: str) -> str:
    """Prompt secrets — délègue à PromptLoader si disponible."""
    if _PROMPT_LOADER_AVAILABLE and _PROMPT_LOADER is not None:
        try:
            result = _PROMPT_LOADER.build_secrets_prompt(findings, target)
            if result:
                return result
        except Exception:
            pass
    # Fallback hardcodé
    secrets = [f for f in findings if f.get("tool", "") in ("gitleaks-secrets", "trufflehog-secrets")]
    if not secrets:
        return None

    secret_list = "\n".join(
        f"- `{f.get('id')}` dans `{f.get('file','?')}:{f.get('line','?')}` — {f.get('description','')[:80]}"
        for f in secrets[:20]
    )

    return f"""## Secrets détectés dans `{target}`

{secret_list}

Pour chaque secret :
1. Est-ce un vrai secret ou un faux positif (ex: valeur d'exemple dans de la documentation) ?
2. Si vrai positif : procédure de rotation urgente recommandée.
3. Comment éviter ce type de fuite à l'avenir (pre-commit hooks, vault, etc.) ?

Réponds en Markdown."""


# ── Analyse principale ────────────────────────────────────────────────────────

def analyze(
    findings: list[dict],
    target: str,
    level: int,
    cfg: dict,
    verbose: bool = False,
) -> dict:
    """
    Lance l'analyse IA complète.
    Retourne un dict avec les sections du rapport IA.
    """
    result = {
        "model": cfg.get("model", "?"),
        "provider": cfg.get("base_url", "?"),
        "triage": "",
        "cve_analysis": "",
        "secrets_analysis": "",
        "executive_summary": "",
        "error": None,
    }

    if not cfg.get("api_key"):
        result["error"] = "Pas de clé API — configurez config.yaml ou la variable GITHUB_COPILOT_TOKEN"
        return result

    if verbose:
        print(f"[AI] 🤖 Modèle : {cfg['model']} @ {cfg['base_url']}")
        print(f"[AI] 📊 Analyse de {len(findings)} findings sur {target}...")

    # Récupérer le prompt système dynamique
    system_prompt = _get_system_prompt(level)

    # 1. Triage général
    triage_prompt = build_triage_prompt(findings, target, level)
    if verbose:
        print("[AI] 🔍 Triage & priorisation...")
    result["triage"] = call_llm(triage_prompt, system_prompt, cfg)

    # 2. Analyse CVE (si findings CVE présents)
    cve_prompt = build_cve_analysis_prompt(findings, target)
    if cve_prompt:
        if verbose:
            print("[AI] 🔴 Analyse CVE...")
        result["cve_analysis"] = call_llm(cve_prompt, system_prompt, cfg)

    # 3. Analyse secrets (si secrets présents)
    secrets_prompt = build_secrets_analysis_prompt(findings, target)
    if secrets_prompt:
        if verbose:
            print("[AI] 🔑 Analyse des secrets exposés...")
        result["secrets_analysis"] = call_llm(secrets_prompt, system_prompt, cfg)

    if verbose:
        print("[AI] ✅ Analyse IA terminée.")

    return result


def format_ai_section(ai_result: dict) -> str:
    """Formate le résultat IA en section Markdown pour le rapport."""
    if ai_result.get("error"):
        return f"\n## ⚠️ Analyse IA indisponible\n\n{ai_result['error']}\n"

    model   = ai_result.get("model", "?")
    base_url = ai_result.get("provider", "?")
    # Extraire juste le domaine pour l'affichage
    try:
        from urllib.parse import urlparse
        provider_name = urlparse(base_url).netloc or base_url
    except Exception:
        provider_name = base_url

    sections = [
        f"\n---\n\n## 🤖 Analyse IA\n\n*Modèle : `{model}` via `{provider_name}`*\n",
    ]

    if ai_result.get("triage"):
        sections.append(f"\n### Triage & Priorisation\n\n{ai_result['triage']}\n")

    if ai_result.get("cve_analysis"):
        sections.append(f"\n### Analyse CVE\n\n{ai_result['cve_analysis']}\n")

    if ai_result.get("secrets_analysis"):
        sections.append(f"\n### Secrets exposés\n\n{ai_result['secrets_analysis']}\n")

    return "\n".join(sections)


# ── CLI standalone ────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="CyberStrikeAI DevSec — Analyse IA des findings de sécurité",
        epilog="""
Exemples :
  python3 scripts/ai_analyzer.py --findings reports/scan/summary.json
  python3 scripts/ai_analyzer.py --findings reports/scan/summary.json --config config.yaml
  python3 scripts/ai_analyzer.py --findings reports/scan/summary.json --output ai_report.md
        """
    )
    parser.add_argument("--findings", type=Path, required=True,
                        help="Fichier summary.json produit par le pipeline")
    parser.add_argument("--config", type=Path, default=None,
                        help="Fichier config.yaml (auto-détecté si absent)")
    parser.add_argument("--output", type=Path, default=None,
                        help="Fichier de sortie Markdown (stdout si absent)")
    parser.add_argument("--level", type=int, choices=[1,2,3], default=2,
                        help="Niveau du scan (1/2/3)")
    parser.add_argument("--verbose", action="store_true",
                        help="Afficher les étapes d'analyse")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.findings.exists():
        print(f"[AI] ❌ Fichier introuvable : {args.findings}", file=sys.stderr)
        sys.exit(1)

    summary = json.loads(args.findings.read_text())
    findings = summary.get("findings", [])
    target   = summary.get("target", "unknown")
    level    = summary.get("level", args.level)

    cfg = load_config(args.config)
    ai_result = analyze(findings, target, level, cfg, verbose=args.verbose)
    report_section = format_ai_section(ai_result)

    if args.output:
        args.output.write_text(report_section)
        print(f"[AI] ✅ Rapport IA écrit dans {args.output}")
    else:
        print(report_section)


if __name__ == "__main__":
    main()
