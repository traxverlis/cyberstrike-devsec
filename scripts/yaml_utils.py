"""
yaml_utils.py — Shared YAML loading for CyberStrikeAI DevSec
=============================================================
Single source of truth for YAML parsing across all scripts.
Uses PyYAML (yaml.safe_load) when available, falls back to a
minimal key:value parser for simple flat YAML files.
"""
import os
from typing import Optional

try:
    import yaml as _yaml
    _HAS_PYYAML = True
except ImportError:
    _HAS_PYYAML = False


def load_yaml(text: str) -> dict:
    """Parse YAML text and return a dict. Uses PyYAML if available."""
    if _HAS_PYYAML:
        return _yaml.safe_load(text) or {}
    return _load_yaml_fallback(text)


def load_yaml_file(path, encoding: str = "utf-8") -> dict:
    """Load and parse a YAML file. Returns empty dict on failure."""
    from pathlib import Path
    p = Path(path)
    if not p.exists():
        return {}
    return load_yaml(p.read_text(encoding=encoding))


def _load_yaml_fallback(text: str) -> dict:
    """
    Minimal YAML parser for simple key:value and key: list files.
    Handles booleans, integers, quoted strings, and simple lists.
    Does NOT support nested dicts or multi-line values.
    """
    result = {}
    current_key = None
    current_list = None

    for line in text.splitlines():
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue

        # Detect list item under a key
        if stripped.startswith("- ") and current_key is not None:
            if current_list is None:
                current_list = []
                result[current_key] = current_list
            current_list.append(stripped[2:].strip())
            continue

        # Key: value
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            current_key = key
            current_list = None

            if val:
                # Booleans
                if val.lower() == "true":
                    result[key] = True
                elif val.lower() == "false":
                    result[key] = False
                else:
                    # Integers
                    try:
                        result[key] = int(val)
                    except ValueError:
                        result[key] = val

    return result


def load_config_yaml(config_path=None) -> dict:
    """
    Load config.yaml with env-var expansion (${VAR} syntax).
    Used by ai_analyzer.py and other scripts needing AI provider config.
    """
    from pathlib import Path

    cfg = {
        "base_url": "https://api.githubcopilot.com",
        "api_key": "",
        "model": "claude-opus-4.6",
        "reasoning_effort": "medium",
        "temperature": 0.1,
        "max_tokens": 4096,
    }

    if config_path is None:
        candidates = [
            Path(__file__).parent.parent / "config.yaml",
            Path("config.yaml"),
        ]
        for c in candidates:
            if c.exists():
                config_path = c
                break

    if config_path and Path(config_path).exists():
        try:
            raw = load_yaml(Path(config_path).read_text())
            for key, val in raw.items():
                k = key.strip().lower()
                v = str(val).strip()
                # Expand ${ENV_VAR} references
                if v.startswith("${") and v.endswith("}"):
                    env_var = v[2:-1]
                    v = os.getenv(env_var, "")
                if k in cfg:
                    cfg[k] = v
        except Exception:
            pass  # Use defaults on parse error

    # Override from environment variables
    env_map = {
        "OPENAI_API_KEY": "api_key",
        "GITHUB_COPILOT_TOKEN": "api_key",
        "AI_API_KEY": "api_key",
        "AI_BASE_URL": "base_url",
        "AI_MODEL": "model",
        "AI_REASONING": "reasoning_effort",
    }
    for env_var, cfg_key in env_map.items():
        val = os.getenv(env_var)
        if val:
            cfg[cfg_key] = val

    return cfg
