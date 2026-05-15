"""Tests for ai_analyzer — AI analysis module."""
import json
import pytest
from pathlib import Path
from ai_analyzer import load_config, build_triage_prompt, call_llm


class TestLoadConfig:
    """Test config loading delegates to yaml_utils correctly."""

    def test_defaults_without_file(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert cfg["model"] == "gpt-4o"
        assert cfg["api_key"] == ""

    def test_with_config_file(self, tmp_path):
        config = tmp_path / "config.yaml"
        config.write_text('model: "llama3:8b"\nbase_url: "http://localhost:11434/v1"')
        cfg = load_config(config)
        assert cfg["model"] == "llama3:8b"
        assert "localhost" in cfg["base_url"]

    def test_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AI_MODEL", "gpt-4-turbo")
        cfg = load_config(tmp_path / "nonexistent.yaml")
        assert cfg["model"] == "gpt-4-turbo"


class TestBuildTriagePrompt:
    """Test triage prompt construction."""

    def test_empty_findings(self):
        prompt = build_triage_prompt([], "https://test.com", 1)
        assert "test.com" in prompt
        assert "0" in prompt

    def test_findings_by_severity(self):
        findings = [
            {"severity": "critical", "tool": "grype", "id": "CVE-2024-1234",
             "description": "Test vuln", "package": "pkg-a"},
            {"severity": "high", "tool": "semgrep", "id": "sql-injection",
             "description": "SQL injection", "file": "app.py", "line": 42},
        ]
        prompt = build_triage_prompt(findings, "./myapp", 1)
        assert "CRITICAL" in prompt
        assert "HIGH" in prompt
        assert "2" in prompt

    def test_level_description(self):
        prompt = build_triage_prompt([], "target", 2)
        assert "scan actif" in prompt.lower() or "active" in prompt.lower() or "2" in prompt


class TestCallLlm:
    """Test LLM call error handling."""

    def test_no_api_key(self):
        cfg = {"base_url": "http://localhost", "api_key": "", "model": "test",
               "temperature": 0.1, "max_tokens": 100}
        result = call_llm("test", "system", cfg)
        assert "clé API" in result or "API" in result

    def test_invalid_endpoint(self):
        cfg = {"base_url": "http://127.0.0.1:1", "api_key": "test-key",
               "model": "test", "temperature": 0.1, "max_tokens": 100}
        result = call_llm("test", "system", cfg)
        assert "Erreur" in result or "❌" in result
