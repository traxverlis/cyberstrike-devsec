"""Tests for yaml_utils — shared YAML loading module."""
import os
import pytest
from yaml_utils import load_yaml, load_config_yaml, _load_yaml_fallback


class TestLoadYaml:
    """Test the load_yaml function."""

    def test_simple_key_value(self):
        text = "name: nmap\nversion: 1.0"
        result = load_yaml(text)
        assert result["name"] == "nmap"
        assert result["version"] == 1.0 or result["version"] == "1.0"

    def test_boolean_values(self):
        text = "enabled: true\ndisabled: false"
        result = load_yaml(text)
        assert result["enabled"] is True
        assert result["disabled"] is False

    def test_comments_ignored(self):
        text = "# This is a comment\nname: test\n# Another comment\nvalue: 42"
        result = load_yaml(text)
        assert result["name"] == "test"
        assert "comment" not in str(result).lower()

    def test_empty_input(self):
        result = load_yaml("")
        assert result == {}

    def test_only_comments(self):
        text = "# comment 1\n# comment 2\n"
        result = load_yaml(text)
        assert result == {}

    def test_quoted_values(self):
        text = 'url: "https://example.com"\nkey: \'value\''
        result = load_yaml(text)
        assert "example.com" in result["url"]

    def test_value_with_colon(self):
        """Values containing colons should be handled correctly."""
        text = 'base_url: "https://api.example.com:8443/v1"'
        result = load_yaml(text)
        assert "example.com" in result["base_url"]

    def test_list_values(self):
        text = "items:\n  - first\n  - second\n  - third"
        result = load_yaml(text)
        assert isinstance(result["items"], list)
        assert len(result["items"]) == 3


class TestLoadYamlFallback:
    """Test the fallback parser specifically."""

    def test_integer_parsing(self):
        text = "port: 8080\nname: test"
        result = _load_yaml_fallback(text)
        assert result["port"] == 8080
        assert isinstance(result["port"], int)

    def test_boolean_true(self):
        result = _load_yaml_fallback("flag: true")
        assert result["flag"] is True

    def test_boolean_false(self):
        result = _load_yaml_fallback("flag: false")
        assert result["flag"] is False

    def test_list_under_key(self):
        text = "params:\n- alpha\n- beta"
        result = _load_yaml_fallback(text)
        assert result["params"] == ["alpha", "beta"]


class TestLoadConfigYaml:
    """Test config.yaml loading with env-var expansion."""

    def test_defaults(self, tmp_path):
        """Without a config file, defaults should be returned."""
        cfg = load_config_yaml(tmp_path / "nonexistent.yaml")
        assert cfg["model"] == "gpt-4o"
        assert cfg["base_url"] == "https://api.business.githubcopilot.com"
        assert cfg["api_key"] == ""

    def test_env_var_expansion(self, tmp_path, monkeypatch):
        """${VAR} references should be expanded from environment."""
        config = tmp_path / "config.yaml"
        config.write_text('api_key: "${MY_TEST_KEY}"\nmodel: "gpt-4o"')
        monkeypatch.setenv("MY_TEST_KEY", "test-secret-123")
        cfg = load_config_yaml(config)
        assert cfg["api_key"] == "test-secret-123"

    def test_env_override(self, monkeypatch, tmp_path):
        """Environment variables should override config file values."""
        config = tmp_path / "config.yaml"
        config.write_text('model: "gpt-3.5"')
        monkeypatch.setenv("AI_MODEL", "claude-sonnet-4-5")
        cfg = load_config_yaml(config)
        assert cfg["model"] == "claude-sonnet-4-5"

    def test_missing_env_var(self, tmp_path):
        """Missing env vars should resolve to empty string."""
        config = tmp_path / "config.yaml"
        config.write_text('api_key: "${NONEXISTENT_VAR_XYZ}"')
        cfg = load_config_yaml(config)
        assert cfg["api_key"] == ""
