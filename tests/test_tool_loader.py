"""Tests for tool_loader — dynamic tool loading from YAML definitions."""
import pytest
from pathlib import Path
from tool_loader import ToolLoader


@pytest.fixture
def tools_dir(tmp_path):
    """Create a temporary tools directory with sample YAML files."""
    # Format A tool (like semgrep)
    (tmp_path / "semgrep.yaml").write_text("""
name: semgrep
command: semgrep
short_description: SAST analysis
parameters:
  - name: config
    flag: --config
    format: flag
    default: auto
  - name: output
    flag: --output
    format: flag
  - name: target
    format: positional
    position: 0
""")
    # Format B tool (like nmap)
    (tmp_path / "nmap.yaml").write_text("""
name: nmap
binary: nmap
short_description: Network scanner
parameters:
  ports:
    type: string
    default: "-"
  target:
    type: string
""")
    # Minimal tool
    (tmp_path / "gitleaks.yaml").write_text("""
name: gitleaks
command: gitleaks
short_description: Secret detection
""")
    return tmp_path


@pytest.fixture
def loader(tools_dir):
    return ToolLoader(tools_dir)


class TestToolLoader:

    def test_load_existing_tool(self, loader):
        tool = loader.load_tool("semgrep")
        assert tool is not None
        assert tool["name"] == "semgrep"

    def test_load_nonexistent_tool(self, loader):
        tool = loader.load_tool("does-not-exist")
        assert tool is None

    def test_tool_caching(self, loader):
        tool1 = loader.load_tool("semgrep")
        tool2 = loader.load_tool("semgrep")
        assert tool1 is tool2

    def test_format_a_parameters(self, loader):
        tool = loader.load_tool("semgrep")
        assert isinstance(tool["parameters"], list)
        assert len(tool["parameters"]) == 3

    def test_build_command_format_a(self, loader):
        tool = loader.load_tool("semgrep")
        cmd = loader.build_command(tool, {"config": "auto", "output": "/tmp/out.json", "target": "."})
        assert cmd[0] == "semgrep"
        assert "--config" in cmd
        assert "auto" in cmd

    def test_build_command_minimal(self, loader):
        tool = loader.load_tool("gitleaks")
        cmd = loader.build_command(tool, {})
        assert cmd == ["gitleaks"]

    def test_get_scan_tools_for_level(self, loader):
        """Level 1 tools should include gitleaks and semgrep."""
        tools = loader.get_scan_tools_for_level(1)
        assert "gitleaks" in tools
        assert "semgrep" in tools

    def test_level_escalation(self, loader):
        """Higher levels should include more tools."""
        l1 = loader.get_scan_tools_for_level(1)
        l2 = loader.get_scan_tools_for_level(2)
        assert len(l2) >= len(l1)
