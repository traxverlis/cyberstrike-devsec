"""Tests for generate-report — report generation and result parsing."""
import json
import pytest
from pathlib import Path

# Import the module under a variable name (filename has hyphens)
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "generate_report",
    str(Path(__file__).parent.parent / "scripts" / "generate-report.py"),
)
generate_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_report)


class TestResultLoaders:
    """Test JSON result file parsers."""

    def test_load_grype_results(self, tmp_path):
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1234",
                        "severity": "Critical",
                        "description": "Test vuln",
                        "cvss": [],
                        "fix": {"versions": ["1.2.3"]},
                    },
                    "artifact": {
                        "name": "test-pkg",
                        "version": "1.0.0",
                    },
                }
            ]
        }
        (tmp_path / "grype.json").write_text(json.dumps(data))
        findings = generate_report.load_grype_results(tmp_path)
        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2024-1234"
        assert findings[0]["severity"] == "Critical"

    def test_load_grype_empty(self, tmp_path):
        findings = generate_report.load_grype_results(tmp_path)
        assert findings == []

    def test_load_semgrep_results(self, tmp_path):
        data = {
            "results": [
                {
                    "check_id": "python.security.sql-injection",
                    "path": "app.py",
                    "start": {"line": 42},
                    "extra": {
                        "severity": "ERROR",
                        "message": "SQL injection detected",
                    },
                }
            ]
        }
        (tmp_path / "semgrep.json").write_text(json.dumps(data))
        findings = generate_report.load_semgrep_results(tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "High"

    def test_load_gitleaks_results(self, tmp_path):
        data = [
            {
                "RuleID": "aws-access-key",
                "Description": "AWS Access Key",
                "File": "config.py",
                "StartLine": 10,
            }
        ]
        (tmp_path / "gitleaks.json").write_text(json.dumps(data))
        findings = generate_report.load_gitleaks_results(tmp_path)
        assert len(findings) == 1
        assert findings[0]["severity"] == "Critical"

    def test_load_gitleaks_empty_array(self, tmp_path):
        (tmp_path / "gitleaks.json").write_text("[]")
        findings = generate_report.load_gitleaks_results(tmp_path)
        assert findings == []

    def test_load_checkov_results(self, tmp_path):
        data = {
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_DOCKER_2",
                        "check_name": "Healthcheck missing",
                        "file_path": "/Dockerfile",
                    }
                ]
            }
        }
        (tmp_path / "checkov.json").write_text(json.dumps(data))
        findings = generate_report.load_checkov_results(tmp_path)
        assert len(findings) == 1
        assert findings[0]["id"] == "CKV_DOCKER_2"


class TestDeduplication:
    """Test finding deduplication."""

    def test_removes_duplicates(self):
        findings = [
            {"tool": "grype", "name": "CVE-2024-1234", "url": "pkg-a"},
            {"tool": "grype", "name": "CVE-2024-1234", "url": "pkg-a"},
            {"tool": "grype", "name": "CVE-2024-5678", "url": "pkg-b"},
        ]
        result = generate_report.deduplicate_findings(findings)
        assert len(result) == 2

    def test_different_tools_not_deduped(self):
        findings = [
            {"tool": "grype", "name": "CVE-2024-1234", "url": "pkg"},
            {"tool": "trivy", "name": "CVE-2024-1234", "url": "pkg"},
        ]
        result = generate_report.deduplicate_findings(findings)
        assert len(result) == 2


class TestCvssScoring:
    """Test CVSS score filling."""

    def test_fills_missing_cvss(self):
        findings = [{"severity": "Critical", "cvss": 0.0}]
        result = generate_report.ensure_cvss_scores(findings)
        assert result[0]["cvss"] == 9.5

    def test_preserves_existing_cvss(self):
        findings = [{"severity": "High", "cvss": 8.1}]
        result = generate_report.ensure_cvss_scores(findings)
        assert result[0]["cvss"] == 8.1


class TestStatistics:
    """Test summary statistics generation."""

    def test_generates_correct_counts(self):
        findings = [
            {"severity": "Critical"},
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]
        stats = generate_report.generate_stats(findings)
        assert stats["Critical"] == 2
        assert stats["High"] == 1
        assert stats["Medium"] == 1
        assert stats["total"] == 4

    def test_empty_findings(self):
        stats = generate_report.generate_stats([])
        assert stats["total"] == 0
