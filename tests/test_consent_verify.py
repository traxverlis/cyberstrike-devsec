"""Tests for consent verification — verify-consent.py."""
import hashlib
import pytest
import sys
from pathlib import Path

# Import the module (filename has hyphens)
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "verify_consent",
    str(Path(__file__).parent.parent / "scripts" / "consent" / "verify-consent.py"),
)
verify_consent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_consent)


class TestFieldExtraction:
    """Test regex-based field extraction from consent PDF text."""

    def test_extract_field_basic(self):
        text = "Target System(s) / IP Range: https://app.example.com"
        result = verify_consent.extract_field(text, "Target System(s) / IP Range")
        assert result == "https://app.example.com"

    def test_extract_field_missing(self):
        result = verify_consent.extract_field("no match here", "Target")
        assert result is None

    def test_extract_hash(self):
        h = "a" * 64
        text = f"Document Hash: {h}"
        result = verify_consent.extract_hash(text)
        assert result == h

    def test_extract_hash_uppercase(self):
        h = "A" * 64
        text = f"Hash: {h}"
        result = verify_consent.extract_hash(text)
        assert result == h.lower()

    def test_extract_hash_not_found(self):
        result = verify_consent.extract_hash("no hash here")
        assert result is None

    def test_extract_uuid(self):
        text = "Reference: 12345678-ABCD-1234-ABCD-123456789ABC"
        result = verify_consent.extract_uuid(text)
        assert result == "12345678-ABCD-1234-ABCD-123456789ABC"


class TestDateWindow:
    """Test authorization window parsing and validation."""

    def test_parse_valid_window(self):
        start, end = verify_consent.parse_date_window("2020-01-01 to 2099-12-31")
        assert start is not None
        assert end is not None

    def test_parse_invalid_window(self):
        start, end = verify_consent.parse_date_window("invalid")
        assert start is None
        assert end is None

    def test_within_valid_window(self):
        valid, msg = verify_consent.is_within_window("2020-01-01 to 2099-12-31")
        assert valid is True

    def test_expired_window(self):
        valid, msg = verify_consent.is_within_window("2020-01-01 to 2020-12-31")
        assert valid is False
        assert "expired" in msg.lower()

    def test_future_window(self):
        valid, msg = verify_consent.is_within_window("2099-01-01 to 2099-12-31")
        assert valid is False
        assert "not started" in msg.lower()


class TestTargetMatch:
    """Test target URL matching logic."""

    def test_exact_match(self):
        assert verify_consent.targets_match("https://app.example.com", "https://app.example.com")

    def test_trailing_slash(self):
        assert verify_consent.targets_match("https://app.example.com/", "https://app.example.com")

    def test_case_insensitive(self):
        assert verify_consent.targets_match("https://APP.Example.Com", "https://app.example.com")

    def test_substring_match(self):
        assert verify_consent.targets_match("https://app.example.com/*", "https://app.example.com")

    def test_mismatch(self):
        assert not verify_consent.targets_match("https://other.com", "https://app.example.com")


class TestSignaturePresence:
    """Test signature block detection."""

    def test_three_signatures_present(self):
        text = "Signature: John\nSignature: Jane\nSignature: Bob"
        valid, msg = verify_consent.signatures_present(text)
        assert valid is True

    def test_missing_signatures(self):
        text = "Signature: John"
        valid, msg = verify_consent.signatures_present(text)
        assert valid is False

    def test_unsigned_placeholder(self):
        text = "Signature: ________\nSignature: Jane\nSignature: Bob"
        valid, msg = verify_consent.signatures_present(text)
        assert valid is False


class TestIntegrity:
    """Test SHA-256 integrity verification."""

    def test_valid_hash(self):
        uuid = "TEST-UUID"
        target = "https://test.com"
        scope = "/*"
        requestor = "Tester"
        company = "TestCo"
        tester = "Red Team"
        duration = "2024-01-01 to 2024-12-31"
        test_types = "recon,nmap"
        exclusions = "none"
        generated = "2024-01-01 00:00 UTC"

        canonical = (
            f"UUID:{uuid}|TARGET:{target}|SCOPE:{scope}|"
            f"REQUESTOR:{requestor}|COMPANY:{company}|TESTER:{tester}|"
            f"DURATION:{duration}|TEST_TYPES:{test_types}|"
            f"EXCLUSIONS:{exclusions}|GENERATED:{generated}"
        )
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        text = f"Some preamble\n{expected_hash}\nSome postamble"
        valid, stored, computed = verify_consent.verify_integrity(
            text, uuid, target, scope, requestor, company, tester,
            duration, test_types, exclusions, generated
        )
        assert valid is True
        assert stored == computed
