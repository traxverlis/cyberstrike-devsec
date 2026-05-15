"""conftest.py — Shared fixtures for CyberStrikeAI DevSec tests."""
import sys
from pathlib import Path

# Ensure scripts/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
