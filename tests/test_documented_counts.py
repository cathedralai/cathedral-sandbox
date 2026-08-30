"""Operator docs do not publish a test total which immediately goes stale."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIM = re.compile(r"(\d[\d,]*)\s*(?:passing\s+)?(tests|passed)\b", re.IGNORECASE)
DOCUMENTED = (
    "README.md",
    "MINING.md",
    "docs/README.md",
    "docs/TESTING.md",
)


def test_operator_docs_do_not_state_a_test_count() -> None:
    for relative in DOCUMENTED:
        path = ROOT / relative
        text = path.read_text(encoding="utf-8")
        assert not CLAIM.search(text), f"remove the stale test total from {relative}"
