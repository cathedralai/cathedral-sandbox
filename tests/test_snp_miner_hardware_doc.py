"""AB#348: the SNP hardware list's claims about this repository stay true.

The list tells miner applicants which CPUs are admissible and how slots are
counted. If the code changes (Turin support, new size.py reserves, another ARK),
this fails so the list is redated instead of quietly going wrong.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "SNP_MINER_HARDWARE.md"


def _doc() -> str:
    return DOC.read_text(encoding="utf-8")


def test_list_is_dated_and_separates_proven_from_quotes() -> None:
    text = _doc()
    assert re.search(r"^# SNP miner hardware list \(\d{4}-\d{2}-\d{2}\)$", text, re.M)
    assert "## 3. Proven" in text
    assert "## 4. Quotes" in text
    assert "—" not in text


def test_broker_verifier_still_refuses_turin_reports() -> None:
    verifier = (ROOT / "room-kit" / "verify_receipts.py").read_text(encoding="utf-8")
    assert 'need(prod in ("Genoa", "Milan"), "only Milan and Genoa TCB layouts are handled")' in verifier
    assert "Turin (EPYC 9xx5, family 0x1A) is not admissible today" in _doc()


def test_genoa_family_models_match_the_sandbox_verifier() -> None:
    snp = (ROOT / "cathedral" / "verify" / "snp.py").read_text(encoding="utf-8")
    assert "0x10 <= parsed.cpuid_model <= 0x1F or 0xA0 <= parsed.cpuid_model <= 0xAF" in snp
    assert "_SUPPORTED_REPORT_VERSIONS = frozenset({3, 4, 5})" in snp
    assert "models 0x10 to 0x1F" in _doc() and "0xA0 to 0xAF" in _doc()


def test_slot_formula_matches_size_py_defaults() -> None:
    size = (ROOT / "room-kit" / "size.py").read_text(encoding="utf-8")
    assert 'ap.add_argument("--reserve-ram-pct", type=float, default=12)' in size
    assert 'ap.add_argument("--reserve-threads", type=int, default=2)' in size
    assert 'ap.add_argument("--disk-max-fill-pct", type=float, default=70)' in size
    assert "slots = min(threads - 2, floor(RAM_GiB * 0.88 / 2))" in _doc()


def test_quote_rows_cost_per_slot_is_price_over_slots() -> None:
    # Rows with an exact slot count: price / slots, rounded to cents.
    rows = re.findall(
        r"^\| [^|]+ \| [^|]+ \| [^|]+ \| [^|]+ \| \d+ \| [^|]+ \| (?:from )?(\$|EUR )([\d,]+(?:\.\d+)?)[^|]* \| (\d+) \| (?:\$|EUR )([\d.]+) \|",
        _doc(),
        re.M,
    )
    assert len(rows) >= 8
    for _, price, slots, per_slot in rows:
        assert round(float(price.replace(",", "")) / int(slots), 2) == float(per_slot), (price, slots, per_slot)
