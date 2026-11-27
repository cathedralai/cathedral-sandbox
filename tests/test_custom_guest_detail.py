"""The detail the operator tool PATCHes to the API on a boot failure is one printable line (rehearsal B, run 3:
a serial tail with newlines got a 422 and the failure could not be recorded)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OPS = REPO / "ops" / "custom-guest"


def load():
    sys.path.insert(0, str(OPS))
    spec = importlib.util.spec_from_file_location("custom_guest_op", OPS / "custom_guest.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_one_line_is_single_line_printable_and_bounded():
    f = load().one_line
    tail = "[    0.1] kernel: line one\r\n\x1b[31mred\x1b[0m\ttab\n\n  no SSH banner\x00\x7f é中"
    out = f(tail)
    assert "\n" not in out and "\r" not in out and "\t" not in out
    assert all(" " <= c <= "~" for c in out), out
    assert "  " not in out
    assert out.startswith("[ 0.1] kernel: line one"), out
    assert len(f("x" * 1000)) == 300
    assert f("x" * 1000, limit=50) == "x" * 50
    assert f("") == "no detail given" and f(None) == "None" and f("\n\n\x00") == "no detail given"
    assert f("a b ".ljust(400, " ") + "tail") == "a b tail"


def test_the_boot_failure_patch_uses_it():
    source = (OPS / "custom_guest.py").read_text()
    assert '"error_detail": one_line(e.detail)' in source
    assert "e.detail[:300]})" not in source.split('"error_detail"')[1][:60]
