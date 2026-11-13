"""The receipt-list checker: old lists keep their output, and the v2 list pack gives its stated answers."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "tests" / "fixtures" / "old_lists"
sys.path.insert(0, str(OLD))

from run_case import run_case  # noqa: E402

OLD_CASES = sorted(json.loads((OLD / "cases.json").read_text()))


@pytest.mark.parametrize("name", OLD_CASES)
def test_old_lists_output_is_byte_identical(name: str) -> None:
    """Lists without numbering, serial or pool fields print what the checker printed before they existed."""
    case = OLD / "cases" / name
    out, code = run_case(name)
    assert out == (case / "golden.stdout").read_bytes()
    assert code == int((case / "golden.exit").read_text())


PACK = ROOT / "tests" / "fixtures" / "receipt_lists_v2"
CHECKER = ROOT / "room-kit" / "verify_receipts.py"


def _pack_cases() -> list[str]:
    return sorted(f"{kind}/{p.name}" for kind in ("good", "bad") for p in (PACK / kind).iterdir() if p.is_dir())


def _pointer(doc, pointer: str):
    for part in [p for p in pointer.split("/") if p]:
        doc = doc[int(part)] if isinstance(doc, list) else doc[part]
    return doc


def _run_pack_case(name: str) -> tuple[dict, dict, int]:
    import subprocess

    folder = PACK / name
    case = json.loads((folder / "case.json").read_text())
    args = [a.replace("{dir}", str(folder)) for a in case["args"]]
    proc = subprocess.run([sys.executable, str(CHECKER), *args], capture_output=True, text=True)
    assert proc.stdout.strip(), proc.stderr
    return case, json.loads(proc.stdout), proc.returncode


@pytest.mark.parametrize("name", _pack_cases())
def test_pack_case_gives_its_stated_answer(name: str) -> None:
    case, out, code = _run_pack_case(name)
    expect = case["expect"]
    assert out["verdict"] == expect["verdict"], out
    assert code == expect["exit_code"]
    if "reason" in expect:
        assert out["reason"] == expect["reason"]
    for pointer, want in expect.get("pointers", {}).items():
        assert _pointer(out, pointer) == want, pointer


def test_good_and_bad_cases_are_each_in_their_folder() -> None:
    for name in _pack_cases():
        case = json.loads((PACK / name / "case.json").read_text())
        assert (case["expect"]["verdict"] == "PASS") == name.startswith("good/"), name


def test_pack_manifest_and_every_file_rebuild_byte_for_byte() -> None:
    import subprocess

    proc = subprocess.run([sys.executable, str(PACK / "generate.py"), "--check"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    manifest = json.loads((PACK / "MANIFEST.json").read_text())
    import hashlib

    for path, digest in manifest["files"].items():
        assert hashlib.sha256((PACK / path).read_bytes()).hexdigest() == digest, path
    lines = "".join(f"{p} {d}\n" for p, d in sorted(manifest["files"].items()))
    assert hashlib.sha256(lines.encode()).hexdigest() == manifest["root_sha256"]
