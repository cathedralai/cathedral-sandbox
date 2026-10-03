"""Pluggable Affine verify pin."""

from __future__ import annotations

import json
from pathlib import Path

from cathedral.affine_verify_pin import load_verify_pin_from_paths, tiny_builtin_pin

FIXTURE = Path(__file__).parent / "fixtures" / "affine_verify_example.py"


def test_tiny_builtin_pin_runs():
    pin = tiny_builtin_pin()
    result = json.loads(pin.run(b"AFFINE:9").decode())
    assert result["passed"] is True
    assert pin.code_sha256


def test_load_module_pin(tmp_path: Path):
    inputs = tmp_path / "inputs.json"
    inputs.write_text(json.dumps({"prefix": "AFFINE"}, sort_keys=True), encoding="utf-8")
    pin = load_verify_pin_from_paths(
        verify_code_path=FIXTURE,
        verify_inputs_path=inputs,
        entrypoint="verify",
    )
    assert json.loads(pin.run(b"AFFINE:70").decode())["passed"] is True
    assert json.loads(pin.run(b"NOPE:70").decode())["passed"] is False
    digests = pin.digests_for(
        miner_payload=b"AFFINE:70",
        verify_result=pin.run(b"AFFINE:70"),
    )
    assert digests["affine_verify_code_sha256"] == pin.code_sha256
