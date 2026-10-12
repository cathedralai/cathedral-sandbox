"""The live TDX check reports each validator verdict, and fails when one is wrong.

The hardware run needs an Intel TDX guest; these tests drive the same check
logic with a fake verifier, so a verifier that accepts a replayed, copied or
relayed quote, or reports an Intel outage as an invalid quote, fails the check.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from cathedral.common import ChannelBinding, ChannelBindingType, report_data_v2

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_live_tdx_check",
    Path(__file__).resolve().parents[1] / "scripts" / "live_tdx_check.py",
)
live = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules[_SPEC.name] = live
_SPEC.loader.exec_module(live)

NONCE = bytes(range(32))
SPKI = bytes(range(32, 64))
QUOTE = bytes(range(256)) * 8
CLAIMS = {
    "intel_verified": True,
    "report_data_match": True,
    "claims_bound_to_quote": True,
    "tcb_status": "UpToDate",
    "measurement": "tdx-measurement-sha256:" + "ab" * 32,
}


def _expected() -> str:
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, SPKI)
    return report_data_v2(NONCE, live.DEFAULT_HOTKEY, binding).hex()


def _verifier(*, accept_any_binding=False, outage_exit=3, good_stdout=None, refusal_exit=1):
    """A fake cathedral-tdx-verifier that decides like the real one."""

    calls: list[list[str]] = []

    def runner(command):
        calls.append(list(command))
        offline = command[0] == "unshare"
        quote_path, report_data = command[-2], command[-1]
        tampered = Path(quote_path).read_bytes() != QUOTE
        if offline:
            code, out = outage_exit, b""
        elif tampered:
            code, out = 1, b""
        elif report_data == _expected() or accept_any_binding:
            code, out = 0, good_stdout if good_stdout is not None else json.dumps(CLAIMS).encode()
        else:
            code, out = refusal_exit, b""
        return subprocess.CompletedProcess(command, code, out, b"verifier says no" if code else b"")

    return runner, calls


def _run(tmp_path, runner, **options):
    return live.run_checks(
        QUOTE,
        nonce=NONCE,
        hotkey=live.DEFAULT_HOTKEY,
        tls_spki_sha256=SPKI,
        verifier=Path("/opt/cathedral-tdx-verifier"),
        workdir=tmp_path,
        runner=runner,
        **options,
    )


def test_an_honest_verifier_passes_every_check(tmp_path):
    runner, calls = _verifier()
    checks = _run(tmp_path, runner)

    assert [check.passed for check in checks] == [True] * 6
    assert "UpToDate" in checks[0].detail
    assert calls[-1][:3] == ["unshare", "--net", "--map-root-user"]


def test_a_verifier_that_ignores_the_binding_fails_replay_copy_and_relay(tmp_path):
    runner, _ = _verifier(accept_any_binding=True)
    checks = {check.name: check.passed for check in _run(tmp_path, runner)}

    assert checks["real quote with the correct binding verifies"] is True
    assert checks["a replayed quote (other nonce) is refused"] is False
    assert checks["a copied quote (other hotkey) is refused"] is False
    assert checks["a relayed quote (other TLS key) is refused"] is False
    assert checks["a tampered quote is refused"] is True


def test_an_outage_reported_as_an_invalid_quote_fails(tmp_path):
    runner, _ = _verifier(outage_exit=1)
    outage = _run(tmp_path, runner)[-1]

    assert outage.name.startswith("with Intel unreachable")
    assert outage.passed is False
    assert "exit 1" in outage.detail


@pytest.mark.parametrize(
    "stdout",
    [
        b"not json",
        b"[]",
        json.dumps({**CLAIMS, "intel_verified": False}).encode(),
        json.dumps({**CLAIMS, "report_data_match": False}).encode(),
        json.dumps({**CLAIMS, "claims_bound_to_quote": False}).encode(),
    ],
    ids=["not-json", "not-object", "not-intel-verified", "no-report-data-match", "not-bound"],
)
def test_a_pass_without_verified_quote_bound_claims_fails(tmp_path, stdout):
    runner, _ = _verifier(good_stdout=stdout)
    assert _run(tmp_path, runner)[0].passed is False


def test_the_outage_check_can_be_skipped(tmp_path):
    runner, calls = _verifier()
    checks = _run(tmp_path, runner, check_outage=False)

    assert len(checks) == 5
    assert all(call[0] != "unshare" for call in calls)


def test_the_tampered_quote_differs_by_one_bit(tmp_path):
    runner, _ = _verifier()
    _run(tmp_path, runner)
    original = (tmp_path / "quote.bin").read_bytes()
    tampered = (tmp_path / "quote-tampered.bin").read_bytes()

    assert original == QUOTE
    assert [i for i, (a, b) in enumerate(zip(original, tampered, strict=True)) if a != b] == [
        live.TAMPER_OFFSET
    ]


def test_main_refuses_a_verifier_that_is_not_executable(tmp_path):
    missing = tmp_path / "absent"
    with pytest.raises(SystemExit, match="not an executable file"):
        live.main(["--verifier", str(missing)])


def test_a_binding_mismatch_reported_as_an_outage_is_not_a_refusal(tmp_path):
    """Exit 3 for a wrong nonce, hotkey or TLS key would let a miner stop the
    validator's round, so only exit 1 counts as a refusal."""

    runner, _ = _verifier(refusal_exit=3)
    checks = {check.name: check.passed for check in _run(tmp_path, runner)}

    assert checks["a replayed quote (other nonce) is refused"] is False
    assert checks["a copied quote (other hotkey) is refused"] is False
    assert checks["a relayed quote (other TLS key) is refused"] is False


def test_the_tamper_offset_is_inside_the_signed_td_body():
    header, body = 48, 584
    assert header <= live.TAMPER_OFFSET < header + body
