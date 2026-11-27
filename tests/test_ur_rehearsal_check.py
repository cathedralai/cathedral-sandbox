"""Rehearsal A checker: synthetic test vector only; the SSH verifier is replaced by a fake runner."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "room-kit"))
import ur_rehearsal_check as rc

VECTOR = json.loads((ROOT / "tests" / "fixtures" / "custom_guest_v1.json").read_text())
LAUNCH_ID = json.loads(VECTOR["bootstrap_utf8"])["launch_id"]


def files(tmp_path, signature=None):
    paths = {}
    for name, data in (("manifest", VECTOR["manifest_utf8"].encode()), ("bootstrap", VECTOR["bootstrap_utf8"].encode()),
                       ("bootstrap_signature", signature or bytes.fromhex(VECTOR["signature_hex"])),
                       ("owner_public_key", bytes.fromhex(VECTOR["owner_public_hex"]))):
        path = tmp_path / name
        path.write_bytes(data)
        paths[name] = str(path)
    return paths


def args(tmp_path, host="192.0.2.1", port=20022, signature=None):
    p = files(tmp_path, signature)
    return rc.parser().parse_args([
        "--host", host, "--port", str(port), "--identity", str(tmp_path / "id"),
        "--manifest", p["manifest"], "--bootstrap", p["bootstrap"],
        "--bootstrap-signature", p["bootstrap_signature"], "--owner-public-key", p["owner_public_key"],
        "--expected-measurement", "aa" * 48, "--expected-chip-id", "bb" * 64, "--expected-cpuid", "26:2:1",
        "--ark-sha256", "cc" * 32, "--known-hosts-out", str(tmp_path / "kh"), "--min-tcb", "snp=1"])


def runner(code=0, out=None, calls=None):
    def fake(argv, **kwargs):
        if calls is not None:
            calls.append(argv)
        doc = out if out is not None else {"verdict": "PASS", "launch_id": LAUNCH_ID, "ssh_channel_binding": "verified",
                                           "ssh_host_key": "ssh-ed25519 AAAA"}
        return subprocess.CompletedProcess(argv, code, stdout=json.dumps(doc).encode() + b"\n", stderr=b"")
    return fake


def status(result):
    return {c["name"]: c["status"] for c in result["checks"]}


def test_pass_needs_both_automated_checks(tmp_path):
    calls = []
    result = rc.run(args(tmp_path), runner(calls=calls))
    assert result["verdict"] == "PASS"
    assert status(result) == {"launch_documents": "pass", "guest_report": "pass",
                              "restart_same_launch": "not_checked", "preserved_work": "not_checked"}
    assert result["checks"][0]["detail"]["host_data"] == VECTOR["host_data_hex"]
    argv = calls[0]
    assert argv[1].endswith("verify_custom_guest.py")
    assert argv[argv.index("--min-tcb") + 1] == "snp=1" and "--ark-crl" not in argv


def test_bad_signature_fails_without_connecting(tmp_path):
    calls = []
    sig = bytearray(bytes.fromhex(VECTOR["signature_hex"]))
    sig[0] ^= 1
    result = rc.run(args(tmp_path, signature=bytes(sig)), runner(calls=calls))
    assert result["verdict"] == "FAIL" and status(result)["launch_documents"] == "fail"
    assert status(result)["guest_report"] == "fail" and calls == []


@pytest.mark.parametrize("host,port", [("192.0.2.9", 20022), ("192.0.2.1", 20023)])
def test_endpoint_must_match_signed_bootstrap(tmp_path, host, port):
    calls = []
    result = rc.run(args(tmp_path, host=host, port=port), runner(calls=calls))
    assert result["verdict"] == "FAIL" and "endpoint" in result["checks"][0]["detail"] and calls == []


@pytest.mark.parametrize("code,out", [
    (1, {"verdict": "FAIL", "reason": "measurement differs"}),
    (0, {"verdict": "FAIL"}),
    (1, {"verdict": "PASS", "launch_id": LAUNCH_ID}),
    (0, {"verdict": "PASS", "launch_id": "cg-ffffffffffff"}),
    (0, ["PASS"]),
])
def test_guest_report_failures_fail_closed(tmp_path, code, out):
    result = rc.run(args(tmp_path), runner(code, out))
    assert result["verdict"] == "FAIL" and status(result)["guest_report"] == "fail"


def test_silent_or_garbled_verifier_fails(tmp_path):
    def silent(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=b"not json\n", stderr=b"")
    assert rc.run(args(tmp_path), silent)["verdict"] == "FAIL"

    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 180)
    assert rc.run(args(tmp_path), timeout)["verdict"] == "FAIL"


def test_oversized_document_fails(tmp_path):
    a = args(tmp_path)
    Path(a.manifest).write_bytes(b" " * (rc.DOC_LIMIT + 1))
    result = rc.run(a, runner())
    assert result["verdict"] == "FAIL" and "too large" in result["checks"][0]["detail"]
