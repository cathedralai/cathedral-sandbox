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
        "--ark-sha256", "cc" * 32, "--known-hosts-out", str(tmp_path / "kh"), "--min-tcb", "turin:fmc=1,bl=1,tee=1,snp=1,ucode=1"])


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


LIVE_KEY = "ssh-ed25519 AAAA"  # what the fake verifier returns as the live report's key
OLD_KEY = "ssh-ed25519 BBBB"   # the boot before the hold
BODY = "%s  data.raw\n%s  root.raw\n" % ("aa" * 32, "bb" * 32)


def listing(taken, body=BODY, launch=LAUNCH_ID):
    return f"# cathedral.preserved/v1 launch_id={launch} taken={taken}\n" + body


def result_line(key, verdict="PASS", launch=LAUNCH_ID, binding="verified"):
    return json.dumps({"verdict": verdict, "launch_id": launch, "ssh_channel_binding": binding, "ssh_host_key": key}) + "\n"


def evidence(a, tmp_path, before=None, after=None, pre=None, restart=None):
    files = {"before": listing("2026-11-27T10:00:00Z") if before is None else before,
             "after": listing("2026-11-27T11:00:00Z") if after is None else after,
             "pre": result_line(OLD_KEY) if pre is None else pre,
             "restart": result_line(LIVE_KEY) if restart is None else restart}
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    a.preserved_before, a.preserved_after, a.pre_hold_result, a.restart_result = (
        str(tmp_path / n) for n in ("before", "after", "pre", "restart"))
    return a


def test_without_evidence_the_verdict_is_incomplete_not_pass(tmp_path):
    """Spock's HOLD on #778: missing restart or disk evidence must never read as PASS."""
    result = rc.run(args(tmp_path), runner())
    assert result["verdict"] == "INCOMPLETE"
    assert status(result) == {"launch_documents": "pass", "guest_report": "pass",
                              "restart_same_launch": "not_checked", "preserved_work": "not_checked"}


def test_main_exits_2_when_incomplete(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rc, "run", lambda a: {"verdict": "INCOMPLETE", "checks": []})
    assert rc.main(["--host", "h", "--identity", "i", "--manifest", "m", "--bootstrap", "b", "--bootstrap-signature", "s",
                    "--owner-public-key", "o", "--expected-measurement", "e", "--expected-chip-id", "c",
                    "--expected-cpuid", "u", "--ark-sha256", "a", "--known-hosts-out", "k", "--min-tcb", "t"]) == 2


@pytest.mark.parametrize("after,why", [
    (listing("2026-11-27T11:00:00Z", "%s  data.raw\n%s  root.raw\n" % ("cc" * 32, "bb" * 32)), "changed during the hold: data.raw"),
    (listing("2026-11-27T11:00:00Z", "%s  root.raw\n" % ("bb" * 32)), "differ"),
    (listing("2026-11-27T11:00:00Z", ""), "no disks"),
    ("", "empty"),
    (BODY, "header"),
    (listing("2026-11-27T11:00:00Z", launch="cg-ffffffffffff"), "another launch"),
    (listing("2026-11-27T10:00:00Z"), "not older"),
    (listing("2026-11-27T09:00:00Z"), "not older"),
    (listing("2026-11-27T11:00:00Z", "not a listing\n"), "sha256sum"),
])
def test_a_changed_stale_or_unheaded_listing_fails(tmp_path, after, why):
    result = rc.run(evidence(args(tmp_path), tmp_path, after=after), runner())
    assert result["verdict"] == "FAIL" and status(result)["preserved_work"] == "fail"
    assert why in result["checks"][-1]["detail"]


def test_the_same_listing_file_twice_fails(tmp_path):
    """Spock's P2: --preserved-before X --preserved-after X must not pass."""
    a = evidence(args(tmp_path), tmp_path)
    a.preserved_after = a.preserved_before
    result = rc.run(a, runner())
    assert status(result)["preserved_work"] == "fail" and "same file" in result["checks"][-1]["detail"]


@pytest.mark.parametrize("pre,restart,why", [
    (None, result_line(OLD_KEY), "another boot"),          # saved pre-hold output passed as the restart
    (result_line(LIVE_KEY), None, "did not change"),        # no reboot happened
    (None, result_line(LIVE_KEY, verdict="FAIL"), "not PASS"),  # FAIL with the right launch id (Spock's mutation note)
    (None, result_line(LIVE_KEY, launch="cg-ffffffffffff"), "another launch"),
    (None, result_line(LIVE_KEY, binding="unchecked"), "SSH-bound"),
    (None, result_line(LIVE_KEY, verdict="FAIL") + result_line(LIVE_KEY), "one JSON line"),
    (None, json.dumps({"verdict": "PASS", "launch_id": LAUNCH_ID, "ssh_channel_binding": "verified"}), "no host key"),
    (None, "", "one JSON line"),
    (None, "[]", "not PASS"),
])
def test_a_bad_or_stale_restart_result_fails(tmp_path, pre, restart, why):
    result = rc.run(evidence(args(tmp_path), tmp_path, pre=pre, restart=restart), runner())
    assert result["verdict"] == "FAIL" and status(result)["restart_same_launch"] == "fail"
    assert why in [c for c in result["checks"] if c["name"] == "restart_same_launch"][0]["detail"]


def test_pass_needs_every_check_including_evidence(tmp_path):
    calls = []
    result = rc.run(evidence(args(tmp_path), tmp_path), runner(calls=calls))
    assert result["verdict"] == "PASS"
    assert set(status(result).values()) == {"pass"}
    assert result["checks"][0]["detail"]["host_data"] == VECTOR["host_data_hex"]
    argv = calls[0]
    assert argv[1].endswith("verify_custom_guest.py")
    assert argv[argv.index("--min-tcb") + 1] == "turin:fmc=1,bl=1,tee=1,snp=1,ucode=1" and "--ark-crl" not in argv


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


def test_acceptance_passes_each_floor_whole(tmp_path, monkeypatch):
    """The live test must hand the verifier complete floors, never comma fragments."""
    sys.path.insert(0, str(ROOT / "room-kit"))
    import verify_receipts
    acceptance = (ROOT / "tests" / "acceptance" / "test_ur_rehearsal_a.py").read_text()
    assert 'env["UR_MIN_TCB"].split()' in acceptance
    floors = "turin:fmc=1,bl=1,tee=1,snp=1,ucode=1".split()
    assert verify_receipts.parse_min_tcb(floors)["turin"]["ucode"] == 1
