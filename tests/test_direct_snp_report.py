"""Direct guest ioctl and independent AMD verification; no SNP hardware is implied."""
import base64
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests import test_verify_receipts_room_report as fixture

KIT = Path(__file__).resolve().parents[1] / "room-kit"
sys.path.insert(0, str(KIT))


def load(name):
    spec = importlib.util.spec_from_file_location(name, KIT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector = load("snp_guest_report")
verifier = load("verify_guest_report")
NONCE = bytes(range(64))
HOST_DATA = "ab" * 32


def fake_ioctl(*, status=0, size=1184, exitinfo2=0, vmpl=0, wrong_nonce=False):
    def call(fd, number, command, mutate):
        assert os.fstat(fd)
        assert number == 0xc0205300 and mutate is True
        assert command.msg_version == 1
        req = collector.ReportRequest.from_address(command.req_data)
        assert bytes(req.user_data) == NONCE and req.vmpl == 0
        assert bytes(req.reserved) == bytes(28)
        assert ctypes.sizeof(req) == 96
        command.exitinfo2 = exitinfo2
        report = bytearray(1184)
        report[0x30:0x34] = vmpl.to_bytes(4, "little")
        report[0x50:0x90] = bytes(64) if wrong_nonce else NONCE
        response = status.to_bytes(4, "little") + size.to_bytes(4, "little") + bytes(24) + report
        ctypes.memmove(command.resp_data, bytes(response), len(response))
        call.fd = fd
    return call


def test_ioctl_abi_and_verbatim_challenge():
    call = fake_ioctl()
    answer = collector.collect(NONCE, "/dev/null", ioctl=call)
    report = base64.b64decode(answer["report_b64"])
    assert report[0x50:0x90] == NONCE
    assert answer["verification"] == "not_checked" and "verdict" not in answer
    with pytest.raises(OSError):
        os.fstat(call.fd)


@pytest.mark.parametrize("change,reason", [
    ({"status": 22}, "MSG_REPORT_RSP status"),
    ({"size": 0}, "report size"), ({"size": 1183}, "report size"),
    ({"size": 4000}, "report size"),
    ({"exitinfo2": 1}, "firmware/VMM"), ({"exitinfo2": 2 << 32}, "firmware/VMM"),
    ({"wrong_nonce": True}, "REPORT_DATA"), ({"vmpl": 1}, "VMPL 0"),
])
def test_bad_ioctl_response_is_not_collected(change, reason):
    with pytest.raises(collector.ReportError, match=reason):
        collector.collect(NONCE, "/dev/null", ioctl=fake_ioctl(**change))


@pytest.mark.parametrize("error", [errno.ENOTTY, errno.EIO, errno.EACCES])
def test_ioctl_errors_do_not_fall_back(error):
    seen = []
    def ioctl(fd, *_):
        seen.append(fd)
        raise OSError(error, os.strerror(error))
    with pytest.raises(collector.ReportError, match="SNP_GET_REPORT failed"):
        collector.collect(NONCE, "/dev/null", ioctl=ioctl)
    assert len(seen) == 1
    with pytest.raises(OSError):
        os.fstat(seen[0])


def test_regular_file_and_missing_device_are_refused(tmp_path):
    path = tmp_path / "not-a-device"
    path.write_bytes(b"")
    with pytest.raises(collector.ReportError, match="character device"):
        collector.collect(NONCE, str(path), ioctl=lambda *_: pytest.fail("must not ioctl a file"))
    with pytest.raises(collector.ReportError, match="cannot open"):
        collector.collect(NONCE, str(tmp_path / "absent"))


def test_real_fcntl_path_refuses_non_snp_device():
    # Exercise ctypes through Python's real ioctl buffer path, without SNP hardware.
    with pytest.raises(collector.ReportError, match="SNP_GET_REPORT failed"):
        collector.collect(NONCE, "/dev/null")


@pytest.mark.parametrize("size", [0, 32, 63, 65])
def test_caller_length_is_exact(size):
    with pytest.raises(collector.ReportError, match="exactly 64"):
        collector.collect(bytes(size), "/dev/null")


def signed_report(tmp_path, *, vmpl=0, debug=False, migration=False):
    raw = bytearray(fixture.snp.make_report(report_data=NONCE))
    raw[0xc0:0xe0] = bytes.fromhex(HOST_DATA)
    raw[0x30:0x34] = vmpl.to_bytes(4, "little")
    policy = int.from_bytes(raw[8:16], "little") | (debug << 19) | (migration << 18)
    raw[8:16] = policy.to_bytes(8, "little")
    cache = tmp_path / "kds"
    report = fixture._sign_with_one_vcek([bytes(raw)], cache)[0]
    return {"report_b64": base64.b64encode(report).decode()}, cache


def verify(answer, cache, **over):
    expected = dict(report_data_hex=NONCE.hex(), expected_measurement=fixture.snp.MEASUREMENT,
                    expected_host_data=HOST_DATA, ark_sha256=fixture.snp.ark_pin(), cache=str(cache))
    expected.update(over)
    return verifier.verify(answer, **expected)


def test_signed_report_passes_with_all_expected_fields(tmp_path):
    answer, cache = signed_report(tmp_path)
    answer.update(host_data="00" * 32, measurement="ff" * 48, verification="PASS")
    result = verify(answer, cache)
    assert result["verdict"] == "PASS"
    assert result["fresh_report"]["host_data"] == HOST_DATA
    assert result["fresh_report"]["report_data_hex"] == NONCE.hex()
    assert result["fresh_report"]["vmpl"] == 0


@pytest.mark.parametrize("field,value,reason", [
    ("report_data_hex", "00" * 64, "REPORT_DATA"),
    ("expected_measurement", "00" * 48, "measurement"),
    ("expected_host_data", "00" * 32, "HOST_DATA"),
    ("ark_sha256", "00" * 32, "ARK"),
    ("ark_sha256", "", "ark-sha256"),
    ("expected_host_data", "", "64 hex"),
    ("expected_measurement", "", "96 hex"),
    ("expected_chip_id", "00" * 64, "chip"),
])
def test_wrong_or_missing_expectation_fails(tmp_path, field, value, reason):
    answer, cache = signed_report(tmp_path)
    with pytest.raises(verifier.vr.Fail, match=reason):
        verify(answer, cache, **{field: value})


@pytest.mark.parametrize("change,reason", [({"vmpl": 1}, "VMPL 0"),
                                           ({"debug": True}, "debug"),
                                           ({"migration": True}, "migration")])
def test_signed_but_unacceptable_policy_fails(tmp_path, change, reason):
    answer, cache = signed_report(tmp_path, **change)
    with pytest.raises(verifier.vr.Fail, match=reason):
        verify(answer, cache)


def test_host_data_tamper_fails_signature_even_when_caller_expects_it(tmp_path):
    answer, cache = signed_report(tmp_path)
    report = bytearray(base64.b64decode(answer["report_b64"]))
    report[0xc0] ^= 1
    answer["report_b64"] = base64.b64encode(report).decode()
    with pytest.raises(verifier.vr.Fail, match="signature"):
        verify(answer, cache, expected_host_data=report[0xc0:0xe0].hex())


def test_verifier_cli_and_missing_pin_fail_closed(tmp_path):
    answer, cache = signed_report(tmp_path)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(answer))
    command = [sys.executable, str(KIT / "verify_guest_report.py"), str(path),
               "--report-data-hex", NONCE.hex(), "--expected-measurement", fixture.snp.MEASUREMENT,
               "--expected-host-data", HOST_DATA, "--ark-sha256", fixture.snp.ark_pin(),
               "--kds-cache", str(cache)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["verdict"] == "PASS"
    index = command.index("--expected-host-data")
    del command[index:index + 2]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 2 and "--expected-host-data" in result.stderr


def test_collector_cli_failure_never_prints_pass(tmp_path):
    result = subprocess.run([sys.executable, str(KIT / "snp_guest_report.py"),
                             "--report-data-hex", NONCE.hex(), "--device", str(tmp_path / "missing")],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert json.loads(result.stdout)["error"] == "report_collection_failed"
    assert "PASS" not in result.stdout
