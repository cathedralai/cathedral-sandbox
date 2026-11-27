"""Fail-closed boot check: verdicts from recorded console text and a fake QEMU, no VM started."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import custom_guest_boot_check as bc

BOOT = "[    0.512] Run /init as init process\n"
LAUNCH_FAIL = BOOT + "cathedral-init: launch documents: no SNP guest device\n[    0.9] reboot: Power down\n"


def test_launch_documents_failure_and_poweroff_passes():
    r = bc.evaluate(LAUNCH_FAIL, exited=True, timed_out=False, expect_stage="launch documents")
    assert r["verdict"] == "PASS" and r["reason"] is None and r["stages_seen"] == ["launch documents"]


def test_unlinked_build_must_stop_at_pins():
    console = BOOT + "cathedral-init: pins: verity pin is not linked in\n"
    assert bc.evaluate(console, True, False, "pins")["verdict"] == "PASS"
    assert bc.evaluate(console, True, False, "launch documents")["verdict"] == "FAIL"


@pytest.mark.parametrize("console,exited,timed_out,why", [
    (LAUNCH_FAIL, False, True, "time limit"),                                   # guest never powered off
    (BOOT, True, False, "never showed cathedral-init"),                          # PID1 printed nothing
    ("[    0.1] Linux version 6.1\n", True, False, "never showed cathedral-init"),  # never reached PID1
    (BOOT + "Kernel panic - not syncing: VFS\n", True, False, "panic"),
    (BOOT + "cathedral-init: panic in boot stage\n", True, False, "panic"),
    (BOOT + "cathedral-init: verified root: bad hash\n", True, False, "expected only"),  # got past launch: impossible without SNP
    (LAUNCH_FAIL + "cathedral-init: exec: exec returned\n", True, False, "expected only"),
    (LAUNCH_FAIL, False, False, "did not exit"),
])
def test_anything_else_fails(console, exited, timed_out, why):
    r = bc.evaluate(console, exited, timed_out, "launch documents")
    assert r["verdict"] == "FAIL" and why in r["reason"]


def files(tmp_path, cmdline="console=ttyS0 cathedral.owner=x systemd.import_credentials=no"):
    for name in ("vmlinuz", "initrd"):
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / "manifest.json").write_text(json.dumps({"cmdline": cmdline}))
    return ["--kernel", str(tmp_path / "vmlinuz"), "--initrd", str(tmp_path / "initrd"),
            "--manifest", str(tmp_path / "manifest.json"), "--qemu", sys.executable]


def test_main_boots_with_the_manifest_cmdline_exactly(tmp_path, capsys):
    seen = []

    def fake(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=LAUNCH_FAIL.encode(), stderr=b"")
    assert bc.main(files(tmp_path), runner=fake) == 0
    argv = seen[0]
    assert argv[argv.index("-append") + 1] == "console=ttyS0 cathedral.owner=x systemd.import_credentials=no"
    assert "-no-reboot" in argv and argv[argv.index("-cpu") + 1] == "max"
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "PASS" and out["snp"] is False and out["qemu_returncode"] == 0


def test_a_qemu_startup_error_shows_its_return_code(tmp_path, capsys):
    def broken(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"qemu: unsupported machine")
    assert bc.main(files(tmp_path), runner=broken) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "FAIL" and out["qemu_returncode"] == 1


def test_main_reports_a_hang_as_fail(tmp_path, capsys):
    def hang(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=BOOT.encode())
    assert bc.main(files(tmp_path), runner=hang) == 1
    out = json.loads(capsys.readouterr().out)
    assert "time limit" in out["reason"] and out["qemu_returncode"] is None


def test_missing_inputs_are_an_error_not_a_fail(tmp_path, capsys):
    args = files(tmp_path)
    (tmp_path / "initrd").unlink()
    assert bc.main(args) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "ERROR"


def test_a_cmdline_without_a_serial_console_is_an_error(tmp_path, capsys):
    assert bc.main(files(tmp_path, cmdline="quiet cathedral.owner=x")) == 2
    assert "ttyS0" in json.loads(capsys.readouterr().out)["reason"]
