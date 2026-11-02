"""Unit tests for #1469 seed-box host supervisor (no live QEMU)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

TOOL_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "snp_seedbox"
    / "supervise_customer_guest.py"
)
_SPEC = importlib.util.spec_from_file_location("supervise_customer_guest", TOOL_PATH)
sb = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(sb)


def _owner_dir(path: Path) -> Path:
    path.mkdir(parents=True, mode=0o700)
    path.chmod(0o700)
    return path


def test_prepare_next_empty(tmp_path: Path):
    run_base = _owner_dir(tmp_path / "runs")
    document = sb.prepare_next(run_base=run_base, stamp="fixed")
    assert document["schema"] == sb.SCHEMA
    assert document["spare_installed"] is False
    run_dir = Path(document["run_dir"])
    assert run_dir == run_base / "customer-run-fixed"
    assert run_dir.is_dir()
    assert list(run_dir.iterdir()) == []


def test_prepare_next_installs_spare(tmp_path: Path):
    run_base = _owner_dir(tmp_path / "runs")
    spare_dir = _owner_dir(tmp_path / "spare")
    spare = spare_dir / "scratch.raw"
    spare.write_bytes(b"\0" * 4096)
    spare.chmod(0o600)
    document = sb.prepare_next(run_base=run_base, spare_scratch=spare, stamp="with-spare")
    assert document["spare_installed"] is True
    dest = Path(document["run_dir"]) / "scratch.raw"
    assert dest.is_file()
    assert dest.stat().st_size == 4096
    assert not spare.exists()


def test_verify_start_script_pin(tmp_path: Path):
    script = tmp_path / "start.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    script.chmod(0o700)
    digest = hashlib.sha256(script.read_bytes()).hexdigest()
    assert sb.verify_start_script(script, digest) == script
    with pytest.raises(SystemExit):
        sb.verify_start_script(script, "0" * 64)


def test_watch_once_exits_when_pid_dead(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    run_dir = _owner_dir(tmp_path / "run")
    (run_dir / "guest.pid").write_text("424242\n", encoding="ascii")
    monkeypatch.setattr(sb, "pid_alive", lambda pid: False)
    assert sb.wait_for_guest_exit(run_dir, poll_seconds=0.01) == 424242


def test_live_gate_blocks_invoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CATHEDRAL_SEEDBOX_LIVE_OK", raising=False)
    script = tmp_path / "start.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    script.chmod(0o700)
    run_dir = _owner_dir(tmp_path / "run")
    with pytest.raises(SystemExit, match="CATHEDRAL_SEEDBOX_LIVE_OK"):
        sb.invoke_start_script(script, run_dir)


def test_cli_prepare_next(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    run_base = _owner_dir(tmp_path / "runs")
    code = sb.main(["prepare-next", "--run-base", str(run_base), "--stamp", "cli"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["run_dir"].endswith("customer-run-cli")
