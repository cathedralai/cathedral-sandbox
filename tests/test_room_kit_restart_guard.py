"""install.sh refuses to restart the room API while it holds live rooms.

A restart forgets every sandbox and the first reconcile pass removes their
containers, so an update during live rooms ends a customer's work.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import tempfile
from pathlib import Path

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _guard(tmp_path: Path, running: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    text = (KIT / "install.sh").read_text()
    fn = re.search(r"^refuse_restart_with_rooms\(\) \{.*?^\}", text, re.S | re.M)
    assert fn, "install.sh has no refuse_restart_with_rooms function"
    assert re.search(r"^refuse_restart_with_rooms$", text, re.M), "install.sh never calls the guard"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    fake.write_text(f"#!/bin/sh\nprintf '%s' '{running}'\n")
    fake.chmod(0o755)
    # A short path: AF_UNIX paths are capped near 104 bytes on macOS.
    sock = Path(tempfile.mkdtemp(dir="/tmp")) / "d.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(sock))
    script = f"SOCK={sock}\nlog() {{ echo \"$*\"; }}\n{fn.group(0)}\nrefuse_restart_with_rooms\necho continued\n"
    try:
        return subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, check=False,
            env={"PATH": f"{bin_dir}:{os.environ['PATH']}", **(env or {})},
        )
    finally:
        server.close()
        sock.unlink()
        sock.parent.rmdir()


def test_live_rooms_stop_the_install(tmp_path) -> None:
    proc = _guard(tmp_path, "abc123\n")
    assert proc.returncode != 0
    assert "continued" not in proc.stdout
    assert "ROOM_RESTART_WITH_ROOMS=1" in proc.stderr


def test_no_rooms_lets_the_install_go_on(tmp_path) -> None:
    assert "continued" in _guard(tmp_path, "").stdout


def test_operator_can_override(tmp_path) -> None:
    proc = _guard(tmp_path, "abc123\n", {"ROOM_RESTART_WITH_ROOMS": "1"})
    assert proc.returncode == 0 and "continued" in proc.stdout
