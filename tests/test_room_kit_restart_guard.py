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


def _guard(tmp_path: Path, running: str | None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    text = (KIT / "install.sh").read_text()
    fn = re.search(r"^refuse_restart_with_rooms\(\) \{.*?^\}", text, re.S | re.M)
    assert fn, "install.sh has no refuse_restart_with_rooms function"
    assert re.search(r"^refuse_restart_with_rooms$", text, re.M), "install.sh never calls the guard"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake = bin_dir / "docker"
    body = "exit 1" if running is None else f"printf '%s' '{running}'"
    fake.write_text(f"#!/bin/sh\n{body}\n")
    fake.chmod(0o755)
    # A short path: AF_UNIX paths are capped near 104 bytes on macOS.
    sock = Path(tempfile.mkdtemp(dir="/tmp")) / "d.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(sock))
    script = f"set -euo pipefail\nSOCK={sock}\nlog() {{ echo \"$*\"; }}\n{fn.group(0)}\nrefuse_restart_with_rooms\necho continued\n"
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


def test_daemon_down_gives_a_reason(tmp_path) -> None:
    # A stale socket after a room daemon crash: docker ps fails. The install
    # must say why it stops, not exit with no output under set -e.
    proc = _guard(tmp_path, None)
    assert proc.returncode != 0
    assert "does not answer" in proc.stderr and "ROOM_RESTART_WITH_ROOMS=1" in proc.stderr


def test_auto_room_nets_keep_the_applied_list_until_step_8(tmp_path) -> None:
    # The running units read room.env. In auto mode the new list is known only
    # at step 8; a re-run that fails before then must not leave room.env
    # without the live room networks (their rooms would lose egress rules).
    text = (KIT / "install.sh").read_text()
    start = text.index("resolve_room_nets\n")
    end = text.index("# ---------------------------------------------------------------- 2. data volume")
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "room.env.applied").write_text('ROOM_ID="r"\nROOM_NETS="10.214.0.0/22 10.214.4.0/22"\n')
    script = (
        f"set -euo pipefail\nROOM_ETC={etc}\nROOM_KEYS='ROOM_ID ROOM_NETS'\nROOM_ID=r\n"
        f"source {KIT}/lib/room_nets_mode.sh\n"
        "write_room_env() { for k in $ROOM_KEYS; do printf '%s=\"%s\"\\n' \"$k\" \"${!k:-}\"; done > \"$ROOM_ETC/room.env\"; }\n"
        + text[start:end]
        + 'echo "after=[$ROOM_NETS] auto=$ROOM_NETS_AUTO"\n'
    )
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert 'ROOM_NETS="10.214.0.0/22 10.214.4.0/22"' in (etc / "room.env").read_text()
    assert "after=[] auto=1" in proc.stdout  # step 8 still plans from scratch
