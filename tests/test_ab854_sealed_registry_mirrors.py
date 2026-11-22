"""AB#854: the sealed guest's Docker Hub mirrors come from SEALED_ROOM_REGISTRY_MIRRORS.

Unset must give the exact room.env line every live sealed build has today, so hotels that
do not set it keep their measurement. Set, it must be 1 to 4 bare https origins, so no
login, path or shell text can reach the measured room.env.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

SEALED = Path(__file__).resolve().parents[1] / "room-kit" / "sealed"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")
BUILD = (SEALED / "build-guest.sh").read_text()
BLOCK = BUILD[BUILD.index("# >>> registry mirrors"):BUILD.index("# <<< registry mirrors")]
CHI = "https://mirror-chi.cathedral.computer:5443"


def _resolve(value: str | None) -> subprocess.CompletedProcess[str]:
    env_line = "" if value is None else f"SEALED_ROOM_REGISTRY_MIRRORS={shlex.quote(value)}\n"
    script = f'set -euo pipefail\n{env_line}{BLOCK}\nprintf "ROOM_REGISTRY_MIRRORS=\\"%s\\"" "$REGISTRY_MIRRORS"'
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin"})


def test_unset_keeps_todays_room_env_line() -> None:
    proc = _resolve(None)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == 'ROOM_REGISTRY_MIRRORS="https://mirror.gcr.io"'


def test_room_env_line_uses_the_checked_value() -> None:
    assert 'ROOM_REGISTRY_MIRRORS="$REGISTRY_MIRRORS"\n' in BUILD
    assert "mirror.gcr.io\"\n" not in BUILD.split("cat > \"$R/opt/room-kit/room.env\"")[1].split("\nEOF\n")[0]
    # validated before the long build, ahead of the data volume checks and debootstrap
    assert BUILD.index("# >>> registry mirrors") < BUILD.index("DATA_GIB=${SEALED_DATA_GIB:-0}")


@pytest.mark.parametrize("value, want", [
    (f"{CHI} https://mirror.gcr.io", f"{CHI} https://mirror.gcr.io"),
    (f"  {CHI}\t https://mirror.gcr.io  ", f"{CHI} https://mirror.gcr.io"),
    (CHI, CHI),
])
def test_valid_lists_are_normalized(value: str, want: str) -> None:
    proc = _resolve(value)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == f'ROOM_REGISTRY_MIRRORS="{want}"'


@pytest.mark.parametrize("value", [
    "http://mirror.gcr.io",
    "https://user:pw@mirror.gcr.io",
    "https://mirror.gcr.io/v2/",
    "https://Mirror.gcr.io",
    "https://mirror.gcr.io:0",
    'https://mirror.gcr.io"; touch /tmp/x; "',
    "https://a.io https://b.io https://c.io https://d.io https://e.io",
    "   ",
])
def test_bad_values_stop_the_build(value: str) -> None:
    proc = _resolve(value)
    assert proc.returncode != 0
    assert "SEALED_ROOM_REGISTRY_MIRRORS" in proc.stderr
