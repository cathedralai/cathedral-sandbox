"""AB#789: build-guest.sh writes the guest volume agent's settings into the measured room.env.

Off (SEALED_ROOM_VOLUMES 0 or unset) must write no volume line, so hotels that do not set it
keep their room.env bytes and measurement. On, the registry and gateway must be bare https
URLs and the registry keys 1 to 4 base64 Ed25519 public keys, so no shell text, login or
foreign key reaches the measured file. The written keys are the ones install.sh reads.
"""
from __future__ import annotations

import base64
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEALED = ROOT / "room-kit" / "sealed"
BASH = shutil.which("bash")
PY = shutil.which("python3")
pytestmark = pytest.mark.skipif(BASH is None or PY is None, reason="needs bash and python3")
BUILD = (SEALED / "build-guest.sh").read_text()
BLOCK = BUILD[BUILD.index("# >>> synced volumes"):BUILD.index("# <<< synced volumes")]
K1 = base64.b64encode(bytes(range(32))).decode()
K2 = base64.b64encode(bytes(range(1, 33))).decode()
REG = "https://api.cathedral.computer"
GW = "https://volumes.cathedral.computer:8443/gw"
ON = {"SEALED_ROOM_VOLUMES": "1", "SEALED_ROOM_VOLUME_REGISTRY_URL": REG,
      "SEALED_ROOM_VOLUME_GATEWAY_URL": GW, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": K1}


def _run(env: dict[str, str], data_ws: str = "/srv/sealed-data/workspaces") -> subprocess.CompletedProcess[str]:
    lines = "".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items())
    script = f'set -euo pipefail\nDATA_WS={shlex.quote(data_ws)}\n{lines}{BLOCK}\nprintf "%s" "$VOLUME_ENV"'
    return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin"})


@pytest.mark.parametrize("env", [{}, {"SEALED_ROOM_VOLUMES": "0"}, {"SEALED_ROOM_VOLUMES": "0", **{
    k: v for k, v in ON.items() if k != "SEALED_ROOM_VOLUMES"}}])
def test_off_writes_no_volume_line(env: dict[str, str]) -> None:
    proc = _run(env, data_ws="")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""


def test_on_writes_the_keys_install_sh_reads() -> None:
    proc = _run({**ON, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": f"{K1},{K2},{K1}",
                 "SEALED_ROOM_VOLUME_COMMIT_SECONDS": "120"})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        "ROOM_VOLUMES=1",
        f"ROOM_VOLUME_REGISTRY_URL={REG}",
        f"ROOM_VOLUME_GATEWAY_URL={GW}",
        f"ROOM_VOLUME_REGISTRY_KEYS={K1},{K2}",
        "ROOM_VOLUME_COMMIT_SECONDS=120",
    ]
    install_keys = re.search(r'^ROOM_KEYS="([^"]*)"', (ROOT / "room-kit" / "install.sh").read_text(), re.M)
    assert install_keys is not None
    for line in proc.stdout.splitlines():
        assert line.split("=", 1)[0] in install_keys.group(1).split()


def test_commit_seconds_empty_keeps_the_agent_default() -> None:
    proc = _run(ON)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines()[-1] == "ROOM_VOLUME_COMMIT_SECONDS="


def test_block_is_checked_before_the_build_and_appended_to_room_env() -> None:
    assert BUILD.index("DATA_WS=/srv/sealed-data/workspaces") < BUILD.index("# >>> synced volumes")
    assert BUILD.index("# <<< synced volumes") < BUILD.index("mmdebstrap")
    room_env = BUILD.split('cat > "$R/opt/room-kit/room.env" <<EOF')[1]
    heredoc, after = room_env.split("\nEOF\n", 1)
    assert "ROOM_VOLUME" not in heredoc  # off keeps the heredoc bytes of every live build
    assert after.index('echo "$VOLUME_ENV"; } >> "$R/opt/room-kit/room.env"') < after.index("$INGRESS_ZONE")


@pytest.mark.parametrize("env, data_ws", [
    ({"SEALED_ROOM_VOLUMES": "yes"}, "/srv/sealed-data/workspaces"),
    (ON, ""),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_URL": "http://api.cathedral.computer"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_URL": "https://u:p@api.cathedral.computer"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_URL": "https://api.cathedral.computer/"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_GATEWAY_URL": ""}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_GATEWAY_URL": 'https://gw.io"; touch /tmp/x; "'}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_GATEWAY_URL": "https://gw.io/?a=b"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": ""}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": "not-base64"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": base64.b64encode(b"x" * 31).decode()}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": f"{K1},"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_REGISTRY_KEYS": ",".join([K1, K2, K1[:-4] + "AAA=", K2[:-4] + "AAA=", K1[:-4] + "AQA="])},
     "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_COMMIT_SECONDS": "29"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_COMMIT_SECONDS": "86401"}, "/srv/sealed-data/workspaces"),
    ({**ON, "SEALED_ROOM_VOLUME_COMMIT_SECONDS": "060"}, "/srv/sealed-data/workspaces"),
])
def test_bad_values_stop_the_build(env: dict[str, str], data_ws: str) -> None:
    proc = _run(env, data_ws=data_ws)
    assert proc.returncode != 0
    assert "SEALED_ROOM_VOLUME" in proc.stderr
