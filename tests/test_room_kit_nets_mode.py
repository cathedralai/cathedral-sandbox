"""Room network default: unset is auto, none and off stay on the main bridge (#291)."""

from __future__ import annotations

import subprocess
from pathlib import Path

KIT = Path(__file__).resolve().parents[1] / "room-kit"
MODE = KIT / "lib" / "room_nets_mode.sh"


def _resolve(assignment: str) -> str:
    script = f"""
set -euo pipefail
source "$MODE"
{assignment}
resolve_room_nets
printf '%s %s\\n' "$ROOM_NETS_AUTO" "$ROOM_NETS"
"""
    proc = subprocess.run(
        ["bash", "-c", script],
        capture_output=True, text=True, check=False,
        env={"MODE": str(MODE), "PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


def test_unset_and_auto_size_room_networks() -> None:
    assert _resolve("unset ROOM_NETS") == "1"
    assert _resolve("ROOM_NETS=auto") == "1"


def test_none_off_and_empty_keep_the_main_bridge() -> None:
    assert _resolve("ROOM_NETS=none") == "0"
    assert _resolve("ROOM_NETS=off") == "0"
    assert _resolve("ROOM_NETS=") == "0"


def test_explicit_cidr_list_is_kept() -> None:
    assert _resolve('ROOM_NETS="10.214.0.0/22 10.214.4.0/22"') == "0 10.214.0.0/22 10.214.4.0/22"


def test_install_uses_the_resolver() -> None:
    text = (KIT / "install.sh").read_text()
    assert "resolve_room_nets" in text
    profile = (KIT / "profiles" / "v1.sh").read_text()
    assert 'CATHEDRAL_ROOM_NETWORK_DNS=\\"$ROOM_DNS\\"' in profile
