"""install.sh: checks that need no host (review round 6, reader I)."""
from __future__ import annotations

import re
from pathlib import Path

KIT = Path(__file__).resolve().parents[1] / "room-kit"
TEXT = (KIT / "install.sh").read_text()


def test_pinned_archives_do_not_keep_their_builders_uid() -> None:
    # uv and Caddy archives carry uid 1001; extracted as root they belonged
    # to whatever second user the host has, and ran as root.
    extracts = [ln for ln in TEXT.splitlines() if re.search(r"\btar -x|\btar --no-same-owner -x", ln)]
    assert extracts and all("--no-same-owner" in ln for ln in extracts), extracts
    assert 'chown -R root:root "$ROOM_OPT/bin"' in TEXT


def test_key_file_is_checked_before_anything_changes() -> None:
    assert TEXT.index('[ -r "${ROOM_API_KEY_FILE:-}" ]') < TEXT.index("0. host packages")


def test_live_rooms_are_checked_again_right_before_each_restart() -> None:
    calls = [m.start() for m in re.finditer(r"^\s*refuse_restart_with_rooms\b(?!\(\))", TEXT, re.M)]
    assert len(calls) >= 3
    daemon_restart = TEXT.index('systemctl restart "$ROOM_ID-docker.service"')
    api_restart = TEXT.index('systemctl restart "$ROOM_ID.service" "$ROOM_ID-health.service"')
    assert any(daemon_restart - 400 < c < daemon_restart for c in calls)
    assert any(api_restart - 800 < c < api_restart for c in calls)


def test_a_failed_apt_does_not_leave_policy_rc_d_behind() -> None:
    assert "trap 'rm -f /usr/sbin/policy-rc.d' EXIT" in TEXT


def test_sizing_sees_the_mounted_volume() -> None:
    mount_check = TEXT.index('mountpoint -q "$ROOM_DATA_DIR"')
    second_assess = TEXT.rindex('python3 "$KIT/assess.py"')
    size_call = TEXT.index("size_room 0 ")
    assert mount_check < second_assess < size_call
