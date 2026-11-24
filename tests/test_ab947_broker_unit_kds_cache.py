"""AB#947: the broker unit makes the AMD KDS cache dir owned by the broker user.

On 24 Nov the UID 19 miner hotel's join failed with 422 every reconciler pass:
/var/lib/thin-broker/amd-kds was owned by root 0755, the broker runs as
thinbroker, and the verifier's VCEK cache write raised PermissionError. The unit
now lists it as a systemd StateDirectory: systemd makes it and gives it to
thinbroker on every start, and refuses to start on a symlink instead of
chowning the link's target (Cursor finding on #721: a root ExecStartPre on a
thinbroker-owned path let that user redirect a root chown).
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "broker" / "thin-broker.service"
KDS = "/var/lib/thin-broker/amd-kds"


def _service() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    section = ""
    for line in UNIT.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if section == "[Service]":
            key, _, value = line.partition("=")
            out.setdefault(key, []).append(value)
    return out


def test_unit_runs_as_thinbroker_with_its_state_dirs() -> None:
    svc = _service()
    assert svc["User"] == ["thinbroker"] and svc["Group"] == ["thinbroker"]
    assert svc["StateDirectory"] == ["thin-broker thin-broker/amd-kds"]


def test_kds_cache_dir_is_a_state_directory() -> None:
    dirs = _service()["StateDirectory"][0].split()
    assert "/var/lib/" + dirs[1] == KDS


def test_no_privileged_exec_touches_the_broker_owned_cache() -> None:
    svc = _service()
    for key in ("ExecStartPre", "ExecStartPost", "ExecStart", "ExecStopPost"):
        for value in svc.get(key, []):
            assert not (value.startswith(("+", "!")) and "/var/lib/thin-broker" in value), (key, value)


def test_unit_path_is_the_documented_kds_cache() -> None:
    assert f'"kds_cache": "{KDS}"' in (ROOT / "broker" / "amd_chain.go").read_text()
