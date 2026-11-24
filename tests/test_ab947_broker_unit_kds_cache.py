"""AB#947: the broker unit makes the AMD KDS cache dir owned by the broker user.

On 24 Nov the UID 19 miner hotel's join failed with 422 every reconciler pass:
/var/lib/thin-broker/amd-kds was owned by root 0755, the broker runs as
thinbroker, and the verifier's VCEK cache write raised PermissionError. The unit
now fixes the owner as root on every start.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

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


def _kds_pre() -> list[str]:
    hits = [v for v in _service().get("ExecStartPre", []) if KDS in v]
    assert len(hits) == 1, hits
    return shlex.split(hits[0])


def test_unit_runs_as_thinbroker_with_its_state_dir() -> None:
    svc = _service()
    assert svc["User"] == ["thinbroker"] and svc["Group"] == ["thinbroker"]
    assert svc["StateDirectory"] == ["thin-broker"]


def test_kds_cache_dir_is_made_as_root_and_owned_by_thinbroker() -> None:
    argv = _kds_pre()
    # "+": runs with full privileges, so it can take over a dir root made.
    assert argv[0] == "+/usr/bin/install"
    assert argv[1:] == ["-d", "-o", "thinbroker", "-g", "thinbroker", "-m", "0700", KDS]


def test_unit_path_is_the_documented_kds_cache() -> None:
    assert f'"kds_cache": "{KDS}"' in (ROOT / "broker" / "amd_chain.go").read_text()


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("install") is None, reason="needs root and install")
def test_install_takes_over_a_root_owned_cache(tmp_path: Path) -> None:
    cache = tmp_path / "amd-kds"
    cache.mkdir(mode=0o755)
    (cache / "vcek.der").write_bytes(b"x")
    argv = _kds_pre()
    argv = [a.lstrip("+") for a in argv]
    argv = ["65534" if a == "thinbroker" else a for a in argv]  # nobody stands in
    argv[-1] = str(cache)
    subprocess.run(["install", *argv[1:]], check=True)
    st = cache.stat()
    assert st.st_uid == 65534 and oct(st.st_mode & 0o777) == "0o700"
    assert (cache / "vcek.der").read_bytes() == b"x"
