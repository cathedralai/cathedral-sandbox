"""The one-page SN94 quickstart stays in step with the README it condenses."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
QUICKSTART = REPO_ROOT / "docs" / "SN94_MINER_QUICKSTART.md"
IMAGE_RE = re.compile(r"ghcr\.io/cathedralai/[a-z0-9-]+@sha256:[0-9a-f]{64}")
CHECKOUT_RE = re.compile(r"checkout --detach ([0-9a-f]{40})\b")
TDX_LAUNCHER_DIGEST_RE = re.compile(
    r"([0-9a-f]{64}) \\\n\s*/usr/local/libexec/cathedral/run-sn94-miner \| sudo sha256sum --check"
)
UNIT_RE = re.compile(
    r"/etc/systemd/system/(cathedral-sn94-[a-z-]+\.service) <<'EOF'\n(.*?)\nEOF\n", re.S
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_quickstart_carries_the_readme_pins() -> None:
    readme = _text(REPO_ROOT / "README.md")
    quickstart = _text(QUICKSTART)

    readme_images = set(IMAGE_RE.findall(readme))
    assert len(readme_images) == 2, readme_images
    assert set(IMAGE_RE.findall(quickstart)) == readme_images

    readme_revisions = set(CHECKOUT_RE.findall(readme))
    assert len(readme_revisions) == 1, readme_revisions
    (revision,) = readme_revisions
    assert f"SOURCE={revision}\n" in quickstart
    assert f"REFRESHER_REVISION='{revision}'" in readme

    readme_digests = TDX_LAUNCHER_DIGEST_RE.findall(readme)
    assert len(readme_digests) == 1, readme_digests
    assert TDX_LAUNCHER_DIGEST_RE.findall(quickstart) == readme_digests


def test_quickstart_is_linked_and_marks_the_validator_dependencies() -> None:
    quickstart = _text(QUICKSTART)
    anchor = "#validator-side-dependencies-not-live-until-the-validator-cutover"

    assert "docs/SN94_MINER_QUICKSTART.md" in _text(REPO_ROOT / "README.md")
    assert "docs/SN94_MINER_QUICKSTART.md" in _text(REPO_ROOT / "MINING.md")
    assert "(SN94_MINER_QUICKSTART.md)" in _text(REPO_ROOT / "docs" / "README.md")
    assert "## Validator-side dependencies (not live until the validator cutover)" in quickstart
    assert anchor in quickstart
    assert f"docs/SN94_MINER_QUICKSTART.md{anchor}" in _text(REPO_ROOT / "README.md")
    for netuid_setting in (
        "CATHEDRAL_VALIDATOR_ACCESS_NETUID=94",
        "CATHEDRAL_VALIDATOR_ACCESS_NETWORK=finney",
        "--network finney --netuid 94 --minimum-stake-rao 0",
        "subnet register --netuid 94",
        "axon set --netuid 94",
    ):
        assert netuid_setting in quickstart, netuid_setting
    assert "<NETUID>" not in quickstart
    assert "REVIEWED_REVISION" not in quickstart


def _commands(text: str) -> list[str]:
    """Shell commands with backslash continuations joined."""

    return [" ".join(command.split()) for command in text.replace("\\\n", " ").splitlines()]


def test_quickstart_never_runs_user_writable_code_as_root() -> None:
    commands = _commands(_text(QUICKSTART))
    for command in commands:
        if "sudo" in command and ".venv/bin/" in command:
            assert "/opt/cathedral-validator-access/.venv/bin/" in command, command
        if "sudo git" in command:
            assert "/opt/cathedral-validator-access" in command, command
    assert not any("sudo .venv" in command for command in commands)


def test_quickstart_units_start_the_installed_launchers() -> None:
    quickstart = _text(QUICKSTART)
    units = dict(UNIT_RE.findall(quickstart))

    assert set(units) == {"cathedral-sn94-tdx-miner.service", "cathedral-sn94-snp-miner.service"}
    expected = {
        "cathedral-sn94-tdx-miner.service": (
            "/usr/local/libexec/cathedral/run-sn94-miner",
            "/etc/cathedral/sn94-tdx-miner.env",
        ),
        "cathedral-sn94-snp-miner.service": (
            "/usr/local/sbin/cathedral-run-sn94-snp-miner",
            "/etc/cathedral/sn94-snp-miner.env",
        ),
    }
    for name, (launcher, environment) in expected.items():
        body = units[name]
        assert f"ExecStart={launcher}\n" in body, name
        assert f"EnvironmentFile={environment}\n" in body, name
        assert "Restart=always\n" in body, name
        assert "cathedral-validator-access-fetch.service" in body, name
        assert f"{launcher}\n" in quickstart.split(f"/etc/systemd/system/{name}")[0], name
        assert f"install -o root -g root -m 0600 /dev/stdin \\\n  {environment} <<EOF" in quickstart


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
def test_systemd_analyze_accepts_the_quickstart_units(tmp_path: Path) -> None:
    units = tmp_path / "units"
    units.mkdir()
    shutil.copy(
        REPO_ROOT / "examples" / "systemd" / "cathedral-validator-access-fetch.service",
        units / "cathedral-validator-access-fetch.service",
    )
    names = []
    for name, body in UNIT_RE.findall(_text(QUICKSTART)):
        (units / name).write_text(body + "\n", encoding="utf-8")
        names.append(name)
    result = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", *(str(units / name) for name in names)],
        capture_output=True,
        text=True,
        env={**os.environ, "SYSTEMD_UNIT_PATH": f"{units}:"},
        timeout=60,
    )
    complaints = [line for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    # The launchers are installed on the miner, not on a build machine, and the
    # fetch unit's own helpers live under /opt and /usr/local on the miner.
    absent = (
        "/usr/local/libexec/cathedral/run-sn94-miner",
        "/usr/local/sbin/cathedral-run-sn94-snp-miner",
        "cathedral-validator-access-fetch.service",
        "docker.service",
    )
    unexpected = [line for line in complaints if not any(path in line for path in absent)]
    assert unexpected == [], complaints
