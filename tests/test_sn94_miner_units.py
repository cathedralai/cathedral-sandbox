"""The example SN94 miner units, read as systemd reads them (review round 6).

These probes assert the behaviour an operator would expect from the docs. A
failing probe is the finding; see the review notes for the consequence.

The SNP example unit is the one docs/AMD_SEV_SNP_FRIEND_TEST.md installs on the
live SNP host, which the docs say is not enrolled in signed updates, so the
drop-in in deploy/miner-update/miner-unit.conf does not apply to it.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SNP_UNIT = REPO_ROOT / "examples/systemd/cathedral-sn94-snp-miner.service"
AUDIT_UNIT = REPO_ROOT / "examples/systemd/cathedral-audit-miner.service"
DROPIN = REPO_ROOT / "deploy/miner-update/miner-unit.conf"


def directives(text: str) -> dict[str, list[str]]:
    """systemd-style: repeated keys accumulate, continuation lines join."""

    result: dict[str, list[str]] = {}
    for line in text.replace("\\\n", " ").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result.setdefault(key.strip(), []).append(value.strip())
    return result


def _success_statuses(unit: dict[str, list[str]]) -> set[str]:
    return {item for value in unit.get("SuccessExitStatus", []) for item in value.split()}


def test_the_audit_unit_restarts_after_a_clean_signal_exit():
    """Control: the TDX example unit was fixed (23ff0d9) to restart after exit 143."""

    unit = directives(AUDIT_UNIT.read_text())
    assert "143" in _success_statuses(unit)
    assert unit["Restart"] == ["always"]


def test_the_release_dropin_restarts_after_a_clean_signal_exit():
    """Control: enrolled hosts get Restart=always from the signed drop-in."""

    dropin = directives(DROPIN.read_text())
    assert dropin["Restart"] == ["always"]


def test_the_snp_unit_restarts_after_a_clean_signal_exit():
    """The SNP example unit counts 143 as success but restarts only on failure.

    A docker daemon restart (an apt upgrade of docker or containerd restarts
    it) stops the container with SIGTERM; tini and python exit 143, the
    launcher's `wait` returns 143, and the unit treats that as a clean exit.
    With Restart=on-failure systemd then leaves the unit inactive. Nothing
    pages: the unit has no OnFailure=, and the fetch alarm watches only the
    snapshot. The audit example unit and the release drop-in were changed to
    Restart=always for exactly this case; the SNP example unit was not.
    """

    unit = directives(SNP_UNIT.read_text())
    assert "143" in _success_statuses(unit), "the premise: 143 is a clean exit for this unit"
    assert unit["Restart"] == ["always"], (
        f"Restart={unit['Restart']}: a 143 exit after a docker daemon restart leaves the "
        "SNP miner inactive with no restart"
    )


def test_the_snp_unit_pages_when_it_stops_restarting():
    """A unit that hits StartLimitBurst stays failed. Only OnFailure= can page.

    The live TDX run in 4f0c702 saw exactly this: the worker refuses to start
    on a stale validator-access snapshot (cli.py raises "validator access
    snapshot is absent, stale, or invalid"), five starts in 300 s hit the
    limit, and the unit stayed failed. On an enrolled host the hourly updater
    pages. On a host that is not enrolled, nothing does.
    """

    unit = directives(SNP_UNIT.read_text())
    assert unit.get("StartLimitBurst") == ["5"] and unit.get("StartLimitIntervalSec") == ["300"]
    assert "OnFailure" in unit, (
        "the SNP miner unit has no OnFailure=: a start-limit failure, or any other failed "
        "state, pages nobody on a host that is not enrolled in signed updates"
    )


def test_the_audit_unit_pages_when_it_stops_restarting():
    """Same gap on the TDX example unit, for completeness."""

    unit = directives(AUDIT_UNIT.read_text())
    assert "OnFailure" in unit, "the TDX miner unit has no OnFailure= either"
