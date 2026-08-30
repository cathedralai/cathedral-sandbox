"""Packaging contracts for clean enrollment role installs."""

from __future__ import annotations

import tomllib
from pathlib import Path

from cathedral.enroll import SIGNATURE_VERIFIER_MODULES


ROOT = Path(__file__).resolve().parent.parent


def _project() -> dict[str, object]:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def _names(requirements: list[str]) -> set[str]:
    return {
        requirement.split("<", 1)[0].split(">", 1)[0].split("=", 1)[0].lower()
        for requirement in requirements
    }


def test_clean_install_extras_supply_each_enrollment_role() -> None:
    project = _project()
    base = _names(project["dependencies"])
    extras = project["optional-dependencies"]
    service = _names(extras["enrollment-service"])
    miner = _names(extras["enrollment-miner"])
    operator = _names(extras["enrollment-operator"])
    development = _names(extras["dev"])

    assert "substrate-interface" not in base
    assert "bittensor-wallet" not in base
    assert "bittensor" not in base
    assert service == {"substrate-interface"}
    assert miner == {"bittensor-wallet"}
    assert operator == {"bittensor"}
    assert "bittensor" not in service
    assert service | miner <= development
    assert "bittensor" not in development
    assert SIGNATURE_VERIFIER_MODULES == ("substrateinterface", "bittensor_wallet")


def test_current_guide_selects_validator_access_roles_not_legacy_enrollment() -> None:
    mining = (ROOT / "README.md").read_text()
    legacy_note = (ROOT / "docs" / "ENROLLMENT_ALLOWLIST.md").read_text()
    producer = (ROOT / "scripts" / "cathedral_enroll_allowlist.py").read_text()

    assert "validator-access-worker" in mining
    assert "enrollment-operator" in mining
    assert "enrollment-miner" not in mining
    assert "/v1/enroll" not in mining
    assert "pip install -e '.[enrollment-service]'" in legacy_note
    assert "pip install -e '.[enrollment-operator]'" in legacy_note
    assert "import bittensor" in producer
    assert "preflight_signature_verifier" in legacy_note
