"""The host-side snapshot producer emits the exact worker artifact."""

from __future__ import annotations

import base64
import importlib.util
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral.admission_policy import load_policy_keys
from cathedral.validator_access import verify_validator_access_snapshot

_SPEC = importlib.util.spec_from_file_location(
    "cathedral_validator_access_tool",
    Path(__file__).resolve().parents[1] / "scripts" / "cathedral_validator_access.py",
)
access_tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(access_tool)

NOW = datetime(2026, 8, 29, 7, 0, 0, tzinfo=UTC)
VALIDATOR_HOTKEY = "5Et6X7z87xENCREUnrQXfGahRraA3eo4KkAZEZP9KagmnTjD"
OTHER_HOTKEY = "5G4hdCSm7mQvP9z19pK3Bwzzvpf1NBBx3jioJBdJgEj4r8Pe"
KEY_ID = "cathedral-validator-access-1"


def _fields(capsys) -> dict[str, str]:
    return dict(line.split(" ", 1) for line in capsys.readouterr().out.splitlines() if " " in line)


def _init_key(tmp_path: Path, capsys) -> tuple[Path, Path, str]:
    seed = tmp_path / "validator-access.seed"
    keys = tmp_path / "validator-access-keys.json"
    assert (
        access_tool.main(
            [
                "init-key",
                "--signing-key-id",
                KEY_ID,
                "--signing-key-out",
                str(seed),
                "--keys-out",
                str(keys),
            ]
        )
        == 0
    )
    fields = _fields(capsys)
    return seed, keys, fields["keys_digest"]


def _neuron(hotkey: str, uid: int, stake_rao: int, *, permit: bool = True):
    return SimpleNamespace(
        hotkey=hotkey,
        uid=uid,
        validator_permit=permit,
        total_stake=SimpleNamespace(rao=stake_rao),
    )


def test_init_key_is_create_only_and_emits_a_loadable_digest_pin(tmp_path, capsys):
    seed, keys, digest = _init_key(tmp_path, capsys)

    assert stat.S_IMODE(seed.stat().st_mode) == 0o600
    assert stat.S_IMODE(keys.stat().st_mode) == 0o644
    assert len(base64.b64decode(seed.read_text().strip(), validate=True)) == 32
    trusted = load_policy_keys(str(keys), production_mode=True, pinned_digest=digest)
    assert set(trusted) == {KEY_ID}

    with pytest.raises(SystemExit, match="refusing to overwrite"):
        access_tool.main(
            [
                "init-key",
                "--signing-key-id",
                KEY_ID,
                "--signing-key-out",
                str(seed),
                "--keys-out",
                str(tmp_path / "other-keys.json"),
            ]
        )


def test_capture_filters_finalized_rows_signs_and_atomically_refreshes(
    tmp_path, capsys, monkeypatch
):
    seed, keys, keys_digest = _init_key(tmp_path, capsys)
    output = tmp_path / "validator-access.json"
    neurons = [
        _neuron(OTHER_HOTKEY, 31, 999),
        _neuron(VALIDATOR_HOTKEY, 30, 2_000),
        _neuron(OTHER_HOTKEY, 32, 3_000, permit=False),
    ]
    monkeypatch.setattr(
        access_tool,
        "_finalized_neurons",
        lambda network, netuid: (8_948_557, "0x" + "a" * 64, neurons),
    )
    monkeypatch.setattr(access_tool, "_now", lambda: NOW)
    command = [
        "capture",
        "--network",
        "finney",
        "--netuid",
        "39",
        "--minimum-stake-rao",
        "1000",
        "--signing-key-id",
        KEY_ID,
        "--signing-key-file",
        str(seed),
        "--out",
        str(output),
        "--require-hotkey",
        VALIDATOR_HOTKEY,
    ]

    assert access_tool.main(command) == 0
    first_inode = output.stat().st_ino
    trusted = load_policy_keys(str(keys), production_mode=True, pinned_digest=keys_digest)
    snapshot = verify_validator_access_snapshot(
        output.read_bytes(),
        trusted,
        network="finney",
        netuid=39,
        required_minimum_stake_rao=1_000,
        now=NOW,
    )
    assert list(snapshot.validators) == [VALIDATOR_HOTKEY]
    assert snapshot.validators[VALIDATOR_HOTKEY].uid == 30

    assert access_tool.main(command) == 0
    assert output.stat().st_ino != first_inode


def test_capture_refuses_duplicate_finalized_uid(tmp_path, capsys, monkeypatch):
    seed, _keys, _digest = _init_key(tmp_path, capsys)
    monkeypatch.setattr(
        access_tool,
        "_finalized_neurons",
        lambda network, netuid: (
            8_948_557,
            "0x" + "a" * 64,
            [
                _neuron(VALIDATOR_HOTKEY, 30, 2_000),
                _neuron(OTHER_HOTKEY, 30, 2_000),
            ],
        ),
    )
    monkeypatch.setattr(access_tool, "_now", lambda: NOW)

    with pytest.raises(SystemExit, match="duplicate validator uids"):
        access_tool.main(
            [
                "capture",
                "--network",
                "finney",
                "--netuid",
                "39",
                "--minimum-stake-rao",
                "1000",
                "--signing-key-id",
                KEY_ID,
                "--signing-key-file",
                str(seed),
                "--out",
                str(tmp_path / "snapshot.json"),
            ]
        )
