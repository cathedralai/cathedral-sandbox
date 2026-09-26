"""File-level checks on the miner's multi-machine fleet manifest.

``validate_fleet_document`` owns the manifest schema and is tested in
``test_validator_access.py``. These tests cover what ``load_fleet_manifest``
adds in front of it, and which the worker relies on at every production start:

  1. An owner-controlled regular file loads, with the chain axon first.
  2. A symlink, even one pointing at a good manifest, is refused, and so is a
     directory or FIFO.
  3. A group- or world-writable file is refused at any owner.
  4. A file owned by another uid is refused, both through ``expected_uid`` and
     through the default of the worker's effective uid.
  5. The read is bounded at ``MAX_FLEET_FILE_BYTES``, inclusive.
  6. Bytes that are not UTF-8 JSON are refused, and a well-formed but wrong
     document still reaches the schema check.
  7. A file swapped between the metadata check and the open is refused, and a
     swap to a symlink is not followed.
"""

from __future__ import annotations

import errno
import json
import os
import stat
from pathlib import Path

import pytest

from cathedral.validator_access import (
    MAX_FLEET_FILE_BYTES,
    WORKER_FLEET_SCHEMA,
    ValidatorAccessError,
    load_fleet_manifest,
)
from tests.test_validator_access import OTHER_VALIDATOR_HOTKEY, WORKER_HOTKEY

PRIMARY = "https://8.8.8.8:8081"
SECONDARY = "https://1.1.1.1:8081"


def _manifest_bytes(
    *,
    worker_hotkey: str = WORKER_HOTKEY,
    endpoints: tuple[str, ...] = (SECONDARY, PRIMARY),
) -> bytes:
    return json.dumps(
        {
            "schema": WORKER_FLEET_SCHEMA,
            "worker_hotkey": worker_hotkey,
            "endpoints": list(endpoints),
        }
    ).encode("utf-8")


def _write(path: Path, encoded: bytes, *, mode: int = 0o600) -> Path:
    path.write_bytes(encoded)
    path.chmod(mode)
    return path


def _load(path: Path, **kwargs: object) -> tuple[str, ...]:
    return load_fleet_manifest(
        str(path),
        worker_hotkey=WORKER_HOTKEY,
        public_endpoint=PRIMARY,
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("mode", [0o600, 0o644, 0o400, 0o444, 0o640, 0o604], ids=oct)
def test_owner_controlled_manifest_loads_with_the_axon_first(tmp_path: Path, mode: int):
    path = _write(tmp_path / "fleet.json", _manifest_bytes(), mode=mode)

    assert _load(path) == (PRIMARY, SECONDARY)
    assert _load(path, expected_uid=path.stat().st_uid) == (PRIMARY, SECONDARY)


def test_symlink_to_a_good_manifest_is_refused(tmp_path: Path):
    target = _write(tmp_path / "real-fleet.json", _manifest_bytes())
    link = tmp_path / "fleet.json"
    link.symlink_to(target)
    assert _load(target) == (PRIMARY, SECONDARY)

    with pytest.raises(ValidatorAccessError, match="regular non-symlink"):
        _load(link)


def test_dangling_symlink_is_refused_without_being_followed(tmp_path: Path):
    link = tmp_path / "fleet.json"
    link.symlink_to(tmp_path / "does-not-exist.json")

    with pytest.raises(ValidatorAccessError, match="regular non-symlink"):
        _load(link)


def test_directory_is_refused(tmp_path: Path):
    directory = tmp_path / "fleet.json"
    directory.mkdir(mode=0o700)

    with pytest.raises(ValidatorAccessError, match="regular non-symlink"):
        _load(directory)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs need os.mkfifo")
def test_fifo_is_refused_before_it_is_opened(tmp_path: Path):
    # Opening a FIFO with no writer would block the worker's startup. The
    # metadata check must refuse it before any open.
    fifo = tmp_path / "fleet.json"
    os.mkfifo(fifo, 0o600)

    with pytest.raises(ValidatorAccessError, match="regular non-symlink"):
        _load(fifo)


def test_missing_manifest_fails_closed(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        _load(tmp_path / "fleet.json")


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o660, 0o606, 0o622, 0o664, 0o666, 0o777], ids=oct)
def test_group_or_world_writable_manifest_is_refused(tmp_path: Path, mode: int):
    path = _write(tmp_path / "fleet.json", _manifest_bytes(), mode=mode)
    assert stat.S_IMODE(path.stat().st_mode) == mode

    with pytest.raises(ValidatorAccessError, match="group or world writable"):
        _load(path)


def test_manifest_owned_by_another_uid_is_refused(tmp_path: Path):
    path = _write(tmp_path / "fleet.json", _manifest_bytes())

    with pytest.raises(ValidatorAccessError, match="owned by the worker user"):
        _load(path, expected_uid=path.stat().st_uid + 1)


def _foreign_owned_regular_file() -> Path | None:
    for candidate in (Path("/etc/passwd"), Path("/etc/group"), Path("/etc/hosts")):
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and not metadata.st_mode & 0o022
            and metadata.st_uid != os.geteuid()
        ):
            return candidate
    return None


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root owns the system files, so none of them is foreign to this process",
)
def test_default_owner_is_the_worker_euid_for_a_real_foreign_file():
    foreign = _foreign_owned_regular_file()
    if foreign is None:
        pytest.skip("no regular, non-writable file owned by another uid was found")

    with pytest.raises(ValidatorAccessError, match="owned by the worker user"):
        _load(foreign)


@pytest.mark.skipif(os.geteuid() != 0, reason="only root can give a file to another uid")
def test_root_worker_refuses_a_manifest_it_does_not_own(tmp_path: Path):
    path = _write(tmp_path / "fleet.json", _manifest_bytes())
    os.chown(path, os.geteuid() + 1, -1)

    with pytest.raises(ValidatorAccessError, match="owned by the worker user"):
        _load(path)


def test_manifest_exactly_at_the_size_cap_is_read(tmp_path: Path):
    encoded = _manifest_bytes()
    padded = encoded + b" " * (MAX_FLEET_FILE_BYTES - len(encoded))
    assert len(padded) == MAX_FLEET_FILE_BYTES
    path = _write(tmp_path / "fleet.json", padded)

    assert _load(path) == (PRIMARY, SECONDARY)


def test_manifest_one_byte_over_the_size_cap_is_refused(tmp_path: Path):
    encoded = _manifest_bytes()
    padded = encoded + b" " * (MAX_FLEET_FILE_BYTES + 1 - len(encoded))
    path = _write(tmp_path / "fleet.json", padded)

    with pytest.raises(ValidatorAccessError, match="size limit"):
        _load(path)


@pytest.mark.parametrize(
    "encoded",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"not json", id="text"),
        pytest.param(b'{"schema": ', id="truncated"),
        pytest.param(b"\x80\x81\x82", id="invalid-utf8"),
        pytest.param(b"\xff\xfe\x00", id="odd-length-utf16"),
    ],
)
def test_manifest_that_is_not_json_is_refused(tmp_path: Path, encoded: bytes):
    path = _write(tmp_path / "fleet.json", encoded)

    with pytest.raises(ValidatorAccessError, match="not valid JSON"):
        _load(path)


@pytest.mark.parametrize(
    ("encoded", "match"),
    [
        pytest.param(b"[]", "fields are invalid", id="array"),
        pytest.param(
            _manifest_bytes(worker_hotkey=OTHER_VALIDATOR_HOTKEY),
            "identity is invalid",
            id="another-worker",
        ),
        pytest.param(
            _manifest_bytes(endpoints=("https://10.0.0.1:8081",)),
            "globally routable",
            id="private-endpoint",
        ),
    ],
)
def test_well_formed_json_still_reaches_the_schema_check(
    tmp_path: Path, encoded: bytes, match: str
):
    path = _write(tmp_path / "fleet.json", encoded)

    with pytest.raises(ValidatorAccessError, match=match):
        _load(path)


def _swap_on_open(monkeypatch, path: Path, replace_with: Path) -> list[bool]:
    """Replace ``path`` after the metadata check, just before the loader opens it."""

    real_open = os.open
    swapped: list[bool] = []

    def swapping_open(file, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not swapped and os.fspath(file) == str(path):
            os.replace(replace_with, path)
            swapped.append(True)
        return real_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swapping_open)
    return swapped


def test_manifest_replaced_between_check_and_open_is_refused(tmp_path: Path, monkeypatch):
    path = _write(tmp_path / "fleet.json", _manifest_bytes())
    replacement = _write(tmp_path / "replacement.json", _manifest_bytes(endpoints=(SECONDARY,)))
    swapped = _swap_on_open(monkeypatch, path, replacement)

    with pytest.raises(ValidatorAccessError, match="changed during read"):
        _load(path)
    assert swapped == [True]

    # The replacement is itself a good manifest: only the swap was refused.
    monkeypatch.undo()
    assert _load(path) == (PRIMARY, SECONDARY)


def test_manifest_swapped_for_a_symlink_after_the_check_is_not_followed(
    tmp_path: Path, monkeypatch
):
    path = _write(tmp_path / "fleet.json", _manifest_bytes())
    target = _write(tmp_path / "elsewhere.json", _manifest_bytes())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    swapped = _swap_on_open(monkeypatch, path, link)

    with pytest.raises(OSError) as raised:
        _load(path)
    assert swapped == [True]
    assert raised.value.errno == errno.ELOOP
    assert path.is_symlink()
