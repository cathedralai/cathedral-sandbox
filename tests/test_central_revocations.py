"""Central revocations persist in the worker's state and follow a local file.

A restart must never drop the revocation list in force, and an older list, or
a different list under the same sequence, must never replace it. The worker
re-reads the operator's list file when it changes and refuses every central
request while that file is missing or unusable.
"""

from __future__ import annotations

import io
import os
import threading
from pathlib import Path

import pytest
from test_central_access import (
    BINDING,
    NETUID,
    NETWORK,
    NOW,
    OTHER_ROOT_SEED,
    ROOT_KEYS,
    ROOT_SEED,
    WORKER,
    _accept,
    _delegation,
    _header,
    _public,
)

from cathedral import central_access as ca
from cathedral.policy_registry import canonical_json


def _revocations(sequence: int, revoked: list[str], *, seed: bytes = ROOT_SEED) -> dict:
    return ca.sign_revocations(
        root_key_id="cathedral-root-1",
        root_seed=seed,
        sequence=sequence,
        issued_at=NOW,
        revoked=revoked,
    )


def _digest(delegation: dict) -> str:
    return ca.verify_delegation(
        delegation, ROOT_KEYS, network=NETWORK, netuid=NETUID, now=NOW
    ).digest


def _authorizer(tmp_path: Path, revocations_path: Path | None = None, keys=ROOT_KEYS):
    return ca.CentralAccessAuthorizer(
        keys,
        worker_hotkey=WORKER,
        network=NETWORK,
        netuid=NETUID,
        channel_binding=BINDING,
        state=ca.open_central_access_state(str(tmp_path / "central-access.sqlite")),
        revocations_path=None if revocations_path is None else str(revocations_path),
    )


def _write(path: Path, document: dict, mode: int = 0o644) -> Path:
    # Replace, never rewrite in place, as an operator's install would.
    staged = path.with_name(path.name + ".new")
    staged.write_bytes(canonical_json(document))
    staged.chmod(mode)
    os.replace(staged, path)
    return path


# State ----------------------------------------------------------------------


def test_state_keeps_only_a_higher_revocation_list(tmp_path):
    state = ca.open_central_access_state(str(tmp_path / "central-access.sqlite"))
    assert state.stored_revocations() == (0, b"")

    assert state.store_revocations(3, b"three") == (3, b"three")
    assert state.store_revocations(2, b"two") == (3, b"three")
    assert state.store_revocations(3, b"other three") == (3, b"three")
    assert state.store_revocations(4, b"four") == (4, b"four")
    assert state.stored_revocations() == (4, b"four")


# Persistence ----------------------------------------------------------------


def test_a_restart_keeps_the_revocation_list_in_force(tmp_path):
    delegation = _delegation()
    _authorizer(tmp_path).install_revocations(_revocations(2, [_digest(delegation)]))

    restarted = _authorizer(tmp_path)

    with pytest.raises(ca.CentralAccessError, match="revoked"):
        _accept(restarted, _header(delegation))


def test_a_restart_refuses_an_older_or_conflicting_list(tmp_path):
    _authorizer(tmp_path).install_revocations(_revocations(5, ["sha256:" + "a" * 64]))
    restarted = _authorizer(tmp_path)

    with pytest.raises(ca.CentralAccessError, match="older"):
        restarted.install_revocations(_revocations(4, []))
    with pytest.raises(ca.CentralAccessError, match="without a new sequence"):
        restarted.install_revocations(_revocations(5, ["sha256:" + "b" * 64]))
    restarted.install_revocations(_revocations(6, []))
    _accept(restarted, _header())


def test_two_workers_on_one_state_file_cannot_roll_the_list_back(tmp_path):
    first = _authorizer(tmp_path)
    second = _authorizer(tmp_path)
    first.install_revocations(_revocations(7, []))

    with pytest.raises(ca.CentralAccessError, match="older than the one in force"):
        second.install_revocations(_revocations(6, []))


def test_two_workers_on_one_state_file_cannot_swap_the_list_under_one_sequence(
    tmp_path,
):
    first = _authorizer(tmp_path)
    second = _authorizer(tmp_path)
    delegation = _delegation()
    first.install_revocations(_revocations(5, [_digest(delegation)]))

    with pytest.raises(ca.CentralAccessError, match="without a new sequence"):
        second.install_revocations(_revocations(5, []))
    with pytest.raises(ca.CentralAccessError, match="revoked"):
        _accept(_authorizer(tmp_path), _header(delegation))


def test_a_stored_list_the_pinned_root_no_longer_signs_stops_the_worker(tmp_path):
    _authorizer(tmp_path).install_revocations(_revocations(1, []))
    other_root = {"cathedral-root-1": _public(OTHER_ROOT_SEED)}

    with pytest.raises(ca.CentralAccessError, match="signature verification failed"):
        _authorizer(tmp_path, keys=other_root)


# The operator's file ---------------------------------------------------------


def test_the_revocation_file_is_installed_at_start_and_followed(tmp_path):
    delegation = _delegation()
    digest = _digest(delegation)
    path = _write(tmp_path / "revocations.json", _revocations(1, [digest]))
    authorizer = _authorizer(tmp_path, path)

    with pytest.raises(ca.CentralAccessError, match="revoked"):
        _accept(authorizer, _header(delegation))

    _write(path, _revocations(2, []))
    _accept(authorizer, _header(delegation, nonce=b"b" * 32))

    _write(path, _revocations(3, [digest]))
    with pytest.raises(ca.CentralAccessError, match="revoked"):
        _accept(authorizer, _header(delegation, nonce=b"c" * 32))
    assert authorizer.state.stored_revocations()[0] == 3


@pytest.mark.parametrize(
    ("replace", "match"),
    [
        (lambda path: _write(path, _revocations(1, [])), "older than the one in force"),
        (
            lambda path: _write(path, _revocations(2, ["sha256:" + "a" * 64])),
            "without a new sequence",
        ),
        (
            lambda path: _write(path, _revocations(3, [], seed=OTHER_ROOT_SEED)),
            "signature verification failed",
        ),
        (lambda path: _write(path, _revocations(3, []), mode=0o664), "only its owner"),
        (lambda path: path.write_bytes(b'{"schema": 1}\n'), "unusable"),
        (lambda path: path.write_bytes(b"x" * (ca.MAX_REVOCATIONS_FILE_BYTES + 1)), "bounded"),
        (lambda path: path.unlink(), "unavailable"),
    ],
    ids=[
        "older",
        "same-sequence",
        "foreign-root",
        "group-writable",
        "malformed",
        "oversize",
        "removed",
    ],
)
def test_an_unusable_revocation_file_refuses_every_central_request(tmp_path, replace, match):
    path = _write(tmp_path / "revocations.json", _revocations(2, []))
    authorizer = _authorizer(tmp_path, path)
    _accept(authorizer, _header())

    replace(path)

    with pytest.raises(ca.CentralAccessError, match=match):
        _accept(authorizer, _header(nonce=b"b" * 32))
    with pytest.raises(ca.CentralAccessError, match=match):
        _accept(authorizer, _header(nonce=b"c" * 32))
    assert authorizer.state.stored_revocations()[0] == 2

    _write(path, _revocations(4, []))
    _accept(authorizer, _header(nonce=b"d" * 32))


def test_a_non_canonical_revocation_file_is_refused(tmp_path):
    path = tmp_path / "revocations.json"
    path.write_bytes(canonical_json(_revocations(1, [])).replace(b",", b", "))
    path.chmod(0o644)

    with pytest.raises(ca.CentralAccessError, match="unusable"):
        _authorizer(tmp_path, path)


def test_a_missing_revocation_file_stops_the_worker_at_start(tmp_path):
    with pytest.raises(ca.CentralAccessError, match="unavailable"):
        _authorizer(tmp_path, tmp_path / "absent.json")


def test_a_symlinked_revocation_file_is_refused(tmp_path):
    target = _write(tmp_path / "real.json", _revocations(1, []))
    link = tmp_path / "revocations.json"
    link.symlink_to(target)

    with pytest.raises(ca.CentralAccessError, match="unavailable"):
        _authorizer(tmp_path, link)


def _without_blocking(action) -> BaseException | None:
    """Run ``action`` in a thread and return what it raised; fail if it blocks."""

    raised: list[BaseException | None] = []

    def run() -> None:
        try:
            action()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test
            raised.append(exc)
        else:
            raised.append(None)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive(), "opening the revocation path blocked on a FIFO"
    return raised[0]


def test_a_fifo_at_the_revocation_path_refuses_to_start_without_blocking(tmp_path):
    # Opened without O_NONBLOCK, a FIFO waits for a writer and hangs startup.
    path = tmp_path / "revocations.json"
    os.mkfifo(path, 0o644)

    raised = _without_blocking(lambda: _authorizer(tmp_path, path))

    assert isinstance(raised, ca.CentralAccessError)
    assert "bounded regular file" in str(raised)


def test_a_fifo_swapped_in_later_refuses_requests_without_blocking(tmp_path):
    path = _write(tmp_path / "revocations.json", _revocations(2, []))
    authorizer = _authorizer(tmp_path, path)
    _accept(authorizer, _header())
    path.unlink()
    os.mkfifo(path, 0o644)

    for nonce in (b"b" * 32, b"c" * 32):
        raised = _without_blocking(lambda nonce=nonce: _accept(authorizer, _header(nonce=nonce)))
        assert isinstance(raised, ca.CentralAccessError)
        assert "bounded regular file" in str(raised)

    _write(path, _revocations(3, []))
    _accept(authorizer, _header(nonce=b"d" * 32))


def test_a_directory_at_the_revocation_path_refuses_to_start(tmp_path):
    # A directory passes the size bound (its st_size is a block), so only the
    # regular-file check keeps the read from raising IsADirectoryError.
    path = tmp_path / "revocations.json"
    path.mkdir(mode=0o755)

    with pytest.raises(ca.CentralAccessError, match="bounded regular file"):
        _authorizer(tmp_path, path)


def test_a_file_that_grows_past_the_cap_while_read_is_refused(tmp_path, monkeypatch):
    path = _write(tmp_path / "revocations.json", _revocations(2, []))
    real_fdopen = os.fdopen

    def grown(descriptor, mode="r", *args, **kwargs):
        if mode == "rb":
            os.close(descriptor)
            return io.BytesIO(b"x" * (ca.MAX_REVOCATIONS_FILE_BYTES + 1))
        return real_fdopen(descriptor, mode, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", grown)
    with pytest.raises(ca.CentralAccessError, match="grew past its size limit"):
        _authorizer(tmp_path, path)


# CLI ------------------------------------------------------------------------


def test_the_worker_cli_refuses_revocations_without_central_access(monkeypatch):
    from cathedral.cli import build_parser, cmd_worker_serve

    monkeypatch.setenv("CATHEDRAL_WORKER_BEARER_TOKEN", "t" * 32)
    args = build_parser().parse_args(
        ["worker", "serve", "--hotkey", "miner", "--central-revocations", "/etc/x.json"]
    )
    with pytest.raises(ValueError, match="--central-revocations requires central access"):
        cmd_worker_serve(args)


@pytest.mark.parametrize(
    "command", ["serve", "serve-snp", "serve-gpu", "serve-g4", "develop", "migrate"]
)
def test_every_signed_access_worker_command_takes_the_revocations_flag(command, capsys):
    from cathedral.cli import build_parser

    with pytest.raises(SystemExit):
        build_parser().parse_args(["worker", command, "--help"])
    assert "--central-revocations" in capsys.readouterr().out
