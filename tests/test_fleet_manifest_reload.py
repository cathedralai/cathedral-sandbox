"""The worker serves a changed fleet manifest without a restart.

``load_fleet_manifest`` and its file refusals are tested on their own. These
tests cover what ``FleetManifest`` adds on top of the loader:

  1. A changed valid file is served on the next read, including through the
     worker's ``/v1/fleet`` route and the ``worker`` CLI wiring.
  2. A replacement the loader refuses keeps the last good manifest, logs one
     warning for that change, and does not stop a later good file loading.
  3. A missing file keeps the last good manifest and warns once.
  4. An unchanged file is not read again, and a rewrite with identical
     content does not swap or log.
  5. Concurrent readers only ever see a complete manifest.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sr25519

import cathedral.validator_access as access_module
from cathedral.cli import build_parser, cmd_worker_serve
from cathedral.common import Evidence, EvidenceKind
from cathedral.remote import RemoteMiner
from cathedral.validator_access import (
    MAX_FLEET_FILE_BYTES,
    WORKER_FLEET_SCHEMA,
    FleetManifest,
    ValidatorAccessState,
    ValidatorRequestAuthorizer,
    fleet_response,
    load_sr25519_verifier,
)
from cathedral.worker import WorkerServer
from tests.test_cli import _tls_material
from tests.test_validator_access import (
    OTHER_VALIDATOR_HOTKEY,
    VALIDATOR_HOTKEY,
    VALIDATOR_PAIR,
    WORKER_HOTKEY,
    _snapshot,
    _tls_contexts,
)

PRIMARY = "https://8.8.8.8:8081"
FIRST = ("https://1.1.1.1:8081",)
SECOND = ("https://1.1.1.1:8081", "https://9.9.9.9:8081", "https://8.8.4.4:8081")


def _manifest_bytes(
    endpoints: tuple[str, ...], *, worker_hotkey: str = WORKER_HOTKEY
) -> bytes:
    return json.dumps(
        {
            "schema": WORKER_FLEET_SCHEMA,
            "worker_hotkey": worker_hotkey,
            "endpoints": list(endpoints),
        }
    ).encode("utf-8")


def _replace(path: Path, encoded: bytes, *, mode: int = 0o600) -> None:
    """Install new bytes the way the README does: write aside, then rename."""

    temporary = path.with_name(f".{path.name}.new")
    temporary.write_bytes(encoded)
    temporary.chmod(mode)
    os.replace(temporary, path)


def _manifest(path: Path, log: list[str]) -> FleetManifest:
    return FleetManifest(
        str(path),
        worker_hotkey=WORKER_HOTKEY,
        public_endpoint=PRIMARY,
        log=log.append,
    )


def _warnings(log: list[str]) -> list[str]:
    return [line for line in log if line.startswith("WARNING:")]


def test_changed_valid_file_is_served_without_restart(tmp_path: Path):
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(FIRST))
    log: list[str] = []
    manifest = _manifest(path, log)
    assert manifest.endpoints() == (PRIMARY, *FIRST)
    assert log == []

    _replace(path, _manifest_bytes(SECOND))
    assert manifest.endpoints() == (PRIMARY, *SECOND)
    assert log == [f"fleet manifest {path} loaded (4 candidates)"]

    # An in-place rewrite keeps the inode; size and times still change.
    path.write_bytes(_manifest_bytes(FIRST))
    assert manifest.endpoints() == (PRIMARY, *FIRST)
    assert log[-1] == f"fleet manifest {path} loaded (2 candidates)"


def test_same_size_in_place_edit_with_restored_mtime_is_detected(tmp_path: Path):
    # `cp -p` or `touch -r` can leave inode, size and mtime unchanged. The
    # kernel always moves ctime, so the identity must include it.
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(("https://1.1.1.1:8081",)))
    log: list[str] = []
    manifest = _manifest(path, log)
    before = path.lstat()

    path.write_bytes(_manifest_bytes(("https://1.1.1.2:8081",)))
    for _ in range(200):
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        if path.lstat().st_ctime_ns != before.st_ctime_ns:
            break
        time.sleep(0.01)
    after = path.lstat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    assert after.st_ctime_ns != before.st_ctime_ns

    assert manifest.endpoints() == (PRIMARY, "https://1.1.1.2:8081")


def _install_symlink(path: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_bytes(_manifest_bytes(SECOND))
    target.chmod(0o600)
    link = tmp_path / ".fleet.json.link"
    link.symlink_to(target)
    os.replace(link, path)


def _install_foreign_owner(path: Path, _tmp_path: Path) -> None:
    _replace(path, _manifest_bytes(SECOND))
    os.chown(path, os.geteuid() + 1, -1)


@pytest.mark.parametrize(
    "install",
    [
        pytest.param(_install_symlink, id="symlink-to-a-good-manifest"),
        pytest.param(
            lambda path, _: _replace(path, _manifest_bytes(SECOND), mode=0o620),
            id="group-writable",
        ),
        pytest.param(
            lambda path, _: _replace(path, _manifest_bytes(SECOND), mode=0o606),
            id="world-writable",
        ),
        pytest.param(
            _install_foreign_owner,
            id="foreign-owner",
            marks=pytest.mark.skipif(
                os.geteuid() != 0, reason="only root can give a file to another uid"
            ),
        ),
        pytest.param(
            lambda path, _: _replace(
                path,
                _manifest_bytes(SECOND).ljust(MAX_FLEET_FILE_BYTES + 1, b" "),
            ),
            id="oversized",
        ),
        pytest.param(lambda path, _: _replace(path, b'{"schema": '), id="malformed-json"),
        pytest.param(
            # json raises RecursionError here, not a ValueError.
            lambda path, _: _replace(path, b"[" * MAX_FLEET_FILE_BYTES),
            id="deeply-nested-json",
        ),
        pytest.param(
            lambda path, _: _replace(
                path, _manifest_bytes(SECOND, worker_hotkey=OTHER_VALIDATOR_HOTKEY)
            ),
            id="another-worker-hotkey",
        ),
    ],
)
def test_refused_replacement_keeps_last_good_and_warns_once(tmp_path: Path, install):
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(FIRST))
    log: list[str] = []
    manifest = _manifest(path, log)
    good = manifest.endpoints()
    assert good == (PRIMARY, *FIRST)

    install(path, tmp_path)
    for _ in range(3):
        assert manifest.endpoints() is good
    warnings = _warnings(log)
    assert len(warnings) == 1
    assert "was refused" in warnings[0]
    assert "still serving the last good manifest (2 candidates)" in warnings[0]

    # The refusal is per change: a later good file is still picked up.
    _replace(path, _manifest_bytes(SECOND))
    assert manifest.endpoints() == (PRIMARY, *SECOND)
    assert log[-1] == f"fleet manifest {path} loaded (4 candidates)"
    assert len(_warnings(log)) == 1


def test_missing_file_keeps_last_good_and_warns_once(tmp_path: Path):
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(SECOND))
    log: list[str] = []
    manifest = _manifest(path, log)
    good = manifest.endpoints()

    path.unlink()
    for _ in range(3):
        assert manifest.endpoints() is good
    assert log == [
        f"WARNING: fleet manifest {path} is missing or unreadable "
        "(No such file or directory); still serving the last good manifest "
        "(4 candidates)"
    ]

    # Restoring the same content is logged, so the warning has an end.
    _replace(path, _manifest_bytes(SECOND))
    assert manifest.endpoints() == good
    assert log[-1] == (
        f"fleet manifest {path} is accepted again, content unchanged (4 candidates)"
    )

    path.unlink()
    assert manifest.endpoints() is good
    assert len(_warnings(log)) == 2


def test_missing_file_still_refuses_startup(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        _manifest(tmp_path / "fleet.json", [])


def test_unchanged_file_is_not_reloaded_and_identical_content_is_not_swapped(
    tmp_path: Path, monkeypatch
):
    real_loader = access_module.load_fleet_manifest
    loads: list[str] = []

    def counting_loader(path: str, **kwargs):  # type: ignore[no-untyped-def]
        loads.append(path)
        return real_loader(path, **kwargs)

    monkeypatch.setattr(access_module, "load_fleet_manifest", counting_loader)
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(SECOND))
    log: list[str] = []
    manifest = _manifest(path, log)
    good = manifest.endpoints()
    assert len(loads) == 1

    for _ in range(50):
        assert manifest.endpoints() is good
    assert len(loads) == 1

    # A new file with the same bytes is checked once, then left alone.
    _replace(path, _manifest_bytes(SECOND))
    assert manifest.endpoints() is good
    assert len(loads) == 2
    for _ in range(50):
        assert manifest.endpoints() is good
    assert len(loads) == 2
    assert log == []


def test_concurrent_readers_never_see_a_partial_manifest(tmp_path: Path):
    path = tmp_path / "fleet.json"
    first = _manifest_bytes(FIRST)
    second = _manifest_bytes(SECOND)
    _replace(path, first)
    manifest = _manifest(path, [])
    complete = {(PRIMARY, *FIRST), (PRIMARY, *SECOND)}
    observed: set[tuple[str, ...]] = set()
    failures: list[BaseException] = []
    stop = threading.Event()

    def reader() -> None:
        try:
            while not stop.is_set():
                # Go through the same path as the /v1/fleet handler.
                response = fleet_response(WORKER_HOTKEY, manifest.endpoints())
                seen = tuple(response["endpoints"])  # type: ignore[arg-type]
                observed.add(seen)
                if seen not in complete:
                    failures.append(AssertionError(f"partial manifest {seen!r}"))
                    return
        except BaseException as exc:  # noqa: BLE001 - surface in the main thread
            failures.append(exc)

    interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    try:
        for thread in threads:
            thread.start()
        for index in range(400):
            _replace(path, second if index % 2 == 0 else first)
        _replace(path, second)
        time.sleep(0.05)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=10)
        sys.setswitchinterval(interval)

    assert failures == []
    assert observed == complete
    assert manifest.endpoints() == (PRIMARY, *SECOND)


def test_one_thread_reloads_while_other_readers_get_the_current_manifest(
    tmp_path: Path, monkeypatch
):
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(FIRST))
    manifest = _manifest(path, [])
    good = manifest.endpoints()
    third = ("https://9.9.9.9:8081",)
    real_loader = access_module.load_fleet_manifest
    loaded: list[tuple[str, ...]] = []
    inside = threading.Event()
    release = threading.Event()

    def slow_loader(path: str, **kwargs):  # type: ignore[no-untyped-def]
        result = real_loader(path, **kwargs)
        loaded.append(result)
        if len(loaded) == 1:
            inside.set()
            release.wait(5)
        return result

    monkeypatch.setattr(access_module, "load_fleet_manifest", slow_loader)
    _replace(path, _manifest_bytes(SECOND))
    reloader = threading.Thread(target=manifest.endpoints)
    reloader.start()
    try:
        assert inside.wait(5)
        # The first reload has read SECOND and not yet published it. A newer
        # file must not let a second reader load and publish ahead of it.
        _replace(path, _manifest_bytes(third))
        assert manifest.endpoints() is good
        assert loaded == [(PRIMARY, *SECOND)]
    finally:
        release.set()
        reloader.join(timeout=10)

    assert manifest.endpoints() == (PRIMARY, *third)


def test_worker_route_serves_a_changed_manifest_without_restart(
    tmp_path: Path, monkeypatch
):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _address: True)
    current = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(
            generated_at=current,
            expires_at=current + timedelta(minutes=10),
            verify_at=current,
        ),
        worker_hotkey=WORKER_HOTKEY,
        channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "validator-access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )

    def evidence_collector(nonce, hotkey, **kwargs):  # type: ignore[no-untyped-def]
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"quote",
            nonce=nonce,
            miner_hotkey=hotkey,
            report_data_version=kwargs["report_data_version"],
            channel_binding=kwargs["channel_binding"],
        )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    primary = f"https://127.0.0.1:{port}"
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(FIRST))
    log: list[str] = []
    manifest = FleetManifest(
        str(path), worker_hotkey=WORKER_HOTKEY, public_endpoint=primary, log=log.append
    )
    with WorkerServer(
        port=port,
        configured_hotkey=WORKER_HOTKEY,
        bearer_token=None,
        evidence_collector=evidence_collector,
        channel_binding=binding,
        tls_context=server_context,
        validator_authorizer=authorizer,
        fleet_endpoints=manifest,
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(
            server.base_url,
            WORKER_HOTKEY,
            ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY,
            validator_signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )
        remote.confirm_channel_binding(remote.fetch_evidence(os.urandom(32)))
        assert remote.fetch_fleet() == (primary, *FIRST)

        _replace(path, _manifest_bytes(SECOND))
        assert remote.fetch_fleet() == (primary, *SECOND)

        _replace(path, _manifest_bytes(FIRST), mode=0o666)
        assert remote.fetch_fleet() == (primary, *SECOND)
    assert len(_warnings(log)) == 1


def test_worker_cli_passes_a_reloading_manifest(tmp_path: Path, monkeypatch):
    certificate, private_key = _tls_material(tmp_path)
    path = tmp_path / "fleet.json"
    _replace(path, _manifest_bytes(FIRST))
    calls: list[dict[str, object]] = []

    class FakeProvider:
        def __init__(self, *_args, **_kwargs):
            pass

        def load(self, *, now):
            return object()

    class FakeAuthorizer:
        def __init__(self, *_args, **_kwargs):
            pass

    class FakeServer:
        host = "0.0.0.0"
        port = 8081

        def __init__(self, *_args, **kwargs):
            calls.append(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def serve_forever(self):
            return None

    monkeypatch.setattr("cathedral.cli.load_policy_keys", lambda *_a, **_k: {"k": b"p" * 32})
    monkeypatch.setattr("cathedral.cli.ValidatorAccessState", lambda _path: object())
    monkeypatch.setattr("cathedral.cli.SignedValidatorSnapshotProvider", FakeProvider)
    monkeypatch.setattr("cathedral.cli.load_sr25519_verifier", lambda: object())
    monkeypatch.setattr("cathedral.cli.preflight_sr25519_verifier", lambda _verifier: None)
    monkeypatch.setattr("cathedral.cli.ValidatorRequestAuthorizer", FakeAuthorizer)
    monkeypatch.setattr("cathedral.cli.WorkerServer", FakeServer)
    args = build_parser().parse_args(
        [
            "worker",
            "serve",
            "--hotkey",
            WORKER_HOTKEY,
            "--host",
            "0.0.0.0",
            "--tls-certificate",
            str(certificate),
            "--tls-private-key",
            str(private_key),
            "--validator-access-snapshot",
            "/srv/cathedral/validator-access.json",
            "--validator-access-keys",
            "/srv/cathedral/keys.json",
            "--validator-access-keys-digest",
            "sha256:" + "cd" * 32,
            "--validator-access-state",
            "/var/lib/cathedral/validator-access.sqlite",
            "--validator-minimum-stake-rao",
            "1000",
            "--public-endpoint",
            PRIMARY,
            "--fleet-manifest",
            str(path),
        ]
    )

    assert cmd_worker_serve(args) == 0
    fleet = calls[0]["fleet_endpoints"]
    assert isinstance(fleet, FleetManifest)
    assert fleet.endpoints() == (PRIMARY, *FIRST)
    _replace(path, _manifest_bytes(SECOND))
    assert fleet.endpoints() == (PRIMARY, *SECOND)
