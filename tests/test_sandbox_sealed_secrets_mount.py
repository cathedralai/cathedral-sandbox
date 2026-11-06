"""The room API side of customer-sealed secrets (AB#417 slice 1).

With CATHEDRAL_SEALED_SECRETS_DIR set (room-kit profile, ROOM_SEALED_SECRETS=1),
each room gets a fresh, empty directory under it, bind-mounted read-only at
/run/secrets. The receipts front writes into it; the room only reads. The
directory goes the moment the room is retired. Unset: no mount, as before.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

KEY = "hotel-key"
A = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-a"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    return docker


def _app(monkeypatch, root: Path | None):
    if root is None:
        monkeypatch.delenv("CATHEDRAL_SEALED_SECRETS_DIR", raising=False)
    else:
        root.mkdir(mode=0o700, exist_ok=True)
        monkeypatch.setenv("CATHEDRAL_SEALED_SECRETS_DIR", str(root))
    provider = DockerGuestProvider()
    return provider, SandboxApplication(provider)


def call(app, method, path, body=None):
    raw = b"" if body is None else json.dumps(body).encode()
    res = app.dispatch(method, path, A, raw)
    return res.status, json.loads(res.body) if res.body else None


def run_mounts(fake) -> list[str]:
    run = [c for c in fake.calls_of("run") if "--name" in c][-1]
    return [run[i + 1] for i, p in enumerate(run) if p == "--mount"]


def test_each_room_mounts_its_own_empty_directory_read_only(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-secrets"
    provider, app = _app(monkeypatch, root)
    try:
        status, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 202, doc
        room = root / doc["id"]
        assert run_mounts(fake) == [f"type=bind,source={room.resolve()},target=/run/secrets,readonly"]
        assert room.is_dir() and not any(room.iterdir())
        assert stat.S_IMODE(room.stat().st_mode) == 0o755
        _, other = call(app, "POST", "/v1/sandboxes", ROOM)
        assert run_mounts(fake) == [f"type=bind,source={(root / other['id']).resolve()},target=/run/secrets,readonly"]
    finally:
        provider.close()


def test_a_leftover_directory_is_emptied_before_the_room_starts(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-secrets"
    provider, app = _app(monkeypatch, root)
    try:
        real = provider._make_secrets_dir  # noqa: SLF001

        def plant_then_make(sandbox_id: str) -> None:
            (root / sandbox_id).mkdir()
            (root / sandbox_id / "STALE").write_text("from an earlier room")
            real(sandbox_id)

        monkeypatch.setattr(provider, "_make_secrets_dir", plant_then_make)
        status, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 202 and not any((root / doc["id"]).iterdir())
    finally:
        provider.close()


def test_delete_removes_the_directory_at_once(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-secrets"
    provider, app = _app(monkeypatch, root)
    try:
        _, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        room = root / doc["id"]
        (room / "OPENAI_API_KEY").write_text("written by the front")
        status, _ = call(app, "DELETE", f"/v1/sandboxes/{doc['id']}")
        assert status == 204
        assert not room.exists()
    finally:
        provider.close()


def test_reconcile_drops_the_directory_of_a_room_with_no_record(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-secrets"
    provider, app = _app(monkeypatch, root)
    try:
        _, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        lost = root / "sbx_lostlostlost"
        lost.mkdir()
        (lost / "OPENAI_API_KEY").write_text("a room this API no longer knows")
        assert provider._sweep_secrets_dirs() == 1  # noqa: SLF001
        assert not lost.exists() and (root / doc["id"]).is_dir()
        with provider._drain_lock:  # noqa: SLF001
            provider._reconcile_locked()  # noqa: SLF001
        assert (root / doc["id"]).is_dir()
    finally:
        provider.close()


def test_a_failed_start_leaves_no_directory(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-secrets"
    provider, app = _app(monkeypatch, root)
    try:
        fake.set(run_fail_images=["alpine:3.20"])
        status, _ = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 502
        assert not any(root.iterdir())
    finally:
        provider.close()


def test_a_missing_root_fails_the_create_closed(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-secrets"
    provider, app = _app(monkeypatch, root)
    try:
        root.rmdir()
        status, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 503 and doc["error"]["code"] == "sealed_secrets_unavailable"
        assert not [c for c in fake.calls_of("run") if "--name" in c]
    finally:
        provider.close()


def test_without_the_setting_no_room_mounts_secrets(fake, tmp_path, monkeypatch) -> None:
    provider, app = _app(monkeypatch, None)
    try:
        status, _ = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 202
        assert run_mounts(fake) == []
    finally:
        provider.close()
