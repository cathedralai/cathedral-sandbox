"""The room API side of a room's env overlay (AB#414).

The receipts front opens a customer-sealed envelope (room-kit sealed-env) and
puts the whole overlay on PUT /v1/sandboxes/{id}/env-sealed. The API keeps it
in the room's guest record and merges it under the env of every later exec and
process start; the command's own env wins. Only a hotel with sealed secrets
(CATHEDRAL_SEALED_SECRETS_DIR) has the front in place, so elsewhere the route
is refused. Values never show in a doc, a log or an error.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cathedral.sandbox_api import ExecRequest
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

KEY = "hotel-key"
A = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-a"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}
VALUE = "overlay-value-plaintext-5151"


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    return docker


@pytest.fixture
def app(fake, tmp_path, monkeypatch):
    root = tmp_path / "room-secrets"
    root.mkdir(mode=0o700)
    monkeypatch.setenv("CATHEDRAL_SEALED_SECRETS_DIR", str(root))
    provider = DockerGuestProvider()
    try:
        yield provider, SandboxApplication(provider)
    finally:
        provider.close()


def call(app, method, path, body=None):
    raw = b"" if body is None else json.dumps(body).encode()
    res = app.dispatch(method, path, A, raw)
    return res.status, res.body, json.loads(res.body) if res.body else None


def _room(app) -> str:
    status, _, doc = call(app, "POST", "/v1/sandboxes", ROOM)
    assert status == 202, doc
    return doc["id"]


def _set(app, room: str, env: dict):
    return call(app, "PUT", f"/v1/sandboxes/{room}/env-sealed", {"env": env})


def _env_of(fake: FakeDocker, marker: str) -> dict[str, str]:
    """The -e pairs of the one docker exec that ran *marker*."""
    (call_,) = [c for c in fake.calls_of("exec") if any(marker in p for p in c)]
    pairs = [call_[i + 1] for i, p in enumerate(call_) if p == "-e"]
    return dict(p.split("=", 1) for p in pairs)


def test_a_set_overlay_is_in_the_next_exec(fake, app) -> None:
    _, api = app
    room = _room(api)
    status, raw, doc = _set(api, room, {"OVERLAY_A": VALUE, "OVERLAY_B": "2"})
    assert (status, doc) == (200, {"sandbox_id": room, "names": ["OVERLAY_A", "OVERLAY_B"]})
    assert VALUE.encode() not in raw
    assert call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "after-set"]})[0] == 200
    assert _env_of(fake, "after-set") == {"OVERLAY_A": VALUE, "OVERLAY_B": "2"}


def test_the_commands_own_env_wins_over_the_overlay(fake, app) -> None:
    _, api = app
    room = _room(api)
    _set(api, room, {"OVERLAY_A": VALUE, "OVERLAY_B": "2"})
    call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "own-env"], "env": {"OVERLAY_B": "mine", "C": "3"}})
    assert _env_of(fake, "own-env") == {"OVERLAY_A": VALUE, "OVERLAY_B": "mine", "C": "3"}


def test_a_new_overlay_replaces_the_old_one_whole_and_empty_clears_it(fake, app) -> None:
    _, api = app
    room = _room(api)
    _set(api, room, {"OVERLAY_A": VALUE, "OVERLAY_B": "2"})
    _set(api, room, {"OVERLAY_B": "two"})
    call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "replaced"]})
    assert _env_of(fake, "replaced") == {"OVERLAY_B": "two"}
    assert _set(api, room, {})[2] == {"sandbox_id": room, "names": []}
    call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "cleared"]})
    assert _env_of(fake, "cleared") == {}


def test_a_process_start_gets_the_overlay(fake, app) -> None:
    _, api = app
    room = _room(api)
    _set(api, room, {"OVERLAY_A": VALUE})
    status, _, doc = call(api, "POST", f"/v1/sandboxes/{room}/processes",
                          {"cmd": ["sleep", "bg-marker"], "env": {"C": "3"}})
    assert status == 202, doc
    assert _env_of(fake, "bg-marker") == {"OVERLAY_A": VALUE, "C": "3"}


def test_a_sealed_exec_gets_the_overlay_too(fake, app) -> None:
    provider, api = app
    room = _room(api)
    _set(api, room, {"OVERLAY_A": VALUE})
    provider.exec(room, ExecRequest(cmd=["echo", "sealed-marker"], env={"C": "3"}, sealed=True))
    assert _env_of(fake, "sealed-marker") == {"OVERLAY_A": VALUE, "C": "3"}


def test_the_image_probes_never_carry_the_overlay(fake, app) -> None:
    # The bash and timeout probes run once, on the first exec after the overlay is set.
    _, api = app
    room = _room(api)
    _set(api, room, {"OVERLAY_A": VALUE})
    call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": "echo probe-marker"})
    probes = [c for c in fake.calls_of("exec") if c[-1] in ("true", ":")]
    assert probes and all("-e" not in c for c in probes)


def test_values_stay_out_of_the_doc_and_the_log(fake, app) -> None:
    _, api = app
    room = _room(api)
    _set(api, room, {"OVERLAY_A": VALUE})
    call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "logged"]})
    for path in (f"/v1/sandboxes/{room}", f"/v1/sandboxes/{room}/logs", "/v1/sandboxes"):
        status, raw, _ = call(api, "GET", path)
        assert status == 200 and VALUE.encode() not in raw and b"OVERLAY_A" not in raw


@pytest.mark.parametrize("env", [
    {"PATH": "/x"}, {"LD_PRELOAD": "/x.so"}, {"A=B": "1"}, {"1A": "1"}, {"": "1"}, {"A": 1}, {"A": "v\0x"},
    {f"N{i}": "1" for i in range(65)}, {"A": "x" * (64 * 1024)},
])
def test_a_bad_overlay_is_refused_and_never_echoed(fake, app, env) -> None:
    _, api = app
    room = _room(api)
    _set(api, room, {"KEEP": VALUE})
    status, raw, doc = _set(api, room, env)
    assert status == 400 and doc["error"]["code"] == "invalid_env"
    assert b"/x" not in raw and b"v\\u0000x" not in raw and b"xxxx" not in raw
    call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "kept"]})
    assert _env_of(fake, "kept") == {"KEEP": VALUE}


def test_not_an_object_is_refused(fake, app) -> None:
    _, api = app
    room = _room(api)
    assert call(api, "PUT", f"/v1/sandboxes/{room}/env-sealed", {"env": ["A"]})[0] == 400
    assert call(api, "PUT", f"/v1/sandboxes/{room}/env-sealed", {})[0] == 400


def test_an_unknown_or_deleted_room_is_404(fake, app) -> None:
    _, api = app
    assert _set(api, "sbx_missing", {"A": "1"})[0] == 404
    room = _room(api)
    _set(api, room, {"A": "1"})
    assert call(api, "DELETE", f"/v1/sandboxes/{room}")[0] == 204
    assert _set(api, room, {"A": "1"})[0] in (404, 409)


def test_a_hotel_without_sealed_secrets_refuses_the_route(fake, tmp_path, monkeypatch) -> None:
    # No receipts front with sealed secrets: the route would carry values in the clear past the host.
    monkeypatch.delenv("CATHEDRAL_SEALED_SECRETS_DIR", raising=False)
    provider = DockerGuestProvider()
    try:
        api = SandboxApplication(provider)
        room = _room(api)
        status, _, doc = _set(api, room, {"A": VALUE})
        assert (status, doc["error"]["code"]) == (501, "env_overlay_not_supported")
        call(api, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["echo", "no-overlay"]})
        assert _env_of(fake, "no-overlay") == {}
    finally:
        provider.close()


def test_the_memory_runtime_has_no_overlay(monkeypatch) -> None:
    from cathedral.sandbox_provider import InMemorySandboxProvider

    api = SandboxApplication(InMemorySandboxProvider())
    room = _room(api)
    status, _, doc = _set(api, room, {"A": "1"})
    assert (status, doc["error"]["code"]) == (501, "env_overlay_not_supported")


def test_the_route_is_not_in_the_published_contract(fake, app) -> None:
    _, api = app
    status, raw, _ = call(api, "GET", "/openapi.json")
    assert status == 200 and b"env-sealed" not in raw
