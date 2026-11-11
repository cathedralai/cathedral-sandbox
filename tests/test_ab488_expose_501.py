"""AB#488: a sealed hotel answers expose with 501, not a URL that nothing serves."""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import install

A = {"Authorization": "Bearer hotel-key", "X-Cathedral-Guest": "guest-a"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


@pytest.fixture
def app(tmp_path, monkeypatch):
    install(tmp_path, monkeypatch).add_image("alpine:3.20")
    provider = DockerGuestProvider()
    yield SandboxApplication(provider)
    provider.close()


def _call(app, method, path, body):
    res = app.dispatch(method, path, A, json.dumps(body).encode())
    return res.status, json.loads(res.body) if res.body else None


def test_expose_on_a_guest_room_is_501(app) -> None:
    status, doc = _call(app, "POST", "/v1/sandboxes", ROOM)
    assert status in (200, 201, 202), doc
    sid = doc["id"]
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/expose", {"port": 8080})
    assert status == 501
    assert doc["error"]["code"] == "expose_not_supported"
    assert "url" not in doc


def test_expose_refusal_leaves_no_exposed_record(app) -> None:
    status, doc = _call(app, "POST", "/v1/sandboxes", ROOM)
    sid = doc["id"]
    _call(app, "POST", f"/v1/sandboxes/{sid}/expose", {"port": 8080})
    res = app.dispatch("GET", f"/v1/sandboxes/{sid}", A, b"")
    assert "exposed" not in json.loads(res.body)
