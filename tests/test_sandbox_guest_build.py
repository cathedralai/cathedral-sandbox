"""Image build on the host (#290): POST /v1/images/build with a Dockerfile
and an optional gzip tar context, cached by content."""

from __future__ import annotations

import base64
import io
import json
import tarfile

import pytest

from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

AUTHZ = {"Authorization": "Bearer k"}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    return install(tmp_path, monkeypatch)


@pytest.fixture
def app(fake):
    provider = DockerGuestProvider()
    yield SandboxApplication(provider)
    provider.close()


def _context(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _build(app, dockerfile: str, context: bytes | None = None):
    body = {"dockerfile": dockerfile}
    if context is not None:
        body["context_tar_b64"] = base64.b64encode(context).decode()
    resp = app.dispatch("POST", "/v1/images/build", AUTHZ, json.dumps(body).encode())
    return resp.status, json.loads(resp.body)


def test_build_with_context_then_cache_hit(fake, app) -> None:
    ctx = _context({"app.py": b"print(1)\n"})
    status, doc = _build(app, "FROM alpine:3.20\nCOPY app.py /app.py\n", ctx)
    assert status == 200, doc
    assert doc["image"].startswith("cathedral-build-") and doc["cached"] is False
    (build,) = fake.state["builds"]
    assert build["files"] == ["Dockerfile", "app.py"]
    status, again = _build(app, "FROM alpine:3.20\nCOPY app.py /app.py\n", ctx)
    assert again["image"] == doc["image"] and again["cached"] is True
    assert len(fake.state["builds"]) == 1


def test_same_dockerfile_with_another_context_is_another_image(fake, app) -> None:
    _, one = _build(app, "FROM alpine:3.20\n", _context({"a": b"1"}))
    _, two = _build(app, "FROM alpine:3.20\n", _context({"a": b"2"}))
    assert one["image"] != two["image"]


def test_build_failure_is_a_json_error(fake, app) -> None:
    fake.set(build_fail=True)
    status, doc = _build(app, "FROM alpine:3.20\nRUN false\n")
    assert status == 502 and doc["error"]["code"] == "image_build_failed"


def test_build_rejects_bad_input(fake, app) -> None:
    status, doc = _build(app, "")
    assert status == 400 and doc["error"]["code"] == "invalid_build"
    resp = app.dispatch("POST", "/v1/images/build", AUTHZ, json.dumps({"dockerfile": "FROM x", "context_tar_b64": "%%%"}).encode())
    assert resp.status == 400 and json.loads(resp.body)["error"]["code"] == "invalid_build_context"
    status, doc = _build(app, "FROM alpine:3.20\n", b"not a tar")
    assert status == 400 and doc["error"]["code"] == "invalid_build_context"


def test_built_image_starts_a_room_without_a_pull(fake, app) -> None:
    _, doc = _build(app, "FROM alpine:3.20\n")
    body = json.dumps({"image": doc["image"], "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}).encode()
    resp = app.dispatch("POST", "/v1/sandboxes", AUTHZ, body)
    assert resp.status in (200, 202), resp.body
    assert fake.calls_of("pull") == []


def test_build_context_fetch_checks_the_address_it_connects_to(monkeypatch) -> None:
    # The guard resolved the name once, then urlopen resolved it again (DNS
    # rebinding) and followed redirects with no check. The address the socket
    # actually reaches must be public, on every hop.
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cathedral import sandbox_guest
    from cathedral.sandbox_provider import SandboxOpError

    class Inside(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"INTERNAL")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Inside)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    real = socket.getaddrinfo
    answers = iter([[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]])

    def rebinding(host, *args, **kwargs):
        if host == "build.test":
            return next(answers, None) or real("127.0.0.1", *args, **kwargs)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    try:
        with pytest.raises(SandboxOpError) as err:
            sandbox_guest._fetch_context_tar(f"http://build.test:{server.server_address[1]}/ctx")
        assert err.value.code == "build_context_forbidden"
    finally:
        server.shutdown()
