"""AB#605 hotel HTTP dial to guest localhost."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from cathedral.guest_port_http import dial_loopback
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_server import SandboxApplication


AUTH = {"Authorization": "Bearer k1"}


@pytest.fixture
def app() -> SandboxApplication:
    provider = InMemorySandboxProvider()
    application = SandboxApplication(provider)
    try:
        yield application
    finally:
        provider.close()


@pytest.fixture
def loopback_http():
    seen: list[tuple[str, str, bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            seen.append(("GET", self.path, b""))
            body = b"ok-from-guest"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(n)
            seen.append(("POST", self.path, payload))
            body = b"posted"
            self.send_response(201)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], seen
    server.shutdown()


def test_dial_loopback_get(loopback_http):
    port, seen = loopback_http
    result = dial_loopback(port, method="GET", path="/hello")
    assert result.status == 200
    assert result.body == b"ok-from-guest"
    assert seen == [("GET", "/hello", b"")]


def test_dial_loopback_refuses_closed_port():
    with pytest.raises(SandboxOpError) as refused:
        dial_loopback(1, method="GET", path="/")
    assert refused.value.code == "port_unreachable"
    assert refused.value.http_status == 502


def _create(app: SandboxApplication) -> str:
    body = {"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}}
    created = app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(body).encode())
    assert created.status == 202, created.body
    return json.loads(created.body)["id"]


def test_sandbox_route_proxies_guest_http(app: SandboxApplication, loopback_http):
    port, seen = loopback_http
    sid = _create(app)
    answer = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/ports/{port}/http",
        {**AUTH, "X-Guest-Method": "GET", "X-Guest-Target": "/hello"},
        b"",
    )
    assert answer.status == 200
    assert answer.body == b"ok-from-guest"
    assert seen[-1][0] == "GET"

    posted = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/ports/{port}/http",
        {**AUTH, "X-Guest-Method": "POST", "X-Guest-Target": "/ingest", "Content-Type": "text/plain"},
        b"payload",
    )
    assert posted.status == 201
    assert posted.body == b"posted"
    assert seen[-1] == ("POST", "/ingest", b"payload")


def test_sandbox_route_maps_unreachable(app: SandboxApplication):
    sid = _create(app)
    answer = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/ports/1/http",
        {**AUTH, "X-Guest-Method": "GET", "X-Guest-Target": "/"},
        b"",
    )
    assert answer.status == 502
    assert json.loads(answer.body)["error"]["code"] == "port_unreachable"
