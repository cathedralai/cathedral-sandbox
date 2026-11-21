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


class _Completed:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _fake_run(runtime: str, dial: _Completed, calls: list):
    def run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "inspect":
            return _Completed(0, f"/var/run/docker/netns/abc true {runtime}\n")
        return dial
    return run


def _answer(status=200, body=b"hi"):
    meta = {"status": status, "headers": [["Content-Type", "text/plain"]], "body_len": len(body)}
    return _Completed(0, json.dumps(meta).encode() + b"\n" + body)


def test_gvisor_room_dials_from_inside_the_room(monkeypatch):
    """AB#772: a runsc room's loopback is in gVisor, not the Docker netns."""
    from cathedral import guest_port_http as gph

    calls: list = []
    monkeypatch.setattr(gph.subprocess, "run", _fake_run("runsc", _answer(200, b"hello"), calls))
    monkeypatch.setattr(gph.os.path, "exists", lambda p: True)
    result = gph.dial_container_loopback(
        "cid1", 8080, method="post", path="/form", query="x=1",
        headers={"Content-Type": "text/plain", "Authorization": "Bearer hotel", "Cookie": "s=1"}, body=b"a",
    )
    assert result.status == 200 and result.body == b"hello"
    dial = calls[-1]
    assert dial[:6] == ["docker", "exec", "-i", "cid1", "python3", "-c"]
    assert "nsenter" not in " ".join(dial[:2])
    args = dial[7:]
    assert args[:3] == ["8080", "POST", "/form?x=1"]
    assert "Authorization" not in args and "Cookie" not in args
    assert args[args.index("Content-Type") + 1] == "text/plain"


def test_runc_room_still_uses_nsenter(monkeypatch):
    from cathedral import guest_port_http as gph

    calls: list = []
    monkeypatch.setattr(gph.subprocess, "run", _fake_run("runc", _answer(), calls))
    monkeypatch.setattr(gph.os.path, "exists", lambda p: True)
    gph.dial_container_loopback("cid1", 8080, method="GET", path="/")
    assert calls[-1][0] == "/usr/bin/nsenter"
    assert calls[-1][1] == "--net=/var/run/docker/netns/abc"


def test_gvisor_room_without_python3_says_why(monkeypatch):
    from cathedral import guest_port_http as gph

    calls: list = []
    monkeypatch.setattr(gph.subprocess, "run", _fake_run("runsc", _Completed(127, b"", b"exec failed"), calls))
    with pytest.raises(SandboxOpError) as refused:
        gph.dial_container_loopback("cid1", 8080, method="GET", path="/")
    assert refused.value.http_status == 502
    assert "python3" in str(refused.value)


def test_gvisor_room_closed_port_is_unreachable(monkeypatch):
    from cathedral import guest_port_http as gph

    calls: list = []
    refused_dial = _Completed(2, b"", b"ConnectionRefusedError: [Errno 111] Connection refused\n")
    monkeypatch.setattr(gph.subprocess, "run", _fake_run("runsc-netraw", refused_dial, calls))
    with pytest.raises(SandboxOpError) as refused:
        gph.dial_container_loopback("cid1", 8080, method="GET", path="/")
    assert refused.value.code == "port_unreachable"
    assert calls[-1][1] == "exec"


def test_in_room_script_round_trips_a_real_server(loopback_http):
    """The script docker exec runs is the same one nsenter runs: prove it end to end."""
    import subprocess
    import sys

    from cathedral import guest_port_http as gph

    port, seen = loopback_http
    argv = [sys.executable, "-c", gph._NSENTER_SCRIPT,  # noqa: SLF001
            *gph._script_args(port, "POST", "/ingest", "a=b", {"Content-Type": "text/plain"}, 5.0)]  # noqa: SLF001
    result = gph._run_dial(argv, port, body=b"payload", timeout_seconds=5.0, in_room=True)  # noqa: SLF001
    assert result.status == 201 and result.body == b"posted"
    assert seen[-1] == ("POST", "/ingest?a=b", b"payload")


@pytest.mark.parametrize(
    "meta",
    [
        {"status": 200, "headers": [["X-Evil", "a\r\nSet-Cookie: s=1"]], "body_len": 0},
        {"status": 200, "headers": [["X-Evil\n", "a"]], "body_len": 0},
        {"status": 200, "headers": [["X-Nul", "a\x00b"]], "body_len": 0},
        {"status": 99, "headers": [], "body_len": 0},
        {"status": 600, "headers": [], "body_len": 0},
    ],
)
def test_gvisor_guest_cannot_split_the_hotel_response(monkeypatch, meta):
    """In a gVisor room the guest writes the answer line itself: control characters and odd statuses refuse."""
    from cathedral import guest_port_http as gph

    calls: list = []
    answer = _Completed(0, json.dumps(meta).encode() + b"\n")
    monkeypatch.setattr(gph.subprocess, "run", _fake_run("runsc", answer, calls))
    with pytest.raises(SandboxOpError) as refused:
        gph.dial_container_loopback("cid1", 8080, method="GET", path="/")
    assert refused.value.code == "port_unreachable"
