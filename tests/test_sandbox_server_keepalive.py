"""The API listener keeps connections alive (HTTP/1.1) and never leaves a client hanging.

Every call used to be a new TCP connection (HTTP/1.0). Keepalive is only safe if
each response says how long it is and a request whose body was not read closes
the connection instead of leaving bytes to be parsed as the next request.
"""

from __future__ import annotations

import http.client
import socket
import threading

import pytest

from cathedral.sandbox_server import Response, serve


class _StubApp:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str, bytes]] = []

    def dispatch(self, method, path, headers, body):  # noqa: ANN001, ARG002
        self.seen.append((method, path, body))
        if path == "/gone":
            return Response.no_content()
        if path == "/bad":
            return Response.error(400, "bad", "no")
        return Response.json(200, {"path": path})


@pytest.fixture()
def server():
    app = _StubApp()
    httpd = serve(app)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield app, httpd.server_address
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_speaks_http11_with_an_idle_timeout(server) -> None:
    _, addr = server
    c = http.client.HTTPConnection(*addr, timeout=5)
    c.request("GET", "/a")
    r = c.getresponse()
    r.read()
    assert r.version == 11
    c.close()
    handler = serve(_StubApp())
    try:
        assert 0 < handler.RequestHandlerClass.timeout <= 120
    finally:
        handler.server_close()


def test_two_calls_share_one_connection(server) -> None:
    _, addr = server
    c = http.client.HTTPConnection(*addr, timeout=5)
    try:
        c.connect()
        sock = c.sock
        c.request("GET", "/one")
        r1 = c.getresponse()
        assert r1.status == 200 and r1.read() == b'{"path": "/one"}'
        c.request("POST", "/two", body=b"hello")
        r2 = c.getresponse()
        assert r2.status == 200 and r2.read() == b'{"path": "/two"}'
        assert c.sock is sock, "the client had to reconnect, so the server closed the connection"
    finally:
        c.close()


@pytest.mark.parametrize("path,status", [("/gone", 204), ("/bad", 400)])
def test_every_kind_of_answer_has_a_length(server, path, status) -> None:
    _, addr = server
    c = http.client.HTTPConnection(*addr, timeout=5)
    try:
        c.request("GET", path)
        r = c.getresponse()
        assert r.status == status
        assert r.getheader("Content-Length") is not None
        r.read()
        # A second call on the same socket proves the first answer was framed.
        c.request("GET", "/after")
        assert c.getresponse().status == 200
    finally:
        c.close()


def test_a_refused_oversize_body_closes_the_connection(server) -> None:
    _, addr = server
    c = http.client.HTTPConnection(*addr, timeout=5)
    try:
        c.putrequest("POST", "/big")
        c.putheader("Content-Length", str(10**10))
        c.endheaders()
        r = c.getresponse()
        assert r.status == 413
        assert (r.getheader("Connection") or "").lower() == "close"
    finally:
        c.close()


def test_a_chunked_request_closes_and_cannot_smuggle_a_second_request(server) -> None:
    app, addr = server
    payload = b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n"
    raw = (
        b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
        + hex(len(payload))[2:].encode() + b"\r\n" + payload + b"\r\n0\r\n\r\n"
    )
    s = socket.create_connection(addr, timeout=5)
    try:
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    assert data.count(b"HTTP/1.") == 1, "the chunked body was parsed as a second request"
    assert b"connection: close" in data.lower()
    assert all(path != "/smuggled" for _, path, _ in app.seen)
