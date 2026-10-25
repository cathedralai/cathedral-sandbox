"""Review round 6 (reader P): hotel API listener fixes of PR #312 that no test guarded.

The broker reads a dropped connection as a hotel outage and rests the hotel
for every guest, so every request must get an answer. Each test here failed
on the code before its fix (22e7824).
"""
from __future__ import annotations

import json
import socket
import threading

import pytest

from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication, run

AUTH = {"Authorization": "Bearer k1"}


@pytest.fixture
def app():
    provider = InMemorySandboxProvider()
    a = SandboxApplication(provider)
    try:
        yield a
    finally:
        provider.close()


@pytest.fixture
def listener(app):
    httpd, (host, port) = run(app, host="127.0.0.1", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield host, int(port)
    finally:
        httpd.shutdown()
        httpd.server_close()


def _raw(host: str, port: int, request: bytes, timeout: float = 2.0) -> bytes:
    """Send one request on a fresh connection; return what came back within *timeout*."""
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(request)
        try:
            while True:
                data = s.recv(65536)
                if not data:
                    break
                chunks.append(data)
        except TimeoutError:
            pass
    return b"".join(chunks)


# ---------------------------------------------------------------- O6: Content-Length guard

@pytest.mark.parametrize("length", ["abc", "300000000", "-1"])
def test_a_bad_or_oversized_content_length_is_refused_before_the_body_is_read(listener, length) -> None:
    # "abc" raised ValueError in the handler: the connection closed with no
    # answer. A 300 MB Content-Length (or -1, read to EOF) held the thread
    # on the body. Both are a 413 before any body byte is read, within 2 s.
    host, port = listener
    request = (f"POST /v1/sandboxes HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer k1\r\n"
               f"Content-Type: application/json\r\nContent-Length: {length}\r\n\r\n").encode()
    answer = _raw(host, port, request)
    status = answer.split(b"\r\n", 1)[0]
    assert status.split(b" ")[1:2] == [b"413"], answer[:200]
    assert json.loads(answer.split(b"\r\n\r\n", 1)[1])["error"]["code"] == "request_too_large"
    # The listener still answers the next request on a fresh connection.
    again = _raw(host, port, f"GET /v1/quota HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer k1\r\n\r\n".encode())
    assert again.split(b"\r\n", 1)[0].split(b" ")[1:2] == [b"200"], again[:200]


# ---------------------------------------------------------------- O15: parser limits are a 400

def test_a_huge_integer_or_deep_nesting_in_a_create_body_is_a_400(app) -> None:
    # Both raised out of dispatch (the int digit limit, the parser's
    # recursion limit) and dropped the connection.
    huge = b'{"image": "repo/x:latest", "ttl_seconds": ' + b"9" * 5000 + b"}"
    deep = b'{"image": "repo/x:latest", "labels": ' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    for body in (huge, deep):
        r = app.dispatch("POST", "/v1/sandboxes", AUTH, body)
        assert r.status == 400, r.body[:200]
        assert json.loads(r.body)["error"]["code"] == "invalid_request"
    assert b"RecursionError" in app.dispatch("POST", "/v1/sandboxes", AUTH, deep).body


def test_an_overflowing_number_in_a_wait_body_is_a_400(app) -> None:
    # int(1e400) raises OverflowError: the one body number that reaches int()
    # with no range check before it.
    created = app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps({"image": "repo/x:latest"}).encode())
    sid = json.loads(created.body)["id"]
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/wait", AUTH, b'{"timeout_seconds": 1e400}')
    assert r.status == 400, r.body[:200]
    assert json.loads(r.body)["error"]["code"] == "invalid_request" and b"OverflowError" in r.body
