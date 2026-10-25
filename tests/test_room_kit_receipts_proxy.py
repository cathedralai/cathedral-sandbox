"""The receipts front (room_receipts.Server): what reaches the API and what gets signed."""
from __future__ import annotations

import http.client
import importlib.util
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_proxy_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32


@pytest.fixture
def front(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    seen: list[tuple[str, bytes]] = []
    mode = {"drop_after_read": False}

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            seen.append((self.path, self.rfile.read(n)))
            if mode["drop_after_read"]:
                # The API ran the command, then died before it answered.
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            out = json.dumps({"exit_code": 0}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, KEY, "/nonexistent.sock")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], seen, mode, ledger
    server.shutdown()
    api.shutdown()


def test_an_exec_whose_answer_was_lost_is_not_sent_again(front) -> None:
    port, seen, mode, ledger = front
    mode["drop_after_read"] = True
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        c.request("POST", "/v1/sandboxes/sbx_1/exec", body=b'{"cmd":["touch","/work/once"]}',
                  headers={"Authorization": "Bearer " + KEY.decode(), "Content-Type": "application/json"})
        status = c.getresponse().status
    except (http.client.HTTPException, OSError):
        status = None
    assert len(seen) == 1, "the API ran the exec twice"
    assert status in (None, 502)


def test_a_chunked_body_is_refused_not_signed_as_empty(front) -> None:
    port, seen, _mode, ledger = front
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(b"POST /v1/sandboxes/sbx_1/exec HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + KEY +
              b"\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    head = s.recv(4096).split(b"\r\n", 1)[0]
    s.close()
    assert b" 411 " in head
    assert seen == [] and ledger.chain == []


@pytest.mark.parametrize("query", ["after=-5", "after=x", "limit=-1", "limit=abc"])
def test_bad_receipt_paging_is_a_400(front, query) -> None:
    port, _seen, _mode, _ledger = front
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/room/receipts?" + query, headers={"Authorization": "Bearer " + KEY.decode()})
    assert c.getresponse().status == 400


def _post(port: int, path: str, body: bytes, extra: dict | None = None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", path, body=body, headers={"Authorization": "Bearer " + KEY.decode(),
                                                 "Content-Type": "application/json", **(extra or {})})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _receipt(headers: dict) -> dict:
    import base64 as b64

    raw = headers["X-Room-Receipt"]
    return json.loads(b64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def test_an_image_given_as_an_object_is_signed_by_its_reference(front, monkeypatch) -> None:
    # The API accepts {"image": {"image": ref, "registry_auth": ...}}. The
    # front crashed on the dict (unhashable) after the create had run, and on
    # a refused create it signed the registry password into the chain.
    port, seen, _mode, ledger = front
    asked = []
    monkeypatch.setattr(rr.Server, "image_digest", lambda self, ref: asked.append(ref) or "sha256:abc")
    body = json.dumps({"image": {"image": "repo/app:latest", "registry_auth": {"username": "u", "password": "hunter2"}}}).encode()
    status, headers, _out = _post(port, "/v1/sandboxes", body)
    assert status == 200 and "X-Room-Receipt" in headers
    st = _receipt(headers)["statement"]
    assert st["image"] == "repo/app:latest" and st["image_digest"] == "sha256:abc" and asked == ["repo/app:latest"]
    assert "hunter2" not in json.dumps(ledger.chain)
    assert len(seen) == 1


def test_a_lone_surrogate_in_the_body_is_refused_before_the_api_runs_it(front) -> None:
    port, seen, _mode, ledger = front
    body = b'{"cmd": ["echo", "\\udc80"]}'
    status, _headers, out = _post(port, "/v1/sandboxes/sbx_1/exec", body)
    assert status == 400 and b"invalid_request" in out
    assert seen == [] and ledger.chain == []


def test_image_inspect_errors_give_no_digest(front, monkeypatch) -> None:
    # The real image_digest must swallow a docker timeout or a missing
    # docker binary: a digest is a bonus, the receipt is the product.
    import subprocess

    port, _seen, _mode, _ledger = front

    def run(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout", 30))

    monkeypatch.setattr(rr.subprocess, "run", run)
    status, headers, _out = _post(port, "/v1/sandboxes", json.dumps({"image": "repo/app:latest"}).encode())
    assert status == 200 and _receipt(headers)["statement"]["image_digest"] is None


def test_a_signing_failure_still_answers_the_caller(front, monkeypatch) -> None:
    # The action ran; a dropped connection would read as a hotel outage at the
    # broker (hotel rested, create retried elsewhere: an orphan room per hotel).
    port, seen, _mode, ledger = front
    monkeypatch.setattr(rr.Server, "image_digest", lambda self, ref: None)

    def broken(statement):
        raise RuntimeError("hsm down")

    monkeypatch.setattr(ledger, "sign", broken)
    status, headers, out = _post(port, "/v1/sandboxes", json.dumps({"image": "repo/app:latest"}).encode())
    assert status == 200 and json.loads(out) == {"exit_code": 0}
    assert "X-Room-Receipt" not in headers and headers.get("X-Room-Receipt-Error") == "RuntimeError"
    assert len(seen) == 1
