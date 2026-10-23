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
