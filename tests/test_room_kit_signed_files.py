"""AB#385 slice 1: file GET/PUT through the receipts front are signed."""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_files_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32


def _signed_action(method: str, path: str) -> str | None:
    bare = urlsplit(path).path
    return next((a for m, p, a in rr.SIGNED if m == method and p.match(bare)), None)


def test_signed_table_includes_file_routes() -> None:
    assert _signed_action("PUT", "/v1/sandboxes/rm_1/files?path=/work/a.txt") == "file_put"
    assert _signed_action("GET", "/v1/sandboxes/rm_1/files?path=/work/a.txt") == "file_get"
    assert _signed_action("PUT", "/v1/sandboxes/rm_1/stat?path=/work") is None


@pytest.fixture
def front(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    seen: list[tuple[str, str, bytes | None]] = []

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def do_PUT(self):  # noqa: N802
            seen.append((self.command, self.path, self._body()))
            path = parse_qs(urlsplit(self.path).query).get("path", [""])[0]
            out = json.dumps({"path": path, "written": len(seen[-1][2] or b"")}).encode()
            self._reply(200, out)

        def do_GET(self):  # noqa: N802
            seen.append((self.command, self.path, None))
            out = b"hello-file"
            self._reply(200, out, ctype="application/octet-stream")

        def _reply(self, status: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, KEY, "/nonexistent.sock")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], seen, ledger
    server.shutdown()
    api.shutdown()


def _receipt(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def test_put_file_is_signed(front) -> None:
    port, seen, ledger = front
    body = b"payload-bytes"
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(
        "PUT",
        "/v1/sandboxes/sbx_9/files?path=/work/x",
        body=body,
        headers={"Authorization": "Bearer " + KEY.decode(), "Content-Type": "application/octet-stream"},
    )
    r = c.getresponse()
    headers = dict(r.getheaders())
    assert r.status == 200 and "X-Room-Receipt" in headers
    st = _receipt(headers)["statement"]
    assert st["action"] == "file_put" and st["sandbox_id"] == "sbx_9" and st["status"] == 200
    assert st["target"] == "PUT /v1/sandboxes/sbx_9/files?path=/work/x"
    assert st["customer_request_sha256"] == rr.sha(body)
    assert len(seen) == 1 and seen[0][0] == "PUT"
    assert len(ledger.chain) == 1


def test_get_file_is_signed(front) -> None:
    port, seen, ledger = front
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(
        "GET",
        "/v1/sandboxes/sbx_9/files?path=/work/x",
        headers={"Authorization": "Bearer " + KEY.decode()},
    )
    r = c.getresponse()
    headers = dict(r.getheaders())
    data = r.read()
    assert r.status == 200 and data == b"hello-file" and "X-Room-Receipt" in headers
    st = _receipt(headers)["statement"]
    assert st["action"] == "file_get" and st["sandbox_id"] == "sbx_9"
    assert st["target"] == "GET /v1/sandboxes/sbx_9/files?path=/work/x"
    assert st["customer_request_sha256"] == rr.sha(b"")
    assert st["result_sha256"] == rr.sha(data)
    assert len(seen) == 1 and seen[0][0] == "GET"
    assert len(ledger.chain) == 1
