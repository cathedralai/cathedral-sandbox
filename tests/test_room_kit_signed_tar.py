"""AB#385 slice 2: tar, process stop, snapshot, freeze, thaw and expose through the receipts front are signed."""
from __future__ import annotations

import base64
import http.client
import importlib.util
import io
import json
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_tar_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
AUTH = {"Authorization": "Bearer " + KEY.decode()}


def _signed_action(method: str, path: str) -> str | None:
    bare = urlsplit(path).path
    return next((a for m, p, a in rr.SIGNED if m == method and p.match(bare)), None)


@pytest.mark.parametrize(("method", "path", "want"), [
    ("PUT", "/v1/sandboxes/rm_1/tar?path=/work", "tar_put"),
    ("GET", "/v1/sandboxes/rm_1/tar?path=/work", "tar_get"),
    ("DELETE", "/v1/sandboxes/rm_1/processes/p_7", "process_stop"),
    ("POST", "/v1/sandboxes/rm_1/snapshot", "snapshot"),
    ("POST", "/v1/sandboxes/rm_1/freeze", "freeze"),
    ("POST", "/v1/sandboxes/rm_1/thaw", "thaw"),
    ("POST", "/v1/sandboxes/rm_1/expose", "expose"),
    ("DELETE", "/v1/sandboxes/rm_1", "delete"),
    # Keepalives stay unsigned: each receipt would stay on the chain.
    ("POST", "/v1/sandboxes/rm_1/heartbeat", None),
    ("POST", "/v1/sandboxes/rm_1/lifetime", None),
    ("PATCH", "/v1/sandboxes/rm_1/lifetime", None),
    ("PATCH", "/v1/sandboxes/rm_1", None),
    ("GET", "/v1/sandboxes/rm_1/processes/p_7/logs", None),
    ("DELETE", "/v1/sandboxes/rm_1/processes/p_7/logs", None),
])
def test_signed_table(method: str, path: str, want: str | None) -> None:
    assert _signed_action(method, path) == want


def _tar(text: str) -> bytes:
    # An uncompressed tar of ASCII text: valid UTF-8, so it would decode if parsed as JSON.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = text.encode()
        info = tarfile.TarInfo("a.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def front(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    seen: list[tuple[str, str, bytes]] = []
    archive = _tar("hello")

    class Api(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _record(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            seen.append((self.command, self.path, self.rfile.read(n) if n else b""))

        def do_PUT(self):  # noqa: N802
            self._record()
            self._reply(200, json.dumps({"written": len(seen[-1][2])}).encode())

        def do_GET(self):  # noqa: N802
            self._record()
            if "missing" in self.path:
                return self._reply(404, b'{"error":{"code":"not_found"}}')
            self._reply(200, archive, ctype="application/x-tar")

        def do_POST(self):  # noqa: N802
            self._record()
            self._reply(202 if self.path.endswith("/snapshot") else 200, b'{"ok":true}')

        def do_DELETE(self):  # noqa: N802
            self._record()
            self._reply(200, b'{"ok":true}')

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
    yield server.server_address[1], seen, ledger, archive
    server.shutdown()
    api.shutdown()


def _call(port: int, method: str, path: str, body: bytes | None = None) -> tuple[int, dict, bytes]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=body, headers=AUTH)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _statement(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))["statement"]


def test_put_tar_is_signed_without_parsing_the_archive(front, monkeypatch) -> None:
    port, seen, ledger, _ = front
    body = _tar("payload")
    parsed: list[bytes] = []
    real = rr.json.loads
    monkeypatch.setattr(rr.json, "loads", lambda b, *a, **k: (parsed.append(b), real(b, *a, **k))[1])
    status, headers, _out = _call(port, "PUT", "/v1/sandboxes/sbx_9/tar?path=/work", body)
    assert status == 200 and "X-Room-Receipt" in headers
    assert body not in parsed
    st = _statement(headers)
    assert st["action"] == "tar_put" and st["sandbox_id"] == "sbx_9" and st["status"] == 200
    assert st["target"] == "PUT /v1/sandboxes/sbx_9/tar?path=/work"
    assert st["customer_request_sha256"] == rr.sha(body)
    assert seen == [("PUT", "/v1/sandboxes/sbx_9/tar?path=/work", body)]
    assert len(ledger.chain) == 1


def test_get_tar_is_signed_over_the_archive_bytes(front) -> None:
    port, _seen, ledger, archive = front
    status, headers, out = _call(port, "GET", "/v1/sandboxes/sbx_9/tar?path=/work")
    assert status == 200 and out == archive and headers["Content-Type"] == "application/x-tar"
    st = _statement(headers)
    assert st["action"] == "tar_get" and st["sandbox_id"] == "sbx_9"
    assert st["customer_request_sha256"] == rr.sha(b"")
    assert st["result_sha256"] == rr.sha(archive)
    assert len(ledger.chain) == 1


def test_failed_get_tar_is_signed_with_its_status(front) -> None:
    port, _seen, _ledger, _ = front
    status, headers, out = _call(port, "GET", "/v1/sandboxes/sbx_9/tar?path=/missing")
    assert status == 404
    st = _statement(headers)
    assert st["action"] == "tar_get" and st["status"] == 404 and st["result_sha256"] == rr.sha(out)


@pytest.mark.parametrize(("method", "path", "action", "status"), [
    ("DELETE", "/v1/sandboxes/sbx_9/processes/p_7", "process_stop", 200),
    ("POST", "/v1/sandboxes/sbx_9/snapshot", "snapshot", 202),
    ("POST", "/v1/sandboxes/sbx_9/freeze", "freeze", 200),
    ("POST", "/v1/sandboxes/sbx_9/thaw", "thaw", 200),
    ("POST", "/v1/sandboxes/sbx_9/expose", "expose", 200),
])
def test_room_mutations_are_signed(front, method, path, action, status) -> None:
    port, _seen, ledger, _ = front
    got, headers, _out = _call(port, method, path, b"{}" if method == "POST" else None)
    assert got == status
    st = _statement(headers)
    assert st["action"] == action and st["sandbox_id"] == "sbx_9" and st["status"] == status
    # A process stop is not a room delete: the room keeps its incarnation.
    assert len(ledger.chain) == 1


def test_heartbeat_stays_unsigned(front) -> None:
    port, _seen, ledger, _ = front
    status, headers, _out = _call(port, "POST", "/v1/sandboxes/sbx_9/heartbeat", b'{"ttl_seconds":60}')
    assert status == 200 and "X-Room-Receipt" not in headers
    assert ledger.chain == []


def test_a_params_suffix_does_not_skip_signing(front) -> None:
    # The API routes on urlparse(path).path, which drops ";p"; the front must match the same path.
    port, seen, _ledger, _ = front
    status, headers, _out = _call(port, "PUT", "/v1/sandboxes/sbx_9/tar;p?path=/work", _tar("x"))
    assert status == 200 and seen[-1][1] == "/v1/sandboxes/sbx_9/tar;p?path=/work"
    st = _statement(headers)
    assert st["action"] == "tar_put" and st["sandbox_id"] == "sbx_9"
    assert st["target"] == "PUT /v1/sandboxes/sbx_9/tar;p?path=/work"
