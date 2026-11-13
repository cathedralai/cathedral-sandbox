"""Shared harness for the receipts front tests: the real room_receipts.Server in front of a fake room API.

The fake API runs on real threads. A request can be held on an event, answered
with a chosen status, or dropped after its body was read (an answer that never
arrives), so a test can place one request inside another.
"""
from __future__ import annotations

import base64
import datetime
import http.client
import importlib.util
import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_front_support", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
AUTH = {"Authorization": "Bearer " + KEY.decode()}
DENY_ALL = {"mode": "deny_all", "allow": []}


class Hold:
    """A held request: `entered` is set when one arrives, it waits for `release`."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def wait_entered(self, timeout: float = 10) -> None:
        assert self.entered.wait(timeout), "the held request never reached the API"


class FakeApi:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.seen: list[tuple[str, str, bytes]] = []
        self.rooms: set[str] = set()
        self.new_ids: list[str] = []
        self.counter = 0
        self.holds: list[tuple[re.Pattern, Hold]] = []
        self.drops: list[list] = []  # [pattern, answers still to drop or None for all]
        self.replies: list[tuple[re.Pattern, int, bytes]] = []
        self.network_policy: dict | None = DENY_ALL
        self.expires_in = 3600.0
        self.expires_at: str | None = None
        self.create_answer: dict = {}
        self.get_replies: dict[str, tuple[int, bytes]] = {}
        self.list_status = 200
        self.list_body: bytes | None = None
        self.server: ThreadingHTTPServer | None = None

    # -- test controls
    def hold(self, pattern: str) -> Hold:
        h = Hold()
        self.holds.append((re.compile(pattern), h))
        return h

    def drop(self, pattern: str, times: int | None = None) -> None:
        """Read the request, then close without an answer: for the next *times* matches, or for all."""
        self.drops.append([re.compile(pattern), times])

    def reply(self, pattern: str, status: int, body: bytes | dict = b"{}") -> None:
        self.replies.append((re.compile(pattern), status, body if isinstance(body, bytes) else json.dumps(body).encode()))

    def count(self, pattern: str) -> int:
        rx = re.compile(pattern)
        with self.lock:
            return sum(1 for m, p, _b in self.seen if rx.fullmatch(f"{m} {p}"))

    # -- the server side
    def _stamp(self, seconds: float) -> str:
        return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)).isoformat()

    def handle(self, h: BaseHTTPRequestHandler) -> None:
        n = int(h.headers.get("Content-Length") or 0)
        body = h.rfile.read(n) if n else b""
        path = h.path.split("?", 1)[0]
        line = f"{h.command} {path}"
        with self.lock:
            self.seen.append((h.command, path, body))
            rooms_now = sorted(self.rooms)
        for rx, hold in list(self.holds):
            if rx.fullmatch(line):
                hold.entered.set()
                hold.release.wait(30)
        with self.lock:
            dropping = False
            for entry in self.drops:
                if entry[0].fullmatch(line) and entry[1] != 0:
                    dropping = True
                    if entry[1] is not None:
                        entry[1] -= 1
                    break
        if dropping:
            h.close_connection = True
            h.connection.shutdown(socket.SHUT_RDWR)
            return
        for rx, status, out in self.replies:
            if rx.fullmatch(line):
                return self._send(h, status, out)
        if line == "POST /v1/sandboxes":
            return self._create(h, body)
        if line == "GET /v1/sandboxes":
            if self.list_body is not None:
                return self._send(h, self.list_status, self.list_body)
            return self._send(h, self.list_status, json.dumps({"sandboxes": [{"id": r} for r in rooms_now]}).encode())
        m = re.fullmatch(r"(GET|DELETE) /v1/sandboxes/([^/]+)", line)
        if m:
            room = m[2]
            if m[1] == "DELETE":
                with self.lock:
                    self.rooms.discard(room)
                return self._send(h, 200, b'{"deleted":true}')
            if room in self.get_replies:
                status, out = self.get_replies[room]
                return self._send(h, status, out)
            if room in rooms_now:
                return self._send(h, 200, json.dumps({"id": room}).encode())
            return self._send(h, 404, b'{"error":{"code":"sandbox_not_found","message":"no such room"}}')
        if re.fullmatch(r"POST /v1/sandboxes/[^/]+/lifetime", line):
            return self._send(h, 200, json.dumps({"expires_at": self._stamp(self.expires_in)}).encode())
        if re.fullmatch(r"POST /v1/sandboxes/[^/]+/exec", line):
            return self._send(h, 200, b'{"exit_code":0}')
        return self._send(h, 200, b"{}")

    def _create(self, h, body: bytes) -> None:
        with self.lock:
            self.counter += 1
            room = self.new_ids.pop(0) if self.new_ids else f"sbx_{self.counter}"
            self.rooms.add(room)
        doc = {"id": room}
        if self.network_policy is not None:
            doc["network"] = {"policy": self.network_policy}
        doc["expires_at"] = self.expires_at or self._stamp(self.expires_in)
        doc.update(self.create_answer)
        self._send(h, 200, json.dumps(doc).encode())

    @staticmethod
    def _send(h, status: int, out: bytes) -> None:
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(out)))
        h.end_headers()
        h.wfile.write(out)

    def start(self) -> None:
        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_ANY(self):  # noqa: N802
                try:
                    api.handle(self)
                except (OSError, ValueError):
                    self.close_connection = True

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_ANY

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def release_all(self) -> None:
        for _rx, hold in self.holds:
            hold.release.set()

    def stop(self) -> None:
        self.release_all()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()


class Front:
    def __init__(self, tmp_path, monkeypatch, **server_kwargs) -> None:
        monkeypatch.setattr(rr, "tsm_provider", lambda: None)
        self.api = FakeApi()
        self.api.start()
        self.ledger = rr.Ledger("room-a", str(tmp_path))
        self.server = rr.Server(("127.0.0.1", 0), self.ledger, self.api.server.server_address[1], 1, KEY,
                                "/nonexistent.sock", **server_kwargs)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def call(self, method: str, path: str, body: bytes | dict | None = None, headers: dict | None = None,
             auth: bool = True, timeout: float = 30):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            hdrs = {**(AUTH if auth else {}), "Content-Type": "application/json", **(headers or {})}
            c.request(method, path, body=body, headers=hdrs)
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def create(self, body: dict | None = None, headers: dict | None = None):
        return self.call("POST", "/v1/sandboxes", body if body is not None else {"image": "repo/app:1"}, headers)

    def exec(self, room: str, cmd: str = "true"):
        return self.call("POST", f"/v1/sandboxes/{room}/exec", {"cmd": [cmd]})

    def put(self, room: str, data: bytes = b"x"):
        return self.call("PUT", f"/v1/sandboxes/{room}/files?path=%2Fwork%2Fa", data)

    def get_file(self, room: str):
        return self.call("GET", f"/v1/sandboxes/{room}/files?path=%2Fwork%2Fa")

    def delete(self, room: str):
        return self.call("DELETE", f"/v1/sandboxes/{room}")

    def room_receipts(self, room: str) -> dict:
        status, _h, out = self.call("GET", f"/v1/sandboxes/{room}/receipts")
        assert status == 200, out
        return json.loads(out)

    def statements(self, room: str) -> list[dict]:
        return [r["statement"] for r in self.room_receipts(room)["receipts"]]

    def close(self) -> None:
        self.api.release_all()
        self.server.shutdown()
        self.server.server_close()
        self.api.stop()


def receipt_of(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def in_thread(fn, *args, **kwargs):
    """Run fn on a thread; returns (thread, box) where box['result'] or box['error'] is set when it ends."""
    box: dict = {}

    def run():
        try:
            box["result"] = fn(*args, **kwargs)
        except BaseException as exc:  # noqa: BLE001 the test reads it
            box["error"] = exc

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box


def finish(t: threading.Thread, box: dict, timeout: float = 20):
    t.join(timeout)
    assert not t.is_alive(), "a request never finished"
    if "error" in box:
        raise box["error"]
    return box["result"]


def assert_idle(ledger) -> None:
    """No request still counted and no token held: a turn never leaks."""
    deadline = time.time() + 5
    while time.time() < deadline:
        with ledger.lock:
            if not getattr(ledger, "in_flight", {}) and not getattr(ledger, "busy", set()):
                return
        time.sleep(0.01)
    with ledger.lock:
        assert getattr(ledger, "in_flight", {}) == {}, "an in-flight count leaked"
        assert getattr(ledger, "busy", set()) == set(), "a token stayed held"
