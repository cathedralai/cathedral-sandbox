"""AB#385: a terminal WebSocket passes through the receipts front, with a signed open and a signed close.

Before this the front dropped Upgrade from what it forwarded, so a terminal socket through it reached the
room API as a plain GET and got 404. These tests run a real WebSocket client against the real front in
front of the real room API (a local shell standing in for the room's).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cathedral import agent_websocket as ws
from cathedral.agent_profile import agent_create_body
from cathedral.agent_pty import PtyProcess
from cathedral.sandbox_api import ApiKey, QuotaLimits
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication, run

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_ws_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"agent-k1"
AUTH = {"Authorization": "Bearer agent-k1"}


class _PtyProvider(InMemorySandboxProvider):
    def create_terminal(self, sandbox_id, *, cols=None, rows=None, mode=None, spawn=None):
        if mode == "pty":
            def spawn(c, r, on_output, on_exit):  # noqa: ANN001
                return PtyProcess(["/bin/sh", "-i"], cols=c, rows=r, on_output=on_output, on_exit=on_exit,
                                  env={"PS1": "$ ", "PATH": "/usr/bin:/bin", "TERM": "xterm"})
        return super().create_terminal(sandbox_id, cols=cols, rows=rows, mode=mode, spawn=spawn)


@pytest.fixture
def stack(tmp_path, monkeypatch):
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    provider = _PtyProvider(keys=[ApiKey(key="agent-k1", project="agent", max_running=8)],
                            limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
                            base_url="http://127.0.0.1")
    httpd, (_host, api_port) = run(SandboxApplication(provider), host="127.0.0.1", port=0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    front = rr.Server(("127.0.0.1", 0), ledger, api_port, 1, KEY, "/x.sock", pool_scan=False)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    try:
        yield front.server_address[1], ledger, api_port
    finally:
        front.shutdown()
        front.server_close()
        httpd.shutdown()
        httpd.server_close()
        provider.close()


def _call(port: int, method: str, path: str, doc=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=json.dumps(doc).encode() if doc is not None else None, headers=AUTH)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _terminal(port: int) -> tuple[str, str, str]:
    status, _h, out = _call(port, "POST", "/v1/sandboxes", agent_create_body())
    assert status in (200, 201, 202), out
    room = json.loads(out)["id"]
    status, _h, out = _call(port, "POST", f"/v1/sandboxes/{room}/terminals", {"mode": "pty", "cols": 80, "rows": 24})
    assert status == 201, out
    tid = json.loads(out)["id"]
    ticket = json.loads(_call(port, "POST", f"/v1/sandboxes/{room}/access-tickets", {})[2])["ticket"]
    return room, tid, ticket


def _handshake(port: int, path: str, ticket: str | None, *, auth: bool = True) -> tuple[socket.socket, bytes, bytes]:
    """Open a WebSocket handshake: (socket, head, bytes already read past the head)."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    req, _key = ws.iter_client_handshake(path, f"127.0.0.1:{port}", ticket=ticket)
    if auth:
        req = req[:-2] + b"Authorization: Bearer agent-k1\r\n\r\n"
    sock.sendall(req)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return sock, head, rest


def _headers(head: bytes) -> dict:
    out = {}
    for line in head.decode("latin-1").split("\r\n")[1:]:
        k, _, v = line.partition(":")
        out[k.strip().lower()] = v.strip()
    return out


def _statement(raw: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))["statement"]


def _payloads(raw: bytearray) -> bytes:
    """The binary payloads of the whole frames in *raw*, joined (output split over frames still matches)."""
    frames, _rest = ws.decode_frames(bytearray(raw))
    return b"".join(p for op, p in frames if op == ws.OP_BINARY)


def _wait_for(ledger, action: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with ledger.lock:
            hit = [r for r in ledger.chain if r["statement"]["action"] == action]
        if hit:
            return hit[-1]
        time.sleep(0.02)
    raise AssertionError(f"no {action} receipt")


def test_a_terminal_session_through_the_front_is_signed_open_and_closed(stack, tmp_path) -> None:
    port, ledger, _api_port = stack
    room, tid, ticket = _terminal(port)
    path = f"/v1/sandboxes/{room}/terminals/{tid}/ws"
    sock, head, got = _handshake(port, path, ticket)
    assert head.split(b"\r\n", 1)[0].split(b" ")[1] == b"101", head
    hdrs = _headers(head)
    opened = _statement(hdrs["x-room-receipt"])
    assert opened["action"] == "terminal_session_open" and opened["status"] == 101
    assert opened["sandbox_id"] == room and opened["terminal_id"] == tid and opened["target"] == f"GET {path}"
    assert len(opened["session_id"]) == 32
    assert hdrs["sec-websocket-protocol"] == f"cathedral.ticket.{ticket}"
    sent = b""
    received = bytearray(got)
    try:
        for frame in (ws.encode_frame(b"echo ws-", opcode=ws.OP_BINARY, masked=True),
                      ws.encode_frame(b"front-ok\n", opcode=ws.OP_BINARY, masked=True)):
            sock.sendall(frame)
            sent += frame
        deadline = time.monotonic() + 10
        while b"ws-front-ok" not in _payloads(received):
            assert time.monotonic() < deadline, bytes(received)
            received += sock.recv(65536)
        frame = ws.encode_frame(b"exit 0\n", opcode=ws.OP_BINARY, masked=True)
        sock.sendall(frame)
        sent += frame
        while True:  # the room closes the socket after the shell exits
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += chunk
    finally:
        sock.close()
    closed = _wait_for(ledger, "terminal_session_close")["statement"]
    assert closed["session_id"] == opened["session_id"] and closed["terminal_id"] == tid
    assert closed["session_open_receipt_sha256"] == next(
        r["receipt_sha256"] for r in ledger.chain if r["statement"]["action"] == "terminal_session_open")
    assert closed["client_bytes"] == len(sent) and closed["client_sha256"] == hashlib.sha256(sent).hexdigest()
    assert closed["room_bytes"] == len(received) and closed["room_sha256"] == hashlib.sha256(received).hexdigest()
    assert closed["close_reason"] in ("room_closed", "client_closed") and closed["duration_ms"] >= 0
    frames, _ = ws.decode_frames(bytearray(received))
    close = next(p for op, p in frames if op == ws.OP_CLOSE)
    assert struct.unpack("!H", close[:2])[0] == 1000 and close[2:] == b"terminal_exited"
    with ledger.lock:
        assert ledger.in_flight == {}
    att, chain = tmp_path / "att.json", tmp_path / "chain.json"
    att.write_text(json.dumps(ledger.attestation()))
    chain.write_text(json.dumps({"binding_sha256": ledger.binding_sha256, "head": ledger.head,
                                 "receipts": ledger.chain}))
    proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att),
                           "--receipts", str(chain)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["verdict"] == "PASS"


def test_a_caller_that_drops_the_socket_ends_the_session_with_a_close_receipt(stack) -> None:
    port, ledger, _api_port = stack
    room, tid, ticket = _terminal(port)
    sock, head, _got = _handshake(port, f"/v1/sandboxes/{room}/terminals/{tid}/ws", ticket)
    assert b" 101 " in head.split(b"\r\n", 1)[0] + b" "
    frame = ws.encode_frame(b"echo hi\n", opcode=ws.OP_BINARY, masked=True)
    sock.sendall(frame)
    time.sleep(0.2)
    sock.close()
    closed = _wait_for(ledger, "terminal_session_close")["statement"]
    assert closed["close_reason"] in ("client_closed", "room_closed") and closed["client_bytes"] == len(frame)
    deadline = time.monotonic() + 5
    while True:
        with ledger.lock:
            if ledger.in_flight == {}:
                break
        assert time.monotonic() < deadline
        time.sleep(0.02)


def test_a_spent_ticket_is_refused_by_the_api_and_the_refusal_is_signed(stack) -> None:
    port, ledger, _api_port = stack
    room, tid, ticket = _terminal(port)
    path = f"/v1/sandboxes/{room}/terminals/{tid}/ws"
    first, head, _ = _handshake(port, path, ticket)
    assert b"101" in head.split(b"\r\n", 1)[0]
    first.close()
    _wait_for(ledger, "terminal_session_close")
    sock, head, body = _handshake(port, path, ticket)
    want = int(_headers(head)["content-length"])
    while len(body) < want:
        body += sock.recv(65536)
    sock.close()
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    assert status == 401, head
    st = _statement(_headers(head)["x-room-receipt"])
    assert st["action"] == "terminal_session_open" and st["status"] == 401 and "session_id" not in st
    assert st["result_sha256"] == rr.sha(body) and b"access_ticket" in body


def test_without_the_key_nothing_is_forwarded_or_signed(stack) -> None:
    port, ledger, _api_port = stack
    room, tid, ticket = _terminal(port)
    before = len(ledger.chain)
    sock, head, _ = _handshake(port, f"/v1/sandboxes/{room}/terminals/{tid}/ws", ticket, auth=False)
    sock.close()
    assert b" 401 " in head.split(b"\r\n", 1)[0] + b" "
    assert len(ledger.chain) == before


def test_a_plain_get_of_the_socket_path_is_forwarded_as_before(stack) -> None:
    port, ledger, _api_port = stack
    room, tid, _ticket = _terminal(port)
    before = len(ledger.chain)
    status, headers, _out = _call(port, "GET", f"/v1/sandboxes/{room}/terminals/{tid}/ws")
    assert status == 404 and "X-Room-Receipt" not in headers and len(ledger.chain) == before


def test_no_answer_from_the_api_is_signed_as_502(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    api_port = dead.getsockname()[1]
    dead.close()
    ledger = rr.Ledger("room-a", str(tmp_path))
    front = rr.Server(("127.0.0.1", 0), ledger, api_port, 1, KEY, "/x.sock", pool_scan=False)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    try:
        sock, head, _ = _handshake(front.server_address[1], "/v1/sandboxes/sbx_1/terminals/t_1/ws", "tkt")
        sock.close()
        assert b" 502 " in head.split(b"\r\n", 1)[0] + b" "
        st = _statement(_headers(head)["x-room-receipt"])
        assert st["action"] == "terminal_session_open" and st["status"] == 502
        assert st["result_sha256"] == rr.sha(rr.WS_NO_ANSWER)
    finally:
        front.shutdown()
        front.server_close()


def test_the_socket_route_stays_closed_on_serial_and_unclaimed_rooms() -> None:
    assert rr.route_kind("GET", "/v1/sandboxes/sbx_1/terminals/t_1/ws") == "other"


@pytest.mark.parametrize(("headers", "want"), [
    ({"Upgrade": "websocket", "Connection": "Upgrade"}, True),
    ({"Upgrade": "WebSocket", "Connection": "keep-alive, Upgrade"}, True),
    ({"Upgrade": "websocket"}, False),
    ({"Connection": "Upgrade"}, False),
    ({"Upgrade": "h2c", "Connection": "Upgrade"}, False),
])
def test_wants_websocket(headers, want) -> None:
    from email.message import Message

    msg = Message()
    for k, v in headers.items():
        msg[k] = v
    assert rr.wants_websocket(msg) is want


# AB#405 step 3: the front's limits match the hotel PTY socket's, and the subprotocol passes through.

def test_the_front_idle_backstop_follows_the_hotel_pty_idle() -> None:
    from cathedral import sandbox_server

    assert rr.HOTEL_PTY_IDLE_SECONDS == sandbox_server.PTY_WS_IDLE_SECONDS
    # Later than the hotel, so the hotel's own idle close frame reaches the caller first.
    assert rr.HOTEL_PTY_IDLE_SECONDS < rr.WS_IDLE_SECONDS <= rr.HOTEL_PTY_IDLE_SECONDS + 60


def test_a_silent_caller_is_ended_by_the_front_with_an_idle_close_receipt(stack, monkeypatch) -> None:
    port, ledger, _api_port = stack
    monkeypatch.setattr(rr, "WS_IDLE_SECONDS", 0.5)
    room, tid, ticket = _terminal(port)
    sock, head, _got = _handshake(port, f"/v1/sandboxes/{room}/terminals/{tid}/ws", ticket)
    try:
        assert b" 101 " in head.split(b"\r\n", 1)[0] + b" "
        closed = _wait_for(ledger, "terminal_session_close")["statement"]
    finally:
        sock.close()
    assert closed["close_reason"] == "idle" and closed["client_bytes"] == 0


def test_an_input_frame_over_the_hotel_limit_gets_the_hotel_1009_through_the_front(stack) -> None:
    from cathedral import sandbox_server

    port, ledger, _api_port = stack
    room, tid, ticket = _terminal(port)
    sock, head, got = _handshake(port, f"/v1/sandboxes/{room}/terminals/{tid}/ws", ticket)
    assert b" 101 " in head.split(b"\r\n", 1)[0] + b" "
    # Far over the limit, so the hotel sees the unfinished frame pass 64 KiB + 16 before it is whole.
    big = ws.encode_frame(b"x" * (16 * sandbox_server.PTY_WS_MAX_FRAME), opcode=ws.OP_BINARY, masked=True)

    def push() -> None:
        try:
            sock.sendall(big)
        except OSError:
            pass  # the far side may close before the whole frame is in

    pusher = threading.Thread(target=push, daemon=True)
    pusher.start()
    received = bytearray(got)
    try:
        while True:
            try:
                chunk = sock.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            received += chunk
    finally:
        pusher.join(5)
        sock.close()
    frames, _ = ws.decode_frames(bytearray(received))
    close = next(p for op, p in frames if op == ws.OP_CLOSE)
    assert struct.unpack("!H", close[:2])[0] == 1009 and close[2:] == b"terminal_input_too_large", close
    closed = _wait_for(ledger, "terminal_session_close")["statement"]
    assert 0 < closed["client_bytes"] <= len(big)
    assert closed["room_bytes"] == len(received) and closed["room_sha256"] == hashlib.sha256(received).hexdigest()


def test_the_terminal_subprotocol_offer_reaches_the_api_and_its_choice_comes_back(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    api = socket.socket()
    api.bind(("127.0.0.1", 0))
    api.listen(1)
    seen: list[bytes] = []

    def answer() -> None:
        conn, _ = api.accept()
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += conn.recv(4096)
        seen.append(buf)
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     b"Sec-WebSocket-Accept: x\r\nSec-WebSocket-Protocol: cathedral.terminal.v1\r\n\r\n")
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    ledger = rr.Ledger("room-a", str(tmp_path))
    front = rr.Server(("127.0.0.1", 0), ledger, api.getsockname()[1], 1, KEY, "/x.sock", pool_scan=False)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    offer = "cathedral.terminal.v1, cathedral.ticket.tkt"
    try:
        sock = socket.create_connection(front.server_address, timeout=10)
        sock.sendall(("GET /v1/sandboxes/sbx_1/terminals/t_1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                      f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {offer}\r\n"
                      "Authorization: Bearer agent-k1\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        sock.close()
        head = buf.partition(b"\r\n\r\n")[0]
        assert b" 101 " in head.split(b"\r\n", 1)[0] + b" "
        assert _headers(head)["sec-websocket-protocol"] == "cathedral.terminal.v1"
        assert f"Sec-WebSocket-Protocol: {offer}\r\n".encode() in seen[0]
        assert b"Upgrade: websocket\r\n" in seen[0]
        _wait_for(ledger, "terminal_session_close")
    finally:
        front.shutdown()
        front.server_close()
        api.close()
