"""WebSocket PTY + RFB desktop streams for Agent IDE (closes Phase 2 open items)."""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from cathedral import agent_rfb
from cathedral import agent_websocket as ws
from cathedral.agent_profile import agent_create_body
from cathedral.agent_websocket import accept_key
from cathedral.sandbox_api import ApiKey, QuotaLimits
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication, run


AUTH = {"Authorization": "Bearer agent-k1"}


@pytest.fixture
def live_app(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CATHEDRAL_AGENT_DESKTOP", "1")
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key="agent-k1", project="agent", max_running=8)],
        limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
        base_url="http://127.0.0.1",
    )
    app = SandboxApplication(provider)
    httpd, (host, port) = run(app, host="127.0.0.1", port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    # Give the listener a moment.
    time.sleep(0.05)
    try:
        yield app, host, int(port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        provider.close()


def _create(app: SandboxApplication) -> str:
    r = app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(agent_create_body()).encode())
    assert r.status == 202, r.body
    return json.loads(r.body)["id"]


def test_websocket_frame_roundtrip_and_accept_key() -> None:
    payload = b"hello"
    frame = ws.encode_frame(payload, opcode=ws.OP_TEXT, masked=True)
    frames, rest = ws.decode_frames(bytearray(frame))
    assert rest == b""
    assert frames == [(ws.OP_TEXT, payload)]
    assert accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_terminal_websocket_pty(live_app) -> None:
    app, host, port = live_app
    sid = _create(app)
    tid = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, b"{}").body)["id"]
    ticket = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/access-tickets", AUTH, b"{}").body)["ticket"]

    sock = socket.create_connection((host, port), timeout=5)
    try:
        req, sec = ws.iter_client_handshake(
            f"/v1/sandboxes/{sid}/terminals/{tid}/ws", f"{host}:{port}", ticket=ticket
        )
        sock.sendall(req)
        # Read HTTP 101 headers
        header_buf = b""
        while b"\r\n\r\n" not in header_buf:
            header_buf += sock.recv(1)
        assert b"101" in header_buf.split(b"\r\n", 1)[0]
        assert accept_key(sec).encode() in header_buf

        # Banner from connect
        raw = sock.recv(4096)
        frames, _ = ws.decode_frames(bytearray(raw))
        assert frames and b"connected" in frames[0][1]

        sock.sendall(ws.encode_frame(b"printf ws-pty-ok", opcode=ws.OP_TEXT, masked=True))
        deadline = time.time() + 5
        got = b""
        while time.time() < deadline and b"ws-pty-ok" not in got:
            chunk = sock.recv(4096)
            if not chunk:
                break
            frames, _ = ws.decode_frames(bytearray(chunk))
            for _, payload in frames:
                got += payload
        assert b"ws-pty-ok" in got
        sock.sendall(ws.encode_frame(b"", opcode=ws.OP_CLOSE, masked=True))
    finally:
        sock.close()


def test_desktop_rfb_websocket(live_app) -> None:
    app, host, port = live_app
    sid = _create(app)
    desk = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/desktop", AUTH, b"").body)
    assert desk["available"] is True and desk["listening"] is True
    ticket = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/access-tickets", AUTH, b"{}").body)["ticket"]

    sock = socket.create_connection((host, port), timeout=5)
    try:
        req, _sec = ws.iter_client_handshake(
            f"/v1/sandboxes/{sid}/desktop/ws", f"{host}:{port}", ticket=ticket
        )
        sock.sendall(req)
        header_buf = b""
        while b"\r\n\r\n" not in header_buf:
            header_buf += sock.recv(1)
        assert b"101" in header_buf.split(b"\r\n", 1)[0]

        # Server sends RFB version as first binary frame
        raw = sock.recv(4096)
        frames, _ = ws.decode_frames(bytearray(raw))
        assert frames and frames[0][1] == agent_rfb.RFB_VERSION

        sock.sendall(ws.encode_frame(agent_rfb.RFB_VERSION, opcode=ws.OP_BINARY, masked=True))
        # Security offer (VNC only)
        raw = sock.recv(4096)
        frames, _ = ws.decode_frames(bytearray(raw))
        assert frames and frames[0][1] == agent_rfb.security_offer_vnc()

        # Select VNC auth
        sock.sendall(ws.encode_frame(bytes([agent_rfb.SECURITY_TYPE_VNC]), opcode=ws.OP_BINARY, masked=True))
        raw = sock.recv(4096)
        frames, _ = ws.decode_frames(bytearray(raw))
        assert frames and len(frames[0][1]) == 16
        challenge = frames[0][1]
        response = agent_rfb.vnc_encrypt_challenge(challenge, ticket)
        sock.sendall(ws.encode_frame(response, opcode=ws.OP_BINARY, masked=True))

        # Collect SecurityResult + ServerInit
        collected = b""
        deadline = time.time() + 5
        while time.time() < deadline and b"cathedral-agent-desktop" not in collected:
            chunk = sock.recv(8192)
            if not chunk:
                break
            frames, _ = ws.decode_frames(bytearray(chunk))
            for _, payload in frames:
                collected += payload
        assert b"cathedral-agent-desktop" in collected

        # FramebufferUpdateRequest → solid update
        fbur = bytes([3, 0]) + struct_pack_fbur()
        sock.sendall(ws.encode_frame(fbur, opcode=ws.OP_BINARY, masked=True))
        raw = sock.recv(65536)
        frames, _ = ws.decode_frames(bytearray(raw))
        assert frames and frames[0][0] == ws.OP_BINARY and len(frames[0][1]) > 16
        sock.sendall(ws.encode_frame(b"", opcode=ws.OP_CLOSE, masked=True))
    finally:
        sock.close()


def struct_pack_fbur() -> bytes:
    import struct

    # incremental=0, x,y,w,h
    return struct.pack("!HHHH", 0, 0, agent_rfb.FB_WIDTH, agent_rfb.FB_HEIGHT)


def test_rfb_helpers_unit() -> None:
    offer = agent_rfb.security_offer_vnc()
    assert offer == bytes([1, agent_rfb.SECURITY_TYPE_VNC])
    challenge = b"\x01" * 16
    password = "sat_test_ticket_password"
    response = agent_rfb.vnc_encrypt_challenge(challenge, password)
    assert agent_rfb.verify_vnc_response(challenge, response, password)
    assert not agent_rfb.verify_vnc_response(challenge, response, "wrong")
    with pytest.raises(RuntimeError):
        agent_rfb.security_handshake_none()
    update = agent_rfb.framebuffer_update_solid()
    assert update[0] == 0 and len(update) > 20


def test_ticket_query_string_rejected(live_app) -> None:
    app, host, port = live_app
    sid = _create(app)
    tid = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, b"{}").body)["id"]
    ticket = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/access-tickets", AUTH, b"{}").body)["ticket"]

    sock = socket.create_connection((host, port), timeout=5)
    try:
        req, _ = ws.iter_client_handshake(
            f"/v1/sandboxes/{sid}/terminals/{tid}/ws",
            f"{host}:{port}",
            ticket=ticket,
            ticket_in_query=True,
        )
        sock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += sock.recv(1)
        # Drain body if present
        sock.settimeout(0.5)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except (TimeoutError, socket.timeout, BlockingIOError, OSError):
            pass
        assert b"401" in buf.split(b"\r\n", 1)[0]
        assert b"ticket_query_forbidden" in buf
    finally:
        sock.close()
