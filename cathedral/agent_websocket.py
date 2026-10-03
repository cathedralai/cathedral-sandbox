"""Minimal RFC 6455 WebSocket helpers for Agent IDE terminal/desktop (stdlib only)."""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from typing import Iterable, Mapping


WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


def accept_key(sec_websocket_key: str) -> str:
    digest = hashlib.sha1((sec_websocket_key.strip() + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def handshake_response(sec_websocket_key: str, *, protocol: str | None = None) -> bytes:
    lines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Accept: {accept_key(sec_websocket_key)}",
    ]
    if protocol:
        lines.append(f"Sec-WebSocket-Protocol: {protocol}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii")


def encode_frame(payload: bytes, *, opcode: int = OP_BINARY, masked: bool = False) -> bytes:
    if opcode not in (OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG, OP_CONTINUATION):
        raise ValueError(f"unsupported opcode {opcode}")
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    mask_bit = 0x80 if masked else 0x00
    n = len(payload)
    if n < 126:
        header.append(mask_bit | n)
    elif n < (1 << 16):
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", n))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", n))
    if masked:
        mask = os.urandom(4)
        header.extend(mask)
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return bytes(header) + data
    return bytes(header) + payload


def decode_frames(buffer: bytearray) -> tuple[list[tuple[int, bytes]], bytearray]:
    """Parse complete frames from *buffer*; return (frames, remainder)."""
    frames: list[tuple[int, bytes]] = []
    while True:
        if len(buffer) < 2:
            break
        b0, b1 = buffer[0], buffer[1]
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        offset = 2
        if length == 126:
            if len(buffer) < 4:
                break
            length = struct.unpack("!H", buffer[2:4])[0]
            offset = 4
        elif length == 127:
            if len(buffer) < 10:
                break
            length = struct.unpack("!Q", buffer[2:10])[0]
            offset = 10
        mask = b""
        if masked:
            if len(buffer) < offset + 4:
                break
            mask = bytes(buffer[offset : offset + 4])
            offset += 4
        if len(buffer) < offset + length:
            break
        payload = bytes(buffer[offset : offset + length])
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        del buffer[: offset + length]
        frames.append((opcode, payload))
        if opcode == OP_CLOSE:
            break
    return frames, buffer


def iter_client_handshake(
    path: str,
    host: str,
    *,
    ticket: str | None = None,
    key: bytes | None = None,
    ticket_in_query: bool = False,
) -> tuple[bytes, str]:
    """Build a client Upgrade request; return (request_bytes, sec_websocket_key).

    Tickets go in ``X-Cathedral-Access-Ticket`` (and optional Sec-WebSocket-Protocol).
    Query-string tickets are refused by the server unless explicitly allowed; pass
    ``ticket_in_query=True`` only for legacy allowlisted tests.
    """
    sec = base64.b64encode(key or os.urandom(16)).decode("ascii")
    target = path if (ticket is None or not ticket_in_query) else f"{path}?ticket={ticket}"
    headers = [
        f"GET {target} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {sec}",
        "Sec-WebSocket-Version: 13",
    ]
    if ticket and not ticket_in_query:
        headers.append(f"X-Cathedral-Access-Ticket: {ticket}")
        # Also advertise as a subprotocol so browser clients can pass it.
        headers.append(f"Sec-WebSocket-Protocol: cathedral.ticket.{ticket}")
    headers.append("")
    headers.append("")
    return "\r\n".join(headers).encode("ascii"), sec


def extract_access_ticket(
    headers: Mapping[str, str],
    query: Mapping[str, list[str]],
) -> tuple[str | None, str | None]:
    """Return ``(ticket, error_code)``. Prefer header / subprotocol over query.

    Query tickets are rejected unless ``CATHEDRAL_WS_ALLOW_TICKET_QUERY=1``.
    """
    for name in ("X-Cathedral-Access-Ticket", "x-cathedral-access-ticket"):
        raw = headers.get(name)
        if raw and raw.strip():
            return raw.strip(), None
    proto = headers.get("Sec-WebSocket-Protocol") or headers.get("sec-websocket-protocol") or ""
    for part in proto.split(","):
        part = part.strip()
        if part.startswith("cathedral.ticket."):
            ticket = part[len("cathedral.ticket.") :]
            if ticket:
                return ticket, None
    q = (query.get("ticket") or [None])[0]
    if q:
        if os.environ.get("CATHEDRAL_WS_ALLOW_TICKET_QUERY") == "1":
            return q, None
        return None, "ticket_query_forbidden"
    return None, None


def read_http_response_headers(sock_file) -> tuple[int, dict[str, str]]:
    status_line = sock_file.readline()
    if not status_line:
        raise ConnectionError("empty response")
    parts = status_line.decode("latin-1", errors="replace").split(" ", 2)
    code = int(parts[1]) if len(parts) > 1 else 0
    headers: dict[str, str] = {}
    while True:
        line = sock_file.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        raw = line.decode("latin-1", errors="replace").rstrip("\r\n")
        if ":" in raw:
            k, _, v = raw.partition(":")
            headers[k.strip().lower()] = v.strip()
    return code, headers


__all__ = [
    "OP_BINARY",
    "OP_CLOSE",
    "OP_PING",
    "OP_PONG",
    "OP_TEXT",
    "accept_key",
    "decode_frames",
    "encode_frame",
    "extract_access_ticket",
    "handshake_response",
    "iter_client_handshake",
    "read_http_response_headers",
]
