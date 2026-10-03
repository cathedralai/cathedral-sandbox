"""Minimal RFB (VNC) protocol helpers for Agent IDE desktop WebSocket (G5).

Uses VNC Authentication (security type 2). SecurityType None is refused —
desktop streams must prove knowledge of the access ticket at the RFB layer too.
"""

from __future__ import annotations

import os
import struct
from typing import Callable


# RFB 3.8 with SecurityType VNC Auth (2). Tiny 8x8 solid framebuffer for reference runtime.
RFB_VERSION = b"RFB 003.008\n"
SECURITY_TYPE_NONE = 1
SECURITY_TYPE_VNC = 2
FB_WIDTH = 8
FB_HEIGHT = 8
PIXEL_FORMAT = struct.pack(
    "!BBBBHHHBBBBBB",
    32,  # bits-per-pixel
    24,  # depth
    0,  # big-endian
    1,  # true-colour
    255,
    255,
    255,  # max r/g/b
    16,
    8,
    0,  # shifts
    0,
    0,
    0,  # padding
)
SERVER_NAME = b"cathedral-agent-desktop"


def server_init() -> bytes:
    name_len = struct.pack("!I", len(SERVER_NAME))
    return struct.pack("!HH", FB_WIDTH, FB_HEIGHT) + PIXEL_FORMAT + name_len + SERVER_NAME


def framebuffer_update_solid(color_bgra: bytes = b"\x22\x66\xaa\xff") -> bytes:
    """One full-screen solid rectangle (encoding 0 = raw)."""
    assert len(color_bgra) == 4
    pixels = color_bgra * (FB_WIDTH * FB_HEIGHT)
    header = struct.pack("!BxH", 0, 1)
    rect = struct.pack("!HHHHi", 0, 0, FB_WIDTH, FB_HEIGHT, 0)  # raw encoding
    return header + rect + pixels


def handle_client_messages(buf: bytearray, send: Callable[[bytes], None]) -> None:
    """Consume RFB client messages; respond to FramebufferUpdateRequest."""
    while buf:
        msg_type = buf[0]
        if msg_type == 3:  # FramebufferUpdateRequest
            if len(buf) < 10:
                return
            del buf[:10]
            send(framebuffer_update_solid())
        elif msg_type == 4:  # KeyEvent
            if len(buf) < 8:
                return
            del buf[:8]
        elif msg_type == 5:  # PointerEvent
            if len(buf) < 6:
                return
            del buf[:6]
        elif msg_type == 2:  # SetEncodings
            if len(buf) < 4:
                return
            n = struct.unpack("!xH", buf[1:4])[0]
            need = 4 + 4 * n
            if len(buf) < need:
                return
            del buf[:need]
        elif msg_type == 0:  # SetPixelFormat
            if len(buf) < 20:
                return
            del buf[:20]
        else:
            del buf[0]


def _bit_reverse(byte: int) -> int:
    """VNC passwords use bit-reversed DES key bytes."""
    byte = ((byte & 0xF0) >> 4) | ((byte & 0x0F) << 4)
    byte = ((byte & 0xCC) >> 2) | ((byte & 0x33) << 2)
    byte = ((byte & 0xAA) >> 1) | ((byte & 0x55) << 1)
    return byte & 0xFF


def _vnc_password_key(password: str) -> bytes:
    raw = password.encode("utf-8")[:8].ljust(8, b"\x00")
    return bytes(_bit_reverse(b) for b in raw)


# --- Minimal DES-ECB (VNC wire format) ---

_IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
)
_FP = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
)
_E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)
_P = (
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
)
_PC1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
)
_PC2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_SBOXES = (
    (
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ),
    (
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ),
    (
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ),
    (
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ),
    (
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ),
    (
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ),
    (
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ),
    (
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ),
)


def _permute(block: int, table: tuple[int, ...], nbits: int) -> int:
    out = 0
    for i, src in enumerate(table):
        if block & (1 << (nbits - src)):
            out |= 1 << (len(table) - 1 - i)
    return out


def _des_subkeys(key8: bytes) -> list[int]:
    key = int.from_bytes(key8, "big")
    key = _permute(key, _PC1, 64)
    c, d = key >> 28, key & ((1 << 28) - 1)
    subkeys: list[int] = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & ((1 << 28) - 1)
        d = ((d << shift) | (d >> (28 - shift))) & ((1 << 28) - 1)
        subkeys.append(_permute((c << 28) | d, _PC2, 56))
    return subkeys


def _f(r: int, subkey: int) -> int:
    e = _permute(r, _E, 32)
    x = e ^ subkey
    s = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 1)
        col = (chunk >> 1) & 0xF
        s = (s << 4) | _SBOXES[i][row * 16 + col]
    return _permute(s, _P, 32)


def _des_ecb_encrypt(block8: bytes, key8: bytes) -> bytes:
    if len(block8) != 8 or len(key8) != 8:
        raise ValueError("DES block/key must be 8 bytes")
    subkeys = _des_subkeys(key8)
    block = int.from_bytes(block8, "big")
    block = _permute(block, _IP, 64)
    l, r = block >> 32, block & 0xFFFFFFFF
    for sk in subkeys:
        l, r = r, l ^ _f(r, sk)
    return _permute((r << 32) | l, _FP, 64).to_bytes(8, "big")


def vnc_encrypt_challenge(challenge: bytes, password: str) -> bytes:
    """Encrypt a 16-byte VNC challenge with the ticket-derived DES key."""
    if len(challenge) != 16:
        raise ValueError("VNC challenge must be 16 bytes")
    key = _vnc_password_key(password)
    return _des_ecb_encrypt(challenge[:8], key) + _des_ecb_encrypt(challenge[8:], key)


def new_vnc_challenge() -> bytes:
    return os.urandom(16)


def security_offer_vnc() -> bytes:
    """SecurityTypes message: only VNC Authentication (type 2)."""
    return bytes([1, SECURITY_TYPE_VNC])


def security_result_ok() -> bytes:
    return struct.pack("!I", 0)


def security_result_fail() -> bytes:
    return struct.pack("!I", 1)


def verify_vnc_response(challenge: bytes, response: bytes, password: str) -> bool:
    if len(challenge) != 16 or len(response) != 16:
        return False
    expected = vnc_encrypt_challenge(challenge, password)
    if len(expected) != len(response):
        return False
    diff = 0
    for x, y in zip(expected, response):
        diff |= x ^ y
    return diff == 0


def security_handshake_none() -> list[bytes]:
    """Removed — SecurityType None is a gap. Callers must use VNC auth."""
    raise RuntimeError(
        "SecurityType None is disabled; use security_offer_vnc + VNC challenge/response"
    )


__all__ = [
    "FB_HEIGHT",
    "FB_WIDTH",
    "RFB_VERSION",
    "SECURITY_TYPE_NONE",
    "SECURITY_TYPE_VNC",
    "framebuffer_update_solid",
    "handle_client_messages",
    "new_vnc_challenge",
    "security_handshake_none",
    "security_offer_vnc",
    "security_result_fail",
    "security_result_ok",
    "server_init",
    "verify_vnc_response",
    "vnc_encrypt_challenge",
]
