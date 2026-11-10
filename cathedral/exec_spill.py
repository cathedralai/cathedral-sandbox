"""Capped stdout and stderr published while one exec is still running.

Follow mode reads these bytes with the existing files route,
``GET /v1/sandboxes/{id}/files?path=/work/.cathedral-spill/{token}/stdout``.
The token is 32 lowercase hex characters, the same id the caller sent as
``spill_token`` on ``POST /exec``. The bytes are the prefix the exec answer
keeps, at most ``cap`` per stream. The command's own argv is unchanged.
"""

from __future__ import annotations

import re
import threading

from cathedral.sandbox_api import spill_token_ok

_PATH = re.compile(r"^/work/\.cathedral-spill/([0-9a-f]{32})/(stdout|stderr)$")

_registry = threading.Lock()
_spills: dict[tuple[str, str], StreamSpill] = {}


def spill_path(token: str, stream: str) -> str:
    return f"/work/.cathedral-spill/{token}/{stream}"


def spill_path_parts(path: str) -> tuple[str, str] | None:
    match = _PATH.fullmatch(path)
    if match is None:
        return None
    return match.group(1), match.group(2)


class StreamSpill:
    """One exec's stdout and stderr. A reader may copy either stream while the drainer appends."""

    def __init__(self, cap: int) -> None:
        self._cap = cap
        self._lock = threading.Lock()
        self._streams = {"stdout": bytearray(), "stderr": bytearray()}

    def add(self, stream: str, data: bytes) -> None:
        with self._lock:
            buf = self._streams[stream]
            room = self._cap - len(buf)
            if room <= 0 or not data:
                return
            buf.extend(data[:room])

    def read(self, stream: str) -> bytes:
        with self._lock:
            return bytes(self._streams[stream])


def open_spill(sandbox_id: str, token: str, cap: int) -> StreamSpill | None:
    if not spill_token_ok(token):
        return None
    spill = StreamSpill(cap)
    with _registry:
        _spills[(sandbox_id, token)] = spill
    return spill


def close_spill(sandbox_id: str, token: str) -> None:
    with _registry:
        _spills.pop((sandbox_id, token), None)


def read_spill(sandbox_id: str, token: str, stream: str) -> bytes | None:
    with _registry:
        spill = _spills.get((sandbox_id, token))
    if spill is None:
        return None
    return spill.read(stream)
