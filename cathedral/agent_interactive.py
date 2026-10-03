"""Agent IDE interactive helpers — tickets, terminal caps, template names (G4–G6)."""

from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


TICKET_TTL_DEFAULT = 60
TICKET_TTL_MIN = 1
TICKET_TTL_MAX = 300
TERMINAL_COLS_DEFAULT = 80
TERMINAL_ROWS_DEFAULT = 24
TERMINAL_DIM_MIN = 1
TERMINAL_DIM_MAX = 1000
_TEMPLATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_ticket_id() -> str:
    return "sat_" + secrets.token_urlsafe(18)


def new_terminal_id() -> str:
    return "term-" + secrets.token_hex(4)


def new_template_uid(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24] or "tmpl"
    return f"sbt-{slug}-{secrets.token_hex(3)}"


def validate_ticket_ttl(ttl_sec: int | None) -> int:
    ttl = TICKET_TTL_DEFAULT if ttl_sec is None else int(ttl_sec)
    if ttl < TICKET_TTL_MIN or ttl > TICKET_TTL_MAX:
        raise ValueError("ttl_sec must be between 1 and 300")
    return ttl


def validate_terminal_size(cols: int | None, rows: int | None) -> tuple[int, int]:
    c = TERMINAL_COLS_DEFAULT if cols is None else int(cols)
    r = TERMINAL_ROWS_DEFAULT if rows is None else int(rows)
    if not (TERMINAL_DIM_MIN <= c <= TERMINAL_DIM_MAX and TERMINAL_DIM_MIN <= r <= TERMINAL_DIM_MAX):
        raise ValueError("cols and rows must be between 1 and 1000")
    return c, r


def validate_template_name(name: str) -> str:
    if not isinstance(name, str) or _TEMPLATE_NAME_RE.fullmatch(name) is None:
        raise ValueError("template name must be 1–64 of [A-Za-z0-9._-] starting alnum")
    return name


@dataclass
class AccessTicket:
    ticket: str
    sandbox_id: str
    expires_at: float
    consumed: bool = False

    def alive(self, now: float | None = None) -> bool:
        t = time.time() if now is None else now
        return not self.consumed and t <= self.expires_at

    def to_document(self) -> dict[str, Any]:
        return {
            "ticket": self.ticket,
            "expires_at": datetime.fromtimestamp(self.expires_at, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
        }


@dataclass
class TerminalSession:
    id: str
    sandbox_id: str
    cols: int
    rows: int
    started_at: datetime
    exited: bool = False
    exit_code: int | None = None
    output: bytearray = field(default_factory=bytearray)
    input_buf: bytearray = field(default_factory=bytearray)
    connected: bool = False

    def to_document(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "id": self.id,
            "cols": self.cols,
            "rows": self.rows,
            "started_at": self.started_at.isoformat().replace("+00:00", "Z"),
            "exited": self.exited,
            "connected": self.connected,
        }
        if self.exited:
            doc["exit_code"] = self.exit_code
        return doc


@dataclass
class SandboxTemplate:
    uid: str
    name: str
    display_name: str
    description: str
    kind: str  # FRESH | USER
    status: str  # PENDING | READY | FAILED
    source_sandbox_id: str | None
    image_ref: str
    resource_name: str = "cpu-small"
    owner_api_key: str | None = None
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)

    def to_document(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "kind": self.kind,
            "status": self.status,
            "source_sandbox_id": self.source_sandbox_id,
            "image_ref": self.image_ref,
            "resource_name": self.resource_name,
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
        }


__all__ = [
    "AccessTicket",
    "SandboxTemplate",
    "TICKET_TTL_DEFAULT",
    "TICKET_TTL_MAX",
    "TICKET_TTL_MIN",
    "TerminalSession",
    "new_template_uid",
    "new_terminal_id",
    "new_ticket_id",
    "utc_now",
    "validate_template_name",
    "validate_terminal_size",
    "validate_ticket_ttl",
]
