"""Who owns a hotel object (workspaces #305, secrets #304).

Owner: a short hash of the hotel API key that made the call, plus the broker
guest id. Two hotel keys never share an owner, even with the same guest id.

The broker sends the guest id in the X-Cathedral-Guest header. It builds each
hotel request itself and copies no guest header, so a guest cannot set it.
A create through the broker also carries the guest id in the broker_guest
label; the hotel uses the label when the header is absent.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from cathedral.sandbox_provider import SandboxOpError

GUEST_HEADER = "X-Cathedral-Guest"
BROKER_GUEST_LABEL = "broker_guest"
GUEST_RE = re.compile(r"^[A-Za-z0-9_.:-]{0,128}$")


def owner_id(api_key: str | None, guest: str | None) -> str:
    key = hashlib.sha256((api_key or "").encode("utf-8")).hexdigest()[:16]
    return f"{key}:{guest or ''}"


def owner_hash(owner: str) -> str:
    """A fixed-length name for an owner, safe in a path or a URL."""
    return hashlib.sha256(owner.encode("utf-8")).hexdigest()


def guest_from(headers: Any, labels: Any = None) -> str:
    """The broker guest id of a call: the header, else the room label."""
    raw = ""
    if headers is not None:
        for k, v in dict(headers).items():
            if k.lower() == GUEST_HEADER.lower():
                raw = str(v)
                break
    if not raw and isinstance(labels, dict):
        raw = str(labels.get(BROKER_GUEST_LABEL) or "")
    if not GUEST_RE.fullmatch(raw):
        raise SandboxOpError("invalid_guest", 400, "the guest id has characters that are not allowed")
    return raw


__all__ = ["BROKER_GUEST_LABEL", "GUEST_HEADER", "GUEST_RE", "guest_from", "owner_hash", "owner_id"]
