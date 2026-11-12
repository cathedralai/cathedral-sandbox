"""Allowlisted image start commands for sealed rooms (AB#709).

The measured guest carries ``start_commands.json``. A create with
``start: "image"`` may start only when the image digest and its Docker
ENTRYPOINT+CMD match an entry exactly.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from cathedral.sandbox_image_owners import IMAGE_ID_RE, normalize_image_id

FORMAT_VERSION = 1
START_COMMANDS_PATH = Path(__file__).with_name("start_commands.json")
INSTALLED_START_COMMANDS_PATH = Path("/usr/share/cathedral/start_commands.json")


class StartCommandsError(ValueError):
    """The allowlist file is missing or invalid (guest must not start)."""


@dataclass(frozen=True)
class StartCommandEntry:
    image_digest: str
    argv: tuple[str, ...]
    note: str = ""


@dataclass(frozen=True)
class StartCommandAllowlist:
    entries: tuple[StartCommandEntry, ...]

    def allows(self, image_digest: str, argv: tuple[str, ...]) -> bool:
        digest = normalize_image_id(image_digest)
        if digest is None:
            return False
        for entry in self.entries:
            if entry.image_digest == digest and entry.argv == argv:
                return True
        return False


def start_commands_path() -> Path:
    override = os.environ.get("CATHEDRAL_START_COMMANDS_PATH", "").strip()
    if override:
        return Path(override)
    if INSTALLED_START_COMMANDS_PATH.is_file():
        return INSTALLED_START_COMMANDS_PATH
    return START_COMMANDS_PATH


def image_config_argv(inspected: dict[str, Any]) -> tuple[str, ...] | None:
    """Docker ENTRYPOINT + CMD as one argv list, or None when the image defines neither."""
    cfg = inspected.get("Config")
    if not isinstance(cfg, dict):
        return None
    entry = cfg.get("Entrypoint")
    cmd = cfg.get("Cmd")
    parts: list[str] = []
    if isinstance(entry, list) and entry:
        if not all(isinstance(part, str) for part in entry):
            return None
        parts.extend(entry)
    if isinstance(cmd, list) and cmd:
        if not all(isinstance(part, str) for part in cmd):
            return None
        parts.extend(cmd)
    return tuple(parts) if parts else None


def image_digest_for_allowlist(inspected: dict[str, Any]) -> str | None:
    """Digest used to match the allowlist and the create receipt's image_digest."""
    for repo_digest in inspected.get("RepoDigests") or []:
        if not isinstance(repo_digest, str):
            continue
        tail = repo_digest.rsplit("@", 1)[-1]
        normalized = normalize_image_id(tail)
        if normalized is not None:
            return normalized
    return normalize_image_id(str(inspected.get("Id") or ""))


def _parse_entries(raw: Any) -> list[StartCommandEntry]:
    if not isinstance(raw, list):
        raise StartCommandsError("entries must be a list")
    entries: list[StartCommandEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            raise StartCommandsError("each allowlist entry must be an object")
        digest = item.get("image_digest")
        if not isinstance(digest, str) or IMAGE_ID_RE.fullmatch(digest.strip().lower()) is None:
            raise StartCommandsError("image_digest must be sha256:<64 lowercase hex>")
        argv_raw = item.get("argv")
        if not isinstance(argv_raw, list) or not argv_raw or not all(isinstance(part, str) for part in argv_raw):
            raise StartCommandsError("argv must be a non-empty list of strings")
        note = item.get("note", "")
        if note is not None and not isinstance(note, str):
            raise StartCommandsError("note must be a string when present")
        entries.append(
            StartCommandEntry(
                image_digest=digest.strip().lower(),
                argv=tuple(argv_raw),
                note=note or "",
            )
        )
    return entries


def load_start_commands(path: Path | None = None) -> StartCommandAllowlist:
    """Load and validate the allowlist. Any error refuses guest startup."""
    target = path or start_commands_path()
    try:
        raw_text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise StartCommandsError(f"start_commands.json is missing or unreadable at {target}") from exc
    try:
        doc = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise StartCommandsError(f"start_commands.json is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise StartCommandsError("start_commands.json must be one JSON object")
    version = doc.get("version")
    if version != FORMAT_VERSION:
        raise StartCommandsError(f"start_commands.json version must be {FORMAT_VERSION}, not {version!r}")
    entries = tuple(_parse_entries(doc.get("entries")))
    return StartCommandAllowlist(entries=entries)


def start_command_sha256(argv: Iterable[str]) -> str:
    """sha256 hex of the canonical JSON encoding of the argv list (matches receipts)."""
    raw = json.dumps(list(argv), separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()
