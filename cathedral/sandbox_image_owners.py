"""Per-guest ownership of hotel-local Docker images (AB#650 part 2 / Gate S.1).

A hotel keeps one Docker image store for every broker guest that lands on it.
Snapshot commits and private pulls therefore leave artifacts that another guest
on the same hotel key could name. This module is the hotel's durable grant
table: only a scope that earned a grant may start that immutable image id.

Grants are keyed by Docker config/image id (``sha256:<64 hex>``), never by a
mutable tag. Registry authorization is a successful pull under the caller's
credentials (or anonymous access); a cache hit alone is not a grant. Missing,
corrupt, or incomplete metadata grants nothing.

Settings:
  CATHEDRAL_IMAGE_OWNERS_PATH   JSON file for the grant table (default under
                                HOME: ``.cathedral-image-owners.json``)
  CATHEDRAL_SHARED_HOTEL_BUILDS ``refuse`` (default on sealed hotels via
                                room-kit) or ``allow``. When ``refuse``, both
                                hotel build routes answer 403
                                ``shared_hotel_build_refused`` before Docker
                                runs (Option A).
"""

from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from typing import Any

from cathedral.sandbox_owner import owner_hash
from cathedral.sandbox_provider import SandboxOpError

FORMAT_VERSION = 1
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROVENANCE = frozenset({"registry", "snapshot", "build"})


def owners_path() -> Path:
    raw = os.environ.get("CATHEDRAL_IMAGE_OWNERS_PATH", "").strip()
    if raw:
        return Path(raw)
    return Path(os.environ.get("HOME", "/tmp")) / ".cathedral-image-owners.json"


def shared_hotel_builds_refused() -> bool:
    """True when hotel-side builds must not run (Option A fail-closed default)."""
    raw = os.environ.get("CATHEDRAL_SHARED_HOTEL_BUILDS", "").strip().lower()
    if raw == "allow":
        return False
    if raw == "refuse":
        return True
    # Unset: refuse only when an owners path was explicitly configured for a
    # sealed/shared hotel roll. Plain unsealed hotels keep builds.
    return bool(os.environ.get("CATHEDRAL_IMAGE_OWNERS_PATH", "").strip())


def refuse_shared_hotel_build() -> None:
    if shared_hotel_builds_refused():
        raise SandboxOpError(
            "shared_hotel_build_refused",
            403,
            "this shared hotel does not build images; push a registry image and name it by tag or digest",
        )


def normalize_image_id(raw: str | None) -> str | None:
    if not raw:
        return None
    value = raw.strip().lower()
    if IMAGE_ID_RE.fullmatch(value):
        return value
    return None


class ImageOwnerStore:
    """Durable map of image id -> allowed owner hashes.

    Writes replace the whole file under an exclusive lock. A failed write fails
    the calling operation; a missing or corrupt file grants nothing.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or owners_path()
        self._lock = threading.Lock()
        self._grants: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            self._grants = {}
            return
        except (OSError, ValueError):
            self._grants = {}
            return
        if not isinstance(data, dict) or data.get("version") != FORMAT_VERSION:
            self._grants = {}
            return
        images = data.get("images")
        if not isinstance(images, dict):
            self._grants = {}
            return
        out: dict[str, dict[str, Any]] = {}
        for image_id, entry in images.items():
            nid = normalize_image_id(str(image_id))
            if nid is None or not isinstance(entry, dict):
                continue
            owners = entry.get("owners")
            if not isinstance(owners, list):
                continue
            cleaned = sorted({str(o) for o in owners if isinstance(o, str) and o})
            if not cleaned:
                continue
            prov = entry.get("provenance")
            out[nid] = {
                "owners": cleaned,
                "provenance": prov if prov in PROVENANCE else "registry",
                "refs": [str(r) for r in (entry.get("refs") or []) if isinstance(r, str)][:32],
            }
        self._grants = out

    def _flush_locked(self) -> None:
        payload = {"version": FORMAT_VERSION, "images": self._grants}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            tmp.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
            os.replace(tmp, self.path)
        except OSError as exc:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise SandboxOpError(
                "image_owner_store_failed",
                503,
                "this hotel could not record image ownership",
                retry_after=30,
            ) from exc

    @staticmethod
    def _scope(owner: str) -> str:
        """Hash of ``owner_id`` (``<keyhash>:<guest>``). Empty owner is its own scope."""
        return owner_hash(owner or "")

    def owns(self, image_id: str, owner: str) -> bool:
        nid = normalize_image_id(image_id)
        if nid is None:
            return False
        scope = self._scope(owner)
        with self._lock:
            entry = self._grants.get(nid)
            return bool(entry and scope in entry["owners"])

    def provenance(self, image_id: str) -> str | None:
        nid = normalize_image_id(image_id)
        if nid is None:
            return None
        with self._lock:
            entry = self._grants.get(nid)
            if entry is None:
                return None
            prov = entry.get("provenance")
            return prov if prov in PROVENANCE else None

    def require(self, image_id: str, owner: str) -> str:
        nid = normalize_image_id(image_id)
        if nid is None or not self.owns(nid, owner):
            raise SandboxOpError(
                "image_not_owned",
                403,
                "this guest cannot use that image on this hotel",
            )
        return nid

    def grant(self, image_id: str, owner: str, *, provenance: str, ref: str | None = None) -> str:
        nid = normalize_image_id(image_id)
        if nid is None:
            raise SandboxOpError("image_not_owned", 403, "this guest cannot use that image on this hotel")
        if provenance not in PROVENANCE:
            raise SandboxOpError("image_owner_store_failed", 500, "unknown image provenance")
        scope = self._scope(owner)
        with self._lock:
            entry = self._grants.get(nid)
            if entry is None:
                entry = {"owners": [], "provenance": provenance, "refs": []}
                self._grants[nid] = entry
            if scope not in entry["owners"]:
                entry["owners"] = sorted([*entry["owners"], scope])
            if ref and ref not in entry["refs"]:
                entry["refs"] = [*entry["refs"], ref][-32:]
            # Prefer the stronger local provenance when a snapshot overwrites a pull.
            if provenance == "snapshot" or entry.get("provenance") not in PROVENANCE:
                entry["provenance"] = provenance
            self._flush_locked()
        return nid

    def drop_owner(self, image_id: str, owner: str) -> None:
        nid = normalize_image_id(image_id)
        if nid is None:
            return
        scope = self._scope(owner)
        with self._lock:
            entry = self._grants.get(nid)
            if entry is None:
                return
            owners = [o for o in entry["owners"] if o != scope]
            if not owners:
                self._grants.pop(nid, None)
            else:
                entry["owners"] = owners
            self._flush_locked()


__all__ = [
    "ImageOwnerStore",
    "normalize_image_id",
    "owners_path",
    "refuse_shared_hotel_build",
    "shared_hotel_builds_refused",
]
