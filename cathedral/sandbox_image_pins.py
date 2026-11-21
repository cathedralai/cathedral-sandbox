"""Image pins: images an owner asked the hotel image GC to keep (AB#860).

A prefetch with "pin": true records each image here. The room kit's image GC
(room-kit/room_image_gc.py --keep-file) reads the same file and never removes
a pinned ref or image id. The file sits in the GC's state directory.

Two caps, both in bytes of distinct images:
- per owner: X-Pin-Max-Bytes from the broker (the guest's pin_max_gib);
- per hotel, all owners: ROOM_IMAGE_PIN_MAX_PCT (default 50) of the data
  volume, so pins can never fill the disk the rooms need.
Over either: 507 pin_cap_exceeded, and nothing is pinned.

Settings:
  CATHEDRAL_IMAGE_PINS_PATH  the pins file; unset: no pins on this hotel
  CATHEDRAL_IMAGE_DATA_DIR   the data volume the hotel ceiling is a share of
  ROOM_IMAGE_PIN_MAX_PCT     the hotel ceiling, percent of that volume
"""

from __future__ import annotations

import json
import math
import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

from cathedral.sandbox_owner import owner_hash
from cathedral.sandbox_provider import SandboxOpError

FORMAT_VERSION = 1
DEFAULT_MAX_PCT = 50.0


def pins_path() -> Path | None:
    raw = os.environ.get("CATHEDRAL_IMAGE_PINS_PATH", "").strip()
    return Path(raw) if raw else None


def hotel_ceiling_bytes() -> int | None:
    """ROOM_IMAGE_PIN_MAX_PCT of the data volume; None when the volume is not set or unreadable."""
    data_dir = os.environ.get("CATHEDRAL_IMAGE_DATA_DIR", "").strip()
    if not data_dir:
        return None
    try:
        pct = float(os.environ.get("ROOM_IMAGE_PIN_MAX_PCT", "") or DEFAULT_MAX_PCT)
    except ValueError:
        pct = DEFAULT_MAX_PCT
    if not math.isfinite(pct) or not 0 <= pct <= 100:
        pct = DEFAULT_MAX_PCT  # 0 is kept: it turns pins off on this hotel
    try:
        total = shutil.disk_usage(data_dir).total
    except OSError:
        return None
    return int(total * pct / 100)


class ImagePinStore:
    """The pins file, replaced whole through a temp file in the same directory."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._pins: list[dict[str, Any]] = self._load()

    def _load(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            print(f"image pins: {self.path} is unreadable, starting empty: {exc}", file=sys.stderr, flush=True)
            return []
        pins = data.get("pins") if isinstance(data, dict) else None
        if not isinstance(pins, list):
            return []
        return [p for p in pins if isinstance(p, dict) and isinstance(p.get("ref"), str) and isinstance(p.get("owner"), str)]

    def _commit_locked(self, pins: list[dict[str, Any]]) -> None:
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({"version": FORMAT_VERSION, "pins": pins}, sort_keys=True, indent=1) + "\n")
            os.replace(tmp, self.path)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise SandboxOpError("image_pins_failed", 503, "this hotel could not record the pins", retry_after=30) from exc
        self._pins = pins

    @staticmethod
    def _bytes(pins: list[dict[str, Any]]) -> int:
        """Bytes of distinct images: two refs of one image take its disk once."""
        sizes: dict[str, int] = {}
        for p in pins:
            sizes[str(p.get("image_id") or p["ref"])] = int(p.get("size_bytes") or 0)
        return sum(sizes.values())

    def pinned_by(self, owner: str) -> list[dict[str, Any]]:
        scope = owner_hash(owner)
        with self._lock:
            return [dict(p) for p in self._pins if p["owner"] == scope]

    def pin(self, owner: str, images: list[dict[str, Any]], *, owner_cap: int | None, ceiling: int | None) -> list[str]:
        """Pin *images* ({ref, image_id, digest, size_bytes}) for *owner*, all or none."""
        scope = owner_hash(owner)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            refs = {i["ref"] for i in images}
            kept = [p for p in self._pins if not (p["owner"] == scope and p["ref"] in refs)]
            new = [{**i, "owner": scope, "pinned_at": now} for i in images]
            after = kept + new
            # The hotel ceiling first: it holds whatever the broker sends.
            if ceiling is not None and self._bytes(after) > ceiling:
                raise SandboxOpError(
                    "pin_cap_exceeded", 507,
                    f"pinned images on this hotel would pass its pin ceiling of {ceiling} bytes",
                )
            if owner_cap is not None and self._bytes([p for p in after if p["owner"] == scope]) > owner_cap:
                raise SandboxOpError(
                    "pin_cap_exceeded", 507,
                    f"this key's pinned images on this hotel would pass its cap of {owner_cap} bytes",
                )
            self._commit_locked(after)
        return [i["ref"] for i in images]

    def unpin(self, owner: str, ref: str) -> bool:
        scope = owner_hash(owner)
        with self._lock:
            kept = [p for p in self._pins if not (p["owner"] == scope and ref in (p["ref"], p.get("image_id")))]
            if len(kept) == len(self._pins):
                return False
            self._commit_locked(kept)
        return True


__all__ = ["ImagePinStore", "hotel_ceiling_bytes", "pins_path"]
