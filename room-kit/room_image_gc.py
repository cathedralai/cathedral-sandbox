#!/usr/bin/env python3
"""LRU cleanup of unused images on a room hotel's data volume (AB#819).

The room daemon keeps every image it ever pulled on the data volume, which it
shares with the rooms' disks. Nothing removed them: on 18 Nov 2026 c46's 60 GB
volume held 43 images (51.6 GB) and pulls and creates failed with "no space
left on device".

Each run (a systemd timer, every 5 minutes):
- notes which images containers use now (state file: first seen, last used);
- does nothing more while the volume is below the high mark;
- above it, removes unused images, least recently used first, until the
  volume is below the low mark.

An image is removed only when ALL of these hold:
- it has a registry digest (RepoDigests), so a later create can pull it again;
  a local build or a snapshot (docker commit) has none;
- it has no cathedral.sandbox.owner label: a room's snapshot carries its
  room's labels, pushed or not;
- no container uses it, running or stopped;
- no container used it, and it was not first seen, within --min-idle-minutes;
- it is not on the keep list (the health probe image);
- no owner pinned it (--keep-file, the hotel API's pins file, AB#860): a ref
  or an image id in the file is kept like --keep. A missing or broken file
  keeps nothing extra and never stops a run.
Removal never forces: Docker itself refuses an image a container uses.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

OWNER_LABEL = "cathedral.sandbox.owner"


def log(msg: str) -> None:
    print(f"room-image-gc: {msg}", flush=True)


class Docker:
    def __init__(self, sock: str) -> None:
        self.base = ["docker", "-H", f"unix://{sock}"]

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run([*self.base, *args], capture_output=True, text=True, timeout=300, check=check)

    def image_ids(self) -> list[str]:
        out = self.run("image", "ls", "-a", "-q", "--no-trunc").stdout.split()
        return sorted(set(out))

    def inspect_images(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        return json.loads(self.run("image", "inspect", *ids).stdout or "[]")

    def used_image_ids(self) -> set[str]:
        """Image ids of every container, running or stopped."""
        cids = self.run("ps", "-a", "-q", "--no-trunc").stdout.split()
        if not cids:
            return set()
        out = self.run("container", "inspect", "--format", "{{.Image}}", *cids).stdout
        return {line.strip() for line in out.splitlines() if line.strip()}

    def remove(self, ref: str) -> tuple[bool, str]:
        r = self.run("image", "rm", ref, check=False)
        return r.returncode == 0, (r.stderr or r.stdout).strip()[:200]


def fill_pct(path: str) -> float:
    st = os.statvfs(path)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    usable = used + st.f_bavail * st.f_frsize  # as df: the root reserve is not usable
    return 100.0 * used / usable if usable else 0.0


def load_state(path: Path) -> dict[str, dict[str, float]]:
    try:
        images = json.loads(path.read_text()).get("images")
    except (OSError, ValueError, AttributeError):
        return {}
    if not isinstance(images, dict):
        return {}
    return {k: v for k, v in images.items() if isinstance(v, dict)}


def save_state(path: Path, images: dict[str, dict[str, float]]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"images": images}, indent=1, sort_keys=True))
    os.replace(tmp, path)


def load_pins(path: str | None) -> set[str]:
    """Refs and image ids in the pins file. Missing: none. Broken: none, said once."""
    if not path:
        return set()
    try:
        pins = json.loads(Path(path).read_text()).get("pins")
        if not isinstance(pins, list) or not all(isinstance(p, dict) for p in pins):
            raise ValueError("no list of pins")
    except FileNotFoundError:
        return set()
    except (OSError, ValueError, AttributeError) as exc:
        log(f"pins file {path} is unreadable, no pins kept this run: {exc}")
        return set()
    out = set()
    for p in pins:
        # A pin protects the image it was counted for. Keeping the ref too would
        # also keep whatever image a moved tag names now, which the pin cap never
        # counted (review HOLD on #642). Only a record without an id keeps by ref.
        iid, ref = p.get("image_id"), p.get("ref")
        if isinstance(iid, str) and iid:
            out.add(iid)
        elif isinstance(ref, str) and ref:
            out.add(ref)
    return out


def removable(img: dict, used: set[str], seen: dict[str, float], keep: set[str], now: float, min_idle: float) -> bool:
    if img["Id"] in used or img["Id"] in keep or not img.get("RepoDigests"):
        return False
    if OWNER_LABEL in ((img.get("Config") or {}).get("Labels") or {}):
        return False
    refs = set(img.get("RepoTags") or []) | set(img.get("RepoDigests") or [])
    if refs & keep:
        return False
    return now - max(seen.get("first_seen", now), seen.get("last_used", 0.0)) >= min_idle


def run_once(args: argparse.Namespace, docker: Docker, fill=fill_pct, now: float | None = None) -> int:
    now = time.time() if now is None else now
    state_path = Path(args.state)
    state = load_state(state_path)
    images = docker.inspect_images(docker.image_ids())
    used = docker.used_image_ids()
    # Forget images that are gone; note new ones and the ones in use now.
    state = {img["Id"]: state.get(img["Id"], {"first_seen": now}) for img in images}
    for iid in used & state.keys():
        state[iid]["last_used"] = now
    save_state(state_path, state)

    before = fill(args.data_dir)
    if before < args.high_pct:
        return 0
    pinned = load_pins(getattr(args, "keep_file", None))
    keep = set(args.keep) | pinned
    candidates = [img for img in images if removable(img, used, state[img["Id"]], keep, now, args.min_idle_minutes * 60)]
    # Least recently used first; of two, the bigger one first.
    candidates.sort(key=lambda i: (max(state[i["Id"]].get("first_seen", now), state[i["Id"]].get("last_used", 0.0)), -i.get("Size", 0)))
    log(f"{args.data_dir} {before:.1f}% full (high mark {args.high_pct}%): {len(candidates)} of {len(images)} images may go")
    fill_now, removed = before, 0
    for img in candidates:
        if fill_now < args.low_pct:
            break
        name = (img.get("RepoTags") or img.get("RepoDigests"))[0]
        if args.dry_run:
            log(f"would remove {name} ({img.get('Size', 0) / 1e9:.2f} GB)")
            continue
        # Every reference, never forced: the image goes once none is left, and
        # Docker refuses one a container started meanwhile.
        ok, why = True, ""
        for ref in (img.get("RepoTags") or []) + (img.get("RepoDigests") or []):
            done, msg = docker.remove(ref)
            if not done and "No such image" not in msg:
                ok, why = False, msg
                break
        if not ok:
            log(f"kept {name}: {why}")
            continue
        removed += 1
        state.pop(img["Id"], None)
        fill_now = fill(args.data_dir)
        log(f"removed {name} ({img.get('Size', 0) / 1e9:.2f} GB); volume {fill_now:.1f}%")
    save_state(state_path, state)
    if fill_now >= args.low_pct and pinned:
        held = [img for img in images if img["Id"] in state and (
            img["Id"] in pinned or (set(img.get("RepoTags") or []) | set(img.get("RepoDigests") or [])) & pinned)]
        if held:
            log(f"pinned images keep {sum(i.get('Size', 0) for i in held) / 1e9:.2f} GB; the volume stays above the low mark")
    log(f"done: {removed} removed, {before:.1f}% to {fill_now:.1f}% (low mark {args.low_pct}%)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sock", required=True, help="the room Docker daemon socket")
    ap.add_argument("--data-dir", required=True, help="the room data volume mount")
    ap.add_argument("--state", required=True, help="state file: when each image was first seen and last used")
    ap.add_argument("--high-pct", type=float, default=85.0)
    ap.add_argument("--low-pct", type=float, default=70.0)
    ap.add_argument("--min-idle-minutes", type=float, default=60.0)
    ap.add_argument("--keep", action="append", default=[], help="an image reference never removed (repeatable)")
    ap.add_argument("--keep-file", help="the hotel API's pins file: its refs and image ids are kept like --keep")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--off", action="store_true", help="ROOM_IMAGE_GC=0: do nothing")
    args = ap.parse_args(argv)
    if args.off:
        return 0
    if not 0 < args.low_pct <= args.high_pct <= 100:
        print("room-image-gc: need 0 < low-pct <= high-pct <= 100", file=sys.stderr)
        return 2
    return run_once(args, Docker(args.sock))


if __name__ == "__main__":
    sys.exit(main())
