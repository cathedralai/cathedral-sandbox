"""Byte quota for a room's /work and for workspaces: xfs project quota (AB#396).

A room can write /work and its workspace without limit: both are bind mounts
of host directories, and ``docker run --storage-opt size=`` covers the
overlay root only. An xfs project quota is a property of the host-side
inodes, so the kernel enforces it whatever the room runtime (runc, runsc's
gofer, Kata's virtiofs). A write past the limit fails with ENOSPC in the room.

How: give a fresh directory a project id with the inherit flag (every file
and directory made under it later gets the same id), and set a hard block
limit on that id.

Project ids: Docker's overlay2 quota takes ids from small numbers upward on
the same file system and only scans its own directories. Ours live in a high
range that Docker does not reach: rooms in ``ROOM_IDS``, workspaces in
``WORKSPACE_IDS``.

Privilege: setting a project id needs only ownership of the directory; the
limit (quotactl) needs CAP_SYS_ADMIN. The room kit grants the API unit that
one ambient capability.
"""

from __future__ import annotations

import secrets
import subprocess
from collections.abc import Callable, Container
from pathlib import Path

ROOM_IDS = range(0x4000_0000, 0x6000_0000)
WORKSPACE_IDS = range(0x6000_0000, 0x7FFF_0000)
GIB = 1024**3

Runner = Callable[..., "subprocess.CompletedProcess[str]"]


class QuotaUnavailable(RuntimeError):
    """The quota could not be read or set. The message names no customer path."""


def _unescape(field: str) -> str:
    return field.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def mount_of(path: Path, mountinfo: str = "/proc/self/mountinfo") -> str:
    """Mount point of the xfs file system with project quota that holds *path*."""
    try:
        lines = Path(mountinfo).read_text().splitlines()
    except OSError as exc:
        raise QuotaUnavailable(f"cannot read {mountinfo}: {exc.strerror}") from None
    target = str(Path(path).resolve())
    best: tuple[str, str, set[str]] | None = None
    for line in lines:
        head, sep, tail = line.partition(" - ")
        fields, rest = head.split(), tail.split()
        if not sep or len(fields) < 5 or len(rest) < 3:
            continue
        point = _unescape(fields[4])
        if target == point or target.startswith(point.rstrip("/") + "/"):
            if best is None or len(point) > len(best[0]):
                best = (point, rest[0], set(rest[2].split(",")))
    if best is None:
        raise QuotaUnavailable("no mount holds the directory")
    point, fstype, options = best
    if fstype != "xfs":
        raise QuotaUnavailable(f"{point} is {fstype}, not xfs")
    if not options & {"prjquota", "pquota"}:
        raise QuotaUnavailable(f"{point} is not mounted with prjquota")
    return point


def pick_id(ids: range, in_use: Container[int], seed: str | None = None) -> int:
    """An id in *ids* that is not in *in_use*. *seed* (hex) makes the first try stable."""
    if seed:
        try:
            first = ids.start + int(seed, 16) % len(ids)
            if first not in in_use:
                return first
        except ValueError:
            pass
    for _ in range(64):
        candidate = ids.start + secrets.randbelow(len(ids))
        if candidate not in in_use:
            return candidate
    raise QuotaUnavailable("no free project id")


class XfsProjectQuota:
    """Set and clear xfs project limits with xfs_quota."""

    def __init__(
        self,
        *,
        binary: str = "xfs_quota",
        runner: Runner | None = None,
        mountinfo: str = "/proc/self/mountinfo",
    ) -> None:
        self.binary = binary
        self.runner = runner or subprocess.run
        self.mountinfo = mountinfo

    def _run(self, path: Path, *commands: str) -> None:
        mount = mount_of(path, self.mountinfo)
        argv = [self.binary, "-x"]
        for command in commands:
            argv += ["-c", command]
        argv.append(mount)
        try:
            result = self.runner(argv, capture_output=True, text=True, timeout=30.0, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise QuotaUnavailable(f"xfs_quota did not run: {type(exc).__name__}") from None
        if result.returncode != 0:
            raise QuotaUnavailable(f"xfs_quota failed (exit {result.returncode})")

    def assign(self, path: Path, project_id: int, limit_bytes: int) -> None:
        """Put the tree at *path* in *project_id* (inherit flag set) with a hard limit.

        For a directory the API just made and owns. ``project -s`` walks the
        tree without following symlinks.
        """
        self._run(
            path,
            f"project -s -p {Path(path).resolve()} {int(project_id)}",
            f"limit -p bhard={int(limit_bytes)} {int(project_id)}",
        )

    def set_limit(self, path: Path, project_id: int, limit_bytes: int) -> None:
        self._run(path, f"limit -p bhard={int(limit_bytes)} {int(project_id)}")

    def clear(self, path: Path, project_id: int) -> None:
        """Drop the limit of *project_id* on the file system that holds *path*."""
        self._run(path, f"limit -p bhard=0 {int(project_id)}")


__all__ = [
    "GIB",
    "QuotaUnavailable",
    "ROOM_IDS",
    "WORKSPACE_IDS",
    "XfsProjectQuota",
    "mount_of",
    "pick_id",
]
