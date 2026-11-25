#!/usr/bin/python3
"""packages.lock for the pinned sealed guest build (AB#383).

Runs on the BUILD host with python3 and the standard library only. build-guest.sh
calls it when SEALED_SNAPSHOT is set:

  packages_lock.py emit ROOT          print the lock of a fresh mmdebstrap root (run
                                      from a customize hook, while the apt lists are
                                      still in the root)
  packages_lock.py check ROOT LOCK    the installed packages of ROOT are exactly the
                                      lock's (name, version, architecture)
  packages_lock.py kernel LOCK        print the one kernel release the lock names
  packages_lock.py snapshot-epoch ID  print the Unix time of a snapshot.ubuntu.com id

A lock line is "<package> <version> <architecture> <sha256>", sorted (C locale).
The sha256 is the one the archive's Packages index gives for that exact version:
apt checked each downloaded .deb against it, and the index is covered by the
signed InRelease of the snapshot. Nothing in the lock names the mirror URL.
"""
from __future__ import annotations

import calendar
import gzip
import lzma
import re
import sys
import time
from pathlib import Path

KERNEL_PACKAGE = re.compile(r"^linux-image-(?:unsigned-)?(\d+\.\d+\.\d+-\d+-[a-z0-9]+)$")
SNAPSHOT_ID = re.compile(r"^\d{8}T\d{6}Z$")


def _stanzas(text: str):
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if not line:
                continue
            if line[0] in " \t":
                continue  # continuation of a multi-line field; none we read is multi-line
            key, _, value = line.partition(":")
            fields[key] = value.strip()
        if fields:
            yield fields


def installed(root: Path) -> list[tuple[str, str, str]]:
    status = (root / "var/lib/dpkg/status").read_text(encoding="utf-8")
    out = []
    for f in _stanzas(status):
        if f.get("Status", "").split()[-1:] == ["installed"]:
            out.append((f["Package"], f["Version"], f["Architecture"]))
    return sorted(out)


def _read_index(path: Path) -> str:
    raw = path.read_bytes()
    if path.name.endswith(".gz"):
        raw = gzip.decompress(raw)
    elif path.name.endswith(".xz"):
        raw = lzma.decompress(raw)
    return raw.decode("utf-8")


def index_sha256(root: Path) -> dict[tuple[str, str, str], str]:
    lists = root / "var/lib/apt/lists"
    files = sorted(p for p in lists.glob("*_Packages*") if p.name.endswith(("_Packages", "_Packages.gz", "_Packages.xz")))
    if not files:
        raise SystemExit(f"no Packages index under {lists}: run emit from an mmdebstrap customize hook")
    sums: dict[tuple[str, str, str], str] = {}
    for path in files:
        for f in _stanzas(_read_index(path)):
            if "SHA256" not in f:
                continue
            k = (f["Package"], f["Version"], f["Architecture"])
            if sums.setdefault(k, f["SHA256"]) != f["SHA256"]:
                raise SystemExit(f"two sha256 values for {' '.join(k)} in the indexes")
    return sums


def emit(root: Path) -> str:
    sums = index_sha256(root)
    lines = []
    for k in installed(root):
        if k not in sums:
            raise SystemExit(f"{' '.join(k)} is installed but not in the archive index")
        lines.append(" ".join((*k, sums[k])))
    return "".join(line + "\n" for line in lines)


def lock_entries(lock: Path) -> list[tuple[str, ...]]:
    out = []
    for n, line in enumerate(lock.read_text(encoding="utf-8").splitlines(), 1):
        parts = tuple(line.split(" "))
        if len(parts) != 4 or not re.fullmatch(r"[0-9a-f]{64}", parts[3]):
            raise SystemExit(f"{lock}:{n}: not '<package> <version> <architecture> <sha256>'")
        out.append(parts)
    return out


def check(root: Path, lock: Path) -> None:
    want = sorted(e[:3] for e in lock_entries(lock))
    have = installed(root)
    if have != want:
        extra = sorted(set(have) - set(want))[:10]
        missing = sorted(set(want) - set(have))[:10]
        raise SystemExit(f"installed packages differ from {lock}: not in lock {extra}, not installed {missing}")


def kernel(lock: Path) -> str:
    found = sorted({m.group(1) for e in lock_entries(lock) if (m := KERNEL_PACKAGE.match(e[0]))})
    if len(found) != 1:
        raise SystemExit(f"{lock} must name exactly one kernel (linux-image-<release>), found {found or 'none'}")
    return found[0]


def snapshot_epoch(snapshot: str) -> int:
    if not SNAPSHOT_ID.match(snapshot):
        raise SystemExit("snapshot id must look like 20261101T000000Z")
    try:
        return calendar.timegm(time.strptime(snapshot, "%Y%m%dT%H%M%SZ"))
    except ValueError:
        raise SystemExit(f"{snapshot} is not a valid UTC time") from None


def main(argv: list[str]) -> int:
    match argv:
        case ["emit", root]:
            sys.stdout.write(emit(Path(root)))
        case ["check", root, lock]:
            check(Path(root), Path(lock))
        case ["kernel", lock]:
            print(kernel(Path(lock)))
        case ["snapshot-epoch", snapshot]:
            print(snapshot_epoch(snapshot))
        case _:
            print(__doc__, file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
