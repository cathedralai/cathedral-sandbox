"""AB#383: two builds of the same inputs give the same initrd bytes.

Uses a fake root tree (the package step is out of scope here): same files,
different mtimes and creation order, must pack to identical bytes.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

PACK = Path(__file__).resolve().parents[1] / "room-kit" / "sealed" / "pack-initrd.sh"
needs = pytest.mark.skipif(not all(shutil.which(t) for t in ("bash", "cpio", "zstd")), reason="needs bash, cpio, zstd")


def _tree(root: Path, order: list[str], mtime: int) -> None:
    for rel in order:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"content of {rel}\n")
        os.utime(p, (mtime, mtime))
    (root / "init").symlink_to("usr/lib/systemd/systemd")


def _pack(root: Path, out: Path, epoch: int) -> str:
    proc = subprocess.run(["bash", "-c", f'source "{PACK}"; pack_initrd "$1" "$2" "$3"', "_", str(root), str(out), str(epoch)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return hashlib.sha256(out.read_bytes()).hexdigest()


@needs
def test_same_inputs_different_mtimes_and_order_give_identical_initrd(tmp_path: Path) -> None:
    files = ["etc/a.conf", "opt/room-kit/x.sh", "usr/local/sbin/boot.sh", "etc/systemd/system/u.service"]
    _tree(tmp_path / "one", files, 1_700_000_000)
    _tree(tmp_path / "two", list(reversed(files)), 1_750_000_000)
    assert _pack(tmp_path / "one", tmp_path / "one.zst", 1_699_000_000) == _pack(tmp_path / "two", tmp_path / "two.zst", 1_699_000_000)


@needs
def test_changed_content_changes_the_initrd(tmp_path: Path) -> None:
    _tree(tmp_path / "one", ["etc/a.conf"], 1_700_000_000)
    _tree(tmp_path / "two", ["etc/a.conf"], 1_700_000_000)
    (tmp_path / "two" / "etc/a.conf").write_text("different\n")
    assert _pack(tmp_path / "one", tmp_path / "one.zst", 1) != _pack(tmp_path / "two", tmp_path / "two.zst", 1)
