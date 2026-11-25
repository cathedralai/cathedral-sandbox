"""AB#383 / AB#968 PR 1a: pinned snapshot, packages.lock, named kernel, constant apt sources.

Runs the pinned-snapshot and base blocks of build-guest.sh with a fake mmdebstrap (no
root, no network): the fake writes a dpkg status, an apt Packages index and two kernels,
runs the customize hooks, then removes the lists the way mmdebstrap's cleanup does.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
BUILD = KIT / "sealed" / "build-guest.sh"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")

spec = importlib.util.spec_from_file_location("packages_lock", KIT / "sealed" / "packages_lock.py")
packages_lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packages_lock)

SNAP = "20261101T000000Z"
SNAP_EPOCH = 1793491200
KIT_EPOCH = "1790000000"
SHA = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("base-files", "kernel", "virtual", "tzdata", "old")}
STATUS = """Package: base-files
Status: install ok installed
Architecture: amd64
Version: 14ubuntu1

Package: linux-image-7.0.0-14-generic
Status: install ok installed
Architecture: amd64
Version: 7.0.0-14.14

Package: linux-image-virtual
Status: install ok installed
Architecture: amd64
Version: 7.0.0-14.14
Description: meta
 continuation line

Package: tzdata
Status: hold ok installed
Architecture: all
Version: 2026a-1

Package: gone
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0
"""
INDEX = f"""Package: base-files
Architecture: amd64
Version: 14ubuntu1
SHA256: {SHA['base-files']}

Package: base-files
Architecture: amd64
Version: 13ubuntu9
SHA256: {SHA['old']}

Package: linux-image-7.0.0-14-generic
Architecture: amd64
Version: 7.0.0-14.14
SHA256: {SHA['kernel']}

Package: linux-image-virtual
Architecture: amd64
Version: 7.0.0-14.14
SHA256: {SHA['virtual']}
"""
INDEX_ALL = f"""Package: tzdata
Architecture: all
Version: 2026a-1
SHA256: {SHA['tzdata']}
"""
LOCK = "".join(f"{line}\n" for line in [
    f"base-files 14ubuntu1 amd64 {SHA['base-files']}",
    f"linux-image-7.0.0-14-generic 7.0.0-14.14 amd64 {SHA['kernel']}",
    f"linux-image-virtual 7.0.0-14.14 amd64 {SHA['virtual']}",
    f"tzdata 2026a-1 all {SHA['tzdata']}",
])

FAKE_MMDEBSTRAP = r'''#!/usr/bin/python3
import json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
hooks = [a.split("=", 1)[1] for a in args if a.startswith("--customize-hook=")]
pos = [a for a in args if not a.startswith("--")]
suite, target, mirror = pos
log = Path(os.environ["FAKE_LOG"])
calls = json.loads(log.read_text()) if log.exists() else []
calls.append({"suite": suite, "mirror": mirror, "hooks": len(hooks), "epoch": os.environ.get("SOURCE_DATE_EPOCH")})
log.write_text(json.dumps(calls))
t = Path(target)
(t / "var/lib/dpkg").mkdir(parents=True)
(t / "var/lib/dpkg/status").write_text(os.environ["FAKE_STATUS"])
lists = t / "var/lib/apt/lists"
lists.mkdir(parents=True)
(lists / "snap_dists_resolute_main_binary-amd64_Packages").write_text(os.environ["FAKE_INDEX"])
import gzip
(lists / "snap_dists_resolute_universe_binary-amd64_Packages.gz").write_bytes(gzip.compress(os.environ["FAKE_INDEX_ALL"].encode()))
for k in ("7.0.0-14-generic", "7.0.0-99-generic"):
    (t / "lib/modules" / k).mkdir(parents=True)
    (t / "boot").mkdir(exist_ok=True)
    (t / "boot" / f"vmlinuz-{k}").write_text(k)
(t / "etc/apt/sources.list.d").mkdir(parents=True)
(t / "etc/apt/sources.list").write_text(f"deb {mirror} {suite} main universe\n")
for h in hooks:
    subprocess.run(["sh", "-c", h, "sh", target], check=True)
for p in lists.iterdir():
    p.unlink()
'''


def _slices() -> str:
    text = BUILD.read_text()
    pinned = text[text.index("# >>> pinned snapshot"):text.index("# <<< pinned snapshot")]
    base = text[text.index("PKGS="):text.index('rm -rf "${R:?}/boot"')]
    return pinned + base


def _build(tmp: Path, **env: str) -> subprocess.CompletedProcess:
    fake = tmp / "fakebin"
    fake.mkdir(exist_ok=True)
    (fake / "mmdebstrap").write_text(FAKE_MMDEBSTRAP)
    (fake / "mmdebstrap").chmod(0o755)
    out = tmp / "out"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    script = tmp / "slice.sh"
    script.write_text('set -euo pipefail\nlog() { echo "[sealed-build] $*"; }\n' + _slices()
                      + 'printf "%s\\n" "$BASE_ID" "$BASE_ROOTFS" "$KVER" > "$OUT/result"\n')
    values = {"KIT": str(KIT), "B": str(tmp / "build"), "OUT": str(out), "DATA_GIB": "0",
              "SEALED_SUITE": "resolute", "SEALED_MIRROR": "http://archive.ubuntu.com/ubuntu",
              "SOURCE_DATE_EPOCH": KIT_EPOCH, "FAKE_LOG": str(tmp / "calls.json"),
              "FAKE_STATUS": STATUS, "FAKE_INDEX": INDEX, "FAKE_INDEX_ALL": INDEX_ALL, **env}
    (tmp / "build").mkdir(exist_ok=True)
    return subprocess.run([BASH, str(script)], capture_output=True, text=True, timeout=60,
                          env={"PATH": f"{fake}:/usr/bin:/bin", "LC_ALL": "C", **values})


def _result(tmp: Path) -> list[str]:
    return (tmp / "out" / "result").read_text().split()


def _calls(tmp: Path) -> list[dict]:
    p = tmp / "calls.json"
    return json.loads(p.read_text()) if p.exists() else []


# ---------------------------------------------------------------- packages_lock.py


def _root(tmp: Path, status: str = STATUS) -> Path:
    root = tmp / "root"
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "var/lib/dpkg/status").write_text(status)
    lists = root / "var/lib/apt/lists"
    lists.mkdir(parents=True)
    (lists / "a_Packages").write_text(INDEX)
    (lists / "b_Packages.gz").write_bytes(gzip.compress(INDEX_ALL.encode()))
    return root


def test_emit_lists_installed_packages_with_the_index_sha256(tmp_path: Path) -> None:
    assert packages_lock.emit(_root(tmp_path)) == LOCK


def test_emit_refuses_a_package_the_index_does_not_have(tmp_path: Path) -> None:
    root = _root(tmp_path, STATUS.replace("Version: 14ubuntu1", "Version: 14ubuntu1+local"))
    with pytest.raises(SystemExit, match="not in the archive index"):
        packages_lock.emit(root)


def test_emit_refuses_without_indexes(tmp_path: Path) -> None:
    root = _root(tmp_path)
    for p in (root / "var/lib/apt/lists").iterdir():
        p.unlink()
    with pytest.raises(SystemExit, match="no Packages index"):
        packages_lock.emit(root)


def test_check_and_kernel(tmp_path: Path) -> None:
    root = _root(tmp_path)
    lock = tmp_path / "packages.lock"
    lock.write_text(LOCK)
    packages_lock.check(root, lock)
    assert packages_lock.kernel(lock) == "7.0.0-14-generic"
    lock.write_text(LOCK.replace("14ubuntu1", "14ubuntu2"))
    with pytest.raises(SystemExit, match="differ"):
        packages_lock.check(root, lock)
    lock.write_text(LOCK + f"linux-image-7.0.0-15-generic 7.0.0-15.15 amd64 {'0' * 64}\n")
    with pytest.raises(SystemExit, match="exactly one kernel"):
        packages_lock.kernel(lock)
    lock.write_text("base-files 14ubuntu1 amd64\n")
    with pytest.raises(SystemExit, match="not '<package>"):
        packages_lock.kernel(lock)


@pytest.mark.parametrize("bad", ["", "2026-11-01", "20261101T000000", "20261301T000000Z", "20261101T250000Z", "x20261101T000000Z"])
def test_snapshot_epoch(bad: str) -> None:
    assert packages_lock.snapshot_epoch(SNAP) == SNAP_EPOCH
    with pytest.raises(SystemExit):
        packages_lock.snapshot_epoch(bad)


# ---------------------------------------------------------------- build-guest.sh blocks


def test_unset_snapshot_builds_as_before(tmp_path: Path) -> None:
    proc = _build(tmp_path)
    assert proc.returncode == 0, proc.stderr
    old_id = hashlib.sha256(f"resolute http://archive.ubuntu.com/ubuntu {BUILD.read_text().split('PKGS=')[1].splitlines()[0]}\n"
                            .encode()).hexdigest()[:12]
    assert _result(tmp_path) == [old_id, old_id, "7.0.0-99-generic"], "same cache key, base_rootfs and newest kernel"
    assert _calls(tmp_path) == [{"suite": "resolute", "mirror": "http://archive.ubuntu.com/ubuntu", "hooks": 0, "epoch": KIT_EPOCH}]
    assert not (tmp_path / "out" / "packages.lock").exists()
    assert not list((tmp_path / "build").glob("*.packages.lock"))


def test_snapshot_update_mode_writes_the_lock_and_names_the_kernel(tmp_path: Path) -> None:
    proc = _build(tmp_path, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK_UPDATE="1")
    assert proc.returncode == 0, proc.stderr
    lock = (tmp_path / "out" / "packages.lock").read_text()
    assert lock == LOCK
    base_id, base_rootfs, kver = _result(tmp_path)
    assert base_rootfs == hashlib.sha256(LOCK.encode()).hexdigest()
    assert kver == "7.0.0-14-generic", "the lock's kernel, not the newest in the root"
    assert (tmp_path / "out" / "vmlinuz").read_text() == "7.0.0-14-generic"
    assert _calls(tmp_path) == [{"suite": "resolute", "mirror": f"https://snapshot.ubuntu.com/ubuntu/{SNAP}",
                                 "hooks": 1, "epoch": str(SNAP_EPOCH)}], "base dates from the snapshot"
    assert (tmp_path / "build" / f"base-{base_id}.packages.lock").read_text() == LOCK


def test_snapshot_cache_key_ignores_the_mirror_url(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    assert _build(a, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK_UPDATE="1").returncode == 0
    assert _build(b, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK_UPDATE="1", SEALED_MIRROR="http://mirror.example/ubuntu").returncode == 0
    assert _result(a) == _result(b)
    assert _calls(b)[0]["mirror"] == f"https://snapshot.ubuntu.com/ubuntu/{SNAP}"


def test_snapshot_build_passes_with_the_same_lock_and_reuses_the_cache(tmp_path: Path) -> None:
    lock = tmp_path / "expected.lock"
    lock.write_text(LOCK)
    first = _build(tmp_path, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK=str(lock))
    assert first.returncode == 0, first.stderr
    second = _build(tmp_path, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK=str(lock))
    assert second.returncode == 0, second.stderr
    assert len(_calls(tmp_path)) == 1, "cached base reused"
    assert _result(tmp_path)[2] == "7.0.0-14-generic"


def test_snapshot_build_fails_when_packages_differ_from_the_lock(tmp_path: Path) -> None:
    lock = tmp_path / "expected.lock"
    lock.write_text(LOCK.replace("2026a-1", "2025c-1"))
    proc = _build(tmp_path, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK=str(lock))
    assert proc.returncode != 0
    assert "resolved packages differ" in proc.stderr
    assert not (tmp_path / "out" / "result").exists()


def test_snapshot_build_fails_when_the_cached_base_drifted(tmp_path: Path) -> None:
    assert _build(tmp_path, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK_UPDATE="1").returncode == 0
    base = next(p for p in (tmp_path / "build").iterdir() if p.is_dir() and p.name.startswith("base-"))
    status = base / "var/lib/dpkg/status"
    status.write_text(status.read_text().replace("Version: 14ubuntu1", "Version: 14ubuntu9"))
    proc = _build(tmp_path, SEALED_SNAPSHOT=SNAP, SEALED_PACKAGES_LOCK_UPDATE="1")
    assert proc.returncode != 0
    assert "does not match its packages.lock" in proc.stderr


@pytest.mark.parametrize(("env", "message"), [
    ({"SEALED_SNAPSHOT": "latest", "SEALED_PACKAGES_LOCK_UPDATE": "1"}, "snapshot.ubuntu.com id"),
    ({"SEALED_SNAPSHOT": SNAP}, "needs SEALED_PACKAGES_LOCK"),
    ({"SEALED_SNAPSHOT": SNAP, "SEALED_PACKAGES_LOCK": "/nonexistent/packages.lock"}, "needs SEALED_PACKAGES_LOCK"),
    ({"SEALED_SNAPSHOT": SNAP, "SEALED_PACKAGES_LOCK_UPDATE": "yes"}, "must be 0 or 1"),
    ({"SEALED_SNAPSHOT": SNAP, "SEALED_PACKAGES_LOCK_UPDATE": "1", "SOURCE_DATE_EPOCH": "0"}, "kit commit time"),
])
def test_snapshot_settings_are_checked_before_the_build(tmp_path: Path, env: dict, message: str) -> None:
    proc = _build(tmp_path, **env)
    assert proc.returncode != 0
    assert message in proc.stderr
    assert _calls(tmp_path) == [], "refused before mmdebstrap"


@pytest.mark.parametrize("mirror", ["http://archive.ubuntu.com/ubuntu", f"https://snapshot.ubuntu.com/ubuntu/{SNAP}"])
def test_snapshot_image_has_constant_apt_sources(tmp_path: Path, mirror: str) -> None:
    text = BUILD.read_text()
    block = text[text.index("# A pinned build ships the same apt sources"):text.index("# The link (host IP, guest IP)")]
    root = tmp_path / "r"
    (root / "etc/apt/sources.list.d").mkdir(parents=True)
    (root / "etc/apt/sources.list").write_text(f"deb {mirror} resolute main universe\n")
    (root / "etc/apt/sources.list.d/x.sources").write_text(f"URIs: {mirror}\n")
    proc = subprocess.run([BASH, "-c", "set -euo pipefail\n" + block], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin", "R": str(root), "SNAPSHOT": SNAP, "SEALED_SUITE": "resolute"})
    assert proc.returncode == 0, proc.stderr
    assert (root / "etc/apt/sources.list").read_text() == "deb http://archive.ubuntu.com/ubuntu resolute main universe\n"
    assert list((root / "etc/apt/sources.list.d").iterdir()) == []


def test_manifest_names_base_rootfs_and_the_lock_stays_outside_the_initrd() -> None:
    text = BUILD.read_text()
    manifest_call = text[text.index('python3 - "$OUT" "$SEALED_VCPUS"'):text.index("<<'EOF'\nimport hashlib, json")]
    assert '"$BASE_ROOTFS"' in manifest_call and '"$BASE_ID"' not in manifest_call
    # packages.lock goes to $OUT next to the image, never into the measured root $R.
    assert 'install -m 0644 "$BASE_LOCK" "$OUT/packages.lock"' in text
    assert "packages.lock\" \"$R" not in text
