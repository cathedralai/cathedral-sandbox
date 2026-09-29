"""T8 storage checks: state in guest memory, scratch on dm-crypt with integrity.

Every probe is injected, so no test needs a device or root. Two tests use the
real statfs(2) on /proc and /dev/shm.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from cathedral.tee_box import storage
from cathedral.tee_box.storage import (
    RAMFS_MAGIC,
    TMPFS_MAGIC,
    Mount,
    StorageError,
    StorageProbe,
    dm_crypt_integrity_check,
    mounts_for,
    parse_crypt_table,
    parse_mountinfo,
    require_memory_backed,
    require_no_swap,
    require_protected_scratch,
    state_paths,
    statfs_type,
)

EXT4_MAGIC = 0xEF53
PROC_MAGIC = 0x9FA0
KEY = ":64:logon:cryptsetup:6f0c1a52-0000-4000-8000-000000000000-d0"


# -- state in guest memory ---------------------------------------------------


def _memory_except(*disk: Path):
    on_disk = {str(path) for path in disk}

    def fs_type(path: str) -> int:
        return EXT4_MAGIC if path in on_disk else TMPFS_MAGIC

    return fs_type


def test_state_in_a_tmpfs_or_ramfs_directory_is_accepted(tmp_path: Path):
    state = tmp_path / "central.sqlite"
    assert require_memory_backed(str(state), fs_type=lambda _p: TMPFS_MAGIC) == (
        "central state on tmpfs"
    )
    assert require_memory_backed(str(state), fs_type=lambda _p: RAMFS_MAGIC) == (
        "central state on ramfs"
    )


def test_state_on_disk_refuses(tmp_path: Path):
    state = tmp_path / "central.sqlite"
    with pytest.raises(StorageError, match=r"tmpfs or ramfs .* type 0xef53$"):
        require_memory_backed(str(state), fs_type=_memory_except(tmp_path.resolve()))


def test_a_state_file_linked_onto_disk_refuses(tmp_path: Path):
    memory, disk = tmp_path / "shm", tmp_path / "disk"
    memory.mkdir()
    disk.mkdir()
    (memory / "central.sqlite").symlink_to(disk / "central.sqlite")  # dangling is enough
    assert str(disk.resolve()) in state_paths(str(memory / "central.sqlite"))
    with pytest.raises(StorageError, match="0xef53"):
        require_memory_backed(
            str(memory / "central.sqlite"), fs_type=_memory_except(disk.resolve())
        )


@pytest.mark.parametrize("suffix", ["", ".lock", "-journal", "-wal", "-shm"])
def test_a_state_side_file_mounted_from_disk_refuses(tmp_path: Path, suffix):
    state = tmp_path / "central.sqlite"
    side = Path(str(state) + suffix)
    side.write_bytes(b"")
    fs_type = _memory_except(side.resolve())
    with pytest.raises(StorageError, match=str(side.resolve())):
        require_memory_backed(str(state), fs_type=fs_type)


def test_a_state_directory_that_does_not_exist_refuses(tmp_path: Path):
    state = tmp_path / "missing" / "central.sqlite"
    with pytest.raises(StorageError, match="cannot be inspected"):
        require_memory_backed(str(state))


def test_statfs_reads_the_real_filesystem_type(tmp_path: Path):
    assert statfs_type("/proc") == PROC_MAGIC
    with pytest.raises(StorageError, match="0x9fa0"):
        require_memory_backed("/proc/central.sqlite")
    with pytest.raises(OSError):
        statfs_type(str(tmp_path / "missing"))


@pytest.mark.skipif(
    not os.path.isdir("/dev/shm") or statfs_type("/dev/shm") != TMPFS_MAGIC,
    reason="/dev/shm is not tmpfs here",
)
def test_real_tmpfs_is_accepted():
    assert require_memory_backed("/dev/shm/cathedral-t8-absent.sqlite") == (
        "central state on tmpfs"
    )


# -- mounts ------------------------------------------------------------------

MOUNTINFO = """\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
25 22 0:23 / /proc rw,nosuid - proc proc rw
90 22 253:3 / /var/lib/docker rw,relatime shared:40 - ext4 /dev/mapper/scratch rw
91 90 0:60 / /var/lib/docker/overlay2/abc/merged rw - overlay overlay rw,lowerdir=x
92 22 8:5 / /srv/with\\040space rw - xfs /dev/sda5 rw
"""


def test_mountinfo_is_parsed_with_escapes():
    mounts = parse_mountinfo(MOUNTINFO)
    assert mounts[2] == Mount("/var/lib/docker", 253, 3, "ext4", "/dev/mapper/scratch")
    assert mounts[4].mount_point == "/srv/with space"


@pytest.mark.parametrize("line", ["22 1 8:1 / / rw", "22 1 sda / / rw - ext4 /dev/sda1 rw"])
def test_a_malformed_mount_table_refuses(line):
    with pytest.raises(StorageError, match="unreadable"):
        parse_mountinfo(line)


def test_the_serving_mount_is_the_deepest_and_topmost():
    mounts = parse_mountinfo(MOUNTINFO + "93 22 0:70 / /var/lib/docker rw - tmpfs tmpfs rw\n")
    selected = mounts_for("/var/lib/docker", mounts)
    assert [(m.mount_point, m.fstype) for m in selected] == [
        ("/var/lib/docker", "tmpfs"),  # mounted over the ext4 one
        ("/var/lib/docker/overlay2/abc/merged", "overlay"),
    ]
    assert mounts_for("/var/lib/dockerx", mounts)[0].mount_point == "/"
    assert mounts_for("/var/lib/docker/image", mounts)[0].fstype == "tmpfs"


# -- dm-crypt tables ---------------------------------------------------------


@pytest.mark.parametrize(
    ("table", "integrity"),
    [
        (
            f"0 20971520 crypt capi:authenc(hmac(sha256),xts(aes))-random {KEY} 0 253:2 0 "
            "1 integrity:48:aead\n",
            "aead",
        ),
        (f"0 8 crypt aes-gcm-random {KEY} 0 253:2 0 2 allow_discards integrity:28:aead", "aead"),
        (
            f"0 8 crypt aes-xts-plain64 {KEY} 0 253:2 0 2 sector_size:4096 "
            "integrity:32:hmac(sha256)",
            "hmac(sha256)",
        ),
    ],
)
def test_crypt_tables_with_authenticated_integrity_are_accepted(table, integrity):
    ok, detail = parse_crypt_table(table)
    assert ok is True, detail
    assert detail.endswith("integrity " + integrity)
    assert "logon" not in detail  # the key field is never reported


@pytest.mark.parametrize(
    ("table", "reason"),
    [
        ("", "empty table"),
        (f"0 8 crypt aes-xts-plain64 {KEY} 0 8:2 0", "has no integrity"),
        (f"0 8 crypt aes-xts-plain64 {KEY} 0 8:2 0 1 allow_discards", "has no integrity"),
        (f"0 8 crypt aes-xts-random {KEY} 0 253:2 0 1 integrity:4:crc32c", "not authenticated"),
        (f"0 8 crypt aes-xts-random {KEY} 0 253:2 0 1 integrity:16:none", "not authenticated"),
        (f"0 8 crypt aes-xts-random {KEY} 0 253:2 0 1 integrity:0:aead", "has no integrity"),
        (f"0 8 crypt aes-gcm-random {KEY} 0 253:2 0 2 integrity:28:aead", "malformed"),
        (f"0 8 crypt aes-gcm-random {KEY} 0 253:2 0 x integrity:28:aead", "malformed"),
        ("0 8 linear 8:2 0", "linear target"),
        # dm-integrity alone (no encryption), even with an HMAC and eight fields.
        ("0 8 integrity 8:2 0 32 J 1 internal_hash:hmac(sha256)", "integrity target"),
        (
            f"0 8 crypt aes-gcm-random {KEY} 0 253:2 0 1 integrity:28:aead\n8 8 linear 8:3 0",
            "linear target",
        ),
    ],
)
def test_crypt_tables_without_authenticated_integrity_refuse(table, reason):
    ok, detail = parse_crypt_table(table)
    assert ok is False
    assert reason in detail


class _Dmsetup:
    def __init__(self, table: str = "", returncode: int = 0) -> None:
        self.table = table
        self.returncode = returncode
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, self.returncode, self.table.encode(), b"")


def _sysfs(tmp_path: Path, device: str, uuid: str, name: str = "cathedral-scratch") -> str:
    base = tmp_path / "dev-block" / device / "dm"
    base.mkdir(parents=True)
    (base / "uuid").write_text(uuid + "\n")
    (base / "name").write_text(name + "\n")
    return str(tmp_path / "dev-block")


AEAD_TABLE = (
    f"0 8 crypt capi:authenc(hmac(sha256),xts(aes))-random {KEY} 0 253:2 0 1 integrity:48:aead\n"
)


def test_a_luks2_device_with_integrity_is_accepted_from_sysfs_and_its_table(tmp_path: Path):
    sysfs = _sysfs(
        tmp_path, "253:3", "CRYPT-LUKS2-6f0c1a5200004000800000000000000-cathedral-scratch"
    )
    dmsetup = _Dmsetup(AEAD_TABLE)
    ok, detail = dm_crypt_integrity_check(dmsetup, sysfs=sysfs)(253, 3)
    assert ok is True, detail
    assert detail.startswith("cathedral-scratch: dm-crypt capi:authenc")
    argv, kwargs = dmsetup.calls[0]
    assert argv == ["/usr/sbin/dmsetup", "table", "cathedral-scratch"]
    assert kwargs["shell"] is False and kwargs["timeout"] == storage.DMSETUP_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("uuid", "name", "reason"),
    [
        ("LVM-abcdef", "vg-scratch", "not a dm-crypt mapping"),
        ("CRYPT-SUBDEV-6f0c1a52-cathedral-scratch_dif", "cathedral-scratch_dif", "not a dm-crypt"),
        ("", "cathedral-scratch", "not a dm-crypt mapping"),
        ("CRYPT-PLAIN-x", "-rf", "unusable name"),
        ("CRYPT-PLAIN-x", "a b", "unusable name"),
    ],
)
def test_devices_that_are_not_crypt_mappings_refuse_without_dmsetup(tmp_path, uuid, name, reason):
    sysfs = _sysfs(tmp_path, "253:3", uuid, name)
    dmsetup = _Dmsetup(AEAD_TABLE)
    ok, detail = dm_crypt_integrity_check(dmsetup, sysfs=sysfs)(253, 3)
    assert ok is False and reason in detail
    assert dmsetup.calls == []


def test_a_device_that_is_not_device_mapper_refuses(tmp_path: Path):
    sysfs = _sysfs(tmp_path, "253:3", "CRYPT-LUKS2-x-cathedral-scratch")
    dmsetup = _Dmsetup(AEAD_TABLE)
    ok, detail = dm_crypt_integrity_check(dmsetup, sysfs=sysfs)(8, 1)
    assert (ok, detail) == (False, "block device 8:1 is not a device-mapper device")


@pytest.mark.parametrize(
    ("runner", "reason"),
    [
        (_Dmsetup(AEAD_TABLE, returncode=1), "needs root"),
        (_Dmsetup(f"0 8 crypt aes-xts-plain64 {KEY} 0 8:2 0\n"), "has no integrity"),
    ],
)
def test_a_crypt_device_whose_table_lacks_integrity_or_is_unreadable_refuses(
    tmp_path, runner, reason
):
    sysfs = _sysfs(tmp_path, "253:3", "CRYPT-LUKS2-x-cathedral-scratch")
    ok, detail = dm_crypt_integrity_check(runner, sysfs=sysfs)(253, 3)
    assert ok is False and reason in detail


def test_a_dmsetup_that_cannot_run_refuses(tmp_path: Path):
    sysfs = _sysfs(tmp_path, "253:3", "CRYPT-LUKS2-x-cathedral-scratch")

    def missing(argv, **kwargs):
        raise FileNotFoundError(argv[0])

    assert dm_crypt_integrity_check(missing, sysfs=sysfs)(253, 3) == (False, "dmsetup table failed")


# -- scratch -----------------------------------------------------------------


def _probe(mountinfo: str, crypt=None, swaps: str = "Filename Type Size Used Priority\n"):
    checked: list[tuple[int, int]] = []

    def crypt_integrity(major: int, minor: int):
        checked.append((major, minor))
        return (crypt or {}).get((major, minor), (False, "not dm-crypt"))

    probe = StorageProbe(lambda _p: TMPFS_MAGIC, lambda: mountinfo, lambda: swaps, crypt_integrity)
    return probe, checked


def _root_table(root: Path, fstype: str = "ext4", device: str = "253:3", extra: str = "") -> str:
    return (
        "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
        f"90 22 {device} / {root} rw - {fstype} /dev/mapper/scratch rw\n" + extra
    )


def test_a_docker_root_on_dm_crypt_with_integrity_is_accepted(tmp_path: Path):
    root = tmp_path.resolve()
    extra = f"91 90 0:60 / {root}/overlay2/abc/merged rw - overlay overlay rw\n"
    extra += f"92 90 0:4 net:[4026532] {root}/netns/x rw - nsfs nsfs rw\n"
    probe, checked = _probe(_root_table(root, extra=extra), {(253, 3): (True, "dm-crypt aead")})
    assert require_protected_scratch(str(root), probe) == f"{root}: dm-crypt aead"
    assert checked == [(253, 3)]  # overlay and nsfs views are not devices to check


@pytest.mark.parametrize("fstype", ["tmpfs", "ramfs"])
def test_a_docker_root_in_memory_is_accepted_without_a_device_check(tmp_path: Path, fstype):
    root = tmp_path.resolve()
    probe, checked = _probe(_root_table(root, fstype=fstype, device="0:70"))
    assert require_protected_scratch(str(root), probe) == f"{root}: {fstype}"
    assert checked == []


def test_a_docker_root_on_a_plain_disk_refuses(tmp_path: Path):
    root = tmp_path.resolve()
    probe, checked = _probe(_root_table(root, fstype="xfs", device="8:2"))
    with pytest.raises(StorageError, match=rf"{root} \(xfs on 8:2\) .* not: not dm-crypt$"):
        require_protected_scratch(str(root), probe)
    assert checked == [(8, 2)]


def test_an_unmounted_docker_root_is_checked_as_the_mount_above_it(tmp_path: Path):
    root = tmp_path.resolve()
    probe, checked = _probe("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n")
    with pytest.raises(StorageError, match=r"/ \(ext4 on 8:1\)"):
        require_protected_scratch(str(root), probe)
    assert checked == [(8, 1)]


def test_a_disk_mounted_below_the_docker_root_refuses(tmp_path: Path):
    root = tmp_path.resolve()
    extra = f"91 90 8:2 / {root}/volumes rw - xfs /dev/sda2 rw\n"
    probe, checked = _probe(_root_table(root, extra=extra), {(253, 3): (True, "dm-crypt aead")})
    with pytest.raises(StorageError, match=rf"{root}/volumes \(xfs on 8:2\)"):
        require_protected_scratch(str(root), probe)
    assert checked == [(253, 3), (8, 2)]


def test_an_overlay_serving_the_docker_root_itself_refuses(tmp_path: Path):
    # The worker sees the root through a container overlay: its real backing
    # is unknown, so it is checked (and refused) as a device.
    root = tmp_path.resolve()
    probe, checked = _probe(_root_table(root, fstype="overlay", device="0:60"))
    with pytest.raises(StorageError, match="overlay on 0:60"):
        require_protected_scratch(str(root), probe)
    assert checked == [(0, 60)]


def test_a_docker_root_the_worker_cannot_see_refuses(tmp_path: Path):
    probe, _checked = _probe(_root_table(tmp_path, fstype="tmpfs"))
    with pytest.raises(StorageError, match="not visible to the worker"):
        require_protected_scratch(str(tmp_path / "missing"), probe)
    with pytest.raises(StorageError, match="absolute"):
        require_protected_scratch("var/lib/docker", probe)


def test_the_containerd_image_store_refuses(tmp_path: Path):
    root = tmp_path.resolve()
    probe, _checked = _probe(_root_table(root, fstype="tmpfs"))
    status = {"driver-type": "io.containerd.snapshotter.v1"}
    with pytest.raises(StorageError, match="containerd image store"):
        require_protected_scratch(str(root), probe, driver_status=status)
    assert require_protected_scratch(str(root), probe, driver_status={"Backing Filesystem": "xfs"})


def test_a_failing_device_check_refuses(tmp_path: Path):
    root = tmp_path.resolve()

    def broken(major: int, minor: int):
        raise RuntimeError("sysfs vanished")

    probe = StorageProbe(lambda _p: TMPFS_MAGIC, lambda: _root_table(root), lambda: "", broken)
    with pytest.raises(StorageError, match="the device check failed: sysfs vanished"):
        require_protected_scratch(str(root), probe)


# -- swap --------------------------------------------------------------------

SWAPS = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


def test_a_swap_table_with_only_its_header_means_no_swap():
    probe, _ = _probe("", swaps=SWAPS)
    assert require_no_swap(probe) == "no swap"


@pytest.mark.parametrize(
    "line",
    [
        "/dev/sda2 partition 8388604 0 -2",
        "/swap\\040file file 2097148 0 -3",
        "/dev/mapper/swap partition 8388604 0 -2",
        "/dev/zram0 partition 4194300 0 100",  # zram may have a backing device
        "/var/zram.img file 2097148 0 -3",  # a name is not a kind
    ],
)
def test_any_swap_refuses(line):
    probe, _ = _probe("", swaps=SWAPS + line + "\n")
    with pytest.raises(StorageError, match=r"^swap is on \(/.+\); swap can write guest memory"):
        require_no_swap(probe)


@pytest.mark.parametrize("text", ["", "/dev/sda2 partition 8388604 0 -2\n", "garbage\n"])
def test_a_swap_table_without_its_header_refuses(text):
    probe, _ = _probe("", swaps=text)
    with pytest.raises(StorageError, match="swap table is unreadable"):
        require_no_swap(probe)
