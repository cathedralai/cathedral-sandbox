"""TEE box storage checks (queue item T8): state in memory, scratch encrypted.

Owner decision 7 (TEE_BOX.md on PR #236): all writable storage lives in guest
memory or on dm-crypt with integrity (AEAD) under a key made inside the TD at
boot. The worker enforces the part it can observe, at startup, in TEE mode
only (the TEE box flags on ``worker serve``):

- ``require_memory_backed``: the central replay, delegation high-water and
  revocation state (``--tee-box-central-state``), its lock and its SQLite
  side files are on tmpfs or ramfs. dm-crypt is not enough here: its sector
  tags do not stop the host replaying an older sector written under the same
  key, which would roll the state back.
- ``require_protected_scratch``: Docker's data root, and every mount below
  it, is on tmpfs or ramfs, or on a dm-crypt device whose table carries an
  authenticated integrity mode. Imported image layers, container overlays,
  gVisor's overlay file, and ``files`` and ``tar`` uploads all live there.
- ``require_no_swap``: no swap at all (not even zram, which can write to a
  backing device), or the tmpfs pages above could reach a host disk in the
  clear.

Making the key (random, inside the TD, never written out) is the appliance
boot's job; see docs/TEE_BOX_SERVICE.md, "Storage (T8)". Every probe is
injectable (``StorageProbe``) so tests need no devices, and every failure
refuses startup.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

# statfs(2) f_type values (linux/magic.h).
TMPFS_MAGIC = 0x01021994
RAMFS_MAGIC = 0x858458F6
MEMORY_MAGICS = {TMPFS_MAGIC: "tmpfs", RAMFS_MAGIC: "ramfs"}
MEMORY_FSTYPES = frozenset({"tmpfs", "ramfs"})
# Network namespace handles below the data root hold no data. Overlay mounts
# below it (a running container's root filesystem) are accepted only when
# every layer directory resolves under the data root (``overlay_dirs``).
VIEW_FSTYPES = frozenset({"nsfs"})
# Docker's overlay2 driver mounts from its own directory with relative
# lowerdir paths, to fit the mount data into one page.
OVERLAY2_HOME = "overlay2"
_OVERLAY_DIR_KEYS = frozenset({"lowerdir", "lowerdir+", "datadir+", "upperdir", "workdir"})
# SQLite and ValidatorAccessState files beside the state database.
STATE_SIDE_SUFFIXES = (".lock", "-journal", "-wal", "-shm")
DMSETUP_PATH = "/usr/sbin/dmsetup"
SYSFS_DEV_BLOCK = "/sys/dev/block"
MOUNTINFO_PATH = "/proc/self/mountinfo"
SWAPS_PATH = "/proc/swaps"
DMSETUP_TIMEOUT_SECONDS = 15.0
# cryptsetup names the device it maps CRYPT-<type>-...; the dm-integrity
# device under a LUKS2 volume with integrity is CRYPT-SUBDEV-..., not a crypt
# target itself.
CRYPT_UUID_PREFIX = "CRYPT-"
CRYPT_SUBDEV_PREFIX = "CRYPT-SUBDEV-"
# dm-crypt's ``integrity:<tag bytes>:<type>`` optional parameter. ``aead``
# covers AEAD ciphers (aes-gcm, chacha20-poly1305, and the authenc() cipher
# cryptsetup builds for --integrity hmac-sha256 with aes-xts); an hmac type
# authenticates each sector with a key the TD holds. Unkeyed checksums
# (crc32c, "none") are refused.
_INTEGRITY_TYPE_RE = re.compile(r"^(?:aead|hmac\(sha(?:256|512)\))$")
# The ciphers each integrity type may pair with. An AEAD type needs a real
# AEAD: authenc of HMAC-SHA-2 and AES-XTS (cryptsetup's --integrity
# hmac-sha256/512 with aes-xts), AES-GCM, or ChaCha20-Poly1305. An HMAC type
# needs AES-XTS. Anything with a null cipher or digest, or ECB, is refused.
_AEAD_CIPHER_RE = re.compile(
    r"^capi:(?:authenc\(hmac\(sha(?:256|512)\),xts\(aes\)\)|gcm\(aes\)"
    r"|rfc7539\(chacha20,poly1305\))-(?:random|plain64)$"
)
_HMAC_CIPHER_RE = re.compile(r"^(?:aes-xts|capi:xts\(aes\))-(?:random|plain64)$")
_WEAK_CIPHER_RE = re.compile(r"null|ecb", re.IGNORECASE)
_INTEGRITY_PARAM_RE = re.compile(r"^integrity:([1-9][0-9]{0,3}):(.+)$")
_DM_NAME_RE = re.compile(r"^[A-Za-z0-9_+.][A-Za-z0-9_+.-]{0,126}$")
_MAJOR_MINOR_RE = re.compile(r"^([0-9]{1,10}):([0-9]{1,10})$")
CONTAINERD_SNAPSHOTTER = "io.containerd.snapshotter.v1"

CryptIntegrityCheck = Callable[[int, int], tuple[bool, str]]


class StorageError(ValueError):
    """TEE box storage is not in guest memory or not encrypted with integrity."""


def statfs_type(path: str) -> int:
    """The filesystem magic statfs(2) reports for ``path``."""

    libc = ctypes.CDLL(None, use_errno=True)
    # struct statfs is 120 bytes on x86-64; f_type is its first member, a
    # native long on the 64-bit Linux ABIs a TD runs.
    buffer = ctypes.create_string_buffer(512)
    if libc.statfs(os.fsencode(path), buffer) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), path)
    return ctypes.c_long.from_buffer(buffer).value & 0xFFFFFFFF


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read(4 * 1024 * 1024)


def device_of(path: str) -> tuple[int, int]:
    """The major and minor number of the filesystem holding ``path`` (stat(2))."""

    device = os.stat(path).st_dev
    return os.major(device), os.minor(device)


@dataclass(frozen=True)
class StorageProbe:
    """What the storage checks read from the guest; tests replace each part."""

    fs_type: Callable[[str], int]
    mountinfo: Callable[[], str]
    swaps: Callable[[], str]
    crypt_integrity: CryptIntegrityCheck
    device_of: Callable[[str], tuple[int, int]] = device_of


def default_storage_probe(
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> StorageProbe:
    return StorageProbe(
        fs_type=statfs_type,
        mountinfo=lambda: _read_text(MOUNTINFO_PATH),
        swaps=lambda: _read_text(SWAPS_PATH),
        crypt_integrity=dm_crypt_integrity_check(runner),
    )


# -- state in guest memory ---------------------------------------------------


def state_paths(path: str) -> tuple[str, ...]:
    """Every location the state at ``path`` uses: its directory and files."""

    resolved = os.path.realpath(path)
    candidates = [os.path.dirname(resolved), os.path.dirname(os.path.abspath(path))]
    for suffix in ("", *STATE_SIDE_SUFFIXES):
        if os.path.lexists(path + suffix):
            candidates.append(os.path.realpath(path + suffix))
    return tuple(dict.fromkeys(candidates))


def require_memory_backed(path: str, *, fs_type: Callable[[str], int] = statfs_type) -> str:
    """Refuse unless the state at ``path`` can live only in guest memory.

    The directory holding the state (before and after resolving symlinks)
    and each existing state file must be on tmpfs or ramfs. The directory
    must exist: mount the tmpfs before the worker starts.
    """

    kinds = set()
    for candidate in state_paths(path):
        try:
            magic = fs_type(candidate)
        except OSError as exc:
            raise StorageError(
                f"the TEE box central state location {candidate} cannot be inspected: "
                f"{exc.strerror or exc}"
            ) from exc
        kind = MEMORY_MAGICS.get(magic)
        if kind is None:
            raise StorageError(
                f"the TEE box central state must be on tmpfs or ramfs (guest memory); "
                f"{candidate} is on filesystem type {magic:#x}"
            )
        kinds.add(kind)
    return "central state on " + "+".join(sorted(kinds))


# -- scratch on memory or dm-crypt with integrity ----------------------------


@dataclass(frozen=True)
class Mount:
    mount_point: str
    major: int
    minor: int
    fstype: str
    source: str
    options: str = ""


def _unescape(field: str) -> str:
    """Undo the kernel's octal escapes (space, tab, newline, backslash)."""

    return re.sub(r"\\([0-7]{3})", lambda found: chr(int(found.group(1), 8)), field)


def parse_mountinfo(text: str) -> tuple[Mount, ...]:
    """Parse /proc/<pid>/mountinfo; a malformed line refuses the whole listing."""

    mounts = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split(" ")
        try:
            separator = fields.index("-", 6)
            device = _MAJOR_MINOR_RE.fullmatch(fields[2])
            if device is None:
                raise ValueError("bad device")
            mounts.append(
                Mount(
                    mount_point=_unescape(fields[4]),
                    major=int(device.group(1)),
                    minor=int(device.group(2)),
                    fstype=fields[separator + 1],
                    source=_unescape(fields[separator + 2]),
                    options=fields[separator + 3],
                )
            )
        except (ValueError, IndexError) as exc:
            raise StorageError("the mount table is unreadable") from exc
    return tuple(mounts)


def _within(path: str, mount_point: str) -> bool:
    return mount_point == "/" or path == mount_point or path.startswith(mount_point + "/")


def mounts_for(root: str, mounts: tuple[Mount, ...], device: tuple[int, int]) -> tuple[Mount, ...]:
    """The mount serving ``root`` first, then every mount strictly below it.

    ``device`` is what stat(2) reports for ``root``: the filesystem that
    really serves the path. The serving mount is the last listed mount of
    that device whose mount point contains ``root``, not the longest mount
    point: a filesystem mounted later over an ancestor (ext4 on ``/x`` after
    tmpfs on ``/x/docker``) hides the deeper one, and its device is the
    answer stat gives. No such mount refuses (empty result).
    """

    serving = None
    for mount in mounts:
        if (mount.major, mount.minor) == device and _within(root, mount.mount_point):
            serving = mount
    if serving is None:
        return ()
    below = tuple(
        mount
        for mount in mounts
        if mount is not serving
        and mount.mount_point != root
        and mount.mount_point.startswith(root.rstrip("/") + "/")
    )
    return (serving, *below)


def overlay_dirs(options: str) -> tuple[str, ...]:
    """Every layer directory an overlay mount's super options name.

    ``lowerdir`` is a colon list (``::`` before data-only layers); the
    kernel escapes commas, colons and spaces inside a path. Refuses options
    with no lower layer.
    """

    dirs = []
    lower = False
    for option in options.split(","):
        key, sep, value = option.partition("=")
        if key not in _OVERLAY_DIR_KEYS:
            continue
        if not sep or not value:
            raise StorageError(f"an overlay mount has an empty {key}")
        if key == "lowerdir":
            parts = [part for part in re.split(r"(?<!\\):", value) if part]
        else:
            parts = [value]
        lower = lower or key in ("lowerdir", "lowerdir+")
        dirs += [_unescape(part).replace("\\:", ":") for part in parts]
    if not lower:
        raise StorageError("an overlay mount names no lower layer")
    return tuple(dirs)


def _overlay_outside(root: str, mount: Mount) -> str | None:
    """The first layer directory of ``mount`` outside ``root``, or None."""

    home = os.path.join(root, OVERLAY2_HOME)
    for path in overlay_dirs(mount.options):
        resolved = os.path.realpath(os.path.join(home, path))
        if resolved != root and not resolved.startswith(root.rstrip("/") + "/"):
            return path
    return None


def parse_crypt_table(text: str) -> tuple[bool, str]:
    """Whether a ``dmsetup table`` listing is dm-crypt with authenticated integrity.

    Every segment must be a ``crypt`` target whose optional parameters carry
    ``integrity:<tag bytes>:<type>`` with an AEAD or HMAC type, and whose
    cipher is on the allowlist for that type. The key field is never kept or
    reported.
    """

    lines = [line.split() for line in text.splitlines() if line.strip()]
    if not lines:
        return False, "the device has an empty table"
    integrity_types = set()
    for fields in lines:
        # <start> <length> crypt <cipher> <key> <iv offset> <device> <offset>
        # [<#opt params> <opt params>...]
        if len(fields) < 8 or fields[2] != "crypt":
            target = fields[2] if len(fields) > 2 else "?"
            return False, f"a segment is a {target!s:.32} target, not crypt"
        cipher = fields[3]
        found = None
        if len(fields) > 8:
            try:
                count = int(fields[8])
            except ValueError:
                return False, "the crypt table is malformed"
            if count != len(fields) - 9:
                return False, "the crypt table is malformed"
            for option in fields[9:]:
                matched = _INTEGRITY_PARAM_RE.fullmatch(option)
                if matched is not None:
                    found = matched.group(2)
        if found is None:
            return False, f"crypt cipher {cipher!s:.64} has no integrity (no AEAD or HMAC tags)"
        if _INTEGRITY_TYPE_RE.fullmatch(found) is None:
            return False, f"crypt integrity {found!s:.32} is not authenticated (need aead or hmac)"
        allowed = _AEAD_CIPHER_RE if found == "aead" else _HMAC_CIPHER_RE
        if _WEAK_CIPHER_RE.search(cipher) or allowed.fullmatch(cipher) is None:
            return False, (
                f"crypt cipher {cipher!s:.64} is not an allowed cipher for integrity {found}"
            )
        integrity_types.add(f"{cipher} integrity {found}")
    return True, "dm-crypt " + ", ".join(sorted(integrity_types))


def dm_crypt_integrity_check(
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
    *,
    dmsetup: str = DMSETUP_PATH,
    sysfs: str = SYSFS_DEV_BLOCK,
    read_text: Callable[[str], str] = _read_text,
) -> CryptIntegrityCheck:
    """Classify block device ``major:minor`` from sysfs and its dm table.

    sysfs gives the device-mapper uuid and name (``dm/uuid``, ``dm/name``)
    to anyone, but not the table. The table comes from ``dmsetup table``,
    which needs CAP_SYS_ADMIN; the worker already runs as guest root to drive
    docker, nft and tc. A device that is not device-mapper, whose uuid is not
    cryptsetup's ``CRYPT-``, or whose table cannot be read, is refused.
    """

    def check(major: int, minor: int) -> tuple[bool, str]:
        base = f"{sysfs}/{major}:{minor}/dm"
        try:
            uuid = read_text(base + "/uuid").strip()
            name = read_text(base + "/name").strip()
        except OSError:
            return False, f"block device {major}:{minor} is not a device-mapper device"
        if not uuid.startswith(CRYPT_UUID_PREFIX) or uuid.startswith(CRYPT_SUBDEV_PREFIX):
            return False, f"device-mapper device {major}:{minor} is not a dm-crypt mapping"
        if _DM_NAME_RE.fullmatch(name) is None:
            return False, f"device-mapper device {major}:{minor} has an unusable name"
        try:
            result = runner(
                [dmsetup, "table", name],
                capture_output=True,
                timeout=DMSETUP_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False, "dmsetup table failed"
        if result.returncode != 0:
            return False, "dmsetup table failed (it needs root)"
        try:
            table = (result.stdout or b"").decode()
        except UnicodeDecodeError:
            return False, "dmsetup table output is invalid"
        ok, detail = parse_crypt_table(table)
        return ok, f"{name}: {detail}"

    return check


def require_protected_scratch(
    root: str,
    probe: StorageProbe,
    *,
    driver_status: dict[str, str] | None = None,
) -> str:
    """Refuse unless Docker's data root, and every mount below it, is protected.

    ``root`` is the daemon's ``DockerRootDir``, looked up in the worker's own
    mount namespace, which must be the daemon's. Each mount must be tmpfs or
    ramfs, or a block device ``probe.crypt_integrity`` accepts. Below the
    root, nsfs mounts are skipped, and an overlay mount passes only when its
    upperdir, workdir and every lowerdir resolve under the root (relative
    ones from Docker's overlay2 directory), whose mounts are all checked.
    """

    if (driver_status or {}).get("driver-type") == CONTAINERD_SNAPSHOTTER:
        raise StorageError(
            "the Docker daemon uses the containerd image store, which keeps images "
            "outside its data root; the TEE box needs the classic graphdriver store"
        )
    if not isinstance(root, str) or not root.startswith("/"):
        raise StorageError("the Docker data root is not an absolute path")
    resolved = os.path.realpath(root)
    if not os.path.isdir(resolved):
        raise StorageError(
            f"the Docker data root {root} is not visible to the worker; run the worker "
            "in the daemon's mount namespace"
        )
    try:
        device = probe.device_of(resolved)
    except OSError as exc:
        raise StorageError(f"the Docker data root {root} cannot be inspected: {exc}") from exc
    selected = mounts_for(resolved, parse_mountinfo(probe.mountinfo()), device)
    if not selected:
        raise StorageError(
            f"no mount of device {device[0]}:{device[1]}, which serves the Docker data "
            f"root {root}, is listed over it"
        )
    details = []
    for index, mount in enumerate(selected):
        where = f"{mount.mount_point} ({mount.fstype} on {mount.major}:{mount.minor})"
        if mount.fstype in MEMORY_FSTYPES:
            details.append(f"{mount.mount_point}: {mount.fstype}")
            continue
        if index > 0 and mount.fstype in VIEW_FSTYPES:
            continue
        if index > 0 and mount.fstype == "overlay":
            outside = _overlay_outside(resolved, mount)
            if outside is not None:
                raise StorageError(
                    f"TEE box scratch must be in guest memory or on dm-crypt with integrity; "
                    f"the overlay on {mount.mount_point} has a layer outside the Docker data "
                    f"root: {outside!s:.256}"
                )
            continue
        try:
            ok, detail = probe.crypt_integrity(mount.major, mount.minor)
        except Exception as exc:  # noqa: BLE001 - any probe failure refuses startup
            ok, detail = False, f"the device check failed: {exc}"
        if ok is not True:
            raise StorageError(
                f"TEE box scratch must be in guest memory or on dm-crypt with integrity; "
                f"{where} under the Docker data root is not: {detail}"
            )
        details.append(f"{mount.mount_point}: {detail}")
    return "; ".join(details)


def require_no_swap(probe: StorageProbe) -> str:
    """Refuse while any swap is active, of any kind.

    ``/proc/swaps`` must be exactly its header line. Anything more refuses:
    swap on a disk or a file writes guest memory, the TEE box state
    included, to host storage, and so can zram, whose ``backing_dev`` writes
    pages to a disk in the clear. A name is never trusted to mean memory.
    """

    lines = [line for line in probe.swaps().splitlines() if line.strip()]
    if not lines or lines[0].split() != ["Filename", "Type", "Size", "Used", "Priority"]:
        raise StorageError("the swap table is unreadable")
    if len(lines) > 1:
        device = _unescape(lines[1].split()[0])
        raise StorageError(
            f"swap is on ({device!s:.128}); swap can write guest memory, including the "
            "TEE box state, to a host disk, so the TEE box needs every swap off"
        )
    return "no swap"
