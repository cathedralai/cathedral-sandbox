"""The signed host bundle: what it contains, how it is built, and how it lands.

A release record names one bundle by ``archive_sha256`` (the exact bytes
fetched) and ``tree_sha256`` (the exact files extracted). The tree is::

    updater/cathedral/__init__.py       the updater's own code, which imports
    updater/cathedral/miner_*.py        only the standard library and cryptography
    miner/launcher                      the product launcher, from scripts/
    miner/unit.conf                     a drop-in for the miner's systemd unit
    trust/release-keys.json             the release keys the *next* check trusts

Extraction and the tree digest follow the validator's updater
(cathedral-validator ``updater.py:417-501``): regular files and directories
only, no links, no absolute or parent paths, bounded size, and a digest over
each path, size, executable bit and content. Every tree is installed into its
own directory named by its digest and never modified afterwards. The only
mutable things are symlinks, and each is replaced with one ``rename(2)``.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import shutil
import stat
import tarfile
import time
from pathlib import Path, PurePosixPath

from cathedral.miner_products import MinerProduct, find_launcher, read_launcher_profile
from cathedral.miner_release import load_trust_root

UPDATER_MODULES = (
    "miner_release.py",
    "miner_products.py",
    "miner_bundle.py",
    "miner_updater.py",
    "miner_update_cli.py",
)
"""The modules that make up the updater. A test proves they import nothing else."""

PACKAGE_INIT = b'"""Cathedral miner updater, as shipped in a signed host bundle."""\n'

TREE_UPDATER = "updater"
TREE_LAUNCHER = "miner/launcher"
TREE_UNIT_CONF = "miner/unit.conf"
TREE_TRUST_ROOT = "trust/release-keys.json"

REPOSITORY_TRUST_ROOT = "deploy/miner-update/release-keys.json"
REPOSITORY_UNIT_CONF = "deploy/miner-update/miner-unit.conf"

MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_TREE_FILES = 256
MAX_TREE_BYTES = 32 * 1024 * 1024


class BundleError(RuntimeError):
    """A bundle could not be built, verified or installed."""


# --- digests -------------------------------------------------------------------


def release_tree_sha256(root: Path) -> str:
    """Hash every path, size, executable bit and byte. Links and special files are refused."""

    if root.is_symlink() or not root.is_dir():
        raise BundleError("release tree is invalid")
    entries: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise BundleError("release tree contains a symlink")
        if path.is_file():
            entries.append(path)
        elif not path.is_dir():
            raise BundleError("release tree contains an unsupported file")
    digest = hashlib.sha256()
    for path in sorted(entries, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        metadata = path.stat()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(metadata.st_size.to_bytes(8, "big"))
        digest.update(b"x" if metadata.st_mode & 0o111 else b"-")
        with path.open("rb") as handle:
            while chunk := handle.read(65_536):
                digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


# --- building (offline, and at bootstrap) -------------------------------------


def _write(path: Path, body: bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(body)
    os.chmod(path, 0o555 if executable else 0o444)


def assemble_tree(
    repository_root: Path,
    product: MinerProduct,
    destination: Path,
    *,
    trust_root: Path | None = None,
) -> None:
    """Lay out one product's bundle tree from a repository checkout.

    Used by the offline builder and by the one-time bootstrap, so the tree a
    host is bootstrapped with is byte-identical to the bundle a release of the
    same commit would ship.
    """

    if destination.exists():
        raise BundleError(f"bundle destination already exists: {destination}")
    destination.mkdir(mode=0o755, parents=True)
    package = destination / TREE_UPDATER / "cathedral"
    _write(package / "__init__.py", PACKAGE_INIT)
    for module in UPDATER_MODULES:
        _write(package / module, (repository_root / "cathedral" / module).read_bytes())

    launcher = find_launcher(repository_root, product)
    read_launcher_profile(launcher)
    _write(destination / TREE_LAUNCHER, launcher.read_bytes(), executable=True)
    _write(destination / TREE_UNIT_CONF, (repository_root / REPOSITORY_UNIT_CONF).read_bytes())

    trust_path = trust_root if trust_root is not None else repository_root / REPOSITORY_TRUST_ROOT
    try:
        trust_bytes = trust_path.read_bytes()
    except FileNotFoundError as exc:
        raise BundleError(
            f"no miner release trust root at {trust_path}; commit the public keys first"
        ) from exc
    load_trust_root(trust_bytes)
    _write(destination / TREE_TRUST_ROOT, trust_bytes)


def build_archive(tree: Path) -> bytes:
    """A deterministic gzip tar of a tree: sorted, root-owned, no timestamps."""

    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(tree.rglob("*"), key=lambda item: item.relative_to(tree).as_posix()):
                info = tarfile.TarInfo(path.relative_to(tree).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                if path.is_dir():
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    archive.addfile(info)
                    continue
                if path.is_symlink() or not path.is_file():
                    raise BundleError("bundle tree contains a non-regular file")
                body = path.read_bytes()
                info.size = len(body)
                info.mode = 0o555 if path.stat().st_mode & 0o111 else 0o444
                archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


# --- installing (on the host) ----------------------------------------------------


def _safe_member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        raise BundleError("bundle archive has an unsafe member path")
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def extract_archive(archive: bytes, destination: Path, *, deadline: float | None = None) -> None:
    """Extract a bounded, regular-file-only archive into a new directory."""

    if destination.exists() or destination.is_symlink():
        raise BundleError("bundle extraction destination already exists")
    destination.mkdir(mode=0o755, parents=True)
    total = 0
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
            for member in bundle:
                if deadline is not None and time.monotonic() > deadline:
                    raise BundleError("bundle extraction exceeded its deadline")
                path = _safe_member_path(member.name)
                if member.isdir():
                    (destination / path).mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.size < 0:
                    raise BundleError("bundle archive contains a non-regular member")
                count += 1
                total += member.size
                if count > MAX_TREE_FILES or total > MAX_TREE_BYTES:
                    raise BundleError("bundle archive exceeds extraction limits")
                target = destination / path
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise BundleError("bundle archive member is unreadable")
                with target.open("xb") as output:
                    while chunk := source.read(65_536):
                        output.write(chunk)
                    output.flush()
                    os.fchmod(output.fileno(), 0o555 if member.mode & 0o111 else 0o444)
                    os.fsync(output.fileno())
        for root, _directories, _files in os.walk(destination, topdown=False):
            os.chmod(root, 0o755)
            _fsync_directory(Path(root))
    except (tarfile.TarError, OSError, EOFError, gzip.BadGzipFile) as exc:
        raise BundleError(f"bundle archive extraction failed: {exc}") from exc


def require_root_controlled(path: Path, *, expected_uid: int = 0) -> None:
    """Refuse a file or directory another user could have written."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BundleError(f"path is unavailable: {path}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise BundleError(f"path is not root-controlled: {path}")


def require_root_controlled_tree(root: Path, *, expected_uid: int = 0) -> None:
    for path in (root, *root.rglob("*")):
        require_root_controlled(path, expected_uid=expected_uid)


def install_tree(
    archive: bytes,
    *,
    archive_sha256: str,
    tree_sha256: str,
    releases: Path,
    expected_uid: int = 0,
    deadline: float | None = None,
) -> Path:
    """Install one verified bundle as ``releases/<tree_sha256>`` and return it.

    Idempotent: an existing directory is accepted only if its digest still
    matches. A new one is extracted beside it, in the same directory so the
    final ``rename(2)`` never crosses a filesystem, and renamed into place. A
    crash leaves either nothing or a complete tree.
    """

    if len(archive) > MAX_ARCHIVE_BYTES:
        raise BundleError("bundle archive exceeds its size limit")
    if sha256_bytes(archive) != archive_sha256:
        raise BundleError("bundle archive does not match the signed archive digest")
    target = releases / tree_sha256
    if target.exists():
        require_root_controlled_tree(target, expected_uid=expected_uid)
        if release_tree_sha256(target) != tree_sha256:
            raise BundleError(f"installed tree no longer matches its digest: {target}")
        return target
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    work = releases / f".staging-{tree_sha256}-{os.getpid()}"
    if work.exists():
        shutil.rmtree(work)
    try:
        extract_archive(archive, work, deadline=deadline)
        if release_tree_sha256(work) != tree_sha256:
            raise BundleError("bundle tree does not match the signed tree digest")
        os.rename(work, target)
        _fsync_directory(releases)
    finally:
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
    return target


def install_directory(source: Path, *, tree_sha256: str, releases: Path) -> Path:
    """Install an already-assembled tree (bootstrap) as ``releases/<tree_sha256>``."""

    if release_tree_sha256(source) != tree_sha256:
        raise BundleError("assembled tree does not match its digest")
    target = releases / tree_sha256
    releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    if target.exists():
        if release_tree_sha256(target) != tree_sha256:
            raise BundleError(f"installed tree no longer matches its digest: {target}")
        return target
    os.rename(source, target)
    _fsync_directory(releases)
    return target


# --- symlinks ---------------------------------------------------------------------


def link_target(link: Path) -> str | None:
    """The literal target of a symlink, or None if there is no link."""

    if not link.is_symlink():
        if link.exists():
            raise BundleError(f"expected a symlink: {link}")
        return None
    return os.readlink(link)


def atomic_symlink(link: Path, target: str) -> None:
    """Point ``link`` at ``target`` with one rename, then fsync the directory."""

    temporary = link.parent / f".{link.name}.{os.getpid()}.tmp"
    if temporary.is_symlink() or temporary.exists():
        temporary.unlink()
    link.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    try:
        os.symlink(target, temporary)
        os.replace(temporary, link)
        _fsync_directory(link.parent)
    finally:
        if temporary.is_symlink():
            temporary.unlink()


def remove_link(link: Path) -> None:
    if link.is_symlink():
        link.unlink()
        _fsync_directory(link.parent)


__all__ = [
    "MAX_ARCHIVE_BYTES",
    "REPOSITORY_TRUST_ROOT",
    "REPOSITORY_UNIT_CONF",
    "TREE_LAUNCHER",
    "TREE_TRUST_ROOT",
    "TREE_UNIT_CONF",
    "TREE_UPDATER",
    "UPDATER_MODULES",
    "BundleError",
    "assemble_tree",
    "atomic_symlink",
    "build_archive",
    "extract_archive",
    "install_directory",
    "install_tree",
    "link_target",
    "release_tree_sha256",
    "remove_link",
    "require_root_controlled",
    "require_root_controlled_tree",
    "sha256_bytes",
]
