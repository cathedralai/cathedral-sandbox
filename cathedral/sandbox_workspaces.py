"""Persistent, versioned workspaces on one hotel (issue #305).

A workspace is a named directory that belongs to one owner. It outlives
rooms. A room mounts it read-write when its create says
``"workspace": "<name>"``. A delete of a room never deletes the workspace.

Owner: the hash of the hotel API key that made the call, plus the broker
guest id. The broker sets the guest id; a guest cannot set it. An owner sees,
mounts, versions and deletes only its own workspaces. A workspace of another
owner answers 404 ``workspace_not_found``, the same as a missing one, so an
owner cannot learn that a name exists.

Layout under the workspace root::

    <root>/<sha256(owner)[:32]>/<name>/meta.json
    <root>/<sha256(owner)[:32]>/<name>/data/          rooms mount this only
    <root>/<sha256(owner)[:32]>/<name>/versions/<n>/  read-only copies

Owner directories are hashes and names match ``NAME_RE``, so no request value
can change a path. The API never follows a path inside ``data/`` or
``versions/``: a room can put symlinks there. Copies, rollback and delete run
in a short helper container (``DockerCopier``) under the room runtime, with
no network. Symlinks then resolve inside the helper, not on the host.

Settings:
  CATHEDRAL_WORKSPACE_ROOT          directory on the hotel; unset: no workspaces
  CATHEDRAL_WORKSPACE_MAX_PER_OWNER workspaces for each owner (default 10)
  CATHEDRAL_WORKSPACE_MAX_VERSIONS  versions for each workspace (default 20)
  CATHEDRAL_WORKSPACE_HELPER_IMAGE  image of the helper container
                                    (default alpine:3.20)
  CATHEDRAL_WORKSPACE_MOUNT_CHECK   "0" skips the check that the root is
                                    mounted nosuid,nodev,noexec (tests only)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from cathedral.sandbox_api import SandboxContractError, WORKSPACE_NAME_RE, validate_workspace_name
from cathedral.sandbox_owner import BROKER_GUEST_LABEL, GUEST_HEADER, guest_from, owner_id
from cathedral.sandbox_provider import SandboxOpError

NAME_RE = WORKSPACE_NAME_RE
SAFE_MOUNT_OPTIONS = ("nosuid", "nodev", "noexec")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_name(name: object) -> str:
    try:
        return validate_workspace_name(name)
    except SandboxContractError as exc:
        raise SandboxOpError(exc.code, 400, str(exc)) from None


def mount_options_safe(path: Path, mountinfo: str = "/proc/self/mountinfo") -> tuple[bool, str]:
    """True when the mount that holds *path* has nosuid, nodev and noexec."""
    try:
        lines = Path(mountinfo).read_text().splitlines()
    except OSError as exc:
        return False, f"cannot read {mountinfo}: {exc.strerror}"
    target = str(path.resolve())
    best: tuple[str, set[str]] | None = None
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        mount_point = fields[4].replace("\\040", " ")
        if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
            if best is None or len(mount_point) > len(best[0]):
                best = (mount_point, set(fields[5].split(",")))
    if best is None:
        return False, "no mount holds the workspace root"
    missing = [o for o in SAFE_MOUNT_OPTIONS if o not in best[1]]
    if missing:
        return False, f"the workspace root mount lacks {','.join(missing)}"
    return True, "ok"


class Copier(Protocol):
    def copy(self, src: Path, dst: Path) -> None: ...  # dst exists and is empty
    def replace(self, src: Path, dst: Path) -> None: ...  # empty dst, then copy src into it
    def clear(self, dst: Path) -> None: ...  # remove everything inside dst


class LocalCopier:
    """Copies in this process. For tests and for an API that runs as root.

    shutil does not follow symlinks here (symlinks=True, rmtree on lstat).
    """

    def copy(self, src: Path, dst: Path) -> None:
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)

    def replace(self, src: Path, dst: Path) -> None:
        self.clear(dst)
        self.copy(src, dst)

    def clear(self, dst: Path) -> None:
        for entry in os.scandir(dst):
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path)
            else:
                os.unlink(entry.path)


class DockerCopier:
    """Copies in a short helper container under the room runtime.

    The helper has no network and sees only the two directories of one
    operation. Files that a room made as root, and symlinks, stay inside the
    helper's view.
    """

    SCRIPTS = {
        "copy": "cp -a /src/. /dst/",
        "replace": "find /dst -mindepth 1 -delete && cp -a /src/. /dst/",
        "clear": "find /dst -mindepth 1 -delete",
    }

    def __init__(self, client: Any, image: str) -> None:
        self.client = client
        self.image = image

    def _run(self, op: str, src: Path | None, dst: Path) -> None:
        self.client.ensure_image(self.image)
        argv = ["docker", "run", "--rm", "--network", "none", "--label", f"cathedral.workspace.op={op}"]
        runtime = getattr(self.client, "guest_runtime", None)
        if runtime:
            argv += ["--runtime", runtime]
        if src is not None:
            argv += ["-v", f"{src}:/src:ro"]
        argv += ["-v", f"{dst}:/dst", self.image, "sh", "-c", self.SCRIPTS[op]]
        result = self.client.run(argv, timeout=1800.0)
        if result.returncode != 0:
            # The helper's stderr names files of the workspace; keep it out of
            # the answer.
            raise SandboxOpError("workspace_copy_failed", 502, f"workspace {op} failed (exit {result.returncode})")

    def copy(self, src: Path, dst: Path) -> None:
        self._run("copy", src, dst)

    def replace(self, src: Path, dst: Path) -> None:
        self._run("replace", src, dst)

    def clear(self, dst: Path) -> None:
        self._run("clear", None, dst)


def _not_found(name: str) -> SandboxOpError:
    return SandboxOpError("workspace_not_found", 404, f"no workspace {name}")


class WorkspaceStore:
    def __init__(
        self,
        root: Path,
        copier: Copier,
        *,
        max_per_owner: int = 10,
        max_versions: int = 20,
        check_mount: bool = True,
    ) -> None:
        self.root = Path(root)
        self.copier = copier
        self.max_per_owner = max(1, max_per_owner)
        self.max_versions = max(1, max_versions)
        self._lock = threading.RLock()
        # (owner, name) -> sandbox ids that mount it now
        self._mounts: dict[tuple[str, str], set[str]] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.disabled_reason: str | None = None
        if check_mount:
            ok, why = mount_options_safe(self.root)
            if not ok:
                self.disabled_reason = why

    @classmethod
    def from_env(cls, client: Any) -> "WorkspaceStore | None":
        raw = os.environ.get("CATHEDRAL_WORKSPACE_ROOT", "").strip()
        if not raw:
            return None

        def env_int(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, "").strip() or default)
            except ValueError:
                return default

        image = os.environ.get("CATHEDRAL_WORKSPACE_HELPER_IMAGE", "").strip() or "alpine:3.20"
        return cls(
            Path(raw),
            DockerCopier(client, image),
            max_per_owner=env_int("CATHEDRAL_WORKSPACE_MAX_PER_OWNER", 10),
            max_versions=env_int("CATHEDRAL_WORKSPACE_MAX_VERSIONS", 20),
            check_mount=os.environ.get("CATHEDRAL_WORKSPACE_MOUNT_CHECK", "1").strip() != "0",
        )

    # ------------------------------------------------------------ paths
    def _owner_dir(self, owner: str) -> Path:
        return self.root / hashlib.sha256(owner.encode("utf-8")).hexdigest()[:32]

    def _dir(self, owner: str, name: str) -> Path:
        validate_name(name)
        owner_dir = self._owner_dir(owner)
        path = owner_dir / name
        # Defence in depth: the name regex already rules out separators.
        if path.parent != owner_dir:
            raise _not_found(name)
        return path

    def _require_enabled(self) -> None:
        if self.disabled_reason is not None:
            raise SandboxOpError("workspaces_unavailable", 503, f"workspaces are off on this hotel: {self.disabled_reason}")

    def _meta(self, path: Path, name: str) -> dict[str, Any]:
        try:
            return json.loads((path / "meta.json").read_text())
        except (OSError, ValueError):
            raise _not_found(name) from None

    def _save_meta(self, path: Path, meta: dict[str, Any]) -> None:
        tmp = path / "meta.json.tmp"
        tmp.write_text(json.dumps(meta, sort_keys=True))
        os.replace(tmp, path / "meta.json")

    def _doc(self, owner: str, name: str, meta: dict[str, Any]) -> dict[str, Any]:
        rooms = sorted(h for h in self._mounts.get((owner, name), ()) if h != "rollback")
        return {
            "name": name,
            "created_at": meta.get("created_at"),
            "versions": [dict(v) for v in meta.get("versions", [])],
            "rooms": rooms,
            "in_use": bool(rooms),
        }

    # ------------------------------------------------------------ API
    def create(self, owner: str, name: str) -> dict[str, Any]:
        self._require_enabled()
        path = self._dir(owner, name)
        with self._lock:
            if (path / "meta.json").exists():
                raise SandboxOpError("workspace_exists", 409, f"workspace {name} exists")
            if len(self._names(owner)) >= self.max_per_owner:
                raise SandboxOpError(
                    "workspace_limit", 409, f"this owner may have {self.max_per_owner} workspaces on this hotel"
                )
            path.parent.mkdir(mode=0o700, exist_ok=True)
            path.mkdir(mode=0o700, exist_ok=True)
            (path / "data").mkdir(mode=0o755, exist_ok=True)
            (path / "versions").mkdir(mode=0o700, exist_ok=True)
            meta = {"name": name, "created_at": _now(), "versions": [], "next_version": 1}
            self._save_meta(path, meta)
            return self._doc(owner, name, meta)

    def _names(self, owner: str) -> list[str]:
        owner_dir = self._owner_dir(owner)
        if not owner_dir.is_dir():
            return []
        return sorted(p.name for p in owner_dir.iterdir() if NAME_RE.fullmatch(p.name) and (p / "meta.json").exists())

    def list(self, owner: str) -> list[dict[str, Any]]:
        self._require_enabled()
        with self._lock:
            out = []
            for name in self._names(owner):
                path = self._dir(owner, name)
                out.append(self._doc(owner, name, self._meta(path, name)))
            return out

    def get(self, owner: str, name: str) -> dict[str, Any]:
        self._require_enabled()
        path = self._dir(owner, name)
        with self._lock:
            return self._doc(owner, name, self._meta(path, name))

    def delete(self, owner: str, name: str) -> None:
        self._require_enabled()
        path = self._dir(owner, name)
        with self._lock:
            meta = self._meta(path, name)
            self._refuse_in_use(owner, name, "delete")
            # meta.json goes first, so a failed clear leaves no half workspace
            # that a room could mount.
            (path / "meta.json").unlink()
        self.copier.clear(path / "data")
        for v in meta.get("versions", []):
            vdir = path / "versions" / str(v["version"])
            if vdir.is_dir():
                self.copier.clear(vdir)
        shutil.rmtree(path)

    def _refuse_in_use(self, owner: str, name: str, what: str) -> None:
        if self._mounts.get((owner, name)):
            raise SandboxOpError(
                "workspace_in_use", 409, f"cannot {what} workspace {name}: a room mounts it; delete the room first"
            )

    def version(self, owner: str, name: str, *, label: str | None = None, reason: str = "request") -> dict[str, Any]:
        self._require_enabled()
        if label is not None and (not isinstance(label, str) or len(label) > 128):
            raise SandboxOpError("invalid_version_label", 400, "label must be a string of at most 128 characters")
        path = self._dir(owner, name)
        with self._lock:
            meta = self._meta(path, name)
            if "rollback" in self._mounts.get((owner, name), ()):
                raise SandboxOpError("workspace_in_use", 409, f"workspace {name} is rolling back; retry")
            if len(meta.get("versions", [])) >= self.max_versions:
                raise SandboxOpError(
                    "version_limit", 409, f"workspace {name} has {self.max_versions} versions, the most allowed"
                )
            number = int(meta.get("next_version", 1))
            meta["next_version"] = number + 1
            vdir = path / "versions" / str(number)
            vdir.mkdir(mode=0o700)
            self._save_meta(path, meta)
        try:
            self.copier.copy(path / "data", vdir)
        except Exception:
            shutil.rmtree(vdir, ignore_errors=True)
            raise
        entry = {"version": number, "created_at": _now(), "reason": reason}
        if label:
            entry["label"] = label
        with self._lock:
            meta = self._meta(path, name)
            meta.setdefault("versions", []).append(entry)
            self._save_meta(path, meta)
        return dict(entry)

    def versions(self, owner: str, name: str) -> list[dict[str, Any]]:
        return self.get(owner, name)["versions"]

    def rollback(self, owner: str, name: str, version: object) -> dict[str, Any]:
        self._require_enabled()
        if not isinstance(version, int) or isinstance(version, bool):
            raise SandboxOpError("invalid_version", 400, "version must be an integer")
        path = self._dir(owner, name)
        with self._lock:
            meta = self._meta(path, name)
            if not any(v.get("version") == version for v in meta.get("versions", [])):
                raise SandboxOpError("version_not_found", 404, f"workspace {name} has no version {version}")
            self._refuse_in_use(owner, name, "roll back")
            # Hold a mount marker so no room mounts it during the copy.
            self._mounts.setdefault((owner, name), set()).add("rollback")
        try:
            self.copier.replace(path / "versions" / str(version), path / "data")
        finally:
            with self._lock:
                self._release(owner, name, "rollback")
        return {"name": name, "rolled_back_to": version, "at": _now()}

    # ------------------------------------------------------------ rooms
    def mount(self, owner: str, name: str, sandbox_id: str) -> Path:
        """Reserve the workspace for a room and return the directory to bind."""
        self._require_enabled()
        path = self._dir(owner, name)
        with self._lock:
            self._meta(path, name)
            holders = self._mounts.setdefault((owner, name), set())
            if "rollback" in holders:
                raise SandboxOpError("workspace_in_use", 409, f"workspace {name} is rolling back; retry")
            holders.add(sandbox_id)
        return path / "data"

    def check(self, owner: str, name: str) -> None:
        """404 when the owner has no such workspace. Runs before a create."""
        self.get(owner, name)

    def unmount(self, owner: str, name: str, sandbox_id: str) -> None:
        with self._lock:
            self._release(owner, name, sandbox_id)

    def _release(self, owner: str, name: str, holder: str) -> None:
        holders = self._mounts.get((owner, name))
        if holders is not None:
            holders.discard(holder)
            if not holders:
                del self._mounts[(owner, name)]


__all__ = [
    "BROKER_GUEST_LABEL",
    "DockerCopier",
    "GUEST_HEADER",
    "LocalCopier",
    "WorkspaceStore",
    "guest_from",
    "mount_options_safe",
    "owner_id",
    "validate_name",
]
