"""Apply signed miner releases to an installed miner.

Host layout (every path is under ``HostPaths.root``, which is ``/`` on a host)::

    /etc/cathedral/miner-update/config.json      deploy config, written once by the bootstrap
    /etc/cathedral/miner-update/paused           operator: pause every check
    /etc/cathedral/miner-update/pin              operator: hold at one version
    /usr/local/lib/cathedral-miner-update/
        bin/cathedral-miner-update               frozen shim, installed by the bootstrap
        updater/releases/<tree>/                 verified bundle trees, never modified
        updater/current, updater/previous        which tree runs the updater
        miner/legacy/                            the miner unit's own launcher and pin
        miner/releases/<activation>/             launcher, release.env, unit.conf, profile.json
        miner/current                            which of those the miner runs
    /etc/systemd/system/<miner unit>.d/50-cathedral-miner-update.conf
                                                 symlink to miner/current/unit.conf
    /var/lib/cathedral-miner-update/state.json   floors, stage, history

One check, in order:

1. Resolve an activation a previous run left behind.
2. Fetch and verify the signed record: signature, identity (product, network,
   netuid, channel), key role, freshness, and the per-channel sequence floor.
   The floor is burned before anything else happens.
3. Self-update first. If the record's bundle is not the tree this updater runs
   from, install it, probe it, make it current, and hand the rest of the check
   to it. The rest of every release therefore runs under the code that
   release ships.
4. Activate. Build the release's activation directory (launcher, image pin,
   unit drop-in), pull and verify the image, re-check that a restart is safe,
   set the latch, flip ``miner/current`` with one rename, and restart. Commit
   only when the running container reports the released image.

Rollback rule (review finding F2)
---------------------------------
The previous version fingerprinted the miner's durable state and allowed a
rollback only if nothing changed. The running miner writes that database on
every validator request, so on a live miner rollback was almost never allowed.

Each record now declares ``state_schema``: the durable-state schema its image
writes. Every image reads every schema up to its own. So a failed activation
rolls back automatically when the previous release's declared schema is at
least the new one's, or when only the launcher or unit changed (same image).
Whatever the new image wrote, the previous image can read. A release that
raises the schema halts for an operator instead, which is a decision the
signer made on purpose, not an accident of a validator probe landing during a
pull. ``resolve`` gives the operator both exits.

The ``may_have_run`` latch is kept from the previous version: it is set before
the swap and cleared only by proof, never by rewriting a pointer.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cathedral.miner_bundle import (
    TREE_LAUNCHER,
    TREE_UNIT_CONF,
    BundleError,
    atomic_symlink,
    install_tree,
    link_target,
    release_tree_sha256,
    remove_link,
    require_root_controlled,
)
from cathedral.miner_products import (
    LauncherProfile,
    LauncherProfileError,
    product_by_name,
    read_launcher_profile,
)
from cathedral.miner_release import (
    CHANNELS,
    MAX_RELEASE_DOCUMENT_BYTES,
    BundleRef,
    MinerRelease,
    MinerReleaseError,
    TrustedKey,
    canonical_json,
    enforce_monotonic_release,
    https_url,
    parse_miner_release,
    strict_json,
)

STATE_SCHEMA = "cathedral_miner_update_state_v1"
CONFIG_SCHEMA = "cathedral_miner_update_config_v1"
STATUS_SCHEMA = "cathedral_miner_update_status_v1"

EXIT_OK = 0
EXIT_REFUSED = 10
EXIT_HALTED = 11
EXIT_ALERT = 12
DOCUMENTED_EXIT_STATUSES = frozenset({EXIT_OK, EXIT_REFUSED, EXIT_HALTED, EXIT_ALERT})
"""Every status the updater exits with on purpose. The shim treats any other
status (a traceback, an import error) as a crash of the updater itself."""

DEFERRAL_ALERT_AFTER = 6
"""Consecutive deferred checks (about six hours) before the check exits with
``EXIT_ALERT``, so the unit shows as failed instead of deferring silently."""

STAGE_PREPARED = "prepared"
STAGE_MAY_HAVE_RUN = "may_have_run"

LEGACY = "legacy"
DROPIN_NAME = "50-cathedral-miner-update.conf"

MAX_STATE_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 16 * 1024
MAX_PIN_BYTES = 256

_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,200}\.service$")
_NETWORK_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_VERSION_RE = re.compile(r"^[0-9a-zA-Z][0-9a-zA-Z._-]{0,63}$")
_TREE_RE = re.compile(r"^[0-9a-f]{64}$")


class MinerUpdateError(RuntimeError):
    """The update did not complete. Nothing unsafe happened."""


class MinerUpdateHalted(MinerUpdateError):
    """An outcome this process must not guess at. Recovery is an operator decision."""


class MinerUpdateRolledBack(MinerUpdateError):
    """The release failed and the previous release was restored and verified."""

    def __init__(self, message: str, *, release: Mapping[str, object] | None = None) -> None:
        super().__init__(message)
        self.release = release


# --- configuration and paths ---------------------------------------------------------


@dataclass(frozen=True)
class HostConfig:
    """Deploy-time config. Every field is required; none has a default."""

    product: str
    network: str
    netuid: int
    channel: str
    channel_url: str
    miner_unit: str
    minimum_sequence: int

    _FIELDS = (
        "product",
        "network",
        "netuid",
        "channel",
        "channel_url",
        "miner_unit",
        "minimum_sequence",
    )

    @classmethod
    def from_document(cls, document: object) -> HostConfig:
        if not isinstance(document, dict) or set(document) != {"schema", *cls._FIELDS}:
            raise MinerUpdateError("updater config fields are invalid")
        if document["schema"] != CONFIG_SCHEMA:
            raise MinerUpdateError("updater config schema is unsupported")
        try:
            product_by_name(document["product"])
        except (ValueError, TypeError) as exc:
            raise MinerUpdateError("updater config names an unknown product") from exc
        network = document["network"]
        if not isinstance(network, str) or _NETWORK_RE.fullmatch(network) is None:
            raise MinerUpdateError("updater config network is invalid")
        netuid = document["netuid"]
        if isinstance(netuid, bool) or not isinstance(netuid, int) or not 0 <= netuid <= 65535:
            raise MinerUpdateError("updater config netuid is invalid")
        if document["channel"] not in CHANNELS:
            raise MinerUpdateError("updater config channel is invalid")
        try:
            https_url(document["channel_url"], "updater config channel URL")
        except MinerReleaseError as exc:
            raise MinerUpdateError(str(exc)) from exc
        unit = document["miner_unit"]
        if not isinstance(unit, str) or _UNIT_RE.fullmatch(unit) is None:
            raise MinerUpdateError("updater config miner unit is invalid")
        minimum = document["minimum_sequence"]
        if isinstance(minimum, bool) or not isinstance(minimum, int) or not 0 <= minimum < 1 << 31:
            raise MinerUpdateError("updater config minimum sequence is invalid")
        return cls(
            product=document["product"],
            network=network,
            netuid=netuid,
            channel=document["channel"],
            channel_url=document["channel_url"],
            miner_unit=unit,
            minimum_sequence=minimum,
        )

    def as_document(self) -> dict[str, object]:
        document: dict[str, object] = {"schema": CONFIG_SCHEMA}
        for name in self._FIELDS:
            document[name] = getattr(self, name)
        return document


def load_config(path: Path, *, expected_uid: int = 0) -> HostConfig:
    try:
        require_root_controlled(path, expected_uid=expected_uid)
        with path.open("rb") as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except (OSError, BundleError) as exc:
        raise MinerUpdateError(f"updater config is unavailable: {exc}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise MinerUpdateError("updater config is unexpectedly large")
    try:
        document = strict_json(raw, label="updater config")
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc
    return HostConfig.from_document(document)


@dataclass(frozen=True)
class HostPaths:
    """Every path the updater touches, under one root so tests can relocate it."""

    root: Path = Path("/")

    def _at(self, relative: str) -> Path:
        return self.root / relative

    @property
    def config_dir(self) -> Path:
        return self._at("etc/cathedral/miner-update")

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.json"

    @property
    def pause_file(self) -> Path:
        return self.config_dir / "paused"

    @property
    def pin_file(self) -> Path:
        return self.config_dir / "pin"

    @property
    def install_root(self) -> Path:
        return self._at("usr/local/lib/cathedral-miner-update")

    @property
    def shim(self) -> Path:
        return self.install_root / "bin" / "cathedral-miner-update"

    @property
    def updater_releases(self) -> Path:
        return self.install_root / "updater" / "releases"

    @property
    def updater_current(self) -> Path:
        return self.install_root / "updater" / "current"

    @property
    def updater_previous(self) -> Path:
        return self.install_root / "updater" / "previous"

    @property
    def miner_dir(self) -> Path:
        return self.install_root / "miner"

    @property
    def miner_releases(self) -> Path:
        return self.miner_dir / "releases"

    @property
    def miner_legacy(self) -> Path:
        return self.miner_dir / LEGACY

    @property
    def miner_current(self) -> Path:
        return self.miner_dir / "current"

    @property
    def state_dir(self) -> Path:
        return self._at("var/lib/cathedral-miner-update")

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / "lock"

    @property
    def records_dir(self) -> Path:
        return self.state_dir / "records"

    @property
    def snapshot(self) -> Path:
        """The validator-access snapshot. ``safe_to_activate`` reads its expiry."""

        return self._at("etc/cathedral/validator-access/validator-access.json")

    @property
    def systemd_dir(self) -> Path:
        return self._at("etc/systemd/system")

    def dropin(self, unit: str) -> Path:
        return self.systemd_dir / f"{unit}.d" / DROPIN_NAME

    @property
    def operator_command(self) -> Path:
        return self._at("usr/local/sbin/cathedral-miner-update")


# --- host effects ---------------------------------------------------------------------


@dataclass
class MinerUpdaterHost:
    """Everything one check needs. Effects on docker, systemd and the network are injected."""

    config: HostConfig
    paths: HostPaths
    trusted_keys: Mapping[str, TrustedKey]
    # The tree digest of the updater code running now, or None if it is not
    # running from an installed release.
    running_tree: str | None
    fetch_metadata: Callable[[], bytes]
    fetch_bundle: Callable[[BundleRef], bytes]
    # (release directory, saved record) -> the probe's JSON document. Raises to refuse.
    probe_updater: Callable[[Path, Path], Mapping[str, object]]
    # (release directory, lock descriptor) -> (exit status, outcome document).
    handoff: Callable[[Path, int], tuple[int, Mapping[str, object] | None]]
    prepare_image: Callable[[MinerRelease, LauncherProfile], None]
    systemctl: Callable[[Sequence[str]], None]
    # The image a container reports right now, or None if it is not running.
    current_image: Callable[[str], str | None]
    # The image a container reports once the unit is active and the container
    # has settled, or None if that does not happen in time.
    settled_image: Callable[[str], str | None]
    safe_to_activate: Callable[[], bool]
    now_unix: Callable[[], int]
    expected_uid: int = 0
    handoff_depth: int = 0
    lock_fd: int | None = None


@dataclass(frozen=True)
class UpdateOutcome:
    """What one run did."""

    action: str
    reason: str
    exit_status: int = EXIT_OK
    release: Mapping[str, object] | None = None
    alert: bool = False
    # True when a handed-off child already recorded this outcome in state.
    recorded: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "exit_status": self.exit_status,
            "release": dict(self.release) if self.release is not None else None,
            "alert": self.alert,
        }


# --- files ----------------------------------------------------------------------------


def _atomic_write(path: Path, body: bytes, *, mode: int) -> None:
    directory = path.parent
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise MinerUpdateError(f"directory is unavailable: {directory}") from exc
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = ""
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise MinerUpdateError(f"file could not be replaced: {path}") from exc
    finally:
        if temporary:
            with contextlib.suppress(OSError):
                os.unlink(temporary)


def empty_state() -> dict[str, object]:
    return {
        "schema": STATE_SCHEMA,
        # Highest authenticated record per channel, burned before any attempt.
        "floors": {},
        "miner": {"current": None, "stage": None, "pending": None},
        # The last release that failed here; it is not retried until a
        # different record arrives or an operator clears it.
        "failed": None,
        "last_check": None,
        "last_refusal": None,
        "consecutive_deferrals": 0,
    }


def read_state(path: Path) -> dict[str, object]:
    """Read the state, keeping any field a newer updater added."""

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return empty_state()
    except OSError as exc:
        raise MinerUpdateError("updater state cannot be read") from exc
    if len(raw) > MAX_STATE_BYTES:
        raise MinerUpdateError("updater state is unexpectedly large")
    try:
        state = strict_json(raw, label="updater state")
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc
    if not isinstance(state, dict) or state.get("schema") != STATE_SCHEMA:
        raise MinerUpdateError("updater state schema is unsupported")
    merged = empty_state()
    merged.update(state)
    miner = merged["miner"]
    if not isinstance(merged["floors"], dict) or not isinstance(miner, dict):
        raise MinerUpdateError("updater state is malformed")
    for key in ("current", "stage", "pending"):
        miner.setdefault(key, None)
    if miner["stage"] not in (None, STAGE_PREPARED, STAGE_MAY_HAVE_RUN):
        raise MinerUpdateError("updater state stage is unrecognised")
    deferrals = merged["consecutive_deferrals"]
    if isinstance(deferrals, bool) or not isinstance(deferrals, int) or deferrals < 0:
        raise MinerUpdateError("updater state deferral count is malformed")
    return merged


def write_state(path: Path, state: Mapping[str, object]) -> None:
    try:
        body = canonical_json(dict(state))
    except MinerReleaseError as exc:
        raise MinerUpdateError("updater state is not serialisable") from exc
    _atomic_write(path, body, mode=0o600)


def read_pin(path: Path) -> str | None:
    """The version an operator pinned, or None. An unreadable pin refuses rather than guesses."""

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_PIN_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MinerUpdateError(f"pin file cannot be read: {path}") from exc
    try:
        version = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise MinerUpdateError("pin file is not ASCII") from exc
    if len(raw) > MAX_PIN_BYTES or _VERSION_RE.fullmatch(version) is None:
        raise MinerUpdateError(f"pin file does not name one version: {path}")
    return version


# --- locking -------------------------------------------------------------------------


@contextlib.contextmanager
def exclusive(path: Path, *, inherited_fd: int | None = None):
    """Hold the updater lock for the whole check.

    Non-blocking, so a manual check that races the timer is refused rather
    than queued behind a long pull. A handed-off child is given the parent's
    locked descriptor and checks that it really is the updater lock.
    """

    if inherited_fd is not None:
        try:
            held = os.fstat(inherited_fd)
            expected = os.stat(path)
            if (held.st_dev, held.st_ino) != (expected.st_dev, expected.st_ino):
                raise MinerUpdateError("inherited descriptor is not the updater lock")
            fcntl.flock(inherited_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise MinerUpdateError("inherited updater lock is not held") from exc
        yield inherited_fd
        return
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        handle = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as exc:
        raise MinerUpdateError("updater lock is unavailable") from exc
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise MinerUpdateError("another update check is already running") from exc
        yield handle
    finally:
        os.close(handle)


# --- activation directories ----------------------------------------------------------


def activation_id(release: MinerRelease, config: HostConfig) -> str:
    """Name an activation by everything its contents are derived from."""

    return hashlib.sha256(
        canonical_json(
            {
                "image": release.image,
                "tree_sha256": release.bundle.tree_sha256,
                "product": config.product,
                "network": config.network,
                "netuid": config.netuid,
            }
        )
    ).hexdigest()


def render_release_env(profile: LauncherProfile, release: MinerRelease, config: HostConfig) -> bytes:
    """The environment the miner unit loads after the operator's own file.

    systemd reads EnvironmentFile= entries in order and a later assignment wins,
    so this pin overrides the one in the operator's file without editing it.
    The network and netuid come from deploy config, so a launcher that starts
    requiring them gets them without a hand edit on the host.
    """

    return (
        "# Written by cathedral-miner-update for one signed release. Do not edit.\n"
        f"{profile.image_variable}={release.image}\n"
        f"CATHEDRAL_NETWORK={config.network}\n"
        f"CATHEDRAL_NETUID={config.netuid}\n"
    ).encode("ascii")


def _activation_files(
    bundle_dir: Path, profile: LauncherProfile, release: MinerRelease, config: HostConfig
) -> dict[str, tuple[bytes, bool]]:
    profile_document = {
        "container": profile.container,
        "image": release.image,
        "image_variable": profile.image_variable,
        "runtime_contract": profile.runtime_contract,
        "tree_sha256": release.bundle.tree_sha256,
        "network": config.network,
        "netuid": config.netuid,
    }
    return {
        "launcher": ((bundle_dir / TREE_LAUNCHER).read_bytes(), True),
        "unit.conf": ((bundle_dir / TREE_UNIT_CONF).read_bytes(), False),
        "release.env": (render_release_env(profile, release, config), False),
        "profile.json": (canonical_json(profile_document) + b"\n", False),
    }


def stage_activation(
    paths: HostPaths,
    bundle_dir: Path,
    profile: LauncherProfile,
    release: MinerRelease,
    config: HostConfig,
    *,
    expected_uid: int = 0,
) -> str:
    """Build ``miner/releases/<activation>`` and return its link target.

    The directory is complete before anything points at it, and it is never
    changed afterwards, so the one rename in ``atomic_symlink`` switches the
    launcher, the image pin and the unit drop-in together.
    """

    identifier = activation_id(release, config)
    target = paths.miner_releases / identifier
    files = _activation_files(bundle_dir, profile, release, config)
    if target.exists():
        present = {path.name for path in target.iterdir()}
        if present != set(files):
            raise MinerUpdateError(f"activation directory has unexpected contents: {target}")
        for name, (body, _executable) in files.items():
            require_root_controlled(target / name, expected_uid=expected_uid)
            if (target / name).read_bytes() != body:
                raise MinerUpdateError(f"activation directory was modified: {target / name}")
        return f"releases/{identifier}"
    paths.miner_releases.mkdir(mode=0o755, parents=True, exist_ok=True)
    work = paths.miner_dir / f".staging-{identifier}-{os.getpid()}"
    if work.exists():
        for leftover in work.iterdir():
            leftover.unlink()
        work.rmdir()
    work.mkdir(mode=0o755)
    for name, (body, executable) in files.items():
        with (work / name).open("xb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(work / name, 0o555 if executable else 0o444)
    os.rename(work, target)
    fd = os.open(paths.miner_releases, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return f"releases/{identifier}"


def read_activation_profile(paths: HostPaths, target: str) -> dict[str, object]:
    try:
        raw = (paths.miner_dir / target / "profile.json").read_bytes()
        document = strict_json(raw, label="activation profile")
    except (OSError, MinerReleaseError) as exc:
        raise MinerUpdateError(f"activation profile is unreadable: {target}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("container"), str):
        raise MinerUpdateError(f"activation profile is malformed: {target}")
    return document


# --- decisions -------------------------------------------------------------------------


def rollback_allowed(pending: Mapping[str, object]) -> tuple[bool, str]:
    """Whether a failed activation may put the previous release back unattended."""

    release = pending.get("release")
    previous_image = pending.get("previous_image")
    if not isinstance(release, Mapping):
        return False, "the pending release is not recorded"
    if not isinstance(previous_image, str) or not previous_image:
        return False, "nothing was running before, so there is nothing to verify a rollback against"
    if previous_image == release.get("image"):
        return True, "the image is unchanged; only the launcher or unit changed"
    previous_schema = pending.get("previous_state_schema")
    new_schema = release.get("state_schema")
    if isinstance(previous_schema, bool) or not isinstance(previous_schema, int):
        return False, "the previous release declares no durable-state schema"
    if isinstance(new_schema, bool) or not isinstance(new_schema, int):
        return False, "the release declares no durable-state schema"
    if previous_schema >= new_schema:
        return True, f"the previous image reads state schema {new_schema}"
    return False, (
        f"the release writes state schema {new_schema}, newer than the "
        f"previous image's {previous_schema}"
    )


def _effective_floor(
    floor: object, minimum_sequence: int
) -> Mapping[str, object] | None:
    if isinstance(floor, dict) and isinstance(floor.get("sequence"), int):
        if floor["sequence"] >= minimum_sequence:
            return floor
    if minimum_sequence > 0:
        return {"sequence": minimum_sequence, "signed_sha256": None}
    return None


def _refuse_known_failure(state: Mapping[str, object], release: MinerRelease) -> None:
    failed = state.get("failed")
    if not isinstance(failed, dict):
        return
    same_record = failed.get("signed_sha256") == release.signed_sha256
    same_updater = (
        failed.get("updater_tree") is not None
        and failed.get("updater_tree") == release.bundle.tree_sha256
    )
    if same_record or same_updater:
        raise MinerUpdateError(
            f"this release already failed on this host ({failed.get('reason')}); "
            "waiting for a newer signed release, or run `resolve --retry`"
        )


def _remember_failure(
    host: MinerUpdaterHost,
    state: dict[str, object],
    release: Mapping[str, object],
    *,
    reason: str,
    updater_tree: str | None = None,
) -> None:
    state["failed"] = {
        "signed_sha256": release.get("signed_sha256"),
        "sequence": release.get("sequence"),
        "version": release.get("version"),
        "updater_tree": updater_tree,
        "reason": reason[:500],
        "at": host.now_unix(),
    }
    write_state(host.paths.state_file, state)


# --- the check ------------------------------------------------------------------------


def update_once(host: MinerUpdaterHost) -> UpdateOutcome:
    """Run one check. Every documented failure comes back as an outcome."""

    if host.paths.pause_file.exists():
        return UpdateOutcome("paused", f"operator pause file present: {host.paths.pause_file}")
    return _locked(host, _check_locked)


def _locked(
    host: MinerUpdaterHost, body: Callable[[MinerUpdaterHost, dict[str, object]], UpdateOutcome]
) -> UpdateOutcome:
    try:
        with exclusive(host.paths.lock_file, inherited_fd=host.lock_fd) as fd:
            host.lock_fd = fd
            try:
                state = read_state(host.paths.state_file)
            except MinerUpdateError as exc:
                return UpdateOutcome("refused", str(exc), EXIT_REFUSED)
            try:
                outcome = body(host, state)
            except MinerUpdateHalted as exc:
                outcome = UpdateOutcome("halted", str(exc), EXIT_HALTED)
            except MinerUpdateRolledBack as exc:
                outcome = UpdateOutcome("rolled_back", str(exc), EXIT_REFUSED, release=exc.release)
            except (MinerUpdateError, MinerReleaseError, BundleError, LauncherProfileError) as exc:
                outcome = UpdateOutcome("refused", str(exc), EXIT_REFUSED)
            except OSError as exc:
                # The host, not the code: a full disk or a missing path is a
                # refusal. Anything else escapes as a crash, which the shim
                # answers by running the previous updater.
                outcome = UpdateOutcome("refused", f"host error: {exc}", EXIT_REFUSED)
            return _record(host, outcome)
    except MinerUpdateError as exc:
        return UpdateOutcome("refused", str(exc), EXIT_REFUSED)


def _record(host: MinerUpdaterHost, outcome: UpdateOutcome) -> UpdateOutcome:
    """Keep the last check, the last refusal and the deferral count for ``status``."""

    if outcome.recorded:
        return outcome
    try:
        state = read_state(host.paths.state_file)
    except MinerUpdateError:
        return outcome
    release = outcome.release or {}
    entry = {
        "at": host.now_unix(),
        "action": outcome.action,
        "reason": outcome.reason[:500],
        "sequence": release.get("sequence"),
        "version": release.get("version"),
    }
    state["last_check"] = entry
    if outcome.exit_status in (EXIT_REFUSED, EXIT_HALTED):
        state["last_refusal"] = entry
    if outcome.action == "deferred":
        count = int(state.get("consecutive_deferrals") or 0) + 1
        state["consecutive_deferrals"] = count
        if count >= DEFERRAL_ALERT_AFTER:
            outcome = dataclasses.replace(
                outcome,
                exit_status=EXIT_ALERT,
                alert=True,
                reason=f"{outcome.reason}; deferred {count} checks in a row",
            )
            state["last_check"] = dict(entry, action="deferred", reason=outcome.reason[:500])
    elif outcome.action in ("activated", "current", "held"):
        state["consecutive_deferrals"] = 0
    try:
        write_state(host.paths.state_file, state)
    except MinerUpdateError:
        pass
    return outcome


def _verify(host: MinerUpdaterHost, raw: object) -> MinerRelease:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_RELEASE_DOCUMENT_BYTES:
        raise MinerUpdateError("release metadata size is out of range")
    config = host.config
    try:
        return parse_miner_release(
            bytes(raw),
            trusted_keys=host.trusted_keys,
            expected_product=config.product,
            expected_network=config.network,
            expected_netuid=config.netuid,
            expected_channel=config.channel,
            now_unix=host.now_unix(),
        )
    except MinerReleaseError as exc:
        raise MinerUpdateError(f"release metadata refused: {exc}") from exc


def _check_locked(host: MinerUpdaterHost, state: dict[str, object]) -> UpdateOutcome:
    if host.running_tree is None or _TREE_RE.fullmatch(host.running_tree) is None:
        raise MinerUpdateError(
            "this updater is not running from an installed release; run it through "
            "the installed cathedral-miner-update command"
        )
    reconcile_interrupted_activation(host, state)

    raw = host.fetch_metadata()
    release = _verify(host, raw)

    channel = host.config.channel
    floors = state["floors"]
    assert isinstance(floors, dict)
    try:
        enforce_monotonic_release(
            _effective_floor(floors.get(channel), host.config.minimum_sequence), release
        )
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc
    # Burn the sequence before any attempt. A failed activation still consumes
    # it, so a different record cannot reuse it and pass the equivocation check.
    floors[channel] = {"sequence": release.sequence, "signed_sha256": release.signed_sha256}
    write_state(host.paths.state_file, state)

    _refuse_known_failure(state, release)

    pin = read_pin(host.paths.pin_file)
    if pin is not None and pin != release.version:
        return UpdateOutcome(
            "held",
            f"operator pinned version {pin}; the channel offers {release.version}",
            release=release.summary(),
        )

    if host.running_tree != release.bundle.tree_sha256:
        return _self_update(host, state, bytes(raw), release)
    return _activate(host, state, release)


# --- self-update ------------------------------------------------------------------------


def _save_record(paths: HostPaths, release: MinerRelease, raw: bytes) -> Path:
    paths.records_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = paths.records_dir / f"{release.signed_sha256}.json"
    _atomic_write(path, raw, mode=0o600)
    for other in paths.records_dir.iterdir():
        if other != path and other.suffix == ".json":
            with contextlib.suppress(OSError):
                other.unlink()
    return path


def _self_update(
    host: MinerUpdaterHost, state: dict[str, object], raw: bytes, release: MinerRelease
) -> UpdateOutcome:
    """Install the release's updater, prove it works, make it current, hand over.

    Three guards stop a bad updater from stranding the host:

    1. The probe. Before the new tree is current, the new code verifies the
       very record that delivered it, with the trust root it ships and this
       host's config, reads this host's state, and hashes its own tree. An
       import error, a broken verifier or a trust root that would lock the
       host out all fail here, and nothing changes.
    2. The first run. The new updater then runs the rest of this check as a
       child that inherits the lock. If it crashes (an exit status the updater
       never uses on purpose), this process puts the previous updater back.
    3. The shim. On any later run, if the current updater crashes, the frozen
       shim runs the previous updater instead (``recover_crashed_updater``).

    A failed release is remembered and not retried until a newer one arrives.
    """

    paths = host.paths
    tree = release.bundle.tree_sha256
    if host.handoff_depth > 0:
        raise MinerUpdateError(
            "the channel moved to another updater during a handoff; the next check applies it"
        )
    archive = host.fetch_bundle(release.bundle)
    release_dir = install_tree(
        archive,
        archive_sha256=release.bundle.archive_sha256,
        tree_sha256=tree,
        releases=paths.updater_releases,
        expected_uid=host.expected_uid,
    )
    record_path = _save_record(paths, release, raw)
    try:
        probe = host.probe_updater(release_dir, record_path)
        if probe.get("signed_sha256") != release.signed_sha256 or probe.get("tree_sha256") != tree:
            raise MinerUpdateError("its probe did not confirm this release")
    except (MinerUpdateError, MinerReleaseError, BundleError, OSError) as exc:
        _remember_failure(
            host, state, release.summary(), reason=f"updater probe failed: {exc}", updater_tree=tree
        )
        raise MinerUpdateError(
            f"the updater in this release failed its probe, so this updater stays current: {exc}"
        ) from exc

    previous = link_target(paths.updater_current)
    if previous is not None:
        atomic_symlink(paths.updater_previous, previous)
    atomic_symlink(paths.updater_current, f"releases/{tree}")

    assert host.lock_fd is not None
    status, document = host.handoff(release_dir, host.lock_fd)
    if (
        status in DOCUMENTED_EXIT_STATUSES
        and isinstance(document, Mapping)
        and isinstance(document.get("action"), str)
    ):
        relayed = document.get("release")
        return UpdateOutcome(
            action=str(document["action"]),
            reason=f"updater {tree[:12]} took over: {document.get('reason', '')}",
            exit_status=status,
            release=relayed if isinstance(relayed, Mapping) else None,
            alert=bool(document.get("alert")),
            recorded=True,
        )

    # The new updater crashed on its first run. Put this one back.
    if previous is not None:
        atomic_symlink(paths.updater_current, previous)
    remove_link(paths.updater_previous)
    fresh = read_state(paths.state_file)
    _remember_failure(
        host,
        fresh,
        release.summary(),
        reason=f"the new updater crashed on its first check (exit status {status})",
        updater_tree=tree,
    )
    raise MinerUpdateError(
        f"the updater in this release crashed on its first check (exit status {status}); "
        "the previous updater was restored"
    )


def recover_crashed_updater(host: MinerUpdaterHost, crashed_release: Path) -> UpdateOutcome:
    """Run by the previous updater when the shim saw the current one crash."""

    def body(host: MinerUpdaterHost, state: dict[str, object]) -> UpdateOutcome:
        paths = host.paths
        current = link_target(paths.updater_current)
        if current is None or (paths.updater_current.parent / current).resolve() != crashed_release.resolve():
            raise MinerUpdateError("the current updater is not the one reported as crashed")
        crashed_tree = crashed_release.resolve().name
        if host.running_tree is None or host.running_tree == crashed_tree:
            raise MinerUpdateError("the recovering updater is the one that crashed")
        atomic_symlink(paths.updater_current, f"releases/{host.running_tree}")
        remove_link(paths.updater_previous)
        _remember_failure(
            host,
            state,
            {},
            reason="the updater crashed and the previous updater took over",
            updater_tree=crashed_tree,
        )
        return _check_locked(host, state)

    return _locked(host, body)


def probe_release(host: MinerUpdaterHost, raw: bytes) -> dict[str, object]:
    """Everything a check needs before it acts, with no side effects.

    Run by a newly installed updater, from its own tree, before it is made
    current. It must verify the record that delivered it with the trust root it
    ships, read the state the previous updater wrote, match its own tree, and
    accept the launcher it ships.
    """

    paths = host.paths
    state = read_state(paths.state_file)
    release = _verify(host, raw)
    floor = state["floors"].get(host.config.channel) if isinstance(state["floors"], dict) else None
    try:
        enforce_monotonic_release(_effective_floor(floor, host.config.minimum_sequence), release)
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc
    if host.running_tree != release.bundle.tree_sha256:
        raise MinerUpdateError("the probe is not running from this release's tree")
    own = paths.updater_releases / release.bundle.tree_sha256
    if release_tree_sha256(own) != release.bundle.tree_sha256:
        raise MinerUpdateError("the probe's own tree does not match its digest")
    _check_launcher(host, own, release)
    return {"probe": "ok", "signed_sha256": release.signed_sha256, "tree_sha256": host.running_tree}


# --- activation -----------------------------------------------------------------------


def _check_launcher(host: MinerUpdaterHost, bundle_dir: Path, release: MinerRelease) -> LauncherProfile:
    profile = read_launcher_profile(bundle_dir / TREE_LAUNCHER)
    product = product_by_name(host.config.product)
    if profile.runtime_contract != product.runtime_contract:
        raise MinerUpdateError("the bundle's launcher runs a different product")
    if profile.runtime_contract != release.runtime_contract:
        raise MinerUpdateError("the release and its launcher name different runtime contracts")
    if profile.image_repository != release.image_repository:
        raise MinerUpdateError("the release image is not in the repository its launcher requires")
    return profile


def _restart_miner(host: MinerUpdaterHost) -> None:
    """Reload units, clear a tripped start limit, restart.

    ``reset-failed`` matters most on rollback: a release that crash-loops can
    exhaust the miner unit's start limit, and systemd then refuses the rollback
    start too (review finding F4).
    """

    unit = host.config.miner_unit
    host.systemctl(["daemon-reload"])
    with contextlib.suppress(MinerUpdateError):
        host.systemctl(["reset-failed", unit])
    host.systemctl(["restart", unit])


def _previous(host: MinerUpdaterHost, state: Mapping[str, object], active: str) -> dict[str, object]:
    profile = read_activation_profile(host.paths, active)
    container = str(profile["container"])
    miner = state["miner"]
    assert isinstance(miner, dict)
    current = miner.get("current")
    if active == LEGACY:
        image = host.current_image(container)
        schema = None
    else:
        image = profile.get("image") if isinstance(profile.get("image"), str) else None
        schema = (
            current.get("state_schema")
            if isinstance(current, dict) and current.get("target") == active
            else None
        )
    return {
        "previous_target": active,
        "previous_container": container,
        "previous_image": image,
        "previous_state_schema": schema,
    }


def _commit(
    host: MinerUpdaterHost, state: dict[str, object], summary: Mapping[str, object], target: str
) -> None:
    miner = state["miner"]
    assert isinstance(miner, dict)
    miner["current"] = dict(summary, target=target)
    miner["stage"] = None
    miner["pending"] = None
    state["failed"] = None
    write_state(host.paths.state_file, state)


def _clear_stage(host: MinerUpdaterHost, state: dict[str, object]) -> None:
    miner = state["miner"]
    assert isinstance(miner, dict)
    miner["stage"] = None
    miner["pending"] = None
    write_state(host.paths.state_file, state)


def _activate(host: MinerUpdaterHost, state: dict[str, object], release: MinerRelease) -> UpdateOutcome:
    paths = host.paths
    summary = release.summary()
    bundle_dir = paths.updater_releases / release.bundle.tree_sha256
    profile = _check_launcher(host, bundle_dir, release)
    target = f"releases/{activation_id(release, host.config)}"

    active = link_target(paths.miner_current)
    if active is None:
        raise MinerUpdateError("miner/current is missing; run the bootstrap again")
    if active == target:
        _commit(host, state, summary, target)
        return UpdateOutcome(
            "current", "the miner already runs this release's image and launcher", release=summary
        )

    if not host.safe_to_activate():
        return UpdateOutcome(
            "deferred", "the miner is not at a safe point to restart", release=summary
        )

    stage_activation(paths, bundle_dir, profile, release, host.config, expected_uid=host.expected_uid)
    miner = state["miner"]
    assert isinstance(miner, dict)
    miner["stage"] = STAGE_PREPARED
    miner["pending"] = {
        "release": summary,
        "target": target,
        "container": profile.container,
        **_previous(host, state, active),
    }
    write_state(paths.state_file, state)

    try:
        host.prepare_image(release, profile)
    except Exception as exc:  # noqa: BLE001 - any pull or verify failure is one case
        _clear_stage(host, state)
        raise MinerUpdateError(
            f"the released image could not be prepared, nothing was changed: {exc}"
        ) from exc

    # Review finding F3: the pull can take minutes, so the margin checked
    # before it may be gone. Check again immediately before the swap.
    if not host.safe_to_activate():
        _clear_stage(host, state)
        return UpdateOutcome(
            "deferred",
            "the validator-access snapshot lost its safety margin during the pull",
            release=summary,
        )

    # The latch. From here the released image may start at any moment,
    # including by systemd's own restart policy or a reboot.
    miner["stage"] = STAGE_MAY_HAVE_RUN
    write_state(paths.state_file, state)

    atomic_symlink(paths.miner_current, target)
    restart_error: Exception | None = None
    try:
        _restart_miner(host)
    except Exception as exc:  # noqa: BLE001 - reported once the outcome is known
        restart_error = exc

    if host.settled_image(profile.container) == release.image:
        _commit(host, state, summary, target)
        return UpdateOutcome("activated", "the released image is running", release=summary)

    detail = (
        f"restart failed ({restart_error})"
        if restart_error is not None
        else "the released image did not come up"
    )
    pending = miner["pending"]
    assert isinstance(pending, dict)
    allowed, why = rollback_allowed(pending)
    if not allowed:
        raise MinerUpdateHalted(
            f"{detail}; not rolling back because {why}. Run `resolve --restore-previous` "
            "or `resolve --accept-release`"
        )
    _rollback(host, state, pending, detail=detail)
    raise MinerUpdateRolledBack(
        f"{detail}; rolled back because {why}, and the previous image is running",
        release=summary,
    )


def _rollback(
    host: MinerUpdaterHost, state: dict[str, object], pending: Mapping[str, object], *, detail: str
) -> None:
    """Point the miner back at the previous release, and prove it came back."""

    paths = host.paths
    try:
        atomic_symlink(paths.miner_current, str(pending["previous_target"]))
        _restart_miner(host)
    except Exception as exc:  # noqa: BLE001
        write_state(paths.state_file, state)
        raise MinerUpdateHalted(
            f"{detail}, and restoring the previous release also failed ({exc}); "
            "the miner may be running nothing. Resolve it explicitly"
        ) from exc
    if host.settled_image(str(pending["previous_container"])) != pending.get("previous_image"):
        write_state(paths.state_file, state)
        raise MinerUpdateHalted(
            f"{detail}, and the previous image did not come back. The miner may be "
            "running nothing. Resolve it explicitly"
        )
    release = pending.get("release")
    miner = state["miner"]
    assert isinstance(miner, dict)
    miner["stage"] = None
    miner["pending"] = None
    _remember_failure(
        host, state, release if isinstance(release, Mapping) else {}, reason=detail
    )


def _valid_pending(pending: object) -> bool:
    return (
        isinstance(pending, dict)
        and isinstance(pending.get("release"), dict)
        and isinstance(pending.get("target"), str)
        and isinstance(pending.get("container"), str)
        and isinstance(pending.get("previous_target"), str)
        and isinstance(pending.get("previous_container"), str)
    )


def reconcile_interrupted_activation(host: MinerUpdaterHost, state: dict[str, object]) -> None:
    """Resolve a stage a previous run left behind.

    ``prepared`` means nothing was swapped, so it is cleared. ``may_have_run``
    is decided on what ``miner/current`` names and what is actually running,
    and a rollback is taken only under ``rollback_allowed``.
    """

    miner = state["miner"]
    assert isinstance(miner, dict)
    stage = miner.get("stage")
    if stage is None:
        return
    if stage == STAGE_PREPARED:
        _clear_stage(host, state)
        return
    pending = miner.get("pending")
    if not _valid_pending(pending):
        raise MinerUpdateHalted(
            "state records an interrupted activation but not which release it was; "
            "resolve it explicitly"
        )
    assert isinstance(pending, dict)
    release = pending["release"]
    active = link_target(host.paths.miner_current)

    if active == pending["previous_target"]:
        # The swap never happened, or a rollback already put it back.
        running = host.current_image(pending["previous_container"])
        if running is not None and running == pending.get("previous_image"):
            _clear_stage(host, state)
            return
        raise MinerUpdateHalted(
            "an interrupted activation left the previous release selected but it is not "
            f"running (running={running!r}); resolve it explicitly"
        )

    if active == pending["target"]:
        running = host.settled_image(pending["container"])
        if running is not None and running == release.get("image"):
            _commit(host, state, release, pending["target"])
            return
        allowed, why = rollback_allowed(pending)
        if allowed:
            _rollback(host, state, pending, detail="an interrupted activation did not come up")
            return
        raise MinerUpdateHalted(
            f"an interrupted activation did not come up (running={running!r}) and "
            f"not rolling back because {why}; resolve it explicitly"
        )

    raise MinerUpdateHalted(
        f"miner/current names neither the pending release nor the previous one ({active!r}); "
        "resolve it explicitly"
    )


# --- operator commands ------------------------------------------------------------------


def resolve(host: MinerUpdaterHost, action: str) -> UpdateOutcome:
    """The operator's exits from a halt, and from failure memory."""

    def body(host: MinerUpdaterHost, state: dict[str, object]) -> UpdateOutcome:
        if action == "retry":
            state["failed"] = None
            write_state(host.paths.state_file, state)
            return UpdateOutcome("resolved", "failure memory cleared; the next check retries")
        miner = state["miner"]
        assert isinstance(miner, dict)
        pending = miner.get("pending")
        if miner.get("stage") != STAGE_MAY_HAVE_RUN or not _valid_pending(pending):
            raise MinerUpdateError("there is no interrupted activation to resolve")
        assert isinstance(pending, dict)
        if action == "accept-release":
            running = host.settled_image(pending["container"])
            if running != pending["release"].get("image"):
                raise MinerUpdateError(
                    f"the release is not running (running={running!r}); start it first "
                    "or restore the previous release"
                )
            if link_target(host.paths.miner_current) != pending["target"]:
                atomic_symlink(host.paths.miner_current, pending["target"])
            _commit(host, state, pending["release"], pending["target"])
            return UpdateOutcome("resolved", "the running release was accepted as current")
        if action == "restore-previous":
            _rollback(host, state, pending, detail="the operator restored the previous release")
            return UpdateOutcome("resolved", "the previous release was restored and is running")
        raise MinerUpdateError(f"unknown resolve action: {action}")

    return _locked(host, body)


def describe_status(paths: HostPaths, config: HostConfig | None) -> dict[str, object]:
    """What is installed and what happened last. Works with the channel unreachable."""

    state = read_state(paths.state_file)
    miner = state["miner"]
    assert isinstance(miner, dict)
    try:
        pinned: object = read_pin(paths.pin_file)
    except MinerUpdateError as exc:
        pinned = f"invalid: {exc}"
    return {
        "schema": STATUS_SCHEMA,
        "config": config.as_document() if config is not None else None,
        "paused": paths.pause_file.exists(),
        "pinned_version": pinned,
        "updater": {
            "current": link_target(paths.updater_current),
            "previous": link_target(paths.updater_previous),
        },
        "miner": {
            "active": link_target(paths.miner_current),
            "current_release": miner.get("current"),
            "stage": miner.get("stage"),
            "pending": miner.get("pending"),
        },
        "needs_operator": miner.get("stage") == STAGE_MAY_HAVE_RUN,
        "last_check": state.get("last_check"),
        "last_refusal": state.get("last_refusal"),
        "consecutive_deferrals": state.get("consecutive_deferrals"),
        "failed": state.get("failed"),
        "floors": state.get("floors"),
    }


__all__ = [
    "CONFIG_SCHEMA",
    "DEFERRAL_ALERT_AFTER",
    "DOCUMENTED_EXIT_STATUSES",
    "DROPIN_NAME",
    "EXIT_ALERT",
    "EXIT_HALTED",
    "EXIT_OK",
    "EXIT_REFUSED",
    "LEGACY",
    "STAGE_MAY_HAVE_RUN",
    "STAGE_PREPARED",
    "STATE_SCHEMA",
    "HostConfig",
    "HostPaths",
    "MinerUpdateError",
    "MinerUpdateHalted",
    "MinerUpdateRolledBack",
    "MinerUpdaterHost",
    "UpdateOutcome",
    "activation_id",
    "describe_status",
    "empty_state",
    "exclusive",
    "load_config",
    "probe_release",
    "read_activation_profile",
    "read_pin",
    "read_state",
    "reconcile_interrupted_activation",
    "recover_crashed_updater",
    "render_release_env",
    "resolve",
    "rollback_allowed",
    "stage_activation",
    "update_once",
    "write_state",
]
