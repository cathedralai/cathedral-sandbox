"""Apply signed miner releases to an installed miner.

Host layout (every path is under ``HostPaths.root``, which is ``/`` on a host)::

    /etc/cathedral/miner-update/config.json      deploy config, written once by the bootstrap
    /etc/cathedral/miner-update/paused           operator: pause every check
    /etc/cathedral/miner-update/pin              operator: hold the release that runs now
    /usr/local/lib/cathedral-miner-update/
        bin/cathedral-miner-update               frozen shim, installed by the bootstrap
        updater/releases/<tree>/                 verified bundle trees, never modified
        updater/current, updater/previous        which tree runs the updater
        miner/legacy/                            the miner unit's own launcher and pin
        miner/releases/<activation>/             launcher, release.env, unit.conf, profile.json
        miner/current                            which of those the miner runs
    /etc/systemd/system/<miner unit>.d/50-cathedral-miner-update.conf
                                                 symlink to miner/current/unit.conf
    /var/lib/cathedral-miner-update/trust.json   the host's trust set (keys, revocations)
    /var/lib/cathedral-miner-update/state.json   floors, stage, history

One check, in order:

1. Resolve an activation a previous run left behind. A halt does not stop the
   rest of the check from verifying the channel and installing a newer updater.
2. Fetch and verify the signed record against the host's trust set: signature,
   identity (product, network, netuid, channel), key role, freshness, and the
   per-channel sequence floor, which is burned before anything else happens.
   Everything up to here handles untrusted bytes, so any exception is a
   refusal, never a crash. The fetched bytes are kept, so the fallback judges
   the same bytes.
3. Take any trust rotation the release's bundle carries. The trust set lives
   in host state and only moves forward; a key it drops is revoked for good.
4. Self-update first. If the record's bundle is not the tree this updater runs
   from, probe it, make it current, and hand the rest of the check to it. It
   stays current only if that first run fetched and verified the channel.
5. Activate. Build the release's activation directory, pull and verify the
   image and its state-schema label, re-check that a restart is safe, set the
   latch, flip ``miner/current`` with one rename, and restart. A container that
   started after the flip, settled, and stayed up through a second sample
   enters probation. A check at least 30 minutes later commits it if the same
   container is still up with no new restarts; one restart, or a reboot,
   restarts probation instead.
6. Escalate. A check with no activation in progress also looks at the miner,
   and alerts if it is inactive, down or restarting, even when the check itself
   only refused or held. Six checks in a row without a verified record alert.

Rollback rule (review finding F2)
---------------------------------
Each record declares ``state_schema``, the durable-state format its image
writes, and the image must carry the same number as a label. Every image reads
every schema up to its own. So a failed activation rolls back automatically
when the previous release's verified schema is at least the new one's, or when
only the launcher or unit changed (same image). Otherwise it halts for an
operator, who has ``resolve --restore-previous``, ``--accept-release`` and
``--abandon``.

The ``may_have_run`` latch is kept from #197: it is set before the swap and
cleared only by proof, never by rewriting a pointer.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import hashlib
import os
import re
import sys
import tempfile
import traceback
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cathedral.miner_bundle import (
    TREE_LAUNCHER,
    TREE_TRUST_ROOT,
    TREE_UNIT_CONF,
    BundleError,
    atomic_symlink,
    install_tree,
    link_target,
    release_tree_sha256,
    remove_link,
    require_root_controlled,
    require_root_controlled_tree,
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
    TRUST_STATE_SCHEMA,
    BundleRef,
    MinerRelease,
    MinerReleaseError,
    TrustState,
    canonical_json,
    enforce_monotonic_release,
    https_url,
    parse_miner_release,
    parse_trust_state,
    rotate_trust,
    strict_json,
)

STATE_SCHEMA = "cathedral_miner_update_state_v1"
CONFIG_SCHEMA = "cathedral_miner_update_config_v1"
STATUS_SCHEMA = "cathedral_miner_update_status_v1"
PIN_SCHEMA = "cathedral_miner_update_pin_v1"

EXIT_OK = 0
EXIT_REFUSED = 10
EXIT_HALTED = 11
EXIT_ALERT = 12
EXIT_FAULT = 13
DOCUMENTED_EXIT_STATUSES = frozenset({EXIT_OK, EXIT_REFUSED, EXIT_HALTED, EXIT_ALERT, EXIT_FAULT})
"""Every status the updater exits with on purpose. 13 means the updater's own
logic failed. The shim hands anything but 0, 11 and 12 to the previous updater's
``fallback``, which decides whether the current updater or the channel is at fault."""

FIRST_RUN_KEEP_STATUSES = frozenset({EXIT_OK, EXIT_REFUSED, EXIT_HALTED, EXIT_ALERT})

DEFERRAL_ALERT_AFTER = 6
"""Consecutive deferred checks (about six hours) before the check exits with
``EXIT_ALERT``. Refusals do not reset the count: a refusal says nothing about
whether the restart gate would pass, and resetting on every channel blip could
hide a gate that never opens."""

UNVERIFIED_ALERT_AFTER = 6
"""Consecutive checks without a verified channel record (about six hours)
before the check exits with ``EXIT_ALERT``: a withheld or expired channel must
not be silent just because refusals do not fail the unit."""

PROBATION_MINIMUM_SECONDS = 1800
"""How long a release stays on probation before a check may commit it, so a
second ``check`` run by hand right after the first cannot commit it."""

PROBATION_RESTARTS_FORGIVEN = 1
"""Container restarts during probation that restart probation instead of
failing the release, as a reboot does. One covers a docker daemon restart."""

INACTIVE_UNIT_STATES = ("inactive", "deactivating")
"""Unit states that mean nothing runs and systemd will not start it again.
The shipped drop-in sets ``Restart=always``, so on a managed release only
``systemctl stop`` leaves the unit here. ``pause`` is how an operator says a
stop is intended; an inactive miner on a host that is not paused alerts."""

STRIKES_TO_DEMOTE = 2
"""Failed checks an updater tree may have, each while the other updater
verified the channel, before the host stops using that tree. One induced or
transient failure never demotes a good updater."""

MAX_REMEMBERED_UPDATERS = 8

FALLBACK_RECORD_MAX_AGE_SECONDS = 600
"""How old the current updater's ``last_check`` may be for the fallback to
trust its ``verified`` flag. The shim runs the fallback as soon as the current
updater exits, so the entry for that run is seconds old."""

STAGE_PREPARED = "prepared"
STAGE_MAY_HAVE_RUN = "may_have_run"
STAGE_PROBATION = "probation"
STAGES = (None, STAGE_PREPARED, STAGE_MAY_HAVE_RUN, STAGE_PROBATION)

LEGACY = "legacy"
DROPIN_NAME = "50-cathedral-miner-update.conf"
STATE_SCHEMA_LABEL = "org.cathedral.state-schema"
"""The image label that must equal the record's ``state_schema``."""

MAX_STATE_BYTES = 256 * 1024
MAX_TRUST_BYTES = 256 * 1024
MAX_CONFIG_BYTES = 16 * 1024
MAX_PIN_BYTES = 4 * 1024

_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,200}\.service$")
_NETWORK_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
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


class GateImpossible(MinerUpdateError):
    """The safe-restart gate can never pass with this host's snapshot lifetime."""


class TrustSetUnavailable(MinerUpdateError):
    """The host trust set cannot be read. It alerts, since it will not heal."""


@dataclass(frozen=True)
class Observation:
    """One look at the miner: its container and its unit."""

    image: str
    started_at: float
    restarts: int
    active: bool


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
    def trust_file(self) -> Path:
        """The host's trust set. Every updater verifies against it."""

        return self.state_dir / "trust.json"

    @property
    def trust_backup(self) -> Path:
        """A verified copy of the last good trust set. Only a bootstrap run with
        ``--repair-trust-set`` reads it, and only to move forward from it."""

        return self.state_dir / "trust.json.backup"

    @property
    def fetched_record(self) -> Path:
        """The bytes the last check fetched from the channel, for the fallback."""

        return self.state_dir / "fetched-record"

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
    # The tree digest of the updater code running now, or None if it is not
    # running from an installed release.
    running_tree: str | None
    fetch_metadata: Callable[[], bytes]
    fetch_bundle: Callable[[BundleRef], bytes]
    # (release directory, saved record) -> the probe's JSON document. Raises to refuse.
    probe_updater: Callable[[Path, Path], Mapping[str, object]]
    # (release directory, lock descriptor) -> (exit status, outcome document).
    handoff: Callable[[Path, int], tuple[int, Mapping[str, object] | None]]
    # Pull and verify the image; return its state-schema label, or None if it has none.
    prepare_image: Callable[[MinerRelease, LauncherProfile], int | None]
    systemctl: Callable[[Sequence[str]], None]
    # The miner unit's ActiveState: active, inactive, failed, activating, ...
    unit_state: Callable[[], str]
    # One look at a container and the unit, without waiting. None if not running.
    observe: Callable[[str], Observation | None]
    # A look once the unit is active and the container has been up for the
    # dwell, or None if that does not happen in time.
    settle: Callable[[str], Observation | None]
    # True when a restart is safe now. Raises GateImpossible if it never can be.
    safe_to_activate: Callable[[], bool]
    now_unix: Callable[[], int]
    sleep: Callable[[float], None]
    boot_id: Callable[[], str]
    expected_uid: int = 0
    handoff_depth: int = 0
    lock_fd: int | None = None
    # Set once this run has fetched and verified a channel record.
    verified: bool = False
    # Set when this run tried to install a newer updater tree and failed in a
    # way that could be this updater's fault ("ambiguous") or was reported by
    # the new tree itself ("new"). The fallback judges the ambiguous ones.
    offered_updater: str | None = None
    updater_blame: str | None = None


@dataclass(frozen=True)
class UpdateOutcome:
    """What one run did."""

    action: str
    reason: str
    exit_status: int = EXIT_OK
    release: Mapping[str, object] | None = None
    alert: bool = False
    # Whether this run fetched and verified a channel record. The fallback and
    # the first-run guard use it to tell a broken updater from a broken channel.
    verified: bool = False
    # True when a handed-off child already recorded this outcome in state.
    recorded: bool = False
    # A newer updater this run could not install, and whose fault that looked.
    updater_offered: str | None = None
    updater_blame: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "exit_status": self.exit_status,
            "release": dict(self.release) if self.release is not None else None,
            "alert": self.alert,
            "verified": self.verified,
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
        # The last release (by image and tree) that failed here. It is not
        # retried, even re-signed, until other content arrives or an operator
        # clears it.
        "failed": None,
        # Updater trees this host no longer runs, and strikes against trees
        # that have failed once while the other updater verified the channel.
        "failed_updaters": {},
        "updater_strikes": {},
        "last_check": None,
        "last_refusal": None,
        "last_fallback": None,
        "consecutive_deferrals": 0,
        "consecutive_unverified": 0,
        # What the last check fetched from the channel, kept so the fallback
        # judges the same bytes rather than fetching its own (trust re-review).
        "last_fetch": None,
        # The highest verified state schema of any release that reached
        # may_have_run, and its image. No other image may declare less.
        "schema_high_water": None,
        # The miner's restart count at the last check, per selected release.
        "miner_health": None,
    }


def read_state(path: Path) -> dict[str, object]:
    """Read the state, keeping any field a newer updater added.

    The schema string never changes through the channel: the probe refuses a
    new updater that reports another one (trust review P2), so a previous
    updater can always read the state and act as the fallback. Newer updaters
    only add fields and stages. An older updater keeps fields it does not
    know, and a stage it does not know stops activation (``reconcile``) but
    not verification, self-update or the fallback.
    """

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
    if (
        not isinstance(merged["floors"], dict)
        or not isinstance(miner, dict)
        or not isinstance(merged["failed_updaters"], dict)
        or not isinstance(merged["updater_strikes"], dict)
    ):
        raise MinerUpdateError("updater state is malformed")
    for key in ("current", "stage", "pending"):
        miner.setdefault(key, None)
    if miner["stage"] is not None and not isinstance(miner["stage"], str):
        raise MinerUpdateError("updater state stage is malformed")
    for counter in ("consecutive_deferrals", "consecutive_unverified"):
        value = merged[counter]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MinerUpdateError(f"updater state {counter} is malformed")
    return merged


def write_state(path: Path, state: Mapping[str, object]) -> None:
    try:
        body = canonical_json(dict(state))
    except MinerReleaseError as exc:
        raise MinerUpdateError("updater state is not serialisable") from exc
    _atomic_write(path, body, mode=0o600)


def read_pin(path: Path) -> dict[str, str] | None:
    """The release an operator pinned, by image and tree digest, or None.

    A pin holds content, not a version string, so a re-signed record with the
    same version but a different image or bundle is still held (trust review P2).
    An unreadable pin refuses rather than guesses.
    """

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_PIN_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MinerUpdateError(f"pin file cannot be read: {path}") from exc
    try:
        document = strict_json(raw, label="pin file")
    except MinerReleaseError as exc:
        raise MinerUpdateError(f"pin file is invalid: {exc}") from exc
    if (
        len(raw) > MAX_PIN_BYTES
        or not isinstance(document, dict)
        or set(document) != {"schema", "image", "tree_sha256", "version"}
        or document["schema"] != PIN_SCHEMA
        or not all(isinstance(document[key], str) for key in ("image", "tree_sha256", "version"))
        or _TREE_RE.fullmatch(document["tree_sha256"]) is None
    ):
        raise MinerUpdateError(f"pin file does not name one release: {path}")
    return {key: document[key] for key in ("image", "tree_sha256", "version")}


def pin_document(current: Mapping[str, object]) -> bytes:
    """The pin for a committed release record."""

    return canonical_json(
        {
            "schema": PIN_SCHEMA,
            "image": current["image"],
            "tree_sha256": current["tree_sha256"],
            "version": current["version"],
        }
    ) + b"\n"


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



# --- the host's trust set ------------------------------------------------------------------


def load_trust_state(path: Path, *, expected_uid: int = 0) -> TrustState:
    """The trust set every updater on this host verifies against."""

    try:
        require_root_controlled(path, expected_uid=expected_uid)
        with path.open("rb") as handle:
            raw = handle.read(MAX_TRUST_BYTES + 1)
    except (OSError, BundleError) as exc:
        raise MinerUpdateError(f"the host trust set is unavailable: {exc}") from exc
    if len(raw) > MAX_TRUST_BYTES:
        raise MinerUpdateError("the host trust set is unexpectedly large")
    try:
        return parse_trust_state(raw)
    except MinerReleaseError as exc:
        raise MinerUpdateError(f"the host trust set is invalid: {exc}") from exc


def trust_backup_path(path: Path) -> Path:
    return path.with_name(path.name + ".backup")


def write_trust_state(path: Path, state: TrustState) -> None:
    """Write the trust set, then its verified backup, each atomically."""

    body = canonical_json(state.as_document()) + b"\n"
    _atomic_write(path, body, mode=0o600)
    _atomic_write(trust_backup_path(path), body, mode=0o600)


def _trust(host: MinerUpdaterHost) -> TrustState:
    """The host trust set. A problem with it alerts at once: it will not heal."""

    path = host.paths.trust_file
    try:
        trust = load_trust_state(path, expected_uid=host.expected_uid)
    except MinerUpdateError as exc:
        raise TrustSetUnavailable(
            f"{exc}. Nothing can be verified until it is repaired: run the bootstrap again "
            "with --repair-trust-set (docs/MINER_AUTO_UPDATE.md, \"Repairing the trust set\")"
        ) from exc
    # Keep the backup current, so a repair never starts from an older set.
    backup = trust_backup_path(path)
    try:
        good = load_trust_state(backup, expected_uid=host.expected_uid).as_document() == trust.as_document()
    except MinerUpdateError:
        good = False
    if not good:
        with contextlib.suppress(MinerUpdateError):
            _atomic_write(backup, canonical_json(trust.as_document()) + b"\n", mode=0o600)
    return trust


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
        return False, "the previous image's durable-state schema is not verified"
    if isinstance(new_schema, bool) or not isinstance(new_schema, int):
        return False, "the release declares no durable-state schema"
    if previous_schema >= new_schema:
        return True, f"the previous image reads state schema {new_schema}"
    return False, (
        f"the release writes state schema {new_schema}, newer than the "
        f"previous image's {previous_schema}"
    )


def _effective_floor(floor: object, minimum_sequence: int) -> Mapping[str, object] | None:
    if isinstance(floor, dict) and isinstance(floor.get("sequence"), int):
        if floor["sequence"] >= minimum_sequence:
            return floor
    if minimum_sequence > 0:
        return {"sequence": minimum_sequence, "signed_sha256": None}
    return None


def _refuse_known_failure(state: Mapping[str, object], release: MinerRelease) -> None:
    """Failure memory is keyed by content, so a weekly re-sign does not retry it."""

    failed = state.get("failed")
    if not isinstance(failed, dict):
        return
    if failed.get("image") == release.image and failed.get("tree_sha256") == release.bundle.tree_sha256:
        raise MinerUpdateError(
            f"this release already failed on this host ({failed.get('reason')}); "
            "waiting for a release with other content, or run `resolve --retry`"
        )


def _remember_failure(
    host: MinerUpdaterHost,
    state: dict[str, object],
    release: Mapping[str, object],
    *,
    reason: str,
) -> None:
    state["failed"] = {
        "image": release.get("image"),
        "tree_sha256": release.get("tree_sha256"),
        "sequence": release.get("sequence"),
        "version": release.get("version"),
        "reason": reason[:500],
        "at": host.now_unix(),
    }
    write_state(host.paths.state_file, state)


def _refuse_updater(state: Mapping[str, object], tree: str) -> None:
    failed = state.get("failed_updaters")
    if isinstance(failed, dict) and tree in failed:
        entry = failed[tree]
        reason = entry.get("reason") if isinstance(entry, dict) else None
        raise MinerUpdateError(
            f"the updater in this release already failed on this host ({reason}); "
            "waiting for a release with another updater, or run `resolve --retry`"
        )


def _retire_updater(host: MinerUpdaterHost, state: dict[str, object], tree: str, reason: str) -> None:
    failed = state.setdefault("failed_updaters", {})
    assert isinstance(failed, dict)
    failed[tree] = {"reason": reason[:500], "at": host.now_unix()}
    while len(failed) > MAX_REMEMBERED_UPDATERS:
        failed.pop(next(iter(failed)))
    strikes = state.setdefault("updater_strikes", {})
    assert isinstance(strikes, dict)
    strikes.pop(tree, None)


def _strike(host: MinerUpdaterHost, state: dict[str, object], tree: str, reason: str) -> int:
    """Count one failure of an updater tree that the other updater did not share."""

    strikes = state.setdefault("updater_strikes", {})
    assert isinstance(strikes, dict)
    count = int(strikes.get(tree, 0)) + 1
    strikes[tree] = count
    if count >= STRIKES_TO_DEMOTE:
        _retire_updater(host, state, tree, reason)
    return count


# --- the check ------------------------------------------------------------------------


def update_once(host: MinerUpdaterHost) -> UpdateOutcome:
    """Run one check. Every failure comes back as an outcome with a documented status."""

    if host.paths.pause_file.exists():
        return UpdateOutcome("paused", f"operator pause file present: {host.paths.pause_file}")
    return _locked(host, _check_locked, after=_after_check)


def _locked(
    host: MinerUpdaterHost,
    body: Callable[[MinerUpdaterHost, dict[str, object]], UpdateOutcome],
    *,
    after: Callable[[MinerUpdaterHost, UpdateOutcome], UpdateOutcome] | None = None,
) -> UpdateOutcome:
    inherited = host.lock_fd
    try:
        with exclusive(host.paths.lock_file, inherited_fd=inherited) as fd:
            host.lock_fd = fd
            host.verified = False
            host.offered_updater = None
            host.updater_blame = None
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
            except GateImpossible as exc:
                outcome = UpdateOutcome("deferred", str(exc), EXIT_ALERT, alert=True)
            except TrustSetUnavailable as exc:
                outcome = UpdateOutcome("refused", str(exc), EXIT_ALERT, alert=True)
            except (MinerUpdateError, MinerReleaseError, BundleError, LauncherProfileError) as exc:
                outcome = UpdateOutcome("refused", str(exc), EXIT_REFUSED)
            except OSError as exc:
                outcome = UpdateOutcome("refused", f"host error: {exc}", EXIT_REFUSED)
            except Exception as exc:  # noqa: BLE001 - the updater's own logic failed
                traceback.print_exc(file=sys.stderr)
                outcome = UpdateOutcome("fault", f"updater fault: {type(exc).__name__}: {exc}", EXIT_FAULT)
            if host.verified and not outcome.verified:
                outcome = dataclasses.replace(outcome, verified=True)
            if host.offered_updater is not None and not outcome.recorded:
                outcome = dataclasses.replace(
                    outcome, updater_offered=host.offered_updater, updater_blame=host.updater_blame
                )
            if after is not None:
                try:
                    outcome = after(host, outcome)
                except Exception as exc:  # noqa: BLE001 - the updater's own logic failed
                    traceback.print_exc(file=sys.stderr)
                    outcome = UpdateOutcome(
                        "fault", f"updater fault: {type(exc).__name__}: {exc}", EXIT_FAULT, verified=outcome.verified
                    )
            return _record(host, outcome)
    except MinerUpdateError as exc:
        return UpdateOutcome("refused", str(exc), EXIT_REFUSED)
    finally:
        # Only a descriptor handed to this process outlives the lock.
        host.lock_fd = inherited


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
        "exit_status": outcome.exit_status,
        "verified": outcome.verified,
        "sequence": release.get("sequence"),
        "version": release.get("version"),
        "updater_offered": outcome.updater_offered,
        "updater_blame": outcome.updater_blame,
    }
    if outcome.action == "deferred":
        count = int(state.get("consecutive_deferrals") or 0) + 1
        state["consecutive_deferrals"] = count
        if count >= DEFERRAL_ALERT_AFTER and outcome.exit_status == EXIT_OK:
            outcome = dataclasses.replace(
                outcome,
                exit_status=EXIT_ALERT,
                alert=True,
                reason=f"{outcome.reason}; deferred {count} checks in a row",
            )
            entry.update(reason=outcome.reason[:500], exit_status=EXIT_ALERT)
    elif outcome.action in ("activated", "probation", "current", "held"):
        state["consecutive_deferrals"] = 0
    state["last_check"] = entry
    if outcome.exit_status in (EXIT_REFUSED, EXIT_HALTED, EXIT_FAULT) or outcome.action == "refused":
        state["last_refusal"] = entry
    try:
        write_state(host.paths.state_file, state)
    except MinerUpdateError:
        pass
    return outcome


def _after_check(host: MinerUpdaterHost, outcome: UpdateOutcome) -> UpdateOutcome:
    """Count checks without a verified record, then escalate what must page.

    When this updater could not verify the channel and a previous updater
    exists, the shim runs that updater's ``fallback`` next, and the fallback
    escalates; escalating here would make the shim skip it.
    """

    if outcome.recorded:
        return outcome  # a handed-off child counted and escalated its own run
    try:
        state = read_state(host.paths.state_file)
    except MinerUpdateError:
        return outcome
    state["consecutive_unverified"] = 0 if outcome.verified else int(state["consecutive_unverified"]) + 1
    write_state(host.paths.state_file, state)
    if (
        not outcome.verified
        and outcome.exit_status == EXIT_REFUSED
        and link_target(host.paths.updater_previous) is not None
    ):
        return outcome
    return _escalate(host, outcome)


def _escalate(host: MinerUpdaterHost, outcome: UpdateOutcome) -> UpdateOutcome:
    """Turn a quiet outcome into an alert when the host needs a person.

    Two things page even though the check itself only refused, held or
    deferred: no verified record for ``UNVERIFIED_ALERT_AFTER`` checks (a
    withheld or expired channel), and a miner that is not running steadily.
    The miner is checked on every check with no activation in progress, so a
    dead miner after a rollback, or on a pinned host, is never silent.
    """

    if outcome.exit_status not in (EXIT_OK, EXIT_REFUSED):
        return outcome
    try:
        state = read_state(host.paths.state_file)
    except MinerUpdateError:
        return outcome
    unverified = int(state["consecutive_unverified"])
    if not outcome.verified and unverified >= UNVERIFIED_ALERT_AFTER:
        return dataclasses.replace(
            outcome,
            exit_status=EXIT_ALERT,
            alert=True,
            reason=f"{outcome.reason}; no verified channel record for {unverified} checks in a row",
        )
    miner = state["miner"]
    assert isinstance(miner, dict)
    if miner.get("stage") is not None or outcome.action == "current":
        return outcome  # an activation is in progress, or `current` just looked
    problem = _miner_health(host, state)
    write_state(host.paths.state_file, state)
    if problem is None:
        return outcome
    return dataclasses.replace(
        outcome,
        action="unhealthy",
        exit_status=EXIT_ALERT,
        alert=True,
        reason=f"{problem}. This check: {outcome.action}: {outcome.reason}",
    )


def _fetch(host: MinerUpdaterHost) -> bytes:
    """Fetch the channel record. Every failure here is the channel's, or looks like it."""

    try:
        raw = host.fetch_metadata()
    except MinerUpdateError:
        raise
    except Exception as exc:  # noqa: BLE001 - untrusted input boundary
        raise MinerUpdateError(f"the channel could not be fetched: {type(exc).__name__}: {exc}") from exc
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_RELEASE_DOCUMENT_BYTES:
        raise MinerUpdateError("release metadata size is out of range")
    return bytes(raw)


def _verify(host: MinerUpdaterHost, raw: bytes) -> MinerRelease:
    """Verify a record against the host trust set. Any exception is a refusal."""

    trust = _trust(host)
    config = host.config
    try:
        return parse_miner_release(
            raw,
            trusted_keys=trust.keys,
            expected_product=config.product,
            expected_network=config.network,
            expected_netuid=config.netuid,
            expected_channel=config.channel,
            now_unix=host.now_unix(),
        )
    except MinerReleaseError as exc:
        raise MinerUpdateError(f"release metadata refused: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - untrusted input boundary
        raise MinerUpdateError(f"release metadata refused: {type(exc).__name__}: {exc}") from exc


def _floor_check(host: MinerUpdaterHost, state: Mapping[str, object], release: MinerRelease) -> None:
    floors = state["floors"]
    assert isinstance(floors, dict)
    try:
        enforce_monotonic_release(
            _effective_floor(floors.get(host.config.channel), host.config.minimum_sequence), release
        )
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc


def _fetch_kept(host: MinerUpdaterHost, state: dict[str, object]) -> bytes:
    """Fetch the channel record and keep the bytes, or the failure, for the fallback.

    The fallback then judges exactly what this updater saw, so a channel that
    shows each updater something different cannot blame this one.
    """

    paths = host.paths
    try:
        raw = _fetch(host)
    except MinerUpdateError as exc:
        state["last_fetch"] = {"at": host.now_unix(), "error": str(exc)[:300]}
        with contextlib.suppress(MinerUpdateError):
            write_state(paths.state_file, state)
        raise
    _atomic_write(paths.fetched_record, raw, mode=0o600)
    state["last_fetch"] = {"at": host.now_unix(), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    write_state(paths.state_file, state)
    return raw


def _judge(host: MinerUpdaterHost, state: Mapping[str, object]) -> tuple[MinerRelease, bytes]:
    """Verify, changing nothing, what the other updater saw on this run.

    If it fetched bytes, those bytes are judged, not a fresh fetch. Only if
    it fetched nothing this run (its fetch failed, or it crashed first) does
    this updater fetch the channel itself.
    """

    last = state.get("last_fetch")
    at = last.get("at") if isinstance(last, dict) else None
    fresh = (
        isinstance(at, int)
        and not isinstance(at, bool)
        and 0 <= host.now_unix() - at <= FALLBACK_RECORD_MAX_AGE_SECONDS
    )
    if fresh and isinstance(last, dict) and isinstance(last.get("sha256"), str):
        try:
            with host.paths.fetched_record.open("rb") as handle:
                raw = handle.read(MAX_RELEASE_DOCUMENT_BYTES + 1)
        except OSError as exc:
            raise MinerUpdateError(f"the record the other updater fetched is unreadable: {exc}") from exc
        if hashlib.sha256(raw).hexdigest() != last["sha256"]:
            raise MinerUpdateError("the record the other updater fetched was changed since")
    else:
        raw = _fetch(host)
    release = _verify(host, raw)
    _floor_check(host, state, release)
    return release, raw


def _bundle_dir(host: MinerUpdaterHost, release: MinerRelease) -> Path:
    """The release's verified tree, installed if it is not already."""

    tree = release.bundle.tree_sha256
    existing = host.paths.updater_releases / tree
    try:
        if existing.is_dir():
            require_root_controlled_tree(existing, expected_uid=host.expected_uid)
            if release_tree_sha256(existing) == tree:
                return existing
        archive = host.fetch_bundle(release.bundle)
        return install_tree(
            archive,
            archive_sha256=release.bundle.archive_sha256,
            tree_sha256=tree,
            releases=host.paths.updater_releases,
            expected_uid=host.expected_uid,
        )
    except (MinerUpdateError, BundleError) as exc:
        raise MinerUpdateError(f"the release bundle is unusable: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - untrusted input until the digests match
        raise MinerUpdateError(f"the release bundle is unusable: {type(exc).__name__}: {exc}") from exc


def _rotate_trust(
    host: MinerUpdaterHost, state: dict[str, object], release: MinerRelease, bundle_dir: Path
) -> None:
    """Take the trust set the release's bundle carries, if it moves forward."""

    trust = _trust(host)
    try:
        proposed = (bundle_dir / TREE_TRUST_ROOT).read_bytes()
        rotated = rotate_trust(
            trust, proposed, signing_key_id=release.signing_key_id, channel=release.channel
        )
    except (OSError, MinerReleaseError) as exc:
        # The trust root is part of the tree, so that tree can never be used
        # here: retire it, and remember the release.
        if release.bundle.tree_sha256 != host.running_tree:
            _retire_updater(host, state, release.bundle.tree_sha256, f"its trust root was refused: {exc}")
        _remember_failure(host, state, release.summary(), reason=f"its trust root was refused: {exc}")
        raise MinerUpdateError(f"the release's trust root was refused: {exc}") from exc
    if rotated is not trust:
        write_trust_state(host.paths.trust_file, rotated)


def _check_locked(host: MinerUpdaterHost, state: dict[str, object]) -> UpdateOutcome:
    if host.running_tree is None or _TREE_RE.fullmatch(host.running_tree) is None:
        raise MinerUpdateError(
            "this updater is not running from an installed release; run it through "
            "the installed cathedral-miner-update command"
        )
    blocker: UpdateOutcome | None = None
    early: UpdateOutcome | None = None
    try:
        early = reconcile_interrupted_activation(host, state)
    except MinerUpdateHalted as exc:
        # A halt blocks activation, not the channel: a newer updater may be the fix.
        blocker = UpdateOutcome("halted", str(exc), EXIT_HALTED)
    except MinerUpdateRolledBack as exc:
        early = UpdateOutcome("rolled_back", str(exc), EXIT_REFUSED, release=exc.release)
    state = read_state(host.paths.state_file)
    if blocker is None and early is None:
        return _check_channel(host, state, None, None)
    try:
        return _check_channel(host, state, blocker, early)
    except (MinerUpdateError, MinerReleaseError, BundleError, LauncherProfileError, OSError) as exc:
        # What reconcile found outranks a refusal of the channel: a halt must
        # keep paging even while the channel is down.
        kept = blocker if blocker is not None else early
        assert kept is not None
        return dataclasses.replace(kept, reason=f"{kept.reason}; the channel check then refused: {exc}")


def _check_channel(
    host: MinerUpdaterHost,
    state: dict[str, object],
    blocker: UpdateOutcome | None,
    early: UpdateOutcome | None,
) -> UpdateOutcome:
    assert host.running_tree is not None
    raw = _fetch_kept(host, state)
    release = _verify(host, raw)
    # From here the channel was fetched and its record verified; any refusal
    # below is about the record's content, not the updater's ability to check.
    host.verified = True
    _floor_check(host, state, release)
    # Burn the sequence before any attempt. A failed activation still consumes
    # it, so a different record cannot reuse it and pass the equivocation check.
    floors = state["floors"]
    assert isinstance(floors, dict)
    floors[host.config.channel] = {"sequence": release.sequence, "signed_sha256": release.signed_sha256}
    tree = release.bundle.tree_sha256
    new_updater = tree != host.running_tree
    failed_updaters = state["failed_updaters"]
    assert isinstance(failed_updaters, dict)
    if not new_updater or tree in failed_updaters:
        # This updater verified, and no newer tree is waiting on it, so its
        # earlier strikes were not consecutive. While a newer tree waits, they
        # stay: an updater that verifies but cannot install one is judged too.
        strikes = state["updater_strikes"]
        assert isinstance(strikes, dict)
        strikes.pop(host.running_tree, None)
    write_state(host.paths.state_file, state)

    if new_updater:
        _refuse_updater(state, tree)
    bundle_dir = _bundle_dir(host, release)
    _rotate_trust(host, state, release, bundle_dir)

    if blocker is not None:
        if new_updater and read_pin(host.paths.pin_file) is None:
            return _self_update(host, state, raw, release, bundle_dir)
        return blocker
    if early is not None:
        return early

    _refuse_known_failure(state, release)
    pin = read_pin(host.paths.pin_file)
    if pin is not None and (pin["image"], pin["tree_sha256"]) != (release.image, tree):
        return UpdateOutcome(
            "held",
            f"operator pinned {pin['version']} ({pin['image']}, tree {pin['tree_sha256'][:12]}); "
            f"the channel offers {release.version}",
            release=release.summary(),
        )
    if new_updater:
        return _self_update(host, state, raw, release, bundle_dir)
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


def _check_probe(probe: object, release: MinerRelease) -> None:
    """A probe must confirm the record, the tree, and the schemas this updater reads."""

    expected = {
        "probe": "ok",
        "signed_sha256": release.signed_sha256,
        "tree_sha256": release.bundle.tree_sha256,
        "state_schema": STATE_SCHEMA,
        "trust_schema": TRUST_STATE_SCHEMA,
    }
    for key, value in expected.items():
        if not isinstance(probe, Mapping) or probe.get(key) != value:
            raise MinerUpdateError(f"its probe did not confirm {key}")


def _self_update(
    host: MinerUpdaterHost,
    state: dict[str, object],
    raw: bytes,
    release: MinerRelease,
    release_dir: Path,
) -> UpdateOutcome:
    """Probe the release's updater, make it current, and keep it only if it proves itself.

    1. The probe. Before the new tree is current, the new code verifies the
       record that delivered it against the host trust set, reads this host's
       state, hashes its own tree, and reports the state and trust schemas it
       reads, which must be this updater's (trust review P2). A failed probe
       is a strike against the new tree.
    2. The first run. The new updater then runs the rest of this check as a
       child that inherits the lock, with a timeout. It stays current only if
       it exits with a status other than a fault and reports that it fetched
       and verified the channel. Otherwise this updater is put back. It counts
       a strike against the new tree only if this updater can verify the
       channel right then, so a channel blip is not blamed on the new updater.
    3. The shim. On any later run, if the current updater cannot verify the
       channel or faults, the shim runs the previous updater's ``fallback``.
    """

    paths = host.paths
    tree = release.bundle.tree_sha256
    if host.handoff_depth > 0:
        raise MinerUpdateError(
            "the channel moved to another updater during a handoff; the next check applies it"
        )
    # Until the new tree reports a verdict of its own, a failure here could
    # be this updater's: the fallback may judge it (trust re-review P1).
    host.offered_updater = tree
    host.updater_blame = "ambiguous"
    record_path = _save_record(paths, release, raw)
    try:
        _check_probe(host.probe_updater(release_dir, record_path), release)
    except (MinerUpdateError, MinerReleaseError, BundleError, OSError) as exc:
        # A strike, not a verdict: a probe can also fail for a reason that is
        # not the new tree's (a timeout on a loaded host), and one failure
        # must never blacklist a good updater (trust review P1-1).
        count = _strike(host, state, tree, f"probe failed: {exc}")
        write_state(paths.state_file, state)
        retired = ", so this host no longer uses that updater" if count >= STRIKES_TO_DEMOTE else ""
        raise MinerUpdateError(
            f"the updater in this release failed its probe, so this updater stays current "
            f"(strike {count} of {STRIKES_TO_DEMOTE}{retired}): {exc}"
        ) from exc

    previous = link_target(paths.updater_current)
    fallback_before = link_target(paths.updater_previous)
    if previous is not None:
        atomic_symlink(paths.updater_previous, previous)
    atomic_symlink(paths.updater_current, f"releases/{tree}")

    assert host.lock_fd is not None
    status, document = host.handoff(release_dir, host.lock_fd)
    reported = document if isinstance(document, Mapping) else {}
    if (
        status in FIRST_RUN_KEEP_STATUSES
        and reported.get("verified") is True
        and isinstance(reported.get("action"), str)
    ):
        relayed = reported.get("release")
        # This updater handed over, so its own strikes no longer count.
        taken = read_state(paths.state_file)
        strikes = taken["updater_strikes"]
        assert isinstance(strikes, dict)
        if strikes.pop(str(host.running_tree), None) is not None:
            write_state(paths.state_file, taken)
        host.offered_updater = None
        return UpdateOutcome(
            action=str(reported["action"]),
            reason=f"updater {tree[:12]} took over: {reported.get('reason', '')}",
            exit_status=status,
            release=relayed if isinstance(relayed, Mapping) else None,
            alert=bool(reported.get("alert")),
            verified=True,
            recorded=True,
        )

    # The new updater did not prove a verified check. Put this one back, with
    # the fallback it had before.
    if isinstance(reported.get("action"), str) or status == 124:
        # It ran and gave its own verdict, or hung: the failure is its own.
        host.updater_blame = "new"
    if previous is not None:
        atomic_symlink(paths.updater_current, previous)
    if fallback_before is not None and fallback_before != previous:
        atomic_symlink(paths.updater_previous, fallback_before)
    else:
        remove_link(paths.updater_previous)
    fresh = read_state(paths.state_file)
    note = ""
    if reported.get("action") != "paused":
        try:
            # Judge what the new updater itself fetched on its first run.
            _judge(host, fresh)
        except MinerUpdateError as exc:
            note = f"; this updater cannot verify the channel either ({exc}), so no strike"
        else:
            count = _strike(host, fresh, tree, f"first run exited {status} without a verified check")
            note = f"; strike {count} of {STRIKES_TO_DEMOTE}"
            if count >= STRIKES_TO_DEMOTE:
                note += ", so this host no longer uses that updater"
    write_state(paths.state_file, fresh)
    raise MinerUpdateError(
        f"the updater in this release did not prove a verified check on its first run "
        f"(exit status {status}, action {reported.get('action')!r}); the previous updater "
        f"was restored{note}"
    )


def _probe_as_fallback(host: MinerUpdaterHost, release: MinerRelease, raw: bytes) -> None:
    """Probe the tree the current updater could not install, from this updater."""

    tree = release.bundle.tree_sha256
    release_dir = host.paths.updater_releases / tree
    try:
        require_root_controlled_tree(release_dir, expected_uid=host.expected_uid)
        if release_tree_sha256(release_dir) != tree:
            raise MinerUpdateError("its installed tree does not match its digest")
        record = _save_record(host.paths, release, raw)
        _check_probe(host.probe_updater(release_dir, record), release)
    except (BundleError, OSError, MinerReleaseError) as exc:
        raise MinerUpdateError(str(exc)) from exc


def _forgive(state: dict[str, object], tree: str) -> None:
    strikes = state["updater_strikes"]
    assert isinstance(strikes, dict)
    count = int(strikes.get(tree, 0)) - 1
    if count > 0:
        strikes[tree] = count
    else:
        strikes.pop(tree, None)


def fallback_to_previous(host: MinerUpdaterHost, current_status: int) -> UpdateOutcome:
    """Run by the previous updater when the current one refused or faulted.

    It judges two kinds of failure, against the host trust set, never its own
    bundled keys, and changing nothing but strikes and the updater link:

    - The current updater could not verify the channel, or faulted. This
      updater verifies the same bytes the current one fetched on that run (or,
      if it fetched none, the channel). If it can, that is a strike against
      the current updater. If it cannot, the channel is at fault.
    - The current updater verified the channel but could not install the
      newer updater the record names, in a way that could be its own fault.
      This updater probes that tree itself. If the probe passes, the failure
      was the current updater's: a strike against it, and the strike it gave
      the new tree is taken back. If not, the refusal stands.

    At ``STRIKES_TO_DEMOTE`` this updater becomes current again, and the other
    tree is not used until a release with another updater arrives. Any other
    verified refusal stands.
    """

    passthrough = current_status if current_status in DOCUMENTED_EXIT_STATUSES else EXIT_FAULT

    def body(host: MinerUpdaterHost, state: dict[str, object]) -> UpdateOutcome:
        paths = host.paths
        current = link_target(paths.updater_current)
        current_tree = current.split("/")[-1] if current else None
        if host.running_tree is None or host.running_tree == current_tree:
            raise MinerUpdateError("the fallback updater is the current updater")
        if link_target(paths.updater_previous) != f"releases/{host.running_tree}":
            raise MinerUpdateError("the fallback updater is not the previous updater")
        last = state.get("last_check")
        # Only the entry the current updater wrote for the run the shim just
        # saw counts: it must carry the same exit status and be recent. An
        # older entry (say the current updater crashed before recording) says
        # nothing about this run.
        at = last.get("at") if isinstance(last, dict) else None
        fresh = (
            isinstance(at, int)
            and not isinstance(at, bool)
            and 0 <= host.now_unix() - at <= FALLBACK_RECORD_MAX_AGE_SECONDS
        )
        stalled: str | None = None
        if (
            current_status == EXIT_REFUSED
            and fresh
            and isinstance(last, dict)
            and last.get("exit_status") == current_status
            and last.get("verified") is True
        ):
            offered = last.get("updater_offered")
            failed = state["failed_updaters"]
            assert isinstance(failed, dict)
            if (
                last.get("updater_blame") == "ambiguous"
                and isinstance(offered, str)
                and _TREE_RE.fullmatch(offered) is not None
                and offered != current_tree
                and offered not in failed
            ):
                stalled = offered
            else:
                return UpdateOutcome(
                    "refused",
                    "the current updater verified the channel, so its refusal stands",
                    EXIT_REFUSED,
                    verified=True,
                    recorded=True,
                )
        entry: dict[str, object] = {
            "at": host.now_unix(),
            "current_tree": current_tree,
            "current_status": current_status,
        }
        try:
            release, raw = _judge(host, state)
            if stalled is not None:
                if release.bundle.tree_sha256 != stalled:
                    raise MinerUpdateError("the record names another updater than the one it could not install")
                _probe_as_fallback(host, release, raw)
        except MinerUpdateError as exc:
            if stalled is not None:
                state["last_fallback"] = dict(entry, result="the new updater fails here too", reason=str(exc)[:300])
                write_state(paths.state_file, state)
                return UpdateOutcome(
                    "refused",
                    f"updater {stalled[:12]} fails for this updater too ({exc}); the current "
                    "updater's refusal stands",
                    EXIT_REFUSED,
                    verified=True,
                    recorded=True,
                )
            state["last_fallback"] = dict(entry, result="the channel could not be verified", reason=str(exc)[:300])
            write_state(paths.state_file, state)
            return _escalate(
                host,
                UpdateOutcome(
                    "refused",
                    f"the previous updater cannot verify what the current updater saw either ({exc}); "
                    "the current updater stays",
                    passthrough,
                    recorded=True,
                ),
            )
        failure = (
            f"it could not install updater {stalled[:12]}, which this updater's probe accepts"
            if stalled is not None
            else f"exit status {current_status} while the previous updater verified the channel"
        )
        if stalled is not None:
            _forgive(state, stalled)
        count = _strike(host, state, current_tree, failure) if current_tree else STRIKES_TO_DEMOTE
        if count < STRIKES_TO_DEMOTE:
            state["last_fallback"] = dict(entry, result=f"strike {count} of {STRIKES_TO_DEMOTE}", reason=failure)
            write_state(paths.state_file, state)
            return _escalate(
                host,
                UpdateOutcome(
                    "refused",
                    f"the current updater failed ({failure}; sequence {release.sequence}); "
                    f"strike {count} of {STRIKES_TO_DEMOTE}",
                    passthrough,
                    verified=True,
                    recorded=True,
                ),
            )
        atomic_symlink(paths.updater_current, f"releases/{host.running_tree}")
        remove_link(paths.updater_previous)
        state["last_fallback"] = dict(entry, result="switched back to the previous updater", reason=failure)
        write_state(paths.state_file, state)
        host.verified = True
        return UpdateOutcome(
            "demoted",
            f"updater {str(current_tree)[:12]} failed {STRIKES_TO_DEMOTE} checks ({failure}); "
            f"switched back to updater {host.running_tree[:12]}",
            EXIT_ALERT,
            alert=True,
        )

    outcome = _locked(host, body)
    if outcome.exit_status == EXIT_REFUSED and passthrough != EXIT_REFUSED:
        # The fallback could not run (the lock is busy, the links moved, the
        # state is unreadable): the current updater's own status stands, so a
        # fault still pages.
        outcome = dataclasses.replace(outcome, exit_status=passthrough)
    return outcome


def probe_release(host: MinerUpdaterHost, raw: bytes) -> dict[str, object]:
    """Everything a check needs before it acts, with no side effects."""

    paths = host.paths
    state = read_state(paths.state_file)
    release = _verify(host, raw)
    _floor_check(host, state, release)
    if host.running_tree != release.bundle.tree_sha256:
        raise MinerUpdateError("the probe is not running from this release's tree")
    own = paths.updater_releases / release.bundle.tree_sha256
    if release_tree_sha256(own) != release.bundle.tree_sha256:
        raise MinerUpdateError("the probe's own tree does not match its digest")
    _check_launcher(host, own, release)
    return {
        "probe": "ok",
        "signed_sha256": release.signed_sha256,
        "tree_sha256": host.running_tree,
        "state_schema": STATE_SCHEMA,
        "trust_schema": TRUST_STATE_SCHEMA,
    }


# --- activation -----------------------------------------------------------------------

PROBATION_SAMPLE_SECONDS = 45
"""The second look, well past the 20 s dwell, before a release enters probation."""


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


def _start(host: MinerUpdaterHost) -> Exception | None:
    try:
        _restart_miner(host)
    except Exception as exc:  # noqa: BLE001 - judged by what runs afterwards
        return exc
    return None


def _previous(host: MinerUpdaterHost, state: Mapping[str, object], active: str) -> dict[str, object]:
    profile = read_activation_profile(host.paths, active)
    container = str(profile["container"])
    miner = state["miner"]
    assert isinstance(miner, dict)
    current = miner.get("current")
    schema: int | None = None
    if active == LEGACY:
        seen = host.observe(container)
        image = seen.image if seen is not None and seen.active else None
    else:
        image = profile.get("image") if isinstance(profile.get("image"), str) else None
        if (
            isinstance(current, dict)
            and current.get("target") == active
            and current.get("schema_verified") is True
            and isinstance(current.get("state_schema"), int)
        ):
            schema = current["state_schema"]
    return {
        "previous_target": active,
        "previous_container": container,
        "previous_image": image,
        "previous_state_schema": schema,
    }


def _commit(
    host: MinerUpdaterHost,
    state: dict[str, object],
    summary: Mapping[str, object],
    target: str,
    *,
    schema_verified: bool,
) -> None:
    miner = state["miner"]
    assert isinstance(miner, dict)
    miner["current"] = dict(summary, target=target, schema_verified=schema_verified)
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


def _unit_inactive(host: MinerUpdaterHost) -> bool:
    return host.unit_state() in INACTIVE_UNIT_STATES


INACTIVE_REASON = (
    "the miner unit is inactive: stopped by hand without `pause`, or exited cleanly "
    "under a unit without Restart=always. Start it, or run `cathedral-miner-update pause` "
    "if the stop is meant"
)


def _miner_health(host: MinerUpdaterHost, state: dict[str, object]) -> str | None:
    """What is wrong with the miner that ``miner/current`` selects, or None.

    Inactive, not running steadily, running another image, or restarted since
    the last check. The restart baseline is kept in ``state`` (not written).
    """

    active = link_target(host.paths.miner_current)
    if active is None:
        return "miner/current is missing"
    try:
        profile = read_activation_profile(host.paths, active)
    except MinerUpdateError as exc:
        return str(exc)
    unit = host.unit_state()
    if unit in INACTIVE_UNIT_STATES:
        return INACTIVE_REASON
    container = str(profile["container"])
    # Wait for the dwell only when the miner may be coming up; a unit that has
    # failed, with no container, is plainly down.
    seen = host.observe(container)
    if seen is None and unit not in ("active", "activating", "reloading"):
        return f"the miner is not running (unit {unit})"
    seen = host.settle(container)
    if seen is None or not seen.active:
        return f"the miner is not running steadily (unit {host.unit_state()})"
    expected = profile.get("image")
    if isinstance(expected, str) and seen.image != expected:
        return f"the miner runs {seen.image}, not the selected release's {expected}"
    baseline = state.get("miner_health")
    state["miner_health"] = {"target": active, "restarts": seen.restarts}
    if (
        isinstance(baseline, dict)
        and baseline.get("target") == active
        and isinstance(baseline.get("restarts"), int)
        and seen.restarts > baseline["restarts"]
    ):
        return f"the miner restarted {seen.restarts - baseline['restarts']} times since the last check"
    return None


def _confirm_current(
    host: MinerUpdaterHost,
    state: dict[str, object],
    release: MinerRelease,
    profile: LauncherProfile,
    target: str,
) -> UpdateOutcome:
    """The miner already selects this release. Say so only if it is running it steadily."""

    del profile
    summary = release.summary()
    miner = state["miner"]
    assert isinstance(miner, dict)
    committed = miner.get("current") if isinstance(miner.get("current"), dict) else {}
    same = committed.get("target") == target
    schema_verified = bool(committed.get("schema_verified")) if same else False
    problem = _miner_health(host, state)
    _commit(host, state, summary, target, schema_verified=schema_verified)
    if problem is not None:
        return UpdateOutcome(
            "unhealthy", f"the miner selects this release, but {problem}", EXIT_ALERT, release=summary, alert=True
        )
    return UpdateOutcome("current", "the miner runs this release's image and launcher", release=summary)


def _refuse_schema_decrease(host: MinerUpdaterHost, state: dict[str, object], release: MinerRelease, active: str) -> None:
    """Schemas never go down, not even after `resolve --abandon` (activation re-review P2).

    The floor is the highest verified schema of any release that reached
    ``may_have_run`` here, since that image may have migrated the state. Only
    that same image may declare less.
    """

    floors: list[tuple[int, object]] = []
    high_water = state.get("schema_high_water")
    if isinstance(high_water, dict) and isinstance(high_water.get("schema"), int):
        floors.append((high_water["schema"], high_water.get("image")))
    miner = state["miner"]
    assert isinstance(miner, dict)
    committed = miner.get("current")
    if (
        isinstance(committed, dict)
        and committed.get("target") == active
        and committed.get("schema_verified") is True
        and isinstance(committed.get("state_schema"), int)
    ):
        floors.append((committed["state_schema"], committed.get("image")))
    for schema, image in floors:
        if release.state_schema < schema and release.image != image:
            # Not remembered as a failure: this is checked before any pull,
            # and the same image may come back declaring the right schema.
            raise MinerUpdateError(
                f"the release declares state schema {release.state_schema}, lower than {schema}, "
                f"which {image} may already have written here; schemas never go down"
            )


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
        return _confirm_current(host, state, release, profile, target)

    miner = state["miner"]
    assert isinstance(miner, dict)
    _refuse_schema_decrease(host, state, release, active)

    if _unit_inactive(host):
        # Never start a miner that is not running: defer, and page.
        return UpdateOutcome(
            "deferred",
            f"{INACTIVE_REASON}; an update never starts a stopped miner",
            EXIT_ALERT,
            release=summary,
            alert=True,
        )
    if not host.safe_to_activate():
        return UpdateOutcome("deferred", "the miner is not at a safe point to restart", release=summary)

    stage_activation(paths, bundle_dir, profile, release, host.config, expected_uid=host.expected_uid)
    previous = _previous(host, state, active)
    pending: dict[str, object] = {
        "release": summary,
        "target": target,
        "container": profile.container,
        **previous,
        "schema_verified": False,
        "flip_unix": None,
        "probation": None,
    }
    miner["stage"] = STAGE_PREPARED
    miner["pending"] = pending
    write_state(paths.state_file, state)

    try:
        label = host.prepare_image(release, profile)
    except Exception as exc:  # noqa: BLE001 - any pull or verify failure is one case
        _clear_stage(host, state)
        raise MinerUpdateError(f"the released image could not be prepared, nothing was changed: {exc}") from exc
    if label is None:
        if release.image != previous["previous_image"]:
            _clear_stage(host, state)
            _remember_failure(host, state, summary, reason="its image carries no state-schema label")
            raise MinerUpdateError(
                f"the image carries no {STATE_SCHEMA_LABEL} label; only the image the miner "
                "already runs can be taken over without one"
            )
    elif label != release.state_schema:
        _clear_stage(host, state)
        _remember_failure(host, state, summary, reason="its image's state-schema label differs")
        raise MinerUpdateError(
            f"the image's {STATE_SCHEMA_LABEL} label is {label}, but the record declares "
            f"{release.state_schema}"
        )
    else:
        pending["schema_verified"] = True

    # Review finding F3: the pull can take minutes, so check the margin again
    # immediately before the swap.
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
    pending["flip_unix"] = host.now_unix()
    if pending["schema_verified"] is True:
        high_water = state.get("schema_high_water")
        if not isinstance(high_water, dict) or release.state_schema > int(high_water.get("schema") or 0):
            state["schema_high_water"] = {"schema": release.state_schema, "image": release.image}
    write_state(paths.state_file, state)
    atomic_symlink(paths.miner_current, target)
    return _prove_start(host, state, pending, _start(host))


def _prove_start(
    host: MinerUpdaterHost,
    state: dict[str, object],
    pending: dict[str, object],
    start_error: Exception | None,
) -> UpdateOutcome:
    """Accept a start only if a container started after the flip and stayed up.

    A container that predates the flip means the release never started (the
    restart did not happen), so it is started once more. A failed restart is
    never ignored, even when the old container runs the same image.
    """

    release = pending["release"]
    assert isinstance(release, dict)
    image = release.get("image")
    container = str(pending["container"])
    flip = float(pending["flip_unix"] or 0)

    seen = host.settle(container) if start_error is None else None
    if start_error is None and seen is not None and seen.started_at < flip:
        # Whatever image it runs, a container from before the flip means the
        # restart never took effect. Judge the release only once it has run.
        start_error = _start(host)
        seen = host.settle(container) if start_error is None else None
    if (
        start_error is None
        and seen is not None
        and seen.active
        and seen.image == image
        and seen.started_at >= flip
    ):
        host.sleep(PROBATION_SAMPLE_SECONDS)
        again = host.observe(container)
        if (
            again is not None
            and again.active
            and again.image == image
            and again.started_at == seen.started_at
            and again.restarts == seen.restarts
        ):
            pending["probation"] = _new_probation(host, seen, None)
            miner = state["miner"]
            assert isinstance(miner, dict)
            miner["stage"] = STAGE_PROBATION
            miner["pending"] = pending
            write_state(host.paths.state_file, state)
            return UpdateOutcome(
                "activated",
                "the released image is running; it is on probation until a check at least "
                f"{PROBATION_MINIMUM_SECONDS // 60} minutes later sees the same container still up",
                release=release,
            )
        detail = "the released image did not stay up through a second look"
    elif start_error is not None:
        detail = f"the restart failed ({start_error})"
    else:
        detail = "the released image did not come up"
    return _fail(host, state, pending, detail)


def _fail(
    host: MinerUpdaterHost, state: dict[str, object], pending: Mapping[str, object], detail: str
) -> UpdateOutcome:
    allowed, why = rollback_allowed(pending)
    # Kept with the stage, so a later check that finishes this rollback still
    # remembers the release as failed.
    if isinstance(pending, dict):
        pending["failure"] = detail[:500]
    if not allowed:
        write_state(host.paths.state_file, state)
        raise MinerUpdateHalted(
            f"{detail}; not rolling back because {why}. Run `resolve --restore-previous`, "
            "`resolve --accept-release` or `resolve --abandon`"
        )
    _rollback(host, state, pending, detail=detail)
    raise MinerUpdateRolledBack(
        f"{detail}; rolled back because {why}, and the previous image is running",
        release=pending.get("release") if isinstance(pending.get("release"), Mapping) else None,
    )


def _rollback(
    host: MinerUpdaterHost, state: dict[str, object], pending: Mapping[str, object], *, detail: str
) -> None:
    """Point the miner back at the previous release, and prove it came back.

    The previous release gets two starts: a registry or systemd blip during the
    first must not strand a host on nothing (activation review P1-4).
    """

    paths = host.paths
    try:
        atomic_symlink(paths.miner_current, str(pending["previous_target"]))
    except OSError as exc:
        write_state(paths.state_file, state)
        raise MinerUpdateHalted(f"{detail}, and the previous release could not be selected ({exc})") from exc
    container = str(pending["previous_container"])
    expected = pending.get("previous_image")
    back = False
    last_error: Exception | None = None
    for _attempt in range(2):
        last_error = _start(host)
        seen = host.settle(container) if last_error is None else None
        if seen is not None and seen.active and seen.image == expected:
            back = True
            break
    if not back:
        write_state(paths.state_file, state)
        now = host.observe(container)
        running = f"it runs {now.image}" if now is not None and now.active else "it may be running nothing"
        raise MinerUpdateHalted(
            f"{detail}, and the previous image did not come back after two starts"
            f"{f' ({last_error})' if last_error else ''}; {running}. Resolve it explicitly"
        )
    miner = state["miner"]
    assert isinstance(miner, dict)
    miner["stage"] = None
    miner["pending"] = None
    release = pending.get("release")
    _remember_failure(host, state, release if isinstance(release, Mapping) else {}, reason=detail)


def _valid_pending(pending: object) -> bool:
    return (
        isinstance(pending, dict)
        and isinstance(pending.get("release"), dict)
        and isinstance(pending.get("target"), str)
        and isinstance(pending.get("container"), str)
        and isinstance(pending.get("previous_target"), str)
        and isinstance(pending.get("previous_container"), str)
    )


def _new_probation(
    host: MinerUpdaterHost, seen: Observation, previous: Mapping[str, object] | None
) -> dict[str, object]:
    forgiven = previous.get("restarts_forgiven") if previous is not None else 0
    return {
        "started_at": seen.started_at,
        "restarts": seen.restarts,
        "boot_id": host.boot_id(),
        "entered_unix": host.now_unix(),
        "restarts_forgiven": forgiven if isinstance(forgiven, int) else 0,
    }


def _confirm_probation(
    host: MinerUpdaterHost, state: dict[str, object], pending: dict[str, object]
) -> UpdateOutcome | None:
    """Commit a release that stayed up long enough, restart probation, or roll it back.

    - Committed only when the same container (StartedAt and NRestarts) is
      still up, and probation began at least ``PROBATION_MINIMUM_SECONDS`` ago.
    - A reboot, or one container restart (a docker daemon restart, say),
      restarts probation instead of failing a good release.
    - An inactive unit alerts and leaves probation as it is: a rollback would
      start a miner that is not running.
    - Anything else goes to the rollback rule.
    """

    probation = pending.get("probation")
    release = pending["release"]
    assert isinstance(release, dict)
    container = str(pending["container"])
    if not isinstance(probation, dict):
        return _fail(host, state, pending, "the release's probation was not recorded")
    active = link_target(host.paths.miner_current)
    if active != pending["target"]:
        raise MinerUpdateHalted(
            f"miner/current changed during probation ({active!r}); resolve it explicitly"
        )
    if _unit_inactive(host):
        return UpdateOutcome(
            "unhealthy",
            f"{INACTIVE_REASON}. The release stays on probation: rolling it back would start the miner",
            EXIT_ALERT,
            release=release,
            alert=True,
        )
    if host.boot_id() != probation.get("boot_id"):
        # The host rebooted, so the container restarted legitimately. Look
        # again and restart probation rather than judge a new container.
        seen = host.settle(container)
        if seen is not None and seen.active and seen.image == release.get("image"):
            pending["probation"] = _new_probation(host, seen, probation)
            write_state(host.paths.state_file, state)
            return UpdateOutcome("probation", "the host rebooted during probation; probation restarted", release=release)
        return _fail(host, state, pending, "the release did not come back after a reboot")
    seen = host.observe(container)
    if (
        seen is not None
        and seen.active
        and seen.image == release.get("image")
        and seen.started_at == probation.get("started_at")
        and seen.restarts == probation.get("restarts")
    ):
        entered = probation.get("entered_unix")
        age = host.now_unix() - (entered if isinstance(entered, int) else 0)
        if age < PROBATION_MINIMUM_SECONDS:
            return UpdateOutcome(
                "probation",
                f"on probation for {age} s of {PROBATION_MINIMUM_SECONDS} s; a later check commits it",
                release=release,
            )
        _commit(host, state, release, str(pending["target"]), schema_verified=pending.get("schema_verified") is True)
        return None
    # The container changed. One restart restarts probation, as a reboot does.
    forgiven = probation.get("restarts_forgiven")
    forgiven = forgiven if isinstance(forgiven, int) else 0
    baseline = probation.get("restarts")
    again = host.settle(container)
    if (
        forgiven < PROBATION_RESTARTS_FORGIVEN
        and again is not None
        and again.active
        and again.image == release.get("image")
        # One automatic restart at most; a restart by hand resets the count.
        and isinstance(baseline, int)
        and again.restarts - baseline <= 1
    ):
        renewed = _new_probation(host, again, probation)
        renewed["restarts_forgiven"] = forgiven + 1
        pending["probation"] = renewed
        write_state(host.paths.state_file, state)
        return UpdateOutcome(
            "probation", "the miner restarted once during probation; probation restarted", release=release
        )
    return _fail(host, state, pending, "the release did not stay up through probation")


def reconcile_interrupted_activation(
    host: MinerUpdaterHost, state: dict[str, object]
) -> UpdateOutcome | None:
    """Resolve a stage a previous run left behind.

    Returns an outcome when it changed what the miner runs, so the check
    reports that instead of starting another activation in the same run.
    """

    miner = state["miner"]
    assert isinstance(miner, dict)
    stage = miner.get("stage")
    if stage is None:
        return None
    if stage == STAGE_PREPARED:
        _clear_stage(host, state)
        return None
    if stage not in STAGES:
        # A newer updater wrote this stage and was then demoted. Activation
        # waits for an operator; verification and self-update go on.
        raise MinerUpdateHalted(
            f"state records activation stage {stage!r}, which a newer updater wrote and this "
            "updater does not know; run `resolve --abandon` or let a newer updater finish it"
        )
    pending = miner.get("pending")
    if not _valid_pending(pending):
        raise MinerUpdateHalted(
            "state records an interrupted activation but not which release it was; "
            "run `resolve --abandon`"
        )
    assert isinstance(pending, dict)
    if stage == STAGE_PROBATION:
        return _confirm_probation(host, state, pending)

    release = pending["release"]
    active = link_target(host.paths.miner_current)
    if active == pending["previous_target"]:
        # The swap never happened, or a rollback already put it back.
        container = str(pending["previous_container"])
        seen = host.observe(container)
        if seen is None or not seen.active or seen.image != pending.get("previous_image"):
            # Retry the known-good previous release once before halting.
            if _start(host) is None:
                seen = host.settle(container)
        if seen is not None and seen.active and seen.image == pending.get("previous_image"):
            failure = pending.get("failure")
            if isinstance(failure, str):
                # A rollback that halted, now complete: remember the release,
                # so it is not tried again every hour.
                miner["stage"] = None
                miner["pending"] = None
                _remember_failure(host, state, release if isinstance(release, Mapping) else {}, reason=failure)
            else:
                _clear_stage(host, state)
            return None
        raise MinerUpdateHalted(
            "an interrupted activation left the previous release selected, and it did not "
            "start again; resolve it explicitly"
        )
    if active == pending["target"]:
        container = str(pending["container"])
        seen = host.observe(container)
        flip = float(pending.get("flip_unix") or 0)
        if (
            seen is not None
            and seen.active
            and seen.image == release.get("image")
            and seen.started_at >= flip
        ):
            return _prove_start(host, state, pending, None)
        # The release never started after the flip (activation review P2, P4):
        # start it now rather than judge the container that was already there.
        return _prove_start(host, state, pending, _start(host))
    raise MinerUpdateHalted(
        f"miner/current names neither the pending release nor the previous one ({active!r}); "
        "resolve it explicitly"
    )


# --- operator commands ------------------------------------------------------------------


def resolve(host: MinerUpdaterHost, action: str) -> UpdateOutcome:
    """The operator's exits from a halt, from probation, and from failure memory."""

    def body(host: MinerUpdaterHost, state: dict[str, object]) -> UpdateOutcome:
        if action == "retry":
            state["failed"] = None
            state["failed_updaters"] = {}
            state["updater_strikes"] = {}
            write_state(host.paths.state_file, state)
            return UpdateOutcome("resolved", "failure memory cleared; the next check retries")
        miner = state["miner"]
        assert isinstance(miner, dict)
        pending = miner.get("pending")
        stage = miner.get("stage")
        if action == "abandon" and stage not in (None, STAGE_PREPARED):
            # Every halt can be left this way, including a stage whose pending
            # record is missing or that a newer updater wrote (P1-3).
            if isinstance(pending, dict) and isinstance(pending.get("release"), dict):
                _remember_failure(host, state, pending["release"], reason="abandoned by the operator")
            _clear_stage(host, state)
            return UpdateOutcome(
                "resolved",
                "the pending release is recorded as failed and the stage is cleared; the next "
                "check can activate a newer release. miner/current is left as it is: "
                f"{link_target(host.paths.miner_current)!r}",
            )
        if stage not in (STAGE_MAY_HAVE_RUN, STAGE_PROBATION) or not _valid_pending(pending):
            raise MinerUpdateError("there is no interrupted activation to resolve")
        assert isinstance(pending, dict)
        release = pending["release"]
        if action == "accept-release":
            seen = host.settle(str(pending["container"]))
            if seen is None or not seen.active or seen.image != release.get("image"):
                raise MinerUpdateError(
                    f"the release is not running (running={seen.image if seen else None!r}); "
                    "start it first, restore the previous release, or abandon it"
                )
            if link_target(host.paths.miner_current) != pending["target"]:
                atomic_symlink(host.paths.miner_current, str(pending["target"]))
                host.systemctl(["daemon-reload"])
            _commit(
                host,
                state,
                release,
                str(pending["target"]),
                schema_verified=pending.get("schema_verified") is True,
            )
            return UpdateOutcome("resolved", "the running release was accepted as current")
        if action == "restore-previous":
            _rollback(host, state, pending, detail="the operator restored the previous release")
            return UpdateOutcome("resolved", "the previous release was restored and is running")
        raise MinerUpdateError(f"unknown resolve action: {action}")

    return _locked(host, body)


def describe_status(paths: HostPaths, config: HostConfig | None, *, expected_uid: int = 0) -> dict[str, object]:
    """What is installed and what happened last. Works with the channel unreachable."""

    state = read_state(paths.state_file)
    miner = state["miner"]
    assert isinstance(miner, dict)
    try:
        pinned: object = read_pin(paths.pin_file)
    except MinerUpdateError as exc:
        pinned = f"invalid: {exc}"
    try:
        trust = load_trust_state(paths.trust_file, expected_uid=expected_uid)
        trust_view: object = {
            "generation": trust.generation,
            "trust_root_sha256": trust.trust_root_sha256,
            "keys": {
                key_id: {"fingerprint": key.fingerprint, "channels": sorted(key.channels)}
                for key_id, key in sorted(trust.keys.items())
            },
            "revoked": sorted(entry["key_id"] for entry in trust.revoked.values()),
        }
    except MinerUpdateError as exc:
        trust_view = f"unavailable: {exc}"
    last = state.get("last_check")
    return {
        "schema": STATUS_SCHEMA,
        "config": config.as_document() if config is not None else None,
        "paused": paths.pause_file.exists(),
        "pinned": pinned,
        "trust": trust_view,
        "updater": {
            "current": link_target(paths.updater_current),
            "previous": link_target(paths.updater_previous),
            "strikes": state.get("updater_strikes"),
            "failed": state.get("failed_updaters"),
            "last_fallback": state.get("last_fallback"),
        },
        "miner": {
            "active": link_target(paths.miner_current),
            "current_release": miner.get("current"),
            "stage": miner.get("stage"),
            "pending": miner.get("pending"),
        },
        "needs_operator": miner.get("stage") not in (None, STAGE_PREPARED, STAGE_PROBATION)
        or (isinstance(last, dict) and last.get("action") == "halted"),
        "last_check": last,
        "last_refusal": state.get("last_refusal"),
        "consecutive_deferrals": state.get("consecutive_deferrals"),
        "consecutive_unverified": state.get("consecutive_unverified"),
        "schema_high_water": state.get("schema_high_water"),
        "last_fetch": state.get("last_fetch"),
        "failed": state.get("failed"),
        "floors": state.get("floors"),
    }


__all__ = [
    "CONFIG_SCHEMA",
    "DEFERRAL_ALERT_AFTER",
    "PROBATION_MINIMUM_SECONDS",
    "UNVERIFIED_ALERT_AFTER",
    "DOCUMENTED_EXIT_STATUSES",
    "DROPIN_NAME",
    "EXIT_ALERT",
    "EXIT_FAULT",
    "EXIT_HALTED",
    "EXIT_OK",
    "EXIT_REFUSED",
    "LEGACY",
    "PROBATION_SAMPLE_SECONDS",
    "STAGE_MAY_HAVE_RUN",
    "STAGE_PREPARED",
    "STAGE_PROBATION",
    "STATE_SCHEMA",
    "STATE_SCHEMA_LABEL",
    "STRIKES_TO_DEMOTE",
    "GateImpossible",
    "TrustSetUnavailable",
    "HostConfig",
    "HostPaths",
    "MinerUpdateError",
    "MinerUpdateHalted",
    "MinerUpdateRolledBack",
    "MinerUpdaterHost",
    "Observation",
    "UpdateOutcome",
    "activation_id",
    "describe_status",
    "empty_state",
    "exclusive",
    "fallback_to_previous",
    "load_config",
    "load_trust_state",
    "pin_document",
    "probe_release",
    "read_activation_profile",
    "read_pin",
    "read_state",
    "reconcile_interrupted_activation",
    "render_release_env",
    "resolve",
    "rollback_allowed",
    "stage_activation",
    "trust_backup_path",
    "update_once",
    "write_state",
    "write_trust_state",
]
