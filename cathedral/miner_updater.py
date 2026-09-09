"""Apply signed SN39 miner releases to an installed miner.

The installed miner pins its version in one shell-style assignment,
``SN39_SNP_MINER_IMAGE``, inside ``/etc/cathedral/sn39-snp-miner.env``. Its
systemd unit reads that file and its launcher refuses anything that is not an
immutable digest in the canonical repository. So applying a release is:
rewrite that one assignment, restart the unit, confirm the *released* image is
what came back.

Everything that touches the host is injected. That is deliberate. The
validator's updater reached the same problem and solved it by hard-coding the
unit name and calling its safety helpers inline at ten sites, which makes the
gate impossible to substitute. Here the gate is one callable supplied by the
caller, because the condition for "safe to restart now" changes the moment this
host carries customer work.

Recovery model
--------------
The hard part is not restarting. It is knowing, after an interruption, whether
the new image ever *ran*. It matters because the launcher bind-mounts durable
state read-write, so a new image that started, wrote, and then died leaves
state the previous image may not understand. Starting the old image against it
is data corruption, not a rollback.

An earlier version of this module inferred that from the pin file. That was
wrong twice over: a restored pin does not prove the new image never ran, and a
swapped pin does not prove it did. This version records the two facts directly
and never re-derives them:

``execution may have happened``
    A one-way latch (``may_have_run``), set before the pin is swapped and
    cleared only by proof. Nothing that merely rewrites the pin clears it.

``durable_digest_before``
    A fingerprint of the state the miner may mutate, taken before the swap.
    Rollback is permitted only while the fingerprint is unchanged, which is
    positive evidence that the new image wrote nothing. Otherwise the updater
    halts for an operator rather than guessing.

Health means the running container reports the released image. "The unit is
active" is not health: after an interrupted activation the *previous*
container is still active, and treating that as success would commit a release
that never started and then report it as current forever.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cathedral.miner_release import (
    CANONICAL_IMAGE_REPOSITORY,
    SN39_SNP_MINER_PRODUCT,
    MinerRelease,
    MinerReleaseError,
    enforce_monotonic_release,
    parse_miner_release,
)

UPDATE_STATE_SCHEMA = "cathedral_sn39_miner_updater_state_v2"

DEFAULT_ENV_PATH = Path("/etc/cathedral/sn39-snp-miner.env")
DEFAULT_STATE_PATH = Path("/var/lib/cathedral-sn39-miner-update/state.json")
DEFAULT_PAUSE_PATH = Path("/etc/cathedral/sn39-snp-miner-update.paused")
DEFAULT_LOCK_PATH = Path("/var/lib/cathedral-sn39-miner-update/updater.lock")

IMAGE_VARIABLE = "SN39_SNP_MINER_IMAGE"

STAGE_PREPARED = "prepared"
STAGE_MAY_HAVE_RUN = "may_have_run"

MAX_ENV_BYTES = 64 * 1024
MAX_STATE_BYTES = 256 * 1024
MAX_METADATA_BYTES = 16 * 1024

# systemd's EnvironmentFile parser tolerates whitespace around the separator,
# so `NAME = value` is a real pin an operator can have on disk. Refusing to
# recognise it would make the updater believe there is no previous image, which
# is exactly the state in which a rollback has nothing to restore.
_ASSIGNMENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


class MinerUpdateError(RuntimeError):
    """The update did not complete."""


class MinerUpdateHalted(MinerUpdateError):
    """An outcome this process must not guess at.

    Raised when the released image may already have run and its success cannot
    be established. Recovery is an operator decision, because both continuing
    and reverting can destroy work.
    """


@dataclass(frozen=True)
class UpdateOutcome:
    """What one updater run did."""

    action: str
    reason: str
    active_image: str | None = None
    active_version: str | None = None
    sequence: int | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "reason": self.reason,
            "active_image": self.active_image,
            "active_version": self.active_version,
            "sequence": self.sequence,
        }


@dataclass
class MinerUpdaterHost:
    """Every effect the updater has on the machine it runs on."""

    fetch_metadata: Callable[[], bytes]
    restart_service: Callable[[], None]
    # The image the running miner container actually reports, or None when no
    # container is running. Implementations should wait for the container to
    # settle before answering. This is the only acceptable notion of health:
    # unit activity alone cannot distinguish the new container from the old.
    running_image: Callable[[], str | None]
    # A fingerprint of the durable state the miner may mutate. Rollback is
    # permitted only while this is unchanged from before the swap.
    durable_digest: Callable[[], str] = lambda: ""
    # Pull and verify the image while the previous one is still pinned.
    prepare_image: Callable[[MinerRelease], None] = lambda release: None
    # Confirm the installed launcher is the one the release was built against
    # and supports the contract it names. Raises to refuse.
    verify_launcher: Callable[[MinerRelease], None] = lambda release: None
    safe_to_activate: Callable[[], bool] = lambda: True
    env_path: Path = DEFAULT_ENV_PATH
    state_path: Path = DEFAULT_STATE_PATH
    pause_path: Path = DEFAULT_PAUSE_PATH
    lock_path: Path = DEFAULT_LOCK_PATH
    # Which assignment in the pin file names this product's image.
    image_variable: str = IMAGE_VARIABLE
    # What this host will accept a release for. Both are caller-supplied so
    # a record for another product fails on identity, not on luck.
    expected_product: str = SN39_SNP_MINER_PRODUCT
    expected_image_repository: str = CANONICAL_IMAGE_REPOSITORY
    trusted_keys: Mapping[str, bytes] = field(default_factory=dict)
    now_unix: Callable[[], int] = lambda: 0


# --- environment file -------------------------------------------------------


def read_env_assignments(path: Path) -> dict[str, str]:
    """Parse a shell-style env file into assignments.

    Only the assignment shapes systemd's EnvironmentFile parser accepts are
    recognised. Comments, blanks and anything else are left alone by the
    rewrite, so an operator's own settings survive untouched.
    """

    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_ENV_BYTES + 1)
    except FileNotFoundError as exc:
        raise MinerUpdateError(f"pin file is missing: {path}") from exc
    except OSError as exc:
        raise MinerUpdateError(f"pin file cannot be read: {path}") from exc
    if len(raw) > MAX_ENV_BYTES:
        raise MinerUpdateError("pin file is unexpectedly large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MinerUpdateError("pin file is not UTF-8") from exc

    assignments: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        match = _ASSIGNMENT_RE.match(line)
        if match is None:
            continue
        value = match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        assignments[match.group(1)] = value
    return assignments


def _atomic_write(path: Path, body: bytes, *, mode: int) -> None:
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
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


def rewrite_pin(path: Path, image: str, *, variable: str = IMAGE_VARIABLE) -> None:
    """Replace only the image assignment, preserving every other line."""

    try:
        original = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MinerUpdateError(f"pin file cannot be read: {path}") from exc

    replaced = False
    output: list[str] = []
    for line in original.splitlines():
        match = _ASSIGNMENT_RE.match(line)
        if match is not None and match.group(1) == variable:
            if replaced:
                # A duplicate assignment means the file disagrees with itself
                # and systemd takes the last one. Collapse to one.
                continue
            output.append(f"{variable}={image}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{variable}={image}")
    _atomic_write(path, ("\n".join(output) + "\n").encode("utf-8"), mode=0o600)


# --- durable state ----------------------------------------------------------


def _empty_state() -> dict[str, object]:
    return {
        "schema": UPDATE_STATE_SCHEMA,
        # Highest authenticated record per channel, advanced on every verified
        # record whether or not it activated. Kept separate from `channels` so
        # a failed attempt still burns its sequence and a second record cannot
        # reuse that sequence with different content.
        "floors": {},
        # Last successfully activated record per channel.
        "channels": {},
        "stage": None,
        "pending": None,
    }


def read_state(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return _empty_state()
    except OSError as exc:
        raise MinerUpdateError("updater state cannot be read") from exc
    if len(raw) > MAX_STATE_BYTES:
        raise MinerUpdateError("updater state is unexpectedly large")
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MinerUpdateError("updater state is not strict JSON") from exc
    if not isinstance(state, dict) or state.get("schema") != UPDATE_STATE_SCHEMA:
        raise MinerUpdateError("updater state schema is unsupported")
    for key in ("floors", "channels"):
        if not isinstance(state.get(key), dict):
            raise MinerUpdateError(f"updater state {key} is malformed")
    return state


def write_state(path: Path, state: Mapping[str, object]) -> None:
    try:
        body = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise MinerUpdateError("updater state is not serialisable") from exc
    _atomic_write(path, body, mode=0o600)


# --- locking ----------------------------------------------------------------


@contextlib.contextmanager
def _exclusive(path: Path):
    """Hold an exclusive lock for the whole check.

    systemd will not run two copies of one oneshot unit, but an operator
    running a manual check while the timer fires can race it, and two processes
    rewriting the pin is the interleaving that leaves a miner running neither
    version. Non-blocking, so a second run reports contention rather than
    queueing behind a long pull.
    """

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise MinerUpdateError("updater lock is unavailable") from exc
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise MinerUpdateError("another update check is already running") from exc
        yield
    finally:
        os.close(handle)


# --- recovery ---------------------------------------------------------------


def _durable_unchanged(host: MinerUpdaterHost, pending: Mapping[str, object]) -> bool:
    """Whether the state the miner may mutate is exactly as it was.

    This is the only positive evidence available that a started image wrote
    nothing. A missing or unreadable fingerprint counts as changed, because an
    unknown answer must never license a rollback.
    """

    before = pending.get("durable_digest_before")
    if not isinstance(before, str) or not before:
        return False
    try:
        return host.durable_digest() == before
    except Exception:  # noqa: BLE001 - an unreadable fingerprint is not proof
        return False


def _restore_pin_if_needed(host: MinerUpdaterHost, previous: object) -> None:
    if not isinstance(previous, str) or not previous:
        return
    if read_env_assignments(host.env_path).get(host.image_variable) != previous:
        rewrite_pin(host.env_path, previous, variable=host.image_variable)


def reconcile_interrupted_activation(host: MinerUpdaterHost, state: dict[str, object]) -> None:
    """Resolve a stage left behind by a previous run.

    ``prepared`` means the pin was never swapped and no restart was issued, so
    nothing new can have started. It is cleared.

    ``may_have_run`` is decided on what is *actually running* and on whether
    durable state moved, never on what the pin says. A pin can have been
    rewritten by a rollback that then failed to restart, so on its own it
    carries no information about execution.
    """

    stage = state.get("stage")
    if stage is None:
        return
    if stage == STAGE_PREPARED:
        state["stage"] = None
        state["pending"] = None
        write_state(host.state_path, state)
        return
    if stage != STAGE_MAY_HAVE_RUN:
        raise MinerUpdateError("updater state stage is unrecognised")

    pending = state.get("pending")
    if not isinstance(pending, dict):
        raise MinerUpdateHalted(
            "durable state records an interrupted activation but not which "
            "release it was; resolve it explicitly"
        )
    expected = pending.get("image")
    previous = pending.get("previous_image")
    running = host.running_image()

    if running is not None and running == expected:
        channel = pending.get("channel")
        record = pending.get("committed_record")
        if isinstance(channel, str) and isinstance(record, dict):
            state.setdefault("channels", {})[channel] = record
        state["stage"] = None
        state["pending"] = None
        write_state(host.state_path, state)
        return

    if running is not None and running == previous and _durable_unchanged(host, pending):
        # The previous image is serving and nothing was written, so the release
        # never got far enough to matter. Put the pin back if a partial
        # rollback left it pointing at the release, then retry later.
        _restore_pin_if_needed(host, previous)
        state["stage"] = None
        state["pending"] = None
        write_state(host.state_path, state)
        return

    raise MinerUpdateHalted(
        "an interrupted activation cannot be resolved automatically "
        f"(running={running!r}, expected={expected!r}, "
        f"durable_state_changed={not _durable_unchanged(host, pending)}); "
        "resolve it explicitly"
    )


# --- the update -------------------------------------------------------------


def update_once(host: MinerUpdaterHost, *, channel: str) -> UpdateOutcome:
    """Run one update check. Returns what happened, raises only on real faults."""

    # Before the lock: a paused miner must never contend for it.
    if host.pause_path.exists():
        return UpdateOutcome("paused", f"operator pause file present: {host.pause_path}")
    with _exclusive(host.lock_path):
        return _update_once_locked(host, channel=channel)


def _update_once_locked(host: MinerUpdaterHost, *, channel: str) -> UpdateOutcome:
    state = read_state(host.state_path)
    reconcile_interrupted_activation(host, state)

    raw = host.fetch_metadata()
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_METADATA_BYTES:
        raise MinerUpdateError("release metadata size is out of range")
    try:
        release = parse_miner_release(
            bytes(raw),
            trusted_keys=host.trusted_keys,
            expected_product=host.expected_product,
            expected_image_repository=host.expected_image_repository,
        )
    except MinerReleaseError as exc:
        raise MinerUpdateError(f"release metadata refused: {exc}") from exc

    if release.channel != channel:
        raise MinerUpdateError("release metadata is for a different channel")
    if release.is_expired(now_unix=host.now_unix()):
        raise MinerUpdateError("release metadata has expired")

    floors = state.setdefault("floors", {})
    try:
        enforce_monotonic_release(floors.get(channel), release)
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc

    # Burn the sequence now, before any attempt. A failed activation must still
    # consume its sequence, or a different record could later reuse it and pass
    # monotonic enforcement, which is exactly what equivocation detection is
    # supposed to prevent.
    floors[channel] = {"sequence": release.sequence, "signed_sha256": release.signed_sha256}
    write_state(host.state_path, state)

    current_image = read_env_assignments(host.env_path).get(host.image_variable)
    if current_image == release.image:
        state.setdefault("channels", {})[channel] = _channel_record(release)
        write_state(host.state_path, state)
        return UpdateOutcome(
            "current",
            "the pinned image already matches the released image",
            active_image=release.image,
            active_version=release.version,
            sequence=release.sequence,
        )

    # Refuse to start without something to go back to. With no recoverable
    # previous pin, a failed activation would have no rollback at all.
    if not current_image:
        raise MinerUpdateError(
            "the pin file names no current image, so a failed update could not "
            "be rolled back; set SN39_SNP_MINER_IMAGE before updating"
        )

    # Compatibility, checked while the previous image is still pinned and
    # serving, so an incompatible release costs nothing.
    host.verify_launcher(release)

    if not host.safe_to_activate():
        return UpdateOutcome(
            "deferred",
            "the miner is not at a safe point to restart",
            active_image=current_image,
            sequence=release.sequence,
        )

    state["stage"] = STAGE_PREPARED
    state["pending"] = {
        "channel": channel,
        "image": release.image,
        "version": release.version,
        "sequence": release.sequence,
        "previous_image": current_image,
        "durable_digest_before": host.durable_digest(),
        "committed_record": _channel_record(release),
    }
    write_state(host.state_path, state)

    try:
        host.prepare_image(release)
    except Exception as exc:  # noqa: BLE001 - any pull or verify failure is one case
        state["stage"] = None
        state["pending"] = None
        write_state(host.state_path, state)
        raise MinerUpdateError(
            f"the released image could not be prepared, nothing was changed: {exc}"
        ) from exc

    # The latch. From here the released image may start at any moment,
    # including by systemd's own restart policy or a reboot, so this is
    # recorded before the pin changes and is never cleared by anything that
    # merely rewrites the pin.
    state["stage"] = STAGE_MAY_HAVE_RUN
    write_state(host.state_path, state)

    rewrite_pin(host.env_path, release.image, variable=host.image_variable)
    restart_error: Exception | None = None
    try:
        host.restart_service()
    except Exception as exc:  # noqa: BLE001 - reported once the outcome is known
        restart_error = exc

    if host.running_image() == release.image:
        state.setdefault("channels", {})[channel] = _channel_record(release)
        state["stage"] = None
        state["pending"] = None
        write_state(host.state_path, state)
        return UpdateOutcome(
            "activated",
            "the released image is running",
            active_image=release.image,
            active_version=release.version,
            sequence=release.sequence,
        )

    detail = (
        f"restart failed ({restart_error})"
        if restart_error is not None
        else "the released image did not come up"
    )
    # Reverting is only safe while there is positive evidence the released
    # image wrote nothing. Not-running is not that evidence: a container can
    # start, write, and exit.
    if not _durable_unchanged(host, state["pending"]):
        raise MinerUpdateHalted(
            f"{detail}, and durable state changed, so the released image may "
            "already have written to it; not reverting. Resolve it explicitly"
        )
    _rollback(host, state, current_image, detail=detail)
    raise MinerUpdateError(f"{detail}; the previous image was restored and verified")


def _channel_record(release: MinerRelease) -> dict[str, object]:
    return {
        "sequence": release.sequence,
        "signed_sha256": release.signed_sha256,
        "image": release.image,
        "version": release.version,
        "runtime_contract": release.runtime_contract,
    }


def _rollback(
    host: MinerUpdaterHost, state: dict[str, object], previous_image: str, *, detail: str
) -> None:
    """Restore the previous pin, and prove it came back.

    Only reached with positive evidence that the released image wrote nothing.
    A restoration that cannot be verified is never reported as one: the latch
    stays set and the caller is told, because a miner running nothing is a
    different situation from a miner running its previous version.

    The concrete failure this guards against: the miner unit allows five starts
    per 300 seconds. A release that fails repeatedly exhausts that allowance,
    after which systemd refuses the rollback start too, and the old code would
    still have reported the previous image restored.
    """

    try:
        rewrite_pin(host.env_path, previous_image, variable=host.image_variable)
        host.restart_service()
    except Exception as exc:  # noqa: BLE001
        write_state(host.state_path, state)
        raise MinerUpdateHalted(
            f"{detail}, and restoring the previous image also failed ({exc}); "
            "the miner may be running nothing. Resolve it explicitly"
        ) from exc

    if host.running_image() != previous_image:
        write_state(host.state_path, state)
        raise MinerUpdateHalted(
            f"{detail}, and the previous image did not come back; "
            "systemd start rate limiting does this after repeated failures. "
            "The miner may be running nothing. Resolve it explicitly"
        )

    state["stage"] = None
    state["pending"] = None
    write_state(host.state_path, state)


def describe_status(host: MinerUpdaterHost) -> dict[str, object]:
    """Report the installed version and update state without exposing secrets."""

    assignments = read_env_assignments(host.env_path)
    state = read_state(host.state_path)
    return {
        "schema": "cathedral_sn39_miner_update_status_v1",
        "pinned_image": assignments.get(host.image_variable),
        "paused": host.pause_path.exists(),
        "stage": state.get("stage"),
        "needs_operator": state.get("stage") == STAGE_MAY_HAVE_RUN,
        "channels": state.get("channels", {}),
        "floors": state.get("floors", {}),
    }


__all__ = [
    "DEFAULT_ENV_PATH",
    "DEFAULT_LOCK_PATH",
    "DEFAULT_PAUSE_PATH",
    "DEFAULT_STATE_PATH",
    "IMAGE_VARIABLE",
    "MinerUpdateError",
    "MinerUpdateHalted",
    "MinerUpdaterHost",
    "STAGE_MAY_HAVE_RUN",
    "STAGE_PREPARED",
    "UPDATE_STATE_SCHEMA",
    "UpdateOutcome",
    "describe_status",
    "read_env_assignments",
    "read_state",
    "reconcile_interrupted_activation",
    "rewrite_pin",
    "update_once",
    "write_state",
]
