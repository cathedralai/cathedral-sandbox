"""Apply signed SN39 miner releases to an installed miner.

The installed miner pins its version in one shell-style assignment,
``SN39_SNP_MINER_IMAGE``, inside ``/etc/cathedral/sn39-snp-miner.env``. Its
systemd unit reads that file and its launcher refuses anything that is not an
immutable digest in the canonical repository. So applying a release is:
rewrite that one assignment, restart the unit, confirm the miner came back.

Everything that touches the host is injected. That is deliberate. The
validator's updater reached the same problem and solved it by hard-coding the
unit name and calling three module-level helpers inline at eight sites, which
makes the safety gate impossible to substitute. Here the gate is one callable
supplied by the caller, because the condition for "safe to restart now" is
going to change the moment this host carries customer work: today nothing is
in flight, later an in-flight customer command must finish first.

Crash safety uses the same two-value ladder as the validator, for the same
reason. ``prepared`` means the pin has not been swapped yet, so the previous
version is still what runs and rolling back is free. ``may_have_run`` means the
pin was swapped and a restart was issued, so the new image may already have
started and may already have touched durable state. A ``may_have_run`` state
found at startup is never silently rolled back or silently retried. It is
reconciled against what is actually running, and if that cannot be established
the updater stops and says so rather than guessing.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cathedral.miner_release import (
    MinerRelease,
    MinerReleaseError,
    enforce_monotonic_release,
    parse_miner_release,
)

UPDATE_STATE_SCHEMA = "cathedral_sn39_miner_updater_state_v1"

DEFAULT_ENV_PATH = Path("/etc/cathedral/sn39-snp-miner.env")
DEFAULT_STATE_PATH = Path("/var/lib/cathedral-sn39-miner-update/state.json")
DEFAULT_PAUSE_PATH = Path("/etc/cathedral/sn39-snp-miner-update.paused")

IMAGE_VARIABLE = "SN39_SNP_MINER_IMAGE"

STAGE_PREPARED = "prepared"
STAGE_MAY_HAVE_RUN = "may_have_run"

MAX_ENV_BYTES = 64 * 1024
MAX_METADATA_BYTES = 16 * 1024

_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


class MinerUpdateError(RuntimeError):
    """The update did not complete. The previous version is unaffected."""


class MinerUpdateHalted(MinerUpdateError):
    """An earlier activation left an outcome this process must not guess at.

    Raised when durable state says a new image may already have run but its
    health cannot be established. Recovery is an operator decision, because
    rolling back could discard work the new version already did.
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
    """Every effect the updater has on the machine it runs on.

    Supplying these lets the whole state machine run against fakes, so the
    crash paths are testable without a confidential guest.
    """

    fetch_metadata: Callable[[], bytes]
    restart_service: Callable[[], None]
    is_healthy: Callable[[], bool]
    # Pull and verify the image before the pin is swapped. This is what the
    # prepared stage covers: an unreachable registry or a digest that does not
    # match is caught while the previous version is still the one pinned.
    prepare_image: Callable[[str], None] = lambda image: None
    safe_to_activate: Callable[[], bool] = lambda: True
    env_path: Path = DEFAULT_ENV_PATH
    state_path: Path = DEFAULT_STATE_PATH
    pause_path: Path = DEFAULT_PAUSE_PATH
    trusted_keys: Mapping[str, bytes] = field(default_factory=dict)
    now_unix: Callable[[], int] = lambda: 0


# --- environment file -------------------------------------------------------


def read_env_assignments(path: Path) -> dict[str, str]:
    """Parse a shell-style env file into assignments.

    systemd's EnvironmentFile syntax is not shell. Only simple assignments are
    supported, comments and blank lines are ignored, and surrounding quotes are
    stripped. Anything else is left alone by rewrite, so an operator's own
    settings survive untouched.
    """

    try:
        raw = path.read_bytes()
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
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGNMENT_RE.match(stripped)
        if match is None:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        assignments[match.group(1)] = value
    return assignments


def rewrite_pin(path: Path, image: str) -> None:
    """Replace only the image assignment, preserving every other line.

    Written atomically through a temporary file in the same directory so a
    crash mid-write cannot leave the miner with a truncated pin file, which
    would stop the unit from starting at all.
    """

    try:
        original = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MinerUpdateError(f"pin file cannot be read: {path}") from exc

    lines = original.splitlines()
    replaced = False
    output: list[str] = []
    for line in lines:
        match = _ASSIGNMENT_RE.match(line.strip())
        if match is not None and match.group(1) == IMAGE_VARIABLE:
            if replaced:
                # A duplicate assignment would mean the last one wins and the
                # file disagrees with itself. Drop the extras.
                continue
            output.append(f"{IMAGE_VARIABLE}={image}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{IMAGE_VARIABLE}={image}")
    body = "\n".join(output) + "\n"

    directory = path.parent
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = ""
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise MinerUpdateError("pin file could not be replaced") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


# --- durable state ----------------------------------------------------------


def read_state(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {"schema": UPDATE_STATE_SCHEMA, "channels": {}, "stage": None}
    except OSError as exc:
        raise MinerUpdateError("updater state cannot be read") from exc
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MinerUpdateError("updater state is not strict JSON") from exc
    if not isinstance(state, dict) or state.get("schema") != UPDATE_STATE_SCHEMA:
        raise MinerUpdateError("updater state schema is unsupported")
    if not isinstance(state.get("channels"), dict):
        raise MinerUpdateError("updater state channels are malformed")
    return state


def write_state(path: Path, state: Mapping[str, object]) -> None:
    directory = path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MinerUpdateError("updater state directory is unavailable") from exc
    body = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("ascii")
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        temporary = ""
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise MinerUpdateError("updater state could not be persisted") from exc
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass


# --- the update -------------------------------------------------------------


def reconcile_interrupted_activation(host: MinerUpdaterHost, state: dict[str, object]) -> None:
    """Resolve a stage left behind by a previous run.

    ``prepared`` means the pin was never swapped, so the stage is simply
    cleared. ``may_have_run`` means the new image may already have started. If
    it is healthy the activation is committed. If it is not, this stops rather
    than rolling back, because a rollback could discard state the new version
    already migrated.
    """

    stage = state.get("stage")
    if stage is None:
        return
    if stage == STAGE_PREPARED:
        state["stage"] = None
        write_state(host.state_path, state)
        return
    if stage != STAGE_MAY_HAVE_RUN:
        raise MinerUpdateError("updater state stage is unrecognised")

    pending = state.get("pending")
    if not isinstance(pending, dict):
        raise MinerUpdateHalted(
            "durable state records an activation that may have run but does not "
            "say which image; resolve it explicitly"
        )
    pinned = read_env_assignments(host.env_path).get(IMAGE_VARIABLE)
    if pinned == pending.get("previous_image"):
        # The swap never landed, so the previous version is still what runs.
        # Nothing new can have executed. Clear and let the caller retry.
        state["stage"] = None
        state.pop("pending", None)
        write_state(host.state_path, state)
        return
    if pinned != pending.get("image"):
        raise MinerUpdateHalted(
            "the pinned image matches neither the previous nor the pending "
            "release; resolve it explicitly"
        )
    if host.is_healthy():
        channel = pending.get("channel")
        record = pending.get("committed_record")
        if isinstance(channel, str) and isinstance(record, dict):
            state.setdefault("channels", {})[channel] = record
        state["stage"] = None
        state.pop("pending", None)
        write_state(host.state_path, state)
        return
    raise MinerUpdateHalted(
        "a previous activation may already have run and is not healthy; "
        "resolve it explicitly rather than letting the updater guess"
    )


def update_once(host: MinerUpdaterHost, *, channel: str) -> UpdateOutcome:
    """Run one update check. Returns what happened, raises only on real faults."""

    if host.pause_path.exists():
        return UpdateOutcome("paused", f"operator pause file present: {host.pause_path}")

    state = read_state(host.state_path)
    reconcile_interrupted_activation(host, state)

    raw = host.fetch_metadata()
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_METADATA_BYTES:
        raise MinerUpdateError("release metadata size is out of range")
    try:
        release = parse_miner_release(bytes(raw), trusted_keys=host.trusted_keys)
    except MinerReleaseError as exc:
        raise MinerUpdateError(f"release metadata refused: {exc}") from exc

    if release.channel != channel:
        raise MinerUpdateError("release metadata is for a different channel")
    now = host.now_unix()
    if release.is_expired(now_unix=now):
        raise MinerUpdateError("release metadata has expired")

    channels = state.setdefault("channels", {})
    previous = channels.get(channel)
    floor = None
    if isinstance(previous, dict):
        floor = {
            "sequence": previous.get("sequence"),
            "signed_sha256": previous.get("signed_sha256"),
        }
    try:
        enforce_monotonic_release(floor, release)
    except MinerReleaseError as exc:
        raise MinerUpdateError(str(exc)) from exc

    assignments = read_env_assignments(host.env_path)
    current_image = assignments.get(IMAGE_VARIABLE)
    if current_image == release.image:
        # Record that this exact record was seen, so the floor advances even
        # when no restart is needed. Otherwise a later equivocating record at
        # the same sequence would not be detected.
        channels[channel] = _channel_record(release)
        state["stage"] = None
        write_state(host.state_path, state)
        return UpdateOutcome(
            "current",
            "the pinned image already matches the released image",
            active_image=release.image,
            active_version=release.version,
            sequence=release.sequence,
        )

    if not host.safe_to_activate():
        return UpdateOutcome(
            "deferred",
            "the miner is not at a safe point to restart",
            active_image=current_image,
            sequence=release.sequence,
        )

    # Rollback-safe for the whole prepared stage: the pin still names the
    # previous image, so whatever happens here, the running miner is unchanged.
    state["stage"] = STAGE_PREPARED
    state["pending"] = {
        "channel": channel,
        "image": release.image,
        "version": release.version,
        "sequence": release.sequence,
        "previous_image": current_image,
        "committed_record": _channel_record(release),
    }
    write_state(host.state_path, state)

    try:
        host.prepare_image(release.image)
    except Exception as exc:  # noqa: BLE001 - any pull or verify failure is the same case
        state["stage"] = None
        state.pop("pending", None)
        write_state(host.state_path, state)
        raise MinerUpdateError(
            f"the released image could not be prepared, nothing was changed: {exc}"
        ) from exc

    # Past this line the new image may run, so the stage is recorded before the
    # pin is swapped, never after. A crash in the gap leaves may_have_run with
    # the previous pin still in place, which reconciliation detects by
    # comparing the pin rather than by guessing from health alone.
    state["stage"] = STAGE_MAY_HAVE_RUN
    write_state(host.state_path, state)

    rewrite_pin(host.env_path, release.image)
    try:
        host.restart_service()
    except Exception as exc:  # noqa: BLE001 - any restart failure is the same case
        _rollback(host, state, current_image)
        raise MinerUpdateError(f"restart failed, previous image restored: {exc}") from exc

    if not host.is_healthy():
        _rollback(host, state, current_image)
        raise MinerUpdateError("the new image did not become healthy, previous image restored")

    channels[channel] = _channel_record(release)
    state["stage"] = None
    state.pop("pending", None)
    write_state(host.state_path, state)
    return UpdateOutcome(
        "activated",
        "the released image is active and healthy",
        active_image=release.image,
        active_version=release.version,
        sequence=release.sequence,
    )


def _channel_record(release: MinerRelease) -> dict[str, object]:
    return {
        "sequence": release.sequence,
        "signed_sha256": release.signed_sha256,
        "image": release.image,
        "version": release.version,
        "runtime_contract": release.runtime_contract,
    }


def _rollback(host: MinerUpdaterHost, state: dict[str, object], previous_image: str | None) -> None:
    """Restore the previous pin after a failed activation.

    Only called on the paths where this process observed the failure itself, so
    it knows the new version did not become healthy. The crash path does not
    come here; it goes through reconciliation, which refuses to guess.
    """

    if previous_image is not None:
        try:
            rewrite_pin(host.env_path, previous_image)
            host.restart_service()
        except Exception:  # noqa: BLE001 - report the original fault, not this one
            state["stage"] = STAGE_MAY_HAVE_RUN
            write_state(host.state_path, state)
            return
    state["stage"] = None
    state.pop("pending", None)
    write_state(host.state_path, state)


def describe_status(host: MinerUpdaterHost) -> dict[str, object]:
    """Report the installed version and update state without exposing secrets."""

    assignments = read_env_assignments(host.env_path)
    state = read_state(host.state_path)
    channels = state.get("channels")
    return {
        "schema": "cathedral_sn39_miner_update_status_v1",
        "pinned_image": assignments.get(IMAGE_VARIABLE),
        "paused": host.pause_path.exists(),
        "stage": state.get("stage"),
        "channels": channels if isinstance(channels, dict) else {},
    }


__all__ = [
    "DEFAULT_ENV_PATH",
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
    "reconcile_interrupted_activation",
    "rewrite_pin",
    "update_once",
]
