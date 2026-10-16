"""Control-plane relaunch state machine for tee-box (scaffolding).

The box itself only reports ``needs_relaunch`` after release. Production
orchestration (ask miner/VMM to reboot → wait → admit with
``require_fresh_boot`` → pin SPKI) lives in the control plane. This module
is the shared state vocabulary and pure transitions — no VMM calls, no
network. Wire an operator/Polaris driver later.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RelaunchPhase(str, Enum):
    IDLE = "idle"
    DRAINED_NEEDS_RELAUNCH = "drained_needs_relaunch"
    RELAUNCH_REQUESTED = "relaunch_requested"
    WAITING_FRESH_BOOT = "waiting_fresh_boot"
    ADMITTING = "admitting"
    READY = "ready"
    FAILED = "failed"


class RelaunchError(ValueError):
    pass


@dataclass(frozen=True)
class RelaunchState:
    phase: RelaunchPhase
    box_id: str
    boot_id: str | None = None
    last_released_at: str | None = None
    requested_at: str | None = None
    fresh_boot_id: str | None = None
    pinned_spki_sha256: str | None = None
    failure_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "box_id": self.box_id,
            "boot_id": self.boot_id,
            "last_released_at": self.last_released_at,
            "requested_at": self.requested_at,
            "fresh_boot_id": self.fresh_boot_id,
            "pinned_spki_sha256": self.pinned_spki_sha256,
            "failure_reason": self.failure_reason,
        }


def _utc_now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def note_release(
    state: RelaunchState,
    *,
    boot_id: str,
    now: datetime | None = None,
) -> RelaunchState:
    """Box reported needs_relaunch after the customer released."""

    if state.phase not in {RelaunchPhase.READY, RelaunchPhase.IDLE, RelaunchPhase.FAILED}:
        raise RelaunchError(f"cannot_note_release_from:{state.phase.value}")
    return RelaunchState(
        phase=RelaunchPhase.DRAINED_NEEDS_RELAUNCH,
        box_id=state.box_id,
        boot_id=boot_id,
        last_released_at=_utc_now_iso(now),
    )


def request_relaunch(
    state: RelaunchState,
    *,
    now: datetime | None = None,
) -> RelaunchState:
    if state.phase is not RelaunchPhase.DRAINED_NEEDS_RELAUNCH:
        raise RelaunchError(f"cannot_request_relaunch_from:{state.phase.value}")
    return RelaunchState(
        phase=RelaunchPhase.RELAUNCH_REQUESTED,
        box_id=state.box_id,
        boot_id=state.boot_id,
        last_released_at=state.last_released_at,
        requested_at=_utc_now_iso(now),
    )


def note_waiting_fresh_boot(state: RelaunchState) -> RelaunchState:
    if state.phase is not RelaunchPhase.RELAUNCH_REQUESTED:
        raise RelaunchError(f"cannot_wait_from:{state.phase.value}")
    return RelaunchState(
        phase=RelaunchPhase.WAITING_FRESH_BOOT,
        box_id=state.box_id,
        boot_id=state.boot_id,
        last_released_at=state.last_released_at,
        requested_at=state.requested_at,
    )


def note_fresh_boot(
    state: RelaunchState,
    *,
    fresh_boot_id: str,
) -> RelaunchState:
    if state.phase is not RelaunchPhase.WAITING_FRESH_BOOT:
        raise RelaunchError(f"cannot_note_fresh_boot_from:{state.phase.value}")
    if not fresh_boot_id or fresh_boot_id == state.boot_id:
        raise RelaunchError("fresh_boot_id_must_differ")
    return RelaunchState(
        phase=RelaunchPhase.ADMITTING,
        box_id=state.box_id,
        boot_id=state.boot_id,
        last_released_at=state.last_released_at,
        requested_at=state.requested_at,
        fresh_boot_id=fresh_boot_id,
    )


def complete_admit(
    state: RelaunchState,
    *,
    pinned_spki_sha256: str,
) -> RelaunchState:
    if state.phase is not RelaunchPhase.ADMITTING:
        raise RelaunchError(f"cannot_complete_admit_from:{state.phase.value}")
    if not pinned_spki_sha256 or not pinned_spki_sha256.startswith("sha256:"):
        raise RelaunchError("pinned_spki_required")
    return RelaunchState(
        phase=RelaunchPhase.READY,
        box_id=state.box_id,
        boot_id=state.fresh_boot_id,
        last_released_at=state.last_released_at,
        requested_at=state.requested_at,
        fresh_boot_id=state.fresh_boot_id,
        pinned_spki_sha256=pinned_spki_sha256,
    )


def fail(state: RelaunchState, *, reason: str) -> RelaunchState:
    return RelaunchState(
        phase=RelaunchPhase.FAILED,
        box_id=state.box_id,
        boot_id=state.boot_id,
        last_released_at=state.last_released_at,
        requested_at=state.requested_at,
        fresh_boot_id=state.fresh_boot_id,
        pinned_spki_sha256=state.pinned_spki_sha256,
        failure_reason=reason,
    )


def initial(box_id: str) -> RelaunchState:
    return RelaunchState(phase=RelaunchPhase.IDLE, box_id=box_id)
