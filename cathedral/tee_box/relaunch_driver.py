"""Operator / control-plane driver over the pure relaunch state machine.

Drives drain → request → wait → admit transitions. VMM reboot is injected via
:class:`VmmHooks` so this module never invents a host API. Use
:class:`DryRunHooks` for offline rehearsal (no network, no reboot).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol

from cathedral.tee_box.relaunch import (
    RelaunchError,
    RelaunchPhase,
    RelaunchState,
    complete_admit,
    fail,
    initial,
    note_fresh_boot,
    note_release,
    note_waiting_fresh_boot,
    request_relaunch,
)


class VmmHooks(Protocol):
    """Host/VMM operations the control plane must supply."""

    def request_reboot(self, box_id: str) -> None:
        """Ask the host to reboot the guest (may be async on the host side)."""

    def read_boot_id(self, box_id: str) -> str:
        """Return the guest's current boot id after (or before) reboot."""

    def read_spki_sha256(self, box_id: str) -> str:
        """Return ``sha256:<64 hex>`` channel pin for the fresh TLS listener."""


@dataclass
class DryRunHooks:
    """In-memory hooks for tests and operator dry-runs (no VMM)."""

    boot_id: str = "boot-dry-0"
    next_boot_id: str = "boot-dry-1"
    spki_sha256: str = "sha256:" + ("ab" * 32)
    reboots: list[str] = field(default_factory=list)

    def request_reboot(self, box_id: str) -> None:
        self.reboots.append(box_id)
        self.boot_id = self.next_boot_id

    def read_boot_id(self, box_id: str) -> str:
        return self.boot_id

    def read_spki_sha256(self, box_id: str) -> str:
        return self.spki_sha256


@dataclass
class DriverResult:
    state: RelaunchState
    steps: list[str]

    @property
    def ok(self) -> bool:
        return self.state.phase is RelaunchPhase.READY


def run_relaunch_cycle(
    box_id: str,
    hooks: VmmHooks,
    *,
    prior_boot_id: str | None = None,
    state: RelaunchState | None = None,
    on_step: Callable[[str, RelaunchState], None] | None = None,
) -> DriverResult:
    """Run one full relaunch cycle using ``hooks``.

    If ``state`` is omitted, starts from IDLE and notes release with
    ``prior_boot_id`` or the current boot id from hooks.
    """

    steps: list[str] = []
    current = state or initial(box_id)

    def step(name: str, nxt: RelaunchState) -> RelaunchState:
        steps.append(name)
        if on_step is not None:
            on_step(name, nxt)
        return nxt

    try:
        if current.phase in {RelaunchPhase.IDLE, RelaunchPhase.READY, RelaunchPhase.FAILED}:
            boot = prior_boot_id or hooks.read_boot_id(box_id)
            current = step("note_release", note_release(current, boot_id=boot))
        if current.phase is RelaunchPhase.DRAINED_NEEDS_RELAUNCH:
            current = step("request_relaunch", request_relaunch(current))
        if current.phase is RelaunchPhase.RELAUNCH_REQUESTED:
            hooks.request_reboot(box_id)
            current = step("note_waiting_fresh_boot", note_waiting_fresh_boot(current))
        if current.phase is RelaunchPhase.WAITING_FRESH_BOOT:
            fresh = hooks.read_boot_id(box_id)
            current = step("note_fresh_boot", note_fresh_boot(current, fresh_boot_id=fresh))
        if current.phase is RelaunchPhase.ADMITTING:
            spki = hooks.read_spki_sha256(box_id)
            current = step("complete_admit", complete_admit(current, pinned_spki_sha256=spki))
    except (RelaunchError, OSError, ValueError) as exc:
        current = fail(current, reason=str(exc))
        steps.append(f"fail:{exc}")
        return DriverResult(state=current, steps=steps)
    return DriverResult(state=current, steps=steps)
