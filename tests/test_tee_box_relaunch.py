"""Tee-box relaunch control-plane state machine."""

from __future__ import annotations

import pytest

from cathedral.tee_box.relaunch import (
    RelaunchError,
    RelaunchPhase,
    complete_admit,
    fail,
    initial,
    note_fresh_boot,
    note_release,
    note_waiting_fresh_boot,
    request_relaunch,
)


def test_happy_path():
    state = initial("box-1")
    state = note_release(state, boot_id="boot-a")
    assert state.phase is RelaunchPhase.DRAINED_NEEDS_RELAUNCH
    state = request_relaunch(state)
    state = note_waiting_fresh_boot(state)
    state = note_fresh_boot(state, fresh_boot_id="boot-b")
    state = complete_admit(state, pinned_spki_sha256="sha256:" + "a" * 64)
    assert state.phase is RelaunchPhase.READY
    assert state.boot_id == "boot-b"
    assert state.pinned_spki_sha256.startswith("sha256:")


def test_rejects_same_boot_id():
    state = note_waiting_fresh_boot(
        request_relaunch(note_release(initial("box-1"), boot_id="boot-a"))
    )
    with pytest.raises(RelaunchError, match="fresh_boot_id_must_differ"):
        note_fresh_boot(state, fresh_boot_id="boot-a")


def test_fail_records_reason():
    state = fail(initial("box-1"), reason="vmm_timeout")
    assert state.phase is RelaunchPhase.FAILED
    assert state.failure_reason == "vmm_timeout"
