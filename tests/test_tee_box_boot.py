"""One customer per boot (cathedral/tee_box/boot.py, docs/TEE_BOX_SERVICE.md
"Relaunch between customers")."""

from __future__ import annotations

import json
import math
import os
import stat
import time
from pathlib import Path

import pytest

from cathedral.tee_box import FakeExecutor, TeeBoxSandboxApi, build_egress_policy
from cathedral.tee_box.boot import (
    MARKER_SCHEMA,
    UNKNOWN_CONSUMER,
    BootError,
    BootGuard,
    RelaunchRequired,
    marker_path_for,
    read_boot_id,
    read_booted_at,
)
from tests.test_tee_box_service import (
    BOOTED_AT,
    BOX_IP,
    CALLER,
    CAPACITY,
    DEFAULT_SHAPE,
    DIGEST,
    OTHER,
    _api,
    _authorizer,
    _binding,
    _BootIds,
    _Clock,
    _handle,
    _push_revocations,
)

THIRD = "central:" + "3" * 64
BOOT_ID_ALT = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"


def _lease(api, caller=CALLER, ttl=60):
    return _handle(api, "POST", "/v1/lease", caller, {"ttl_seconds": ttl})


def _boot_view(api, caller=CALLER):
    status, contract = _handle(api, "GET", "/v1/box", caller)
    assert status == 200
    return contract["boot"]


def _relaunch_required(api, caller=OTHER) -> bool:
    status, body = _lease(api, caller)
    return status == 409 and body["reason"] == "relaunch_required"


@pytest.fixture
def box(tmp_path: Path):
    clock = _Clock()
    boot_ids = _BootIds()
    marker = tmp_path / "central.sqlite.boot"
    api, fake = _api(tmp_path, _binding(), clock=clock, boot_ids=boot_ids, marker=marker)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    return api, fake, clock, boot_ids, marker


def _restart(tmp_path: Path, clock, boot_ids, marker, fake=None):
    """A new worker process in the same guest (same tmpfs, same boot id unless changed)."""

    api, fake = _api(
        tmp_path,
        _binding(),
        clock=clock,
        boot_ids=boot_ids,
        marker=marker,
        executor=fake or FakeExecutor(),
        ready=False,
    )
    api._revocations_issued_at = clock.value  # noqa: SLF001
    api.reap()  # the first sweep, as the worker's reaper runs at start
    return api


# -- the kernel readers -----------------------------------------------------


def test_the_boot_id_reader_takes_the_kernel_uuid(tmp_path: Path):
    path = tmp_path / "boot_id"
    path.write_text("6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f\n")
    assert read_boot_id(str(path)) == "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"
    for junk in ("", "not-a-uuid\n", "6F1C2D3E-4B5A-4C6D-8E7F-0A1B2C3D4E5F\n"):
        path.write_text(junk)
        with pytest.raises(BootError):
            read_boot_id(str(path))
    with pytest.raises(BootError):
        read_boot_id(str(tmp_path / "missing"))


def test_the_boot_time_reader_takes_btime(tmp_path: Path):
    path = tmp_path / "stat"
    path.write_text("cpu  1 2 3\nbtime 1899990000\nprocesses 7\n")
    assert read_booted_at(str(path)) == 1_899_990_000
    for junk in ("cpu 1 2 3\n", "btime -5\n", "btime soon\n"):
        path.write_text(junk)
        with pytest.raises(BootError):
            read_booted_at(str(path))


@pytest.mark.skipif(not os.path.exists("/proc/sys/kernel/random/boot_id"), reason="Linux only")
def test_the_real_kernel_readers_agree_with_proc():
    first, second = read_boot_id(), read_boot_id()
    assert first == second and len(first) == 36
    assert 0 < read_booted_at() <= time.time()


def test_a_guard_refuses_to_start_without_a_boot_id(tmp_path: Path):
    def broken() -> str:
        raise BootError("no boot id")

    with pytest.raises(BootError, match="no boot id"):
        BootGuard(None, read_boot_id=broken, read_booted_at=lambda: BOOTED_AT)
    with pytest.raises(BootError, match="no boot id"):
        BootGuard(None, read_boot_id=lambda: "junk", read_booted_at=lambda: BOOTED_AT)
    with pytest.raises(BootError, match="no time"):
        BootGuard(None, read_boot_id=_BootIds(), read_booted_at=lambda: True)


def test_the_sandbox_api_requires_a_boot_guard(tmp_path: Path):
    with pytest.raises(ValueError, match="boot guard"):
        TeeBoxSandboxApi(
            executor=FakeExecutor(),
            authorizer=_authorizer(tmp_path, _binding()),
            egress=build_egress_policy([BOX_IP]),
            capacity=CAPACITY,
            default_shape=DEFAULT_SHAPE,
            boot=None,
        )


def test_the_record_sits_beside_the_central_state():
    assert marker_path_for("/run/cathedral-tee-box/central.sqlite") == (
        "/run/cathedral-tee-box/central.sqlite.boot"
    )


# -- one customer per boot --------------------------------------------------


def test_a_second_customer_is_refused_after_the_first_lease_ends(box):
    api, fake, clock, _boot_ids, _marker = box
    assert _lease(api)[0] == 200
    sid = _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 600},
    )[1]["id"]
    # While the lease is live the answer stays box_busy.
    assert _lease(api, OTHER)[1]["reason"] == "box_busy"
    clock.value += 10.25
    assert _handle(api, "DELETE", "/v1/lease")[1] == {
        "released": True,
        "draining": False,
        "needs_relaunch": True,
    }
    assert fake.deleted == [sid]
    for caller in (OTHER, THIRD):
        assert _relaunch_required(api, caller)
        # Sandbox routes answer the same, not lease_required.
        status, body = _handle(api, "GET", "/v1/sandboxes", caller)
        assert (status, body["reason"]) == (409, "relaunch_required")
    # Time passing does not help: only a relaunch does.
    clock.value += 30 * 24 * 3600
    _push_revocations(api)
    assert _relaunch_required(api)


def test_the_same_customer_may_lease_again_without_a_relaunch(box):
    api, _fake, clock, boot_ids, _marker = box
    first_boot = boot_ids.value
    assert _lease(api)[0] == 200
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    clock.value += 5
    status, lease = _lease(api)
    assert status == 200 and lease["lease"]["holder"] == CALLER
    assert lease["lease"]["acquired_at"] == int(clock.value)
    assert boot_ids.value == first_boot
    # Still one customer per boot: the other is refused after this lease too.
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    assert _relaunch_required(api)
    assert _lease(api)[0] == 200


def test_needs_relaunch_is_reported_with_the_boot_and_the_release(box):
    api, _fake, clock, boot_ids, _marker = box
    fresh = _boot_view(api)
    assert fresh == {
        "boot_id": boot_ids.value,
        "booted_at": BOOTED_AT,
        "consumed": False,
        "consumed_by_caller": False,
        "needs_relaunch": False,
        "last_released_at": None,
    }
    assert _lease(api)[0] == 200
    leased = _boot_view(api)
    assert (leased["consumed"], leased["consumed_by_caller"], leased["needs_relaunch"]) == (
        True,
        True,
        False,
    )
    assert _boot_view(api, OTHER)["consumed_by_caller"] is False
    clock.value += 7.25
    released_at = clock.value
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    clock.value += 100
    view = _boot_view(api, OTHER)
    assert view["needs_relaunch"] is True and view["consumed"] is True
    assert view["consumed_by_caller"] is False
    # Rounded up, so evidence verified after it is after the release.
    assert view["last_released_at"] == math.ceil(released_at) == int(released_at) + 1
    assert view["boot_id"] == boot_ids.value
    # A new lease by the same customer: no longer waiting for a relaunch.
    assert _lease(api)[0] == 200
    again = _boot_view(api)
    assert again["needs_relaunch"] is False
    assert again["last_released_at"] == math.ceil(released_at)


def test_an_expired_lease_records_the_release(box):
    api, _fake, clock, _boot_ids, _marker = box
    assert _lease(api)[0] == 200
    clock.value += 61
    api.reap()
    view = _boot_view(api, OTHER)
    assert view["needs_relaunch"] is True
    assert view["last_released_at"] == math.ceil(clock.value)
    assert _relaunch_required(api)


def test_a_new_boot_id_clears_the_record(box):
    api, _fake, _clock, boot_ids, _marker = box
    assert _lease(api)[0] == 200
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    old_boot = boot_ids.value
    assert _relaunch_required(api)
    boot_ids.relaunch()
    view = _boot_view(api, OTHER)
    assert view["boot_id"] == boot_ids.value != old_boot
    assert view == {
        "boot_id": boot_ids.value,
        "booted_at": BOOTED_AT,
        "consumed": False,
        "consumed_by_caller": False,
        "needs_relaunch": False,
        "last_released_at": None,
    }
    status, lease = _lease(api, OTHER)
    assert status == 200 and lease["lease"]["holder"] == OTHER
    # The new boot now belongs to OTHER.
    assert _handle(api, "DELETE", "/v1/lease", OTHER)[0] == 200
    assert _relaunch_required(api, CALLER)


# -- the record on tmpfs ----------------------------------------------------


def test_the_record_is_written_before_the_lease_and_owner_only(box):
    api, _fake, clock, boot_ids, marker = box
    assert not marker.exists()
    assert _lease(api)[0] == 200
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    record = json.loads(marker.read_bytes())
    assert record == {
        "schema": MARKER_SCHEMA,
        "boot_id": boot_ids.value,
        "consumed_by": CALLER,
        "consumed_at": clock.value,
        "released_at": None,
    }
    clock.value += 3
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    assert json.loads(marker.read_bytes())["released_at"] == clock.value
    assert [path.name for path in marker.parent.iterdir() if ".tmp-" in path.name] == []


def test_a_restarted_worker_in_the_same_boot_keeps_the_customer(box, tmp_path: Path):
    api, _fake, clock, boot_ids, marker = box
    assert _lease(api)[0] == 200
    # The worker dies with the lease live; its lease table is gone.
    clock.value += 20
    restarted = _restart(tmp_path, clock, boot_ids, marker)
    assert _relaunch_required(restarted, OTHER)
    view = _boot_view(restarted, OTHER)
    assert view["needs_relaunch"] is True
    # Unknown when the old lease ended: no later than the restart.
    assert view["last_released_at"] == math.ceil(clock.value)
    assert _lease(restarted, CALLER)[0] == 200


def test_a_record_from_another_boot_is_ignored(box, tmp_path: Path):
    api, _fake, clock, boot_ids, marker = box
    assert _lease(api)[0] == 200
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    assert marker.exists()
    # A relaunch whose tmpfs somehow kept the file: the boot id differs.
    boot_ids.relaunch()
    restarted = _restart(tmp_path, clock, boot_ids, marker)
    assert restarted.boot.record.consumed_by is None  # dropped on load, not only on use
    assert _boot_view(restarted, OTHER)["consumed"] is False
    assert _lease(restarted, OTHER)[0] == 200
    assert json.loads(marker.read_bytes())["boot_id"] == boot_ids.value


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{not json",
        b"[]",
        json.dumps({"schema": "other", "boot_id": BOOT_ID_ALT}).encode(),
        json.dumps(
            {
                "schema": MARKER_SCHEMA,
                "boot_id": BOOT_ID_ALT,
                "consumed_by": 7,
                "consumed_at": None,
                "released_at": None,
            }
        ).encode(),
        json.dumps(
            {
                "schema": MARKER_SCHEMA,
                "boot_id": BOOT_ID_ALT,
                "consumed_by": None,
                "consumed_at": None,
                "released_at": "soon",
            }
        ).encode(),
        b" " * 5000,
    ],
)
def test_an_unreadable_record_refuses_every_customer(tmp_path: Path, content):
    marker = tmp_path / "central.sqlite.boot"
    marker.write_bytes(content)
    boot_ids = _BootIds()
    boot_ids.value = BOOT_ID_ALT
    api = _restart(tmp_path, _Clock(), boot_ids, marker)
    assert api.boot.record.consumed_by == UNKNOWN_CONSUMER
    for caller in (CALLER, OTHER):
        assert _relaunch_required(api, caller)
    assert _boot_view(api)["needs_relaunch"] is True


def test_a_symlinked_record_refuses_every_customer(tmp_path: Path):
    marker = tmp_path / "central.sqlite.boot"
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    marker.symlink_to(target)
    api = _restart(tmp_path, _Clock(), _BootIds(), marker)
    assert _relaunch_required(api, CALLER) and _relaunch_required(api, OTHER)


def test_a_record_that_cannot_be_written_refuses_the_lease(box):
    api, _fake, _clock, _boot_ids, marker = box
    marker.mkdir()  # os.replace onto a directory fails
    status, body = _lease(api)
    assert (status, body["reason"]) == (503, "boot_record_unavailable")
    assert api.lease.current() is None
    assert api.boot.record.consumed_by is None
    # Nothing was granted, so nothing was consumed: any customer may try again.
    marker.rmdir()
    assert _lease(api, OTHER)[0] == 200
    assert api.boot.record.consumed_by == OTHER


def test_a_boot_id_that_can_no_longer_be_read_refuses_new_leases(box):
    api, _fake, _clock, boot_ids, _marker = box
    boot_ids.value = "unreadable"
    assert _relaunch_required(api, CALLER) and _relaunch_required(api, OTHER)
    assert _boot_view(api) == {
        "boot_id": None,
        "booted_at": None,
        "consumed": True,
        "consumed_by_caller": False,
        "needs_relaunch": True,
        "last_released_at": None,
    }


def test_a_live_lease_renews_even_when_the_boot_id_is_unreadable(box):
    # Renewal is not a new customer; the check guards new grants only.
    api, _fake, _clock, boot_ids, _marker = box
    assert _lease(api)[0] == 200
    boot_ids.value = "unreadable"
    assert _lease(api)[0] == 200
    with pytest.raises(RelaunchRequired):
        api.boot.check(CALLER)


def test_the_create_path_under_the_lease_lock_refuses_the_same_way(box):
    api, _fake, _clock, _boot_ids, _marker = box
    assert _lease(api)[0] == 200
    assert _handle(api, "DELETE", "/v1/lease")[0] == 200
    with api.lease.locked():
        with pytest.raises(RelaunchRequired):
            api.lease.require_locked(OTHER)
    with pytest.raises(RelaunchRequired):
        api.lease.require(OTHER)
