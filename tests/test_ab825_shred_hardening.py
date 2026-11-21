"""AB#825: shred hardening at the registry contract.

One key id binds one volume, forever; only the owner shreds; destroy_key runs
off the registry lock with a bounded wait, so a hung key service blocks no
other volume.
"""
from __future__ import annotations

import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral import volume_chain as vc
from cathedral import volume_log as vl

T0 = 1_800_000_000
SHORT = 0.2  # seconds shred waits on a blocked key service in these tests
DEADLINE = 5.0  # seconds a test waits for a worker thread to finish


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def binding(key: Ed25519PrivateKey) -> dict:
    return {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": "hotel-a", "boot_id": "b1",
            "receipt_key_ed25519_b64": vc.public_b64(key), "measurement": "aa" * 48}


def refused(code: str, fn, *args, **kwargs):
    with pytest.raises(vc.VolumeRefused) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code


def log_keys(registry) -> dict[str, bytes]:
    return {registry.log_signing_key_id: registry.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}


class KeyService:
    def __init__(self, result=True):
        self.calls: list[str] = []
        self.result = result

    def __call__(self, volume_id: str, key_id: str):
        self.calls.append(key_id)
        return self.result


class BlockedKeyService:
    """destroy_key that blocks until released, then reports the key destroyed."""

    def __init__(self):
        self.release = threading.Event()
        self.started = threading.Event()
        self.calls: list[str] = []

    def __call__(self, volume_id: str, key_id: str):
        self.calls.append(key_id)
        self.started.set()
        self.release.wait(DEADLINE)
        return True


@pytest.fixture
def registry():
    return vc.VolumeRegistry(Ed25519PrivateKey.generate(), now=Clock(), lease_seconds=600)


def live_volume(registry, volume_id: str, owner: str, *, snapshots=("s1",)):
    """Create a volume keyed vk:<volume_id>, lease it and commit the snapshots. Returns (holder, lease)."""
    registry.create(volume_id, owner, key_id="vk:" + volume_id)
    holder = Ed25519PrivateKey.generate()
    lease = registry.grant(volume_id, binding(holder))
    for snapshot in snapshots:
        commit_next(registry, volume_id, holder, lease, snapshot)
    return holder, lease


def commit_next(registry, volume_id: str, holder, lease, snapshot: str) -> dict:
    head = registry.head(volume_id)["statement"]
    return registry.accept(vc.make_commit(holder, lease, generation=head["generation"] + 1,
                                          parent_sha256=head["head_sha256"], restic_repo_id="repo-" + volume_id,
                                          restic_snapshot_id=snapshot))


def wait_until_not_in_progress(registry, volume_id: str):
    deadline = time.monotonic() + DEADLINE
    while registry.volumes[volume_id].shred_in_flight:
        assert time.monotonic() < deadline, "destroy_key worker did not finish"
        time.sleep(0.01)


# --- one key, one volume ------------------------------------------------------


def test_create_with_a_key_bound_to_another_volume_is_refused(registry):
    registry.create("vol-1", "customer-1", key_id="k1")
    refused("key_bound_elsewhere", registry.create, "vol-2", "customer-2", key_id="k1")
    refused("volume_unknown", registry.volume, "vol-2")
    assert registry.key_volumes == {"k1": "vol-1"}


def test_duplicate_create_is_volume_exists_not_key_bound_elsewhere(registry):
    registry.create("vol-1", "customer-1", key_id="k1")
    refused("volume_exists", registry.create, "vol-1", "customer-1", key_id="k1")


def test_bind_key_of_another_volumes_key_is_refused(registry):
    registry.create("vol-1", "customer-1", key_id="k1")
    registry.create("vol-2", "customer-2")
    refused("key_bound_elsewhere", registry.bind_key, "vol-2", "k1")
    assert registry.volumes["vol-2"].key_id is None
    registry.bind_key("vol-2", "k2")
    registry.bind_key("vol-2", "k2")  # same key on the same volume stays a no-op
    registry.bind_key("vol-1", "k1")
    refused("key_already_bound", registry.bind_key, "vol-2", "k3")
    refused("key_bound_elsewhere", registry.create, "vol-3", "customer-3", key_id="k2")
    assert registry.key_volumes == {"k1": "vol-1", "k2": "vol-2"}


def test_a_shredded_volumes_key_is_never_bound_again(registry):
    live_volume(registry, "vol-1", "customer-1")
    registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=KeyService())
    refused("key_bound_elsewhere", registry.create, "vol-2", "customer-1", key_id="vk:vol-1")
    registry.create("vol-3", "customer-1")
    refused("key_bound_elsewhere", registry.bind_key, "vol-3", "vk:vol-1")
    assert registry.key_volumes == {"vk:vol-1": "vol-1"}


# --- owner check --------------------------------------------------------------


def test_wrong_owner_is_refused_before_the_key_is_touched(registry):
    live_volume(registry, "vol-1", "customer-1")
    keys = KeyService()
    before = registry.log_entries()
    for owner in ("customer-2", "", None, "Customer-1"):
        refused("not_owner", registry.shred, "vol-1", owner=owner, key_id="vk:vol-1", destroy_key=keys)
    # The wrong owner learns nothing about the volume's state, not even a bad key id.
    refused("not_owner", registry.shred, "vol-1", owner="customer-2", key_id="k/1", destroy_key=keys)
    assert keys.calls == []
    assert registry.log_entries() == before
    assert registry.head("vol-1")["statement"]["generation"] == 1  # not frozen


def test_wrong_owner_is_refused_on_the_resend_path(registry):
    live_volume(registry, "vol-1", "customer-1")
    receipt = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=KeyService())
    log = registry.log_entries()
    keys = KeyService()
    refused("not_owner", registry.shred, "vol-1", owner="customer-2", key_id="vk:vol-1", destroy_key=keys)
    refused("not_owner", registry.shred, "vol-1", owner="customer-2", key_id="vk:other", destroy_key=keys)
    assert registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=keys) == receipt
    assert keys.calls == []
    assert registry.log_entries() == log


def test_wrong_owner_is_refused_while_pending(registry):
    live_volume(registry, "vol-1", "customer-1")
    refused("key_not_destroyed", registry.shred, "vol-1", owner="customer-1", key_id="vk:vol-1",
            destroy_key=KeyService(result=False))
    keys = KeyService()
    refused("not_owner", registry.shred, "vol-1", owner="customer-2", key_id="vk:vol-1", destroy_key=keys)
    assert keys.calls == []
    refused("shred_pending", registry.head, "vol-1")


def test_unknown_volume_comes_before_owner(registry):
    refused("volume_unknown", registry.shred, "vol-9", owner="customer-1", key_id="vk:vol-9",
            destroy_key=KeyService())


# --- bounded destroy_key, lock not held ---------------------------------------


def test_blocked_key_service_times_out_then_a_retry_finishes(registry):
    live_volume(registry, "vol-1", "customer-1")
    blocked = BlockedKeyService()
    before = registry.log_entries()
    started = time.monotonic()
    refused("key_service_timeout", registry.shred, "vol-1", owner="customer-1", key_id="vk:vol-1",
            destroy_key=blocked, timeout_seconds=SHORT)
    assert time.monotonic() - started < SHORT + 2.0
    assert registry.log_entries() == before
    refused("shred_pending", registry.head, "vol-1")
    # The worker is still blocked: a second shred does not start another.
    second = KeyService()
    refused("shred_in_progress", registry.shred, "vol-1", owner="customer-1", key_id="vk:vol-1",
            destroy_key=second)
    assert second.calls == []
    blocked.release.set()
    wait_until_not_in_progress(registry, "vol-1")
    # The late True from the timed-out worker logged nothing; the retry finishes the shred.
    assert registry.log_entries() == before
    retry = KeyService()
    receipt = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=retry)
    assert retry.calls == ["vk:vol-1"]
    vl.verify_shred_receipt(receipt, public_keys_by_id=log_keys(registry), entries=registry.log_entries())
    assert receipt["final_generation"] == 1


def test_other_volumes_work_while_a_shred_waits(registry):
    live_volume(registry, "vol-1", "customer-1")
    holder2, lease2 = live_volume(registry, "vol-2", "customer-2")
    blocked = BlockedKeyService()
    result: dict = {}

    def shred_vol_1():
        try:
            result["receipt"] = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1",
                                               destroy_key=blocked, timeout_seconds=DEADLINE)
        except vc.VolumeRefused as refusal:
            result["refused"] = refusal.code

    waiter = threading.Thread(target=shred_vol_1)
    waiter.start()
    try:
        assert blocked.started.wait(DEADLINE)
        # destroy_key for vol-1 is running: the registry lock is free for vol-2.
        new_head = commit_next(registry, "vol-2", holder2, lease2, "t2")
        assert registry.head("vol-2") == new_head
        assert new_head["statement"]["generation"] == 2
    finally:
        blocked.release.set()
        waiter.join(DEADLINE)
    assert not waiter.is_alive()
    assert "refused" not in result
    log = registry.log_entries()
    receipt = result["receipt"]
    vl.verify_shred_receipt(receipt, public_keys_by_id=log_keys(registry), entries=log)
    vol_2_head = max(e["seq"] for e in log if e["volume_id"] == "vol-2" and e["generation"] == 2)
    shred_entry = next(e for e in log if e["kind"] == vl.KIND_SHRED)
    assert shred_entry["volume_id"] == "vol-1"
    assert shred_entry["seq"] > vol_2_head
    assert receipt["log_entry_sha256"] == vl.entry_sha256(shred_entry)


def test_resend_right_after_success_gets_the_receipt(registry):
    live_volume(registry, "vol-1", "customer-1")
    receipt = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=KeyService())
    keys = KeyService()
    assert registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=keys) == receipt
    refused("volume_shredded", registry.shred, "vol-1", owner="customer-1", key_id="vk:other", destroy_key=keys)
    assert keys.calls == []


def test_immediate_retry_after_refusal_is_not_in_progress(registry):
    # The worker clears in_flight before waking the caller, so a retry never races it.
    for attempt in range(50):
        volume_id = f"vol-{attempt}"
        live_volume(registry, volume_id, "customer-1")
        refused("key_not_destroyed", registry.shred, volume_id, owner="customer-1", key_id="vk:" + volume_id,
                destroy_key=KeyService(result=False))
        receipt = registry.shred(volume_id, owner="customer-1", key_id="vk:" + volume_id,
                                 destroy_key=KeyService())
        assert receipt["volume_id"] == volume_id


def test_late_worker_after_the_shred_committed_gets_the_stored_receipt(registry):
    # Caller A's worker returned True and cleared in_flight; before A took the lock
    # again, caller B started its own worker. A commits first; B's worker then also
    # returns True and B must get A's receipt, never log_refused.
    live_volume(registry, "vol-1", "customer-1")
    hold = threading.Event()
    entered = threading.Event()
    results: dict[str, object] = {}

    def slow(volume_id, key_id):
        entered.set()
        hold.wait(DEADLINE)
        return True

    def caller_b():
        results["b"] = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=slow,
                                      timeout_seconds=DEADLINE)

    # Make vol-1 pending and not in flight, then start B's worker and finish the shred under it.
    refused("key_not_destroyed", registry.shred, "vol-1", owner="customer-1", key_id="vk:vol-1",
            destroy_key=KeyService(result=False))
    b = threading.Thread(target=caller_b)
    b.start()
    try:
        assert entered.wait(DEADLINE)
        volume = registry.volumes["vol-1"]
        # A's worker returned True and cleared in_flight before B started; simulate A committing now.
        with registry.lock:
            volume.shred_in_flight = False
        receipt = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=KeyService())
    finally:
        hold.set()
        b.join(DEADLINE)
    assert results["b"] == receipt
    assert [e["kind"] for e in registry.log_entries()].count(vl.KIND_SHRED) == 1


def test_thread_start_failure_clears_in_flight(registry, monkeypatch):
    live_volume(registry, "vol-1", "customer-1")

    def refuse_start(self):
        raise RuntimeError("can't start new thread")

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", refuse_start)
        refused("key_not_destroyed", registry.shred, "vol-1", owner="customer-1", key_id="vk:vol-1",
                destroy_key=KeyService())
    assert registry.volumes["vol-1"].shred_in_flight is False
    receipt = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=KeyService())
    assert receipt["key_id"] == "vk:vol-1"


@pytest.mark.parametrize("timeout", [0, -1, 61, 60.5, 0.05, True, False, "10", None, float("nan")])
def test_bad_timeout_changes_nothing(registry, timeout):
    live_volume(registry, "vol-1", "customer-1")
    keys = KeyService()
    before = registry.log_entries()
    refused("bad_timeout", registry.shred, "vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=keys,
            timeout_seconds=timeout)
    # Checked before any lookup: an unknown volume or a wrong owner still says bad_timeout.
    refused("bad_timeout", registry.shred, "vol-9", owner="nobody", key_id="vk:vol-1", destroy_key=keys,
            timeout_seconds=timeout)
    assert keys.calls == []
    assert registry.log_entries() == before
    assert registry.head("vol-1")["statement"]["generation"] == 1


@pytest.mark.parametrize("timeout", [0.1, 1, 60])
def test_timeout_bounds_are_accepted(registry, timeout):
    live_volume(registry, "vol-1", "customer-1")
    receipt = registry.shred("vol-1", owner="customer-1", key_id="vk:vol-1", destroy_key=KeyService(),
                             timeout_seconds=timeout)
    assert receipt["key_id"] == "vk:vol-1"
