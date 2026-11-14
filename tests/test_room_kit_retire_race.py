"""A room made again under the same id keeps what the front holds for its new incarnation (AB#384).

The API answers a repeated create (same Idempotency-Key) with the room it recorded, so the front can sign a new
create receipt for an id whose delete or room_end it signed a moment before. What the delete or room_end
retires belongs to the old incarnation only.
"""
from __future__ import annotations

import json
import threading

import pytest
from room_front_support import Front, assert_idle, finish, in_thread, receipt_of, rr

ROOM = "sbx_same"


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    root = tmp_path / "secrets-root"
    root.mkdir()
    f.ledger.secrets, f.ledger.sealed_exec, f.ledger.sealed_env = rr.SealedSecrets(str(root)), rr.SealedExec(), rr.SealedEnv()
    f.secrets_root = root
    yield f
    f.close()


def plant(front: Front, incarnation: str) -> None:
    """What the three stores hold for a room's incarnation after a write, a sealed exec and an env set."""
    ledger = front.ledger
    (front.secrets_root / ROOM).mkdir(exist_ok=True)
    (front.secrets_root / ROOM / "TOKEN").write_bytes(b"x")
    with ledger.secrets.lock:
        ledger.secrets.record(ROOM, incarnation, "TOKEN", rr.AcceptedSecret(1, "e" * 64, "k", None))
    with ledger.sealed_exec.lock:
        ledger.sealed_exec.rooms[ROOM] = (incarnation, {"replay-key": 1})
    with ledger.sealed_env.lock:
        ledger.sealed_env.rooms[ROOM] = (incarnation, rr.AcceptedEnv(1, "e" * 64, "k", ["A"], None))


def held(front: Front, incarnation: str) -> dict:
    ledger = front.ledger
    return {
        "secret_entry": ledger.secrets.rooms.get(ROOM, (None,))[0] == incarnation,
        "secret_file": (front.secrets_root / ROOM / "TOKEN").exists(),
        "exec_entry": ledger.sealed_exec.rooms.get(ROOM, (None,))[0] == incarnation,
        "env_entry": ledger.sealed_env.rooms.get(ROOM, (None,))[0] == incarnation,
    }


def hold_retire(monkeypatch):
    """Make the first retire_room call wait after the ending receipt is signed and before it runs."""
    entered, release, real = threading.Event(), threading.Event(), rr.retire_room
    first = []

    def slow(ledger, room):
        if not first:
            first.append(1)
            entered.set()
            assert release.wait(30)
        return real(ledger, room)

    monkeypatch.setattr(rr, "retire_room", slow)
    return entered, release


def test_a_delete_does_not_retire_a_room_made_again_while_it_waited(front, monkeypatch) -> None:
    front.api.new_ids = [ROOM, ROOM]
    assert front.create()[0] == 200
    entered, release = hold_retire(monkeypatch)
    d, dbox = in_thread(front.delete, ROOM)
    assert entered.wait(10)
    status, headers, _out = front.create()  # the same id answered again
    assert status == 200
    new = receipt_of(headers)["receipt_sha256"]
    assert front.ledger.room_incarnation(ROOM) == new
    plant(front, new)
    release.set()
    assert finish(d, dbox)[0] == 200
    assert held(front, new) == {"secret_entry": True, "secret_file": True, "exec_entry": True, "env_entry": True}
    assert_idle(front.ledger)


def test_a_room_end_does_not_retire_a_room_made_again_while_it_waited(front, monkeypatch) -> None:
    front.api.new_ids = [ROOM, ROOM]
    assert front.create()[0] == 200
    front.api.rooms.discard(ROOM)  # reaped
    entered, release = hold_retire(monkeypatch)
    t, box = in_thread(front.server.look_all)
    assert entered.wait(10)
    status, headers, _out = front.create()
    assert status == 200
    new = receipt_of(headers)["receipt_sha256"]
    plant(front, new)
    release.set()
    finish(t, box)
    assert held(front, new) == {"secret_entry": True, "secret_file": True, "exec_entry": True, "env_entry": True}
    assert_idle(front.ledger)


def test_a_delete_still_retires_the_old_incarnation(front) -> None:
    front.api.new_ids = [ROOM]
    _s, headers, _o = front.create()
    old = receipt_of(headers)["receipt_sha256"]
    plant(front, old)
    assert front.delete(ROOM)[0] == 200
    assert held(front, old) == {"secret_entry": False, "secret_file": False, "exec_entry": False, "env_entry": False}
    assert_idle(front.ledger)


# ---------------------------------------------------------------- where the check sits

STORES = {"secrets": "secrets", "exec": "sealed_exec", "env": "sealed_env"}


def plant_one(front: Front, which: str, incarnation: str) -> None:
    """Plant one store's state for *incarnation* without taking its lock (the caller holds it)."""
    ledger = front.ledger
    if which == "secrets":
        (front.secrets_root / ROOM).mkdir(exist_ok=True)
        (front.secrets_root / ROOM / "TOKEN").write_bytes(b"x")
        ledger.secrets.record(ROOM, incarnation, "TOKEN", rr.AcceptedSecret(1, "e" * 64, "k", None))
    elif which == "exec":
        ledger.sealed_exec.rooms[ROOM] = (incarnation, {"replay-key": 1})
    else:
        ledger.sealed_env.rooms[ROOM] = (incarnation, rr.AcceptedEnv(1, "e" * 64, "k", ["A"], None))


@pytest.mark.parametrize("which", ["secrets", "exec", "env"])
def test_each_stores_retire_asks_for_the_live_incarnation_inside_its_own_lock(front, which) -> None:
    ledger = front.ledger
    front.api.new_ids = [ROOM]
    assert front.create()[0] == 200
    store = getattr(ledger, STORES[which])
    store.lock.acquire()
    try:
        # The delete is signed: the old incarnation is gone. Retire starts, and waits for the store's lock.
        ledger.sign({"action": "delete", "target": f"DELETE /v1/sandboxes/{ROOM}", "sandbox_id": ROOM, "status": 200})
        assert ledger.room_incarnation(ROOM) is None
        t = threading.Thread(target=store.retire, args=(ROOM, ledger.room_incarnation), daemon=True)
        t.start()
        t.join(0.5)
        assert t.is_alive(), "retire did not wait for the store's lock"
        # The same id is made again while retire waits, and the new incarnation's state is in place.
        new = ledger.sign({"action": "create", "target": "POST /v1/sandboxes", "sandbox_id": ROOM,
                           "status": 200})["receipt_sha256"]
        plant_one(front, which, new)
    finally:
        store.lock.release()
    t.join(10)
    assert not t.is_alive()
    assert ledger.room_incarnation(ROOM) == new
    survived = {"secrets": lambda: ledger.secrets.rooms.get(ROOM, (None,))[0] == new
                and (front.secrets_root / ROOM / "TOKEN").exists(),
                "exec": lambda: ledger.sealed_exec.rooms.get(ROOM, (None,))[0] == new,
                "env": lambda: ledger.sealed_env.rooms.get(ROOM, (None,))[0] == new}[which]
    assert survived(), f"the retire that waited for the {which} lock dropped the new incarnation's state"
