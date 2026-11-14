"""A room that ends keeps no exec results, and a room made again under its id never gets the old room's (AB#384).

The front keeps the answer of an exec that carries X-Room-Exec-Handle and serves it back by handle. A signed delete
forgets the room's results; so must a room_end. Each result belongs to the incarnation of the room that ran it.
"""
from __future__ import annotations

import json
import threading

import pytest
from room_front_support import Front, assert_idle, finish, in_thread, receipt_of, rr

ROOM = "sbx_same"
OLD, NEW = "a" * 32, "b" * 32


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def exec_with(front: Front, handle: str, cmd: str = "true"):
    return front.call("POST", f"/v1/sandboxes/{ROOM}/exec", {"cmd": [cmd]}, headers={"X-Room-Exec-Handle": handle})


def result(front: Front, handle: str, method: str = "GET"):
    return front.call(method, f"/v1/sandboxes/{ROOM}/exec/result?handle={handle}")


def code(out: bytes) -> str:
    return json.loads(out)["error"]["code"]


def hold_retire(monkeypatch):
    entered, release, real, first = threading.Event(), threading.Event(), rr.retire_room, []

    def slow(*args, **kwargs):
        if not first:
            first.append(1)
            entered.set()
            assert release.wait(30)
        return real(*args, **kwargs)

    monkeypatch.setattr(rr, "retire_room", slow)
    return entered, release


def test_a_kept_result_is_served_while_the_room_lives(front) -> None:
    front.api.new_ids = [ROOM]
    assert front.create()[0] == 200
    assert exec_with(front, OLD)[0] == 200
    status, headers, _out = result(front, OLD)
    assert status == 200 and headers["X-Room-Exec-State"] == "done"


def test_a_room_that_ends_without_a_request_answers_exec_unknown_for_its_old_handle(front) -> None:
    front.api.new_ids = [ROOM]
    assert front.create()[0] == 200
    assert exec_with(front, OLD)[0] == 200
    front.api.rooms.discard(ROOM)  # reaped
    front.server.look_all()
    assert front.ledger.room_incarnation(ROOM) is None
    status, _headers, out = result(front, OLD)
    assert status == 404 and code(out) == "exec_unknown"
    status, _headers, out = result(front, OLD, "DELETE")
    assert status == 404 and code(out) == "exec_unknown"
    assert not front.server.exec_results.entries, "the ended room's results were kept"
    assert_idle(front.ledger)


def test_a_signed_delete_forgets_the_rooms_results_as_before(front) -> None:
    front.api.new_ids = [ROOM]
    assert front.create()[0] == 200
    assert exec_with(front, OLD)[0] == 200
    assert front.delete(ROOM)[0] == 200
    status, _headers, out = result(front, OLD)
    assert status == 404 and code(out) == "exec_unknown"
    assert not front.server.exec_results.entries
    assert_idle(front.ledger)


def test_a_room_made_again_keeps_its_results_when_the_old_retirement_runs_late(front, monkeypatch) -> None:
    front.api.new_ids = [ROOM, ROOM]
    assert front.create()[0] == 200
    assert exec_with(front, OLD)[0] == 200
    front.api.rooms.discard(ROOM)
    entered, release = hold_retire(monkeypatch)
    t, box = in_thread(front.server.look_all)  # room_end is signed, its retirement waits
    assert entered.wait(10)
    assert front.create()[0] == 200  # the same id answered again: a new incarnation
    assert exec_with(front, NEW, "second")[0] == 200
    # Before the old retirement has run, the old room's result is not served to the new room.
    status, _headers, out = result(front, OLD)
    assert status == 404 and code(out) == "exec_unknown"
    release.set()
    finish(t, box)
    status, headers, _out = result(front, NEW)
    assert status == 200 and headers["X-Room-Exec-State"] == "done", "the new room lost its own result"
    status, _headers, out = result(front, OLD)
    assert status == 404 and code(out) == "exec_unknown"
    assert_idle(front.ledger)


def test_a_signed_delete_that_retires_late_keeps_the_new_rooms_results(front, monkeypatch) -> None:
    front.api.new_ids = [ROOM, ROOM]
    assert front.create()[0] == 200
    assert exec_with(front, OLD)[0] == 200
    entered, release = hold_retire(monkeypatch)
    d, dbox = in_thread(front.delete, ROOM)
    assert entered.wait(10)
    assert front.create()[0] == 200
    assert exec_with(front, NEW, "second")[0] == 200
    release.set()
    assert finish(d, dbox)[0] == 200
    assert result(front, NEW)[0] == 200
    assert result(front, OLD)[0] == 404
    assert_idle(front.ledger)
