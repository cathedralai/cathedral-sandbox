"""A receipt when a room ends without a request (AB#384).

The front finds out by looking: a copy of its live-room table, then the API's list, then one GET
for each room the list lacks. A room the API answers 404 sandbox_not_found or 409 sandbox_deleting
for gets one `room_end` receipt, which ends its incarnation exactly as a delete does. A room with a
request in flight is never ended, and a room made after the table was copied is never ended.
"""
from __future__ import annotations

import json
import threading
import time

import pytest
from room_front_support import Front, assert_idle, finish, in_thread, receipt_of

SERIAL = {"image": "repo/app:1", "labels": {"cathedral_serial": "1"}}


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


class Retired:
    def __init__(self) -> None:
        self.rooms: list[str] = []

    def retire(self, room: str) -> None:
        self.rooms.append(room)


def make_room(front: Front) -> tuple[str, str]:
    status, headers, out = front.create()
    assert status == 200
    return json.loads(out)["id"], receipt_of(headers)["receipt_sha256"]


def ends(front: Front, room: str) -> list[dict]:
    return [s for s in front.statements(room) if s["action"] == "room_end"]


def test_a_room_the_api_no_longer_lists_gets_one_end_receipt(front) -> None:
    front.ledger.secrets, front.ledger.sealed_exec = Retired(), Retired()
    room, create_sha = make_room(front)
    front.exec(room)
    front.api.rooms.discard(room)  # the reaper removed it
    front.server.look_all()
    (end,) = ends(front, room)
    assert end["target"] is None and end["sandbox_id"] == room
    assert end["room_create_receipt_sha256"] == create_sha
    assert end["status"] == 404 and end["reason"] == "sandbox_not_found" and end["room_sequence"] == 3
    assert len(end["result_sha256"]) == 64
    assert front.ledger.room_incarnation(room) is None
    assert front.ledger.secrets.rooms == [room] and front.ledger.sealed_exec.rooms == [room]
    front.server.look_all()
    assert len(ends(front, room)) == 1  # one end per room
    assert_idle(front.ledger)


def test_a_room_end_drops_the_serial_mark(front) -> None:
    status, _headers, out = front.create(SERIAL)
    room = json.loads(out)["id"]
    assert room in front.ledger.serial
    front.api.rooms.discard(room)
    front.server.look_all()
    assert room not in front.ledger.serial and room not in front.ledger.broken
    assert_idle(front.ledger)


def test_an_api_restart_ends_every_room(front) -> None:
    rooms = [make_room(front)[0] for _ in range(3)]
    front.api.rooms.clear()
    front.server.look_all()
    assert all(len(ends(front, r)) == 1 for r in rooms)


def test_a_bulk_delete_of_three_rooms_ends_each_at_the_next_look(front) -> None:
    rooms = [make_room(front)[0] for _ in range(3)]
    keep, _sha = make_room(front)
    status, headers, _out = front.call("DELETE", "/v1/sandboxes?label=x%3D1")
    assert status == 200 and receipt_of(headers)["statement"]["sandbox_id"] is None
    front.api.rooms.difference_update(rooms)
    front.server.look_all()
    assert [len(ends(front, r)) for r in rooms] == [1, 1, 1]
    assert ends(front, keep) == []


def test_a_delete_whose_answer_was_lost_is_ended_at_the_next_look(front) -> None:
    room, _sha = make_room(front)
    front.api.drop(rf"DELETE /v1/sandboxes/{room}")
    status, headers, _out = front.delete(room)
    assert status == 502
    front.api.rooms.discard(room)  # the delete ran
    front.server.look_all()
    actions = [(s["action"], s["status"]) for s in front.statements(room)]
    assert actions == [("create", 200), ("delete", 502), ("room_end", 404)]
    assert_idle(front.ledger)


def test_a_listed_room_is_kept(front) -> None:
    room, _sha = make_room(front)
    front.server.look_all()
    assert ends(front, room) == []
    assert front.ledger.room_incarnation(room) is not None


def test_a_room_missing_from_the_list_but_answered_200_is_kept(front) -> None:
    room, _sha = make_room(front)
    front.api.list_body = json.dumps({"sandboxes": []}).encode()
    front.server.look_all()
    assert ends(front, room) == []


@pytest.mark.parametrize("failure", ["list_500", "list_garbage", "list_shape", "get_503", "get_404_other",
                                     "get_409_other", "get_200"])
def test_a_failed_look_ends_nothing(front, failure) -> None:
    room, _sha = make_room(front)
    front.api.rooms.discard(room)
    if failure == "list_500":
        front.api.list_status = 500
    elif failure == "list_garbage":
        front.api.list_body = b"not json"
    elif failure == "list_shape":
        front.api.list_body = b'{"sandboxes": [1, 2]}'
    elif failure == "get_503":
        front.api.get_replies[room] = (503, b'{"error":{"code":"sandbox_not_found"}}')
    elif failure == "get_404_other":
        front.api.get_replies[room] = (404, b'{"error":{"code":"route_not_found"}}')
    elif failure == "get_409_other":
        front.api.get_replies[room] = (409, b'{"error":{"code":"sandbox_frozen"}}')
    else:
        front.api.get_replies[room] = (200, b'{"id":"x"}')
    front.server.look_all()
    assert ends(front, room) == []
    assert front.ledger.room_incarnation(room) is not None


def test_a_room_the_api_says_is_deleting_is_ended_with_that_reason(front) -> None:
    room, _sha = make_room(front)
    front.api.rooms.discard(room)
    front.api.get_replies[room] = (409, b'{"error":{"code":"sandbox_deleting"}}')
    front.server.look_all()
    (end,) = ends(front, room)
    assert end["status"] == 409 and end["reason"] == "sandbox_deleting"


def test_a_read_of_one_rooms_receipts_looks_first(front) -> None:
    room, _sha = make_room(front)
    front.api.rooms.discard(room)
    assert [s["action"] for s in front.statements(room)] == ["create", "room_end"]
    # One GET of that room, no list.
    assert front.api.count(r"GET /v1/sandboxes") == 0
    assert front.api.count(rf"GET /v1/sandboxes/{room}") == 1


def test_a_receipts_read_of_a_live_room_changes_nothing(front) -> None:
    room, _sha = make_room(front)
    assert [s["action"] for s in front.statements(room)] == ["create"]
    assert front.api.count(rf"GET /v1/sandboxes/{room}") == 1


def test_a_room_end_never_lands_inside_a_turn(front) -> None:
    status, _headers, out = front.create(SERIAL)
    room = json.loads(out)["id"]
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    t, box = in_thread(front.exec, room)
    held.wait_entered()
    front.api.rooms.discard(room)
    front.server.look_all()
    assert ends(front, room) == [], "the room was ended while a request was in flight"
    held.release.set()
    finish(t, box)
    assert_idle(front.ledger)
    front.server.look_all()
    assert len(ends(front, room)) == 1


# ---------------------------------------------------------------- real threads against a held API

def test_a_room_created_while_the_list_is_on_its_way_is_not_ended(front) -> None:
    old, _sha = make_room(front)
    front.api.rooms.discard(old)
    held = front.api.hold(r"GET /v1/sandboxes")
    t, box = in_thread(front.server.look_all)
    held.wait_entered()
    new, _sha = make_room(front)  # lands after the copy, and the list was read before it
    held.release.set()
    finish(t, box)
    assert len(ends(front, old)) == 1 and ends(front, new) == []
    assert front.ledger.room_incarnation(new) is not None
    assert_idle(front.ledger)


def test_a_delete_in_flight_during_a_look_is_not_ended_by_it(front) -> None:
    room, _sha = make_room(front)
    front.api.list_body = json.dumps({"sandboxes": []}).encode()  # deleting rooms are hidden from the list
    front.api.get_replies[room] = (409, b'{"error":{"code":"sandbox_deleting"}}')
    held = front.api.hold(rf"DELETE /v1/sandboxes/{room}")
    d, dbox = in_thread(front.delete, room)
    held.wait_entered()
    front.server.look_all()
    assert ends(front, room) == []
    held.release.set()
    assert finish(d, dbox)[0] == 200
    front.server.look_all()
    assert [s["action"] for s in front.statements(room)] == ["create", "delete"]
    assert_idle(front.ledger)


def test_two_looks_on_a_held_list_sign_one_end(front) -> None:
    room, _sha = make_room(front)
    front.api.rooms.discard(room)
    held = front.api.hold(r"GET /v1/sandboxes")
    a, abox = in_thread(front.server.look_all)
    b, bbox = in_thread(front.server.look_all)
    held.wait_entered()
    deadline = time.time() + 10
    while front.api.count(r"GET /v1/sandboxes") < 2 and time.time() < deadline:
        time.sleep(0.01)
    held.release.set()
    finish(a, abox)
    finish(b, bbox)
    assert len(ends(front, room)) == 1
    assert_idle(front.ledger)


def test_a_room_made_again_between_the_copy_and_the_end_is_not_ended(front) -> None:
    front.api.new_ids = ["sbx_again", "sbx_again"]
    room, _sha = make_room(front)
    front.api.rooms.discard(room)
    held = front.api.hold(r"GET /v1/sandboxes")
    t, box = in_thread(front.server.look_all)
    held.wait_entered()
    front.delete(room)
    again, _sha = make_room(front)
    assert again == room
    front.api.get_replies[room] = (404, b'{"error":{"code":"sandbox_not_found"}}')
    held.release.set()
    finish(t, box)
    assert ends(front, room) == [], "an earlier incarnation's look ended the new room"
    assert front.ledger.room_incarnation(room) is not None
    assert_idle(front.ledger)


# ---------------------------------------------------------------- the loop

def test_the_loop_ends_a_reaped_room_and_stops_with_the_server(tmp_path, monkeypatch) -> None:
    f = Front(tmp_path, monkeypatch, look_seconds=0.05)
    try:
        room, _sha = make_room(f)
        f.api.rooms.discard(room)
        deadline = time.time() + 10
        while time.time() < deadline and f.ledger.room_incarnation(room) is not None:
            time.sleep(0.02)
        assert f.ledger.room_incarnation(room) is None
        thread = f.server.look_thread
    finally:
        f.close()
    thread.join(5)
    assert not thread.is_alive()


def test_the_loop_is_off_unless_asked_for(front) -> None:
    assert front.server.look_thread is None
    assert not any(t.name == "room-look" for t in threading.enumerate())
