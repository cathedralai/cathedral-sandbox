"""A bulk delete whose outcome is not certain, replays of a claim, and the bounds of the wait (AB#535).

A bulk delete picks its targets once, when it starts, and keeps running if the front stops waiting for its answer.
So when a bulk delete ends without a certain answer (the API gave none, or a 5xx), the front cannot vouch for any
pool room it knew: each is marked unknown and no claim on it is signed. A claim already answered is replayed only
while the room is still there.
"""
from __future__ import annotations

import json
import socket
import time

import pytest
from room_front_support import AUTH, Front, assert_idle, finish, in_thread, receipt_of, rr
from test_room_kit_pool_rooms import BULK, CID, POOL_TEAM, claim, code, pool_room

TEAM_A = {"cathedral_pool": "1", "team": "a"}


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def wait_for(predicate, what: str, seconds: float = 10) -> None:
    deadline = time.time() + seconds
    while not predicate() and time.time() < deadline:
        time.sleep(0.01)
    assert predicate(), what


def claims_of(front: Front, room: str) -> list[dict]:
    with front.ledger.lock:
        return [front.ledger.chain[i]["statement"] for i in front.ledger.by_room.get(room, [])
                if front.ledger.chain[i]["statement"]["action"] == "claim"]


def lost_bulk(front: Front):
    """A bulk delete the front gives up on while the API keeps running it. Returns the event that lets it finish."""
    release = front.api.lose_bulk()
    assert front.call("DELETE", BULK)[0] == 502
    return release


# ---------------------------------------------------------------- an uncertain end

def test_a_claim_after_a_bulk_delete_with_no_answer_is_refused_for_a_room_that_existed_before_it(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    release = lost_bulk(front)
    assert_idle(front.ledger)
    status, headers, out = claim(front, "sbx_x")
    assert status == 409 and code(out) == "pool_room_unknown" and "X-Room-Receipt" not in headers
    assert front.api.count(r"POST /v1/sandboxes/sbx_x/lifetime") == 0
    release.set()  # the bulk delete now removes the room
    wait_for(lambda: "sbx_x" not in front.api.rooms, "the still-running bulk delete never removed the room")
    assert not [c for c in claims_of(front, "sbx_x") if c["status"] == 200], "a 200 claim for a removed room"
    assert_idle(front.ledger)


def test_a_pool_room_made_after_the_bulk_delete_was_given_up_on_is_not_one_of_its_targets(front) -> None:
    release = lost_bulk(front)
    front.api.new_ids = ["sbx_y"]
    assert front.create(POOL_TEAM)[0] == 200
    release.set()
    time.sleep(0.3)
    assert "sbx_y" in front.api.rooms  # the targets were picked when the bulk delete started
    status, _headers, out = claim(front, "sbx_y")
    assert status == 200 and json.loads(out)["status"] == "claimed"
    assert_idle(front.ledger)


def test_a_5xx_bulk_answer_is_not_certain_either(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    front.api.reply(r"DELETE /v1/sandboxes", 500, {"error": {"code": "boom"}})
    assert front.call("DELETE", BULK)[0] == 500
    status, _headers, out = claim(front, "sbx_x")
    assert status == 409 and code(out) == "pool_room_unknown"
    assert_idle(front.ledger)


@pytest.mark.parametrize("answer", [200, 204, 400])
def test_a_bulk_answer_that_is_certain_leaves_a_fresh_claim_to_the_apis_own_check(front, answer) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create({**POOL_TEAM, "labels": {"cathedral_pool": "1", "team": "b"}})[0] == 200
    front.api.reply(r"DELETE /v1/sandboxes", answer, b"" if answer == 204 else {"x": 1})
    assert front.call("DELETE", BULK)[0] == answer
    assert claim(front, "sbx_x")[0] == 200  # a bulk delete that ran or was refused leaves this room alone
    assert_idle(front.ledger)


def test_an_unknown_room_is_cleared_by_a_delete_that_succeeded(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    lost_bulk(front)
    assert front.delete("sbx_x")[0] == 200
    status, _headers, out = claim(front, "sbx_x")
    assert status == 409 and code(out) == "pool_room_gone"
    assert "sbx_x" not in front.ledger.unknown
    assert_idle(front.ledger)


def test_an_unknown_room_is_cleared_when_the_room_ends(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    release = lost_bulk(front)
    release.set()
    wait_for(lambda: "sbx_x" not in front.api.rooms, "the bulk delete never ran")
    front.server.look_all()
    assert "sbx_x" not in front.ledger.unknown
    assert code(claim(front, "sbx_x")[2]) == "pool_room_gone"
    assert_idle(front.ledger)


# ---------------------------------------------------------------- a repeat claim after the room is gone

def test_a_repeat_claim_is_refused_when_a_bulk_delete_removed_the_claimed_room(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    assert claim(front, "sbx_x")[0] == 200  # a claim changes the lifetime only: the labels are still there
    assert front.call("DELETE", BULK)[0] == 200
    assert "sbx_x" not in front.api.rooms
    status, headers, out = claim(front, "sbx_x")
    assert status == 409 and code(out) == "pool_room_gone" and "X-Room-Receipt" not in headers
    assert_idle(front.ledger)


def test_a_repeat_claim_is_refused_for_a_room_an_uncertain_bulk_delete_may_remove(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    assert claim(front, "sbx_x")[0] == 200
    lost_bulk(front)
    status, _headers, out = claim(front, "sbx_x")
    assert status == 409 and code(out) == "pool_room_unknown"
    assert_idle(front.ledger)


def test_a_repeat_claim_is_refused_when_the_api_cannot_say_the_room_is_there(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    assert claim(front, "sbx_x")[0] == 200
    front.api.get_replies["sbx_x"] = (503, b'{"error":{"code":"busy"}}')
    assert code(claim(front, "sbx_x")[2]) == "pool_room_unknown"
    assert_idle(front.ledger)


def test_a_repeat_claim_of_a_room_that_is_there_still_gets_the_stored_answer(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    first = claim(front, "sbx_x")
    again = claim(front, "sbx_x")
    assert again[0] == 200 and again[2] == first[2] and again[1]["X-Room-Receipt"] == first[1]["X-Room-Receipt"]
    assert len(claims_of(front, "sbx_x")) == 1
    assert_idle(front.ledger)


# ---------------------------------------------------------------- the bound is a deadline, and a caller who left

def test_a_claim_whose_answer_trickles_in_ends_at_the_claims_bound_not_per_read(front, monkeypatch) -> None:
    monkeypatch.setattr(rr, "CLAIM_WAIT_SECONDS", 1.0)
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    front.api.trickle(r"POST /v1/sandboxes/sbx_x/lifetime", 0.6)  # three pieces: 1.8 s in all, 0.6 s between reads
    started = time.monotonic()
    status, headers, out = claim(front, "sbx_x")
    took = time.monotonic() - started
    assert took < 1.5, f"the claim took {took:.1f} s: the bound is per read"
    assert status == 409 and code(out) == "pool_claim_failed" and receipt_of(headers)["statement"]["status"] == 502
    assert_idle(front.ledger)


def test_a_bulk_delete_behind_a_trickling_claim_runs_when_the_claim_is_cut_at_its_bound(front, monkeypatch) -> None:
    monkeypatch.setattr(rr, "CLAIM_WAIT_SECONDS", 1.0)
    monkeypatch.setattr(rr, "BULK_CLAIM_WAIT_SECONDS", 1.5)
    front.api.new_ids = ["sbx_x"]
    assert front.create({**POOL_TEAM, "labels": {"cathedral_pool": "1", "team": "b"}})[0] == 200
    front.api.trickle(r"POST /v1/sandboxes/sbx_x/lifetime", 0.6)
    c, cbox = in_thread(claim, front, "sbx_x")
    wait_for(lambda: front.ledger.claims_in_flight == 1, "the claim never started")
    status, _headers, out = front.call("DELETE", BULK)
    assert status == 200, (status, out)
    finish(c, cbox)
    assert front.api.count(r"DELETE /v1/sandboxes") == 1
    assert_idle(front.ledger)


def test_a_caller_that_leaves_just_before_the_last_claim_ends_forwards_nothing(front, monkeypatch) -> None:
    monkeypatch.setattr(rr, "BULK_POLL_SECONDS", 5.0)  # the wait is woken by the claim, not by a poll
    front.api.new_ids = ["sbx_x"]
    assert front.create({**POOL_TEAM, "labels": {"cathedral_pool": "1", "team": "b"}})[0] == 200
    held = front.api.hold(r"POST /v1/sandboxes/sbx_x/lifetime")
    c, cbox = in_thread(claim, front, "sbx_x")
    held.wait_entered()
    s = socket.create_connection(("127.0.0.1", front.port), timeout=10)
    s.sendall(f"DELETE {BULK} HTTP/1.1\r\nHost: x\r\nAuthorization: {AUTH['Authorization']}\r\n"
              f"Content-Length: 0\r\n\r\n".encode())
    wait_for(lambda: front.ledger.bulk_pending == 1, "the bulk delete never reached the front")
    s.close()
    time.sleep(0.2)
    held.release.set()
    assert finish(c, cbox)[0] == 200
    wait_for(lambda: front.ledger.bulk_pending == 0, "the bulk delete stayed pending")
    time.sleep(0.3)
    assert front.api.count(r"DELETE /v1/sandboxes") == 0, "the bulk delete was forwarded for a caller that had left"
    assert_idle(front.ledger)


def test_a_claimed_room_marked_unknown_is_used_as_before(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    assert claim(front, "sbx_x")[0] == 200
    lost_bulk(front)
    assert "sbx_x" in front.ledger.unknown
    status, headers, _out = front.exec("sbx_x")
    assert status == 200 and receipt_of(headers)["statement"]["action"] == "exec"
    status, headers, _out = front.get_file("sbx_x")
    assert status == 200 and receipt_of(headers)["statement"]["action"] == "file_get"
    status, headers, _out = front.put("sbx_x")
    assert status == 200 and receipt_of(headers)["statement"]["action"] == "file_put"
    assert_idle(front.ledger)


def test_a_bulk_delete_the_machine_does_not_answer_within_the_bound_is_cut_and_uncertain(front, monkeypatch) -> None:
    monkeypatch.setattr(rr, "BULK_FORWARD_SECONDS", 0.8)
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    held = front.api.hold(r"DELETE /v1/sandboxes")
    started = time.monotonic()
    status, headers, out = front.call("DELETE", BULK)
    took = time.monotonic() - started
    held.release.set()
    assert status == 502 and code(out) == "hotel_api_no_answer" and took < 1.6
    assert receipt_of(headers)["statement"]["status"] == 502
    assert "sbx_x" in front.ledger.unknown
    assert_idle(front.ledger)
