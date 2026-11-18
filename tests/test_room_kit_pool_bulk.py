"""Bulk deletes and claims on the receipts front (AB#535).

A bulk delete by label names no room until the API runs it, so it never runs beside a claim: one that arrives while
a claim is in flight waits for it (bounded by the claim's own upstream timeout plus a margin), then runs. While a
bulk delete is waiting or running a new claim is refused with 409 pool_bulk_delete_busy, so the wait cannot be
starved, and the API creates a cold room instead. A claim already answered is replayed from the stored answer.
"""
from __future__ import annotations

import json
import socket
import time

import pytest
from room_front_support import AUTH, Front, assert_idle, finish, in_thread, receipt_of, rr
from test_room_kit_pool_rooms import BULK, CID, OTHER, POOL, POOL_TEAM, claim, code, pool_room

BULK_B = "/v1/sandboxes?label=team%3Db"
TEAM_B = {"cathedral_pool": "1", "team": "b"}


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


def pending(front: Front) -> int:
    with front.ledger.lock:
        return getattr(front.ledger, "bulk_pending", 0)


def claim_held(front: Front, room: str, cid: str = CID):
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/lifetime")
    t, box = in_thread(claim, front, room, cid)
    held.wait_entered()
    return held, t, box


def started_bulk(front: Front, path: str = BULK):
    t, box = in_thread(front.call, "DELETE", path)
    wait_for(lambda: pending(front) >= 1, "the bulk delete never reached the front")
    return t, box


def test_a_repeat_claim_by_the_same_id_during_a_bulk_delete_gets_the_stored_answer(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    status, headers, _out = claim(front, room)
    assert status == 200
    first = receipt_of(headers)
    held = front.api.hold(r"DELETE /v1/sandboxes")
    t, box = in_thread(front.call, "DELETE", BULK)
    held.wait_entered()
    status, headers, out = claim(front, room)
    try:
        assert status == 200, (status, out)
        assert receipt_of(headers) == first
    finally:
        held.release.set()
        finish(t, box)
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 1
    assert_idle(front.ledger)


def test_a_repeat_claim_by_another_id_during_a_bulk_delete_is_still_refused(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    assert claim(front, room)[0] == 200
    held = front.api.hold(r"DELETE /v1/sandboxes")
    t, box = in_thread(front.call, "DELETE", BULK)
    held.wait_entered()
    status, _headers, out = claim(front, room, OTHER)
    held.release.set()
    finish(t, box)
    assert status == 409 and code(out) in ("pool_room_claimed", "pool_bulk_delete_busy")
    assert_idle(front.ledger)


def test_a_bulk_delete_with_one_claim_in_flight_waits_and_then_runs(front) -> None:
    room = pool_room(front, labels={"cathedral_pool": "1", "team": "a"})
    held, c, cbox = claim_held(front, room)
    t, box = started_bulk(front)
    time.sleep(0.5)
    assert t.is_alive() and front.api.count(r"DELETE /v1/sandboxes") == 0, "the bulk delete did not wait"
    held.release.set()
    status, headers, out = finish(c, cbox)
    assert status == 200 and json.loads(out)["status"] == "claimed"
    assert finish(t, box)[0] == 200
    assert front.api.count(r"DELETE /v1/sandboxes") == 1
    assert room not in front.api.rooms  # the claimed room is subject to the label like any room
    assert_idle(front.ledger)


def test_a_bulk_delete_with_two_claims_in_flight_waits_for_both(front) -> None:
    a, b = pool_room(front, labels=TEAM_B), pool_room(front, labels=TEAM_B)
    held_a, ca, cabox = claim_held(front, a)
    held_b, cb, cbbox = claim_held(front, b, OTHER)
    t, box = started_bulk(front)
    held_a.release.set()
    assert finish(ca, cabox)[0] == 200
    time.sleep(0.5)
    assert t.is_alive() and front.api.count(r"DELETE /v1/sandboxes") == 0, "the bulk delete ran with a claim in flight"
    held_b.release.set()
    assert finish(cb, cbbox)[0] == 200
    assert finish(t, box)[0] == 200
    assert front.api.count(r"DELETE /v1/sandboxes") == 1
    assert_idle(front.ledger)


def test_a_new_claim_while_a_bulk_delete_waits_is_refused(front) -> None:
    a, b = pool_room(front, labels=TEAM_B), pool_room(front, labels=TEAM_B)
    held, c, cbox = claim_held(front, a)
    t, box = started_bulk(front)
    status, headers, out = claim(front, b, OTHER)
    assert status == 409 and code(out) == "pool_bulk_delete_busy" and "X-Room-Receipt" not in headers
    assert front.api.count(rf"POST /v1/sandboxes/{b}/lifetime") == 0
    held.release.set()
    assert finish(c, cbox)[0] == 200
    assert finish(t, box)[0] == 200
    assert_idle(front.ledger)


def test_a_new_claim_while_a_bulk_delete_runs_is_refused(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    held = front.api.hold(r"DELETE /v1/sandboxes")
    t, box = in_thread(front.call, "DELETE", BULK)
    held.wait_entered()
    status, _headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_bulk_delete_busy"
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 0
    held.release.set()
    assert finish(t, box)[0] == 200
    assert claim(front, room)[0] == 200  # after the bulk delete the claim goes through
    assert_idle(front.ledger)


def test_two_bulk_deletes_both_wait_for_the_claim_and_both_run(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    held, c, cbox = claim_held(front, room)
    t1, b1 = started_bulk(front, BULK)
    t2, b2 = in_thread(front.call, "DELETE", BULK_B)
    wait_for(lambda: pending(front) >= 2, "the second bulk delete never reached the front")
    time.sleep(0.3)
    assert front.api.count(r"DELETE /v1/sandboxes") == 0
    held.release.set()
    assert finish(c, cbox)[0] == 200
    assert finish(t1, b1)[0] == 200 and finish(t2, b2)[0] == 200
    assert front.api.count(r"DELETE /v1/sandboxes") == 2
    assert_idle(front.ledger)


def test_a_waiting_client_that_disconnects_forwards_nothing_and_leaks_nothing(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    held, c, cbox = claim_held(front, room)
    s = socket.create_connection(("127.0.0.1", front.port), timeout=10)
    s.sendall(f"DELETE {BULK} HTTP/1.1\r\nHost: x\r\nAuthorization: {AUTH['Authorization']}\r\n"
              f"Content-Length: 0\r\n\r\n".encode())
    wait_for(lambda: pending(front) == 1, "the bulk delete never reached the front")
    s.close()
    wait_for(lambda: pending(front) == 0, "the wait did not end when the client left")
    assert front.api.count(r"DELETE /v1/sandboxes") == 0
    held.release.set()
    assert finish(c, cbox)[0] == 200
    assert front.api.count(r"DELETE /v1/sandboxes") == 0
    assert_idle(front.ledger)


@pytest.mark.parametrize("how", ["fails", "lost"])
def test_a_bulk_delete_still_runs_when_the_claim_it_waited_for_fails_or_is_lost(front, how) -> None:
    room = pool_room(front, labels={"cathedral_pool": "1", "team": "a"})
    if how == "fails":
        front.api.reply(rf"POST /v1/sandboxes/{room}/lifetime", 500, {"error": {"code": "boom"}})
    else:
        front.api.drop(rf"POST /v1/sandboxes/{room}/lifetime")
    held, c, cbox = claim_held(front, room)
    t, box = started_bulk(front)
    held.release.set()
    status, _headers, out = finish(c, cbox)
    assert status == 409 and code(out) == "pool_claim_failed"
    assert finish(t, box)[0] == 200
    assert front.api.count(r"DELETE /v1/sandboxes") == 1
    assert room not in front.api.rooms
    assert_idle(front.ledger)


def test_a_bulk_delete_that_outwaits_the_bound_is_refused_unsent_and_logged(front, monkeypatch, capsys) -> None:
    monkeypatch.setattr(rr, "BULK_CLAIM_WAIT_SECONDS", 0.6)
    room = pool_room(front, labels=TEAM_B)
    held, c, cbox = claim_held(front, room)
    status, headers, out = front.call("DELETE", BULK)
    assert status == 409 and code(out) == "bulk_delete_claim_busy" and "X-Room-Receipt" not in headers
    assert front.api.count(r"DELETE /v1/sandboxes") == 0
    assert "bulk delete refused" in capsys.readouterr().err
    assert pending(front) == 0
    held.release.set()
    assert finish(c, cbox)[0] == 200
    assert_idle(front.ledger)


def test_failed_and_lost_bulk_deletes_release_the_guard(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    front.api.reply(r"DELETE /v1/sandboxes", 500, {"error": {"code": "boom"}})
    assert front.call("DELETE", BULK)[0] == 500
    assert_idle(front.ledger)
    front.api.replies.clear()
    front.api.drop(r"DELETE /v1/sandboxes", times=1)
    assert front.call("DELETE", BULK)[0] == 502
    assert_idle(front.ledger)  # the guard is released either way
    # The outcome of both is uncertain, so the room is not claimable; a room made afterwards is.
    assert code(claim(front, room)[2]) == "pool_room_unknown"
    assert claim(front, pool_room(front, labels=TEAM_B))[0] == 200
    assert_idle(front.ledger)


def test_two_running_bulk_deletes_then_a_claim(front) -> None:
    room = pool_room(front, labels=TEAM_B)
    h = front.api.hold(r"DELETE /v1/sandboxes")
    t1, b1 = in_thread(front.call, "DELETE", BULK)
    t2, b2 = in_thread(front.call, "DELETE", "/v1/sandboxes?label=team%3Dc")
    h.wait_entered()
    wait_for(lambda: front.ledger.bulk_in_flight == 2, "both bulk deletes did not run")
    assert code(claim(front, room)[2]) == "pool_bulk_delete_busy"
    h.release.set()
    assert finish(t1, b1)[0] == 200 and finish(t2, b2)[0] == 200
    assert claim(front, room)[0] == 200
    assert_idle(front.ledger)


def test_a_claim_whose_client_left_is_still_waited_for_by_a_bulk_delete(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    held = front.api.hold(r"POST /v1/sandboxes/sbx_x/lifetime")
    body = json.dumps({"cathedral_sandbox_id": CID, "lifetime_seconds": 600}).encode()
    s = socket.create_connection(("127.0.0.1", front.port))
    s.sendall(b"POST /v1/sandboxes/sbx_x/claim HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
              + f"Authorization: {AUTH['Authorization']}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    held.wait_entered()
    s.close()
    t, box = started_bulk(front)
    time.sleep(0.4)
    assert front.api.count(r"DELETE /v1/sandboxes") == 0
    held.release.set()
    assert finish(t, box)[0] == 200
    assert_idle(front.ledger)
    # The claim was signed (200) before the bulk delete ran and removed the room, so a replay now finds it gone.
    with front.ledger.lock:
        statuses = [front.ledger.chain[i]["statement"]["status"] for i in front.ledger.by_room["sbx_x"]
                    if front.ledger.chain[i]["statement"]["action"] == "claim"]
    assert statuses == [200]
    assert code(claim(front, "sbx_x")[2]) == "pool_room_gone"


def test_a_bulk_delete_entirely_before_the_claim_leaves_the_claim_refused(front) -> None:
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    assert front.call("DELETE", BULK)[0] == 200
    assert "sbx_x" not in front.api.rooms
    status, headers, out = claim(front, "sbx_x")
    assert status == 409 and code(out) == "pool_claim_failed"
    assert receipt_of(headers)["statement"]["status"] == 404  # a non-2xx claim receipt is signed
    assert "sbx_x" in front.ledger.broken and "sbx_x" not in front.ledger.claimed
    assert_idle(front.ledger)
