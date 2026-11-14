"""Exec result memory on the receipts front (AB#756).

The broker's background exec path sends its own handle in X-Room-Exec-Handle. For those execs only,
the front keeps the answer it signed, so a broker that restarted while the command ran reads it back
with GET /v1/sandboxes/{id}/exec/result?handle= and drops it with DELETE once saved.
"""
from __future__ import annotations

import http.client
import json
import socket
import time

import pytest
from room_front_support import KEY, Front, assert_idle, finish, in_thread, receipt_of, rr

H1 = "a" * 32
H2 = "b" * 32


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def room_of(front: Front, body: dict | None = None) -> str:
    return json.loads(front.create(body)[2])["id"]


def kept_exec(front: Front, room: str, handle: str = H1, cmd: str = "job"):
    return front.call("POST", f"/v1/sandboxes/{room}/exec", {"cmd": [cmd]}, headers={rr.EXEC_HANDLE_HEADER: handle})


def result(front: Front, room: str, handle: str = H1, wait: int = 0, method: str = "GET", **kwargs):
    return front.call(method, f"/v1/sandboxes/{room}/exec/result?handle={handle}&wait={wait}", **kwargs)


def code(out: bytes) -> str:
    return json.loads(out)["error"]["code"]


def test_running_then_done_replays_the_signed_answer_byte_for_byte(front) -> None:
    room = room_of(front)
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    t, box = in_thread(kept_exec, front, room)
    hold.wait_entered()
    status, headers, out = result(front, room, wait=0)
    assert status == 200 and headers[rr.EXEC_STATE_HEADER] == "running" and json.loads(out) == {"state": "running"}
    hold.release.set()
    status0, headers0, out0 = finish(t, box)
    assert status0 == 200 and rr.EXEC_STATE_HEADER not in headers0
    status, headers, out = result(front, room, wait=5)
    assert (status, out) == (status0, out0)
    assert headers[rr.EXEC_STATE_HEADER] == "done"
    assert headers["X-Room-Receipt"] == headers0["X-Room-Receipt"]
    assert receipt_of(headers)["statement"]["result_sha256"] == rr.sha(out)
    # A read signs nothing and reaches no API.
    assert len(front.statements(room)) == 2  # create, exec
    assert front.api.count(r"GET /v1/sandboxes/.*/exec/result") == 0
    # Reads do not consume: a second read gets the same.
    assert result(front, room)[2] == out0
    assert_idle(front.ledger)


def test_the_handle_header_never_reaches_the_api(front, monkeypatch) -> None:
    seen = []
    real = front.api.handle

    def spy(h):
        seen.append(h.headers.get(rr.EXEC_HANDLE_HEADER))
        return real(h)

    monkeypatch.setattr(front.api, "handle", spy)
    room = room_of(front)
    kept_exec(front, room)
    assert seen and all(v is None for v in seen)


def test_an_answer_whose_caller_went_away_is_kept(front) -> None:
    room = room_of(front)
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    body = b'{"cmd":["job"]}'
    s = socket.create_connection(("127.0.0.1", front.port), timeout=10)
    s.sendall(f"POST /v1/sandboxes/{room}/exec HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY.decode()}\r\n"
              f"{rr.EXEC_HANDLE_HEADER}: {H1}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
              .encode() + body)
    hold.wait_entered()
    s.close()  # the broker died
    hold.release.set()
    status, headers, out = result(front, room, wait=10)
    assert status == 200 and headers[rr.EXEC_STATE_HEADER] == "done" and json.loads(out) == {"exit_code": 0}
    assert receipt_of(headers)["statement"]["action"] == "exec"
    assert_idle(front.ledger)


def test_an_api_answer_that_never_came_is_kept_as_the_signed_502(front) -> None:
    room = room_of(front)
    front.api.drop(r"POST /v1/sandboxes/[^/]+/exec")
    status0, headers0, out0 = kept_exec(front, room)
    assert status0 == 502
    status, headers, out = result(front, room)
    assert (status, out) == (502, out0) and headers[rr.EXEC_STATE_HEADER] == "done"
    assert headers["X-Room-Receipt"] == headers0["X-Room-Receipt"]


def test_a_front_failure_after_the_mark_ends_the_entry_as_a_502(front, monkeypatch) -> None:
    room = room_of(front)

    def boom(self, *args, **kwargs):
        raise RuntimeError("front bug")

    monkeypatch.setattr(rr.Handler, "upstream", boom)
    try:
        kept_exec(front, room)
    except (http.client.HTTPException, OSError):
        pass
    status, headers, out = result(front, room, wait=5)
    assert status == 502 and headers[rr.EXEC_STATE_HEADER] == "done" and code(out) == "hotel_api_no_answer"


def test_unknown_bad_and_unauthorized_reads(front) -> None:
    room = room_of(front)
    status, _h, out = result(front, room)
    assert status == 404 and code(out) == "exec_unknown"
    assert result(front, room, handle="ABC")[0] == 400
    assert result(front, room, handle="a" * 31)[0] == 400
    assert front.call("GET", f"/v1/sandboxes/{room}/exec/result?handle={H1}&wait=26")[0] == 400
    assert front.call("GET", f"/v1/sandboxes/{room}/exec/result?handle={H1}&wait=x")[0] == 400
    assert result(front, room, auth=False)[0] == 401
    assert result(front, room, method="DELETE", auth=False)[0] == 401
    assert front.api.count(r".*/exec/result") == 0


def test_an_exec_without_the_header_is_not_kept(front) -> None:
    room = room_of(front)
    assert front.exec(room)[0] == 200
    assert code(result(front, room)[2]) == "exec_unknown"


def test_a_bad_handle_header_is_refused_unsent(front) -> None:
    room = room_of(front)
    status, _h, _out = kept_exec(front, room, handle="nothex")
    assert status == 400 and front.api.count(r"POST /v1/sandboxes/[^/]+/exec") == 0


def test_a_running_handle_is_never_replaced(front) -> None:
    room = room_of(front)
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    t, box = in_thread(kept_exec, front, room, H1, "first")
    hold.wait_entered()
    status, _h, out = kept_exec(front, room, H1, "second")
    assert status == 409 and code(out) == "exec_handle_in_use"
    assert front.api.count(r"POST /v1/sandboxes/[^/]+/exec") == 1, "the second exec ran"
    hold.release.set()
    _s, headers0, out0 = finish(t, box)
    _s, headers, out = result(front, room, wait=5)
    assert out == out0 and headers["X-Room-Receipt"] == headers0["X-Room-Receipt"]
    assert_idle(front.ledger)


def test_a_finished_handle_used_again_holds_the_newer_answer(front) -> None:
    room = room_of(front)
    kept_exec(front, room, H1, "first")
    _s, headers2, _o = kept_exec(front, room, H1, "second")
    assert result(front, room)[1]["X-Room-Receipt"] == headers2["X-Room-Receipt"]


def test_delete_drops_a_finished_answer_and_refuses_a_running_one(front) -> None:
    room = room_of(front)
    kept_exec(front, room)
    status, _h, out = result(front, room, method="DELETE")
    assert status == 200 and json.loads(out) == {"dropped": True}
    assert result(front, room)[0] == 404
    assert result(front, room, method="DELETE")[0] == 404
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    t, box = in_thread(kept_exec, front, room, H2)
    hold.wait_entered()
    status, _h, out = result(front, room, H2, method="DELETE")
    assert status == 409 and code(out) == "exec_running"
    hold.release.set()
    finish(t, box)
    assert result(front, room, H2)[0] == 200


def test_the_read_works_on_a_serial_room(front) -> None:
    status, _h, out = front.create({"image": "repo/app:1", "labels": {"cathedral_serial": "1"}})
    room = json.loads(out)["id"]
    assert kept_exec(front, room)[0] == 200
    status, headers, _o = result(front, room)
    assert status == 200 and headers[rr.EXEC_STATE_HEADER] == "done"
    assert result(front, room, method="DELETE")[0] == 200
    assert_idle(front.ledger)


def test_a_room_delete_drops_its_answers(front) -> None:
    room, other = room_of(front), room_of(front)
    kept_exec(front, room)
    kept_exec(front, other)
    assert front.delete(room)[0] == 200
    assert result(front, room)[0] == 404
    assert result(front, other)[0] == 200


def test_a_wait_returns_when_the_exec_ends(front) -> None:
    room = room_of(front)
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    t, box = in_thread(kept_exec, front, room)
    hold.wait_entered()
    r, rbox = in_thread(result, front, room, H1, 20)
    time.sleep(0.2)
    hold.release.set()
    start = time.time()
    status, headers, _o = finish(r, rbox)
    assert status == 200 and headers[rr.EXEC_STATE_HEADER] == "done" and time.time() - start < 5
    finish(t, box)


def test_a_full_table_of_running_execs_runs_the_next_untracked(front) -> None:
    front.server.exec_results = rr.ExecResults(max_entries=1)
    room = room_of(front)
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    t, box = in_thread(kept_exec, front, room, H1)
    hold.wait_entered()
    hold.release.set()
    finish(t, box)
    # One finished entry: evicted for the next one.
    assert kept_exec(front, room, H2)[0] == 200
    assert result(front, room, H1)[0] == 404 and result(front, room, H2)[0] == 200
    # One running entry: the next exec still runs, untracked.
    front.api.holds.clear()
    hold = front.api.hold(r"POST /v1/sandboxes/[^/]+/exec")
    front.server.exec_results = rr.ExecResults(max_entries=1)
    t, box = in_thread(kept_exec, front, room, H1)
    hold.wait_entered()
    t2, box2 = in_thread(kept_exec, front, room, H2)
    time.sleep(0.2)
    hold.release.set()
    assert finish(t2, box2)[0] == 200
    finish(t, box)
    assert result(front, room, H2)[0] == 404 and result(front, room, H1)[0] == 200


# ---------------------------------------------------------------- the table alone

def test_bounds_count_bytes_age_and_size() -> None:
    res = rr.ExecResults(keep=60, max_entries=3, max_bytes=10)
    for i, h in enumerate(["1" * 32, "2" * 32, "3" * 32]):
        assert res.begin("r", h) == "tracked"
        res.finish("r", h, 200, {}, b"x" * 4, "application/json")
        time.sleep(0.001)
    # 12 bytes > 10: the oldest went.
    assert res.get("r", "1" * 32, 0) is None and res.bytes == 8
    assert res.begin("r", "4" * 32) == "tracked"
    assert res.begin("r", "5" * 32) == "tracked"  # evicts the oldest finished
    assert res.get("r", "2" * 32, 0) is None
    assert res.begin("r", "6" * 32) == "tracked"
    assert res.begin("r", "7" * 32) == "full"  # three running: nothing to evict
    res.finish("r", "4" * 32, 200, {}, b"y" * 11, "application/json")
    assert res.get("r", "4" * 32, 0) is None, "an answer over the byte bound is forgotten, not cut"


def test_age_bound() -> None:
    res = rr.ExecResults(keep=0.05)
    res.begin("r", H1)
    res.finish("r", H1, 200, {}, b"{}", "application/json")
    assert res.get("r", H1, 0) is not None
    time.sleep(0.1)
    assert res.get("r", H1, 0) is None and res.bytes == 0


def test_rooms_are_separate() -> None:
    res = rr.ExecResults()
    res.begin("r1", H1)
    res.finish("r1", H1, 200, {}, b"one", "application/json")
    assert res.get("r2", H1, 0) is None
    assert res.begin("r2", H1) == "tracked"
    assert res.get("r1", H1, 0).body == b"one"

