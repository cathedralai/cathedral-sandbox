"""Serial rooms on the receipts front (AB#384).

A create that carries the label `cathedral_serial` = "1" makes a serial room: one
signed request at a time, so the order of its receipts is the order things ran.
The rules under test: the flag is signed on receipt 1 and only with nothing in
flight for the room; a second signed request meanwhile is refused (409
room_busy); a lost or unsigned answer breaks the room (delete only); routes that
are neither signed nor reads are refused; an ordinary room is untouched.

Every test that runs requests ends with the in-flight table and the token set empty.
"""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time

import pytest
from room_front_support import AUTH, Front, assert_idle, finish, in_thread, receipt_of, rr

SERIAL = {"image": "repo/app:1", "labels": {"cathedral_serial": "1"}}


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def serial_room(front: Front) -> str:
    status, headers, out = front.create(SERIAL)
    assert status == 200
    statement = receipt_of(headers)["statement"]
    assert statement["serial"] is True and statement["room_sequence"] == 1
    return json.loads(out)["id"]


def plain_room(front: Front) -> str:
    return json.loads(front.create()[2])["id"]


def code(out: bytes) -> str:
    return json.loads(out)["error"]["code"]


def lost_call(front: Front, method: str, path: str, body=None) -> None:
    try:
        front.call(method, path, body)
    except (http.client.HTTPException, OSError):
        pass


# ---------------------------------------------------------------- the flag

def test_the_flag_is_signed_on_receipt_one_and_only_for_the_label(front) -> None:
    room = serial_room(front)
    assert room in front.ledger.serial
    other = plain_room(front)
    assert "serial" not in front.statements(other)[0]
    assert other not in front.ledger.serial
    front.delete(room)
    front.delete(other)
    assert_idle(front.ledger)


@pytest.mark.parametrize("key", ["abc", ""])
def test_an_idempotency_key_on_a_serial_create_is_refused_unsent(front, key) -> None:
    status, headers, out = front.create(SERIAL, {"Idempotency-Key": key})
    assert status == 400 and code(out) == "idempotency_key_refused"
    assert "X-Room-Receipt" not in headers
    assert front.api.seen == [] and front.ledger.chain == []


def test_an_idempotency_key_on_an_ordinary_create_passes(front) -> None:
    status, headers, _out = front.create({"image": "repo/app:1"}, {"Idempotency-Key": "k1"})
    assert status == 200 and "X-Room-Receipt" in headers


@pytest.mark.parametrize("value", ["0", "true", "", 1, True, None, ["1"]])
def test_a_serial_label_value_other_than_one_is_refused(front, value) -> None:
    status, _headers, out = front.create({"image": "repo/app:1", "labels": {"cathedral_serial": value}})
    assert status == 400 and code(out) == "reserved_label_invalid"
    assert front.api.seen == [] and front.ledger.chain == []


def test_the_serial_and_pool_labels_together_are_refused(front) -> None:
    status, _headers, out = front.create(
        {"image": "repo/app:1", "labels": {"cathedral_serial": "1", "cathedral_pool": "1"}})
    assert status == 400 and code(out) == "reserved_label_invalid"
    assert front.api.seen == []


# ---------------------------------------------------------------- one at a time

def test_two_at_once_one_runs_and_the_second_is_refused_unsent(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    t, box = in_thread(front.exec, room, "a")
    held.wait_entered()
    status, headers, out = front.exec(room, "b")
    assert status == 409 and code(out) == "room_busy" and "X-Room-Receipt" not in headers
    assert front.api.count(rf"POST /v1/sandboxes/{room}/exec") == 1
    held.release.set()
    assert finish(t, box)[0] == 200
    status, headers, _out = front.exec(room, "b")
    assert status == 200 and receipt_of(headers)["statement"]["room_sequence"] == 3
    assert_idle(front.ledger)


def test_a_slow_first_request_signs_before_any_later_one(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    threading.Timer(2, held.release.set).start()
    t, box = in_thread(front.exec, room, "slow")
    held.wait_entered()
    refusals = [front.exec(room, "later")[0], front.put(room)[0]]
    assert refusals == [409, 409]
    assert finish(t, box)[0] == 200
    assert front.exec(room, "after")[0] == 200
    statements = front.statements(room)
    assert [s["room_sequence"] for s in statements] == [1, 2, 3]
    assert statements[1]["sequence"] < statements[2]["sequence"]
    assert statements[1]["command_sha256"] != statements[2]["command_sha256"]
    assert_idle(front.ledger)


def test_reads_pass_while_a_request_is_in_flight(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    t, box = in_thread(front.exec, room)
    held.wait_entered()
    base = f"/v1/sandboxes/{room}"
    reads = [("GET", base), ("POST", base + "/wait"), ("GET", base + "/logs"), ("GET", base + "/stat"),
             ("GET", base + "/tar"), ("GET", base + "/desktop"), ("GET", base + "/terminals"),
             ("GET", base + "/processes/1/logs"), ("GET", base + "/sealed-secrets"), ("GET", base + "/entries")]
    for method, path in reads:
        status, _headers, out = front.call(method, path, b"{}" if method == "POST" else None)
        assert status != 409, (method, path, out)
    held.release.set()
    assert finish(t, box)[0] == 200
    assert len(front.statements(room)) == 2  # reads sign nothing
    assert_idle(front.ledger)


def test_the_plain_heartbeat_and_lifetime_routes_are_refused(front) -> None:
    room = serial_room(front)
    base = f"/v1/sandboxes/{room}"
    seen = len(front.api.seen)
    for method, path in [("POST", base + "/heartbeat"), ("POST", base + "/lifetime"), ("PATCH", base + "/lifetime")]:
        status, _headers, out = front.call(method, path, {"ttl_seconds": 60})
        assert status == 409 and code(out) == "room_serial_unsigned", (method, path)
    assert len(front.api.seen) == seen
    assert_idle(front.ledger)


def test_a_semicolon_alias_patch_cannot_bypass_the_serial_gate(front) -> None:
    # AB#384: urlparse (API) strips ";alias"; urlsplit (old front) did not, so
    # PATCH /v1/sandboxes/{id};alias skipped the serial token and mutated the room.
    room = serial_room(front)
    seen, before = len(front.api.seen), len(front.statements(room))
    status, _headers, out = front.call("PATCH", f"/v1/sandboxes/{room};alias", {"labels": {"x": "y"}})
    assert status == 409 and code(out) == "room_serial_unsigned"
    assert len(front.api.seen) == seen
    assert len(front.statements(room)) == before
    assert_idle(front.ledger)


def test_a_semicolon_alias_delete_names_the_real_room(front) -> None:
    # DELETE with ";alias" must gate and sign under the real room id, not the alias spelling.
    room = serial_room(front)
    status, headers, _out = front.call("DELETE", f"/v1/sandboxes/{room};alias")
    assert status == 200
    statement = receipt_of(headers)["statement"]
    assert statement["action"] == "delete"
    assert statement["sandbox_id"] == room
    assert ";alias" not in statement["target"]
    assert room not in front.ledger.serial
    assert all(";alias" not in (s.get("sandbox_id") or "") for s in front.statements(room))
    assert_idle(front.ledger)


def test_api_request_path_drops_semicolon_params() -> None:
    path, forward = rr.api_request_path("/v1/sandboxes/sbx_1;alias?x=1")
    assert path == "/v1/sandboxes/sbx_1"
    assert forward == "/v1/sandboxes/sbx_1?x=1"
    assert rr.room_of(path) == "sbx_1"
    assert rr.room_of("/v1/sandboxes/sbx_1;alias") == "sbx_1;alias"  # callers must pass urlparse path
    assert rr.route_kind("PATCH", path) == "other"


@pytest.mark.parametrize("method,tail", [
    ("POST", "/terminals"), ("PUT", "/directories"), ("POST", "/snapshot"), ("POST", "/expose"),
    ("POST", "/terminals/t1/input"), ("DELETE", "/processes/1"), ("PUT", "/tar"),
    ("POST", "/freeze"), ("GET", "/terminals/t1/output"), ("PATCH", ""),
])
def test_unlisted_routes_are_refused_on_a_serial_room_and_pass_on_an_ordinary_one(front, method, tail) -> None:
    serial, ordinary = serial_room(front), plain_room(front)
    seen = len(front.api.seen)
    status, _headers, out = front.call(method, f"/v1/sandboxes/{serial}{tail}", b"{}")
    assert status == 409 and code(out) == "room_serial_unsigned"
    assert len(front.api.seen) == seen
    status, _headers, _out = front.call(method, f"/v1/sandboxes/{ordinary}{tail}", b"{}")
    assert status == 200 and len(front.api.seen) == seen + 1
    assert_idle(front.ledger)


@pytest.mark.parametrize("tail", ["/sealed-exec", "/sealed-secrets"])
def test_front_owned_sealed_handlers_are_refused_on_a_serial_room(front, tail) -> None:
    serial, ordinary = serial_room(front), plain_room(front)
    status, _headers, out = front.call("POST", f"/v1/sandboxes/{serial}{tail}", {"x": 1})
    assert status == 409 and code(out) == "room_serial_unsigned"
    # An ordinary room reaches the handler (this hotel has the feature off).
    status, _headers, out = front.call("POST", f"/v1/sandboxes/{ordinary}{tail}", {"x": 1})
    assert status == 403
    assert_idle(front.ledger)


def test_an_ordinary_room_runs_two_execs_at_once(front) -> None:
    room = plain_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    a, abox = in_thread(front.exec, room, "a")
    b, bbox = in_thread(front.exec, room, "b")
    deadline = time.time() + 10
    while front.api.count(rf"POST /v1/sandboxes/{room}/exec") < 2 and time.time() < deadline:
        time.sleep(0.01)
    assert front.api.count(rf"POST /v1/sandboxes/{room}/exec") == 2, "the second exec waited for the first"
    with front.ledger.lock:
        assert front.ledger.in_flight == {room: 2} and front.ledger.busy == set()
    held.release.set()
    assert finish(a, abox)[0] == 200 and finish(b, bbox)[0] == 200
    assert_idle(front.ledger)


# ---------------------------------------------------------------- the flag against a request in the gap

def test_a_request_in_flight_before_the_create_is_signed_leaves_the_room_ordinary(front) -> None:
    front.api.new_ids = ["sbx_gap"]
    create_hold = front.api.hold(r"POST /v1/sandboxes")
    exec_hold = front.api.hold(r"POST /v1/sandboxes/sbx_gap/exec")
    c, cbox = in_thread(front.create, SERIAL)
    create_hold.wait_entered()
    e, ebox = in_thread(front.exec, "sbx_gap")
    exec_hold.wait_entered()
    create_hold.release.set()
    status, headers, _out = finish(c, cbox)
    assert status == 200
    statement = receipt_of(headers)["statement"]
    assert "serial" not in statement and "sbx_gap" not in front.ledger.serial
    exec_hold.release.set()
    assert finish(e, ebox)[0] == 200
    assert_idle(front.ledger)


def test_a_request_already_signed_before_the_create_leaves_the_room_ordinary(front) -> None:
    front.api.reply(r"POST /v1/sandboxes/sbx_late/exec", 404, {"error": {"code": "sandbox_not_found"}})
    assert front.exec("sbx_late")[0] == 404
    front.api.new_ids = ["sbx_late"]
    status, headers, _out = front.create(SERIAL)
    statement = receipt_of(headers)["statement"]
    assert status == 200 and statement["room_sequence"] == 2 and "serial" not in statement
    assert "sbx_late" not in front.ledger.serial
    assert_idle(front.ledger)


# ---------------------------------------------------------------- a broken room

def test_a_lost_exec_answer_is_signed_as_502_and_breaks_the_room(front) -> None:
    room = serial_room(front)
    front.api.drop(rf"POST /v1/sandboxes/{room}/exec")
    status, headers, _out = front.exec(room)
    assert status == 502
    assert receipt_of(headers)["statement"]["status"] == 502
    seen = len(front.api.seen)
    for call in (lambda: front.exec(room), lambda: front.get_file(room), lambda: front.call("GET", f"/v1/sandboxes/{room}"),
                 lambda: front.put(room)):
        status, headers, out = call()
        assert status == 409 and code(out) == "room_broken" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == seen
    status, headers, _out = front.delete(room)
    assert status == 200 and receipt_of(headers)["statement"]["action"] == "delete"
    assert room not in front.ledger.serial and room not in front.ledger.broken
    assert [s["status"] for s in front.statements(room)] == [200, 502, 200]
    assert_idle(front.ledger)


def test_a_signed_file_get_that_raises_breaks_the_room(front) -> None:
    room = serial_room(front)
    front.api.drop(rf"GET /v1/sandboxes/{room}/files")
    lost_call(front, "GET", f"/v1/sandboxes/{room}/files?path=%2Fwork%2Fa")
    assert_idle(front.ledger)
    for call in (lambda: front.exec(room), lambda: front.call("GET", f"/v1/sandboxes/{room}")):
        status, _headers, out = call()
        assert status == 409 and code(out) == "room_broken"
    assert front.delete(room)[0] == 200
    assert_idle(front.ledger)


def test_a_receipt_that_cannot_be_signed_breaks_the_room(front, monkeypatch) -> None:
    room = serial_room(front)
    real = front.ledger.key

    class Failing:
        def sign(self, *_a):
            raise RuntimeError("no signature")

    front.ledger.key = Failing()
    status, headers, _out = front.exec(room)
    assert status == 200 and "X-Room-Receipt" not in headers and "X-Room-Receipt-Error" in headers
    front.ledger.key = real
    status, _headers, out = front.exec(room)
    assert status == 409 and code(out) == "room_broken"
    assert front.delete(room)[0] == 200
    assert_idle(front.ledger)


def test_a_refused_request_that_never_reached_the_api_does_not_break_the_room(front) -> None:
    room = serial_room(front)
    status, _headers, out = front.call("POST", f"/v1/sandboxes/{room}/exec", b'{"cmd": ["echo", "\\udc80"]}')
    assert status == 400
    assert front.exec(room)[0] == 200
    assert room not in front.ledger.broken
    assert_idle(front.ledger)


def test_a_failed_delete_with_an_answer_leaves_the_room_serial_and_open(front) -> None:
    room = serial_room(front)
    front.api.reply(rf"DELETE /v1/sandboxes/{room}", 500, {"error": {"code": "boom"}})
    status, headers, _out = front.delete(room)
    assert status == 500 and receipt_of(headers)["statement"]["status"] == 500
    assert room in front.ledger.serial and room not in front.ledger.broken
    assert front.exec(room)[0] == 200
    assert_idle(front.ledger)


def test_a_bulk_delete_then_a_delete_keeps_the_room_list_whole(front) -> None:
    room = serial_room(front)
    assert front.exec(room)[0] == 200
    status, headers, _out = front.call("DELETE", "/v1/sandboxes?label=cathedral_serial%3D1")
    assert status == 200 and receipt_of(headers)["statement"]["action"] == "bulk_delete"
    assert front.delete(room)[0] == 200
    statements = front.statements(room)
    assert [s["action"] for s in statements] == ["create", "exec", "delete"]
    assert [s["room_sequence"] for s in statements] == [1, 2, 3]
    assert all(s["status"] == 200 for s in statements)
    assert_idle(front.ledger)


# ---------------------------------------------------------------- nothing leaks

def test_a_client_that_hangs_up_mid_request_leaves_no_count_and_no_token(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    body = b'{"cmd":["true"]}'
    s = socket.create_connection(("127.0.0.1", front.port), timeout=10)
    s.sendall(f"POST /v1/sandboxes/{room}/exec HTTP/1.1\r\nHost: x\r\nAuthorization: {AUTH['Authorization']}\r\n"
              f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    held.wait_entered()
    s.close()
    held.release.set()
    assert_idle(front.ledger)
    assert room not in front.ledger.broken
    assert front.exec(room)[0] == 200
    assert_idle(front.ledger)


def test_refusals_leave_no_count_and_no_token(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    t, box = in_thread(front.exec, room)
    held.wait_entered()
    for _ in range(5):
        assert front.exec(room)[0] == 409
        assert front.call("POST", f"/v1/sandboxes/{room}/terminals", {})[0] == 409
    with front.ledger.lock:
        assert front.ledger.in_flight == {room: 1} and front.ledger.busy == {room}
    held.release.set()
    finish(t, box)
    assert_idle(front.ledger)


def test_a_turn_is_released_when_the_handler_raises_before_the_api(front, monkeypatch) -> None:
    room = serial_room(front)

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(front.server.RequestHandlerClass, "owner_gate", boom)
    lost_call(front, "POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["true"]})
    assert_idle(front.ledger)
    assert room not in front.ledger.broken  # nothing reached the API
    monkeypatch.undo()
    assert front.exec(room)[0] == 200
    assert_idle(front.ledger)


def test_the_sealed_env_handler_is_refused_on_a_serial_room_and_its_read_passes(front) -> None:
    serial, ordinary = serial_room(front), plain_room(front)
    seen = len(front.api.seen)
    status, headers, out = front.call("POST", f"/v1/sandboxes/{serial}/sealed-env", {"x": 1})
    assert status == 409 and code(out) == "room_serial_unsigned" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == seen
    # The read is on the reads list: it reaches the handler (this hotel has the feature off).
    assert front.call("GET", f"/v1/sandboxes/{serial}/sealed-env")[0] == 403
    # An ordinary room reaches the handler for both.
    assert front.call("POST", f"/v1/sandboxes/{ordinary}/sealed-env", {"x": 1})[0] == 403
    assert_idle(front.ledger)


def test_a_signed_get_on_a_serial_room_is_sent_once_and_a_lost_answer_signs_502_and_breaks_the_room(front) -> None:
    room = serial_room(front)
    front.api.drop(rf"GET /v1/sandboxes/{room}/files", times=1)  # the API receives it, then no answer
    status, headers, _out = front.get_file(room)
    assert status == 502 and receipt_of(headers)["statement"]["status"] == 502
    assert front.api.count(rf"GET /v1/sandboxes/{room}/files") == 1, "one receipt, one request"
    status, _headers, out = front.exec(room)
    assert status == 409 and code(out) == "room_broken"
    assert room in front.ledger.broken
    assert front.delete(room)[0] == 200
    assert_idle(front.ledger)


def test_on_an_ordinary_room_a_lost_get_answer_is_retried_and_signs_one_success(front) -> None:
    room = plain_room(front)
    front.api.drop(rf"GET /v1/sandboxes/{room}/files", times=1)
    status, headers, _out = front.get_file(room)
    assert status == 200 and receipt_of(headers)["statement"]["status"] == 200
    assert front.api.count(rf"GET /v1/sandboxes/{room}/files") == 2
    assert [s["action"] for s in front.statements(room)] == ["create", "file_get"]
    assert_idle(front.ledger)


def test_a_request_for_a_busy_serial_room_returns_at_once(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    t, box = in_thread(front.exec, room)
    held.wait_entered()
    started = time.monotonic()
    status, _headers, out = front.exec(room, "second")
    assert status == 409 and code(out) == "room_busy"
    assert time.monotonic() - started < 1.0, "the second request waited for the first"
    held.release.set()
    finish(t, box)
    assert_idle(front.ledger)


# ---------------------------------------------------------------- an unsigned write before the create is signed

def _held_create(front: Front, ids: list[str]):
    front.api.new_ids = list(ids)
    hold = front.api.hold(r"POST /v1/sandboxes")
    t, box = in_thread(front.create, SERIAL)
    hold.wait_entered()
    return hold, t, box


def test_an_unsigned_write_that_completes_before_the_create_is_signed_withholds_the_flag(front) -> None:
    hold, t, box = _held_create(front, ["sbx_t"])
    assert front.call("PUT", "/v1/sandboxes/sbx_t/tar?path=/work", b"tar-bytes")[0] == 200  # no receipt, no longer in flight
    with front.ledger.lock:
        assert front.ledger.in_flight == {}
    hold.release.set()
    status, headers, _out = finish(t, box)
    statement = receipt_of(headers)["statement"]
    assert status == 200 and "serial" not in statement and statement["room_sequence"] == 1
    assert "sbx_t" not in front.ledger.serial
    assert_idle(front.ledger)


def test_a_post_the_api_answers_404_before_the_create_is_signed_withholds_the_flag(front) -> None:
    front.api.reply(r"POST /v1/sandboxes/sbx_t/exec", 404, {"error": {"code": "sandbox_not_found"}})
    hold, t, box = _held_create(front, ["sbx_t"])
    assert front.exec("sbx_t")[0] == 404
    hold.release.set()
    _status, headers, _out = finish(t, box)
    assert "serial" not in receipt_of(headers)["statement"] and "sbx_t" not in front.ledger.serial
    assert_idle(front.ledger)


def test_a_read_of_the_new_id_before_the_create_is_signed_keeps_the_flag(front) -> None:
    hold, t, box = _held_create(front, ["sbx_t"])
    front.api.rooms.add("sbx_t")  # the API lists a new room before the front has signed its create
    assert front.call("GET", "/v1/sandboxes/sbx_t")[0] == 200
    assert front.call("GET", "/v1/sandboxes/sbx_t/logs")[0] == 200
    hold.release.set()
    _status, headers, _out = finish(t, box)
    assert receipt_of(headers)["statement"]["serial"] is True and "sbx_t" in front.ledger.serial
    assert front.delete("sbx_t")[0] == 200
    assert_idle(front.ledger)


def _wait_creates(front: Front, n: int) -> None:
    deadline = time.time() + 10
    while front.api.count(r"POST /v1/sandboxes") < n and time.time() < deadline:
        time.sleep(0.01)
    assert front.api.count(r"POST /v1/sandboxes") == n


def test_overlapping_creates_keep_their_flags_when_an_unrelated_id_is_touched(front) -> None:
    front.api.new_ids = ["sbx_a", "sbx_b"]
    hold = front.api.hold(r"POST /v1/sandboxes")
    a, abox = in_thread(front.create, SERIAL)
    b, bbox = in_thread(front.create, SERIAL)
    _wait_creates(front, 2)
    assert front.exec("sbx_unrelated")[0] == 200
    hold.release.set()
    for t, box in ((a, abox), (b, bbox)):
        assert receipt_of(finish(t, box)[1])["statement"]["serial"] is True
    assert {"sbx_a", "sbx_b"} <= front.ledger.serial
    assert_idle(front.ledger)


def _touch_while_pending(front: Front, monkeypatch, cap: int, ids: list[str]):
    """Hold a create, run one non-read request for each id (each enters and leaves), and return the held create."""
    from room_front_support import rr

    monkeypatch.setattr(rr, "TOUCHED_CAP", cap)
    front.api.new_ids = ["sbx_fresh"]
    hold = front.api.hold(r"POST /v1/sandboxes")
    c, cbox = in_thread(front.create, SERIAL)
    hold.wait_entered()
    for unknown in ids:  # an unsigned write: no receipt, so the id stays unknown to the ledger
        assert front.call("PUT", f"/v1/sandboxes/{unknown}/tar?path=/work", b"x")[0] == 200
    return hold, c, cbox


def test_a_touched_set_exactly_at_its_cap_keeps_the_flag(front, monkeypatch) -> None:
    hold, c, cbox = _touch_while_pending(front, monkeypatch, 3, ["u1", "u2", "u3"])
    with front.ledger.lock:
        assert len(front.ledger.touched) == 3 and not front.ledger.overflow
    hold.release.set()
    assert receipt_of(finish(c, cbox)[1])["statement"]["serial"] is True
    assert front.delete("sbx_fresh")[0] == 200
    assert_idle(front.ledger)


def test_one_id_past_the_cap_withholds_every_flag_until_the_creates_end(front, monkeypatch) -> None:
    hold, c, cbox = _touch_while_pending(front, monkeypatch, 3, ["u1", "u2", "u3", "u4"])
    with front.ledger.lock:
        assert len(front.ledger.touched) == 3 and front.ledger.overflow
    # An id already held does not add anything new.
    assert front.call("PUT", "/v1/sandboxes/u1/tar?path=/work", b"x")[0] == 200
    with front.ledger.lock:
        assert front.ledger.overflow and len(front.ledger.touched) == 3
    hold.release.set()
    assert "serial" not in receipt_of(finish(c, cbox)[1])["statement"]
    assert_idle(front.ledger)
    front.api.new_ids = ["sbx_c"]
    assert receipt_of(front.create(SERIAL)[1])["statement"]["serial"] is True
    assert_idle(front.ledger)


# ---------------------------------------------------------------- a request that spans the create

def _spanning(front: Front, request, hold_pattern: str, create_body: dict, create_id: str, request_id: str = ""):
    """request enters and is held inside the API; the create is then sent and held; request is released and
    completes while the create is unsigned; then the create is released. Returns the create's answer."""
    front.api.new_ids = [create_id]
    request_hold = front.api.hold(hold_pattern)
    r, rbox = in_thread(request)
    request_hold.wait_entered()
    create_hold = front.api.hold(r"POST /v1/sandboxes")
    c, cbox = in_thread(front.create, create_body)
    create_hold.wait_entered()
    request_hold.release.set()
    finish(r, rbox)
    create_hold.release.set()
    return finish(c, cbox)


def test_a_write_in_flight_before_the_create_that_ends_before_it_is_signed_withholds_the_flag(front) -> None:
    status, headers, _out = _spanning(
        front, lambda: front.call("PUT", "/v1/sandboxes/sbx_x/tar?path=/work", b"tar"),
        r"PUT /v1/sandboxes/sbx_x/tar", SERIAL, "sbx_x", "sbx_x")
    statement = receipt_of(headers)["statement"]
    assert status == 200 and "serial" not in statement and statement["room_sequence"] == 1
    assert "sbx_x" not in front.ledger.serial
    assert_idle(front.ledger)


def test_an_unrelated_request_spanning_the_create_leaves_the_new_rooms_flag(front) -> None:
    _status, headers, _out = _spanning(
        front, lambda: front.call("PUT", "/v1/sandboxes/sbx_other/tar?path=/work", b"tar"),
        r"PUT /v1/sandboxes/sbx_other/tar", SERIAL, "sbx_new", "sbx_other")
    assert receipt_of(headers)["statement"]["serial"] is True and "sbx_new" in front.ledger.serial
    assert front.delete("sbx_new")[0] == 200
    assert_idle(front.ledger)


def test_a_read_spanning_the_create_leaves_the_flag(front) -> None:
    front.api.rooms.add("sbx_x")
    _status, headers, _out = _spanning(
        front, lambda: front.call("GET", "/v1/sandboxes/sbx_x/logs"),
        r"GET /v1/sandboxes/sbx_x/logs", SERIAL, "sbx_x", "sbx_x")
    assert receipt_of(headers)["statement"]["serial"] is True
    assert front.delete("sbx_x")[0] == 200
    assert_idle(front.ledger)


# ---------------------------------------------------------------- a bulk delete by label

SERIAL_TEAM = {"image": "repo/app:1", "labels": {"cathedral_serial": "1", "team": "a"}}
BULK = "/v1/sandboxes?label=team%3Da"


def test_a_bulk_delete_that_removes_the_room_while_its_create_is_unsigned_withholds_the_flag(front) -> None:
    front.api.new_ids = ["sbx_x"]
    answer = front.api.hold_create_answers()  # the API made the room; its create is not signed yet
    c, cbox = in_thread(front.create, SERIAL_TEAM)
    answer.wait_entered()
    assert front.call("DELETE", BULK)[0] == 200
    assert "sbx_x" not in front.api.rooms  # the fake really deleted it
    answer.release.set()
    status, headers, _out = finish(c, cbox)
    statement = receipt_of(headers)["statement"]
    assert status == 200 and "serial" not in statement and "sbx_x" not in front.ledger.serial
    assert_idle(front.ledger)


def test_a_bulk_delete_that_starts_before_the_create_and_ends_while_it_is_pending_withholds_the_flag(front) -> None:
    bulk_hold = front.api.hold(r"DELETE /v1/sandboxes")
    b, bbox = in_thread(front.call, "DELETE", BULK)
    bulk_hold.wait_entered()
    front.api.new_ids = ["sbx_x"]
    answer = front.api.hold_create_answers()
    c, cbox = in_thread(front.create, SERIAL_TEAM)
    answer.wait_entered()
    bulk_hold.release.set()
    finish(b, bbox)
    answer.release.set()
    assert "serial" not in receipt_of(finish(c, cbox)[1])["statement"]
    assert_idle(front.ledger)


def test_a_bulk_delete_that_ended_before_the_create_was_sent_leaves_the_flag(front) -> None:
    assert front.call("DELETE", BULK)[0] == 200
    with front.ledger.lock:
        assert not front.ledger.overflow and front.ledger.bulk_in_flight == 0
    assert receipt_of(front.create(SERIAL_TEAM)[1])["statement"]["serial"] is True
    assert_idle(front.ledger)


def test_a_bulk_delete_while_no_create_is_pending_leaves_overflow_false(front) -> None:
    held = front.api.hold(r"DELETE /v1/sandboxes")
    b, bbox = in_thread(front.call, "DELETE", BULK)
    held.wait_entered()
    with front.ledger.lock:
        assert front.ledger.bulk_in_flight == 1 and not front.ledger.overflow
    held.release.set()
    finish(b, bbox)
    assert_idle(front.ledger)


def test_a_bulk_delete_is_not_held_back_by_a_busy_serial_room(front) -> None:
    room = serial_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    t, box = in_thread(front.exec, room)
    held.wait_entered()
    started = time.monotonic()
    assert front.call("DELETE", BULK)[0] == 200
    assert time.monotonic() - started < 1.0
    held.release.set()
    finish(t, box)
    assert_idle(front.ledger)


# ---------------------------------------------------------------- what a broken room answers

def test_every_request_naming_a_broken_room_but_a_delete_gets_room_broken_and_its_receipts_still_read(front) -> None:
    room = serial_room(front)
    front.api.drop(rf"POST /v1/sandboxes/{room}/exec", times=1)
    assert front.exec(room)[0] == 502
    seen = len(front.api.seen)
    base = f"/v1/sandboxes/{room}"
    for method, path in [("GET", base), ("GET", base + "/logs"), ("POST", base + "/wait"), ("POST", base + "/exec"),
                         ("PUT", base + "/files"), ("GET", base + "/files"), ("POST", base + "/heartbeat")]:
        status, _headers, out = front.call(method, path, b"{}" if method in ("POST", "PUT") else None)
        assert status == 409 and code(out) == "room_broken", (method, path)
    assert len(front.api.seen) == seen
    listing = front.room_receipts(room)  # the room's receipt list is answered before the gate
    assert listing["count"] == 2 and listing["receipts"][-1]["statement"]["status"] == 502
    assert front.delete(room)[0] == 200
    assert_idle(front.ledger)


def test_a_read_whose_answer_is_lost_answers_502_signs_nothing_and_does_not_break_the_room(front) -> None:
    room = serial_room(front)
    front.api.drop(rf"GET /v1/sandboxes/{room}/logs", times=1)
    status, headers, _out = front.call("GET", f"/v1/sandboxes/{room}/logs")
    assert status == 502 and "X-Room-Receipt" not in headers
    assert room not in front.ledger.broken
    assert front.exec(room)[0] == 200
    assert [s["action"] for s in front.statements(room)] == ["create", "exec"]
    assert_idle(front.ledger)


# ---------------------------------------------------------------- each bulk guard alone, and a bulk delete's release

def test_a_create_signed_while_an_earlier_bulk_delete_is_still_pending_gets_no_flag(front) -> None:
    bulk_hold = front.api.hold(r"DELETE /v1/sandboxes")
    b, bbox = in_thread(front.call, "DELETE", BULK)
    bulk_hold.wait_entered()
    front.api.new_ids = ["sbx_x"]
    status, headers, _out = front.create(SERIAL_TEAM)  # signed while the bulk delete is held
    assert status == 200 and "serial" not in receipt_of(headers)["statement"]
    bulk_hold.release.set()
    finish(b, bbox)
    assert_idle(front.ledger)


def test_a_create_signed_while_a_bulk_delete_that_started_after_it_is_still_pending_gets_no_flag(front) -> None:
    front.api.new_ids = ["sbx_x"]
    answer = front.api.hold_create_answers()
    c, cbox = in_thread(front.create, SERIAL_TEAM)
    answer.wait_entered()
    bulk_hold = front.api.hold(r"DELETE /v1/sandboxes")
    b, bbox = in_thread(front.call, "DELETE", BULK)
    bulk_hold.wait_entered()
    answer.release.set()
    status, headers, _out = finish(c, cbox)  # signed while the bulk delete is held
    assert status == 200 and "serial" not in receipt_of(headers)["statement"]
    bulk_hold.release.set()
    finish(b, bbox)
    assert_idle(front.ledger)


def _counting_end_bulk(front: Front, monkeypatch) -> list[int]:
    calls: list[int] = []
    real = front.ledger.end_bulk
    monkeypatch.setattr(front.ledger, "end_bulk", lambda: (calls.append(1), real())[1])
    return calls


def test_a_bulk_delete_whose_upstream_call_raises_is_released_once(front, monkeypatch) -> None:
    calls = _counting_end_bulk(front, monkeypatch)

    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(front.server.RequestHandlerClass, "upstream", boom)
    lost_call(front, "DELETE", BULK)
    assert_idle(front.ledger)
    assert len(calls) == 1
    monkeypatch.undo()
    assert receipt_of(front.create(SERIAL)[1])["statement"]["serial"] is True
    assert_idle(front.ledger)


def test_a_client_that_hangs_up_during_a_bulk_delete_releases_it_once(front, monkeypatch) -> None:
    calls = _counting_end_bulk(front, monkeypatch)
    held = front.api.hold(r"DELETE /v1/sandboxes")
    s = socket.create_connection(("127.0.0.1", front.port), timeout=10)
    s.sendall(f"DELETE {BULK} HTTP/1.1\r\nHost: x\r\nAuthorization: {AUTH['Authorization']}\r\n"
              f"Content-Length: 0\r\n\r\n".encode())
    held.wait_entered()
    with front.ledger.lock:
        assert front.ledger.bulk_in_flight == 1
    s.close()
    held.release.set()
    assert_idle(front.ledger)
    assert len(calls) == 1
    assert receipt_of(front.create(SERIAL)[1])["statement"]["serial"] is True
    assert_idle(front.ledger)
