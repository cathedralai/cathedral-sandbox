"""Pre-made rooms on the receipts front (AB#535).

A create that carries the label `cathedral_pool` = "1" and the exact shape the pool uses (an image, resources,
the broker's deny_all network, labels, ttl_seconds, no Idempotency-Key) makes a room that is signed `pool: true`
when nothing ran in it first. Until it is claimed the room is closed: delete, claim and reads of its record
only. `POST /v1/sandboxes/<id>/claim` binds it to one sandbox id, one try per room, and signs `claim`.
"""
from __future__ import annotations

import datetime
import http.client
import json
import threading
import time

import pytest
from room_front_support import KEY, Front, assert_idle, finish, in_thread, receipt_of, rr

CID = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
OTHER = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
DENY = {"mode": "deny_all", "allow": []}
POOL = {"image": "repo/app@sha256:" + "a" * 64, "resources": {"cpu": 1}, "network": DENY,
        "labels": {"cathedral_pool": "1"}, "ttl_seconds": 900}


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def code(out: bytes) -> str:
    return json.loads(out)["error"]["code"]


def pool_room(front: Front, **changes) -> str:
    status, headers, out = front.create({**POOL, **changes})
    assert status == 200, out
    statement = receipt_of(headers)["statement"]
    assert statement["pool"] is True and statement["room_sequence"] == 1
    return json.loads(out)["id"]


def claim(front: Front, room: str, cid: str = CID, lifetime: int = 600):
    return front.call("POST", f"/v1/sandboxes/{room}/claim", {"cathedral_sandbox_id": cid, "lifetime_seconds": lifetime})


# ---------------------------------------------------------------- the pool create

def test_a_clean_pool_create_is_signed_pool_and_marked_unclaimed(front) -> None:
    room = pool_room(front)
    assert room in front.ledger.pool
    (create,) = front.statements(room)
    assert "cathedral_sandbox_id" not in create and create["network_policy"] == DENY
    assert "serial" not in create


@pytest.mark.parametrize("key,value", [
    ("entrypoint", ["x"]), ("env", {"A": "b"}), ("user", "root"), ("workdir", "/"), ("workspace", "w"),
    ("tunables", {}), ("start", ["x"]), ("build", {}), ("snapshot_id", "s"), ("count", 1),
    ("idle_timeout_seconds", 5), ("network_allow", []), ("zzz_unknown", 1),
])
def test_a_forbidden_key_on_a_pool_create_is_refused_unsent(front, key, value) -> None:
    status, headers, out = front.create({**POOL, key: value})
    assert status == 400 and code(out) == "pool_create_invalid" and "X-Room-Receipt" not in headers
    assert front.api.seen == [] and front.ledger.chain == []


@pytest.mark.parametrize("network", [
    "deny_all", {"mode": "deny_all"}, {"mode": "deny_all", "allow": ["example.com"]}, {"mode": "internet", "allow": []},
    {"mode": "allowlist", "allow": ["a"]}, {"mode": "deny_all", "allow": [], "credentials": []}, None, 5,
])
def test_any_network_but_the_exact_broker_form_is_refused(front, network) -> None:
    status, _headers, out = front.create({**POOL, "network": network})
    assert status == 400 and code(out) == "pool_create_invalid"
    assert front.api.seen == []


def test_a_pool_create_without_a_network_is_refused(front) -> None:
    body = {k: v for k, v in POOL.items() if k != "network"}
    assert front.create(body)[0] == 400 and front.api.seen == []


@pytest.mark.parametrize("changes", [
    {"image": {"image": "repo/app@sha256:" + "a" * 64, "registry_auth": {"username": "u", "password": "p"}}},
    {"image": ""}, {"image": 5}, {"resources": "big"}, {"ttl_seconds": "900"}, {"ttl_seconds": True},
    {"labels": {"cathedral_pool": "1", "cathedral_sandbox_id": CID}},
])
def test_each_other_shape_problem_is_refused(front, changes) -> None:
    status, _headers, out = front.create({**POOL, **changes})
    assert status == 400 and code(out) == "pool_create_invalid"
    assert front.api.seen == []


def test_a_pool_create_without_an_image_is_refused(front) -> None:
    assert front.create({k: v for k, v in POOL.items() if k != "image"})[0] == 400


@pytest.mark.parametrize("labels", [{"cathedral_pool": "0"}, {"cathedral_pool": 1}, {"cathedral_pool": ""},
                                    {"cathedral_pool": "1", "cathedral_serial": "1"},
                                    {"cathedral_pool": "x", "cathedral_serial": "1"}])
def test_the_pool_label_value_and_the_pair_of_labels_are_refused(front, labels) -> None:
    status, _headers, out = front.create({**POOL, "labels": labels})
    assert status == 400 and code(out) == "reserved_label_invalid"
    assert front.api.seen == []


def test_an_idempotency_key_on_a_pool_create_is_refused(front) -> None:
    status, _headers, out = front.create(POOL, {"Idempotency-Key": "k"})
    assert status == 400 and code(out) == "idempotency_key_refused"
    assert front.api.seen == []


def test_a_create_count_other_than_one_is_still_refused_first(front) -> None:
    status, _headers, out = front.create({**POOL, "count": 2})
    assert status == 400 and code(out) == "create_count_refused"


@pytest.mark.parametrize("setup", ["internet", "no_network", "no_expiry", "naive", "past", "too_far", "garbage"])
def test_an_answer_without_deny_all_or_a_usable_expiry_is_signed_unflagged(front, setup) -> None:
    api = front.api
    now = datetime.datetime.now(datetime.timezone.utc)
    if setup == "internet":
        api.network_policy = {"mode": "internet", "allow": []}
    elif setup == "no_network":
        api.network_policy = None
    elif setup == "no_expiry":
        api.omit_expires = True
    elif setup == "naive":
        api.expires_at = (now + datetime.timedelta(hours=1)).replace(tzinfo=None).isoformat()
    elif setup == "past":
        api.expires_at = (now - datetime.timedelta(seconds=5)).isoformat()
    elif setup == "too_far":
        api.expires_at = (now + datetime.timedelta(hours=49)).isoformat()
    else:
        api.expires_at = "tomorrow"
    status, headers, out = front.create(POOL)
    room = json.loads(out)["id"]
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    assert room not in front.ledger.pool
    assert front.exec(room)[0] == 200  # an ordinary room
    assert_idle(front.ledger)


def test_an_expiry_inside_the_window_is_flagged(front) -> None:
    front.api.expires_at = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=47)).isoformat()
    room = pool_room(front)
    assert room in front.ledger.pool


def test_a_request_in_flight_before_the_create_is_signed_leaves_it_unflagged(front) -> None:
    front.api.new_ids = ["sbx_gap"]
    create_hold = front.api.hold(r"POST /v1/sandboxes")
    exec_hold = front.api.hold(r"POST /v1/sandboxes/sbx_gap/exec")
    c, cbox = in_thread(front.create, POOL)
    create_hold.wait_entered()
    e, ebox = in_thread(front.exec, "sbx_gap")
    exec_hold.wait_entered()
    create_hold.release.set()
    status, headers, _out = finish(c, cbox)
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    exec_hold.release.set()
    finish(e, ebox)
    assert "sbx_gap" not in front.ledger.pool
    assert_idle(front.ledger)


def test_an_ordinary_create_is_untouched_by_the_pool_rules(front) -> None:
    status, headers, _out = front.create({"image": "x", "env": {"A": "b"}, "labels": {"team": "a"}},
                                         {"Idempotency-Key": "k"})
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]


# ---------------------------------------------------------------- the closed room

def test_every_route_but_delete_claim_and_record_reads_is_refused_on_an_unclaimed_room(front) -> None:
    room = pool_room(front)
    base = f"/v1/sandboxes/{room}"
    routes = [("POST", "/exec"), ("PUT", "/files"), ("GET", "/files"), ("POST", "/processes"), ("PUT", "/network"),
              ("POST", "/heartbeat"), ("POST", "/lifetime"), ("PATCH", "/lifetime"), ("GET", "/logs"),
              ("GET", "/stat"), ("GET", "/tar"), ("PUT", "/tar"), ("POST", "/terminals"), ("PATCH", ""),
              ("POST", "/sealed-exec"), ("POST", "/sealed-secrets"), ("GET", "/sealed-secrets"),
              ("POST", "/snapshot"), ("GET", "/desktop"), ("GET", "/terminals")]
    seen = len(front.api.seen)
    for method, tail in routes:
        status, headers, out = front.call(method, base + tail, b"{}")
        assert status == 409 and code(out) == "pool_room_unclaimed", (method, tail)
        assert "X-Room-Receipt" not in headers
    assert len(front.api.seen) == seen
    assert len(front.statements(room)) == 1
    # The record reads pass.
    assert front.call("GET", base)[0] == 200
    assert front.call("POST", base + "/wait", b"{}")[0] == 200
    assert_idle(front.ledger)


def test_an_unclaimed_room_can_be_deleted_and_the_mark_goes(front) -> None:
    room = pool_room(front)
    assert front.delete(room)[0] == 200
    assert room not in front.ledger.pool
    assert [s["action"] for s in front.statements(room)] == ["create", "delete"]
    assert_idle(front.ledger)


# ---------------------------------------------------------------- the claim

def test_a_claim_signs_the_claim_clears_the_mark_and_opens_the_room(front) -> None:
    room = pool_room(front)
    create_sha = front.room_receipts(room)["receipts"][0]["receipt_sha256"]
    status, headers, out = claim(front, room, lifetime=900)
    assert status == 200
    answer = json.loads(out)
    assert answer["status"] == "claimed" and answer["sandbox_id"] == room
    assert answer["cathedral_sandbox_id"] == CID and answer["lifetime_seconds"] == 900
    assert answer["pooled_from"] == create_sha and answer["expires_at"]
    statement = receipt_of(headers)["statement"]
    assert statement["action"] == "claim" and statement["room_sequence"] == 2
    assert statement["pooled_from"] == create_sha and statement["cathedral_sandbox_id"] == CID
    assert statement["lifetime_seconds"] == 900 and statement["status"] == 200 and statement["target"].endswith("/claim")
    assert "pool" not in statement
    lifetime = [b for m, p, b in front.api.seen if p.endswith("/lifetime")]
    assert [json.loads(b) for b in lifetime] == [{"ttl_seconds": 900}]
    assert room not in front.ledger.pool
    status, headers, _out = front.exec(room)
    assert status == 200 and receipt_of(headers)["statement"]["room_sequence"] == 3
    assert [s["action"] for s in front.statements(room)] == ["create", "claim", "exec"]
    assert "pool" not in [k for s in front.statements(room)[1:] for k in s]
    assert_idle(front.ledger)


def test_the_same_id_claiming_again_gets_the_stored_answer_and_no_new_receipt(front) -> None:
    room = pool_room(front)
    first = claim(front, room)
    again = claim(front, room)
    assert again[0] == 200 and again[2] == first[2]
    assert again[1]["X-Room-Receipt"] == first[1]["X-Room-Receipt"]
    assert len([s for s in front.statements(room) if s["action"] == "claim"]) == 1
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 1
    other = claim(front, room, OTHER)
    assert other[0] == 409 and code(other[2]) == "pool_room_claimed" and "X-Room-Receipt" not in other[1]
    assert_idle(front.ledger)


def test_a_claim_of_an_ordinary_room_is_refused(front) -> None:
    room = json.loads(front.create()[2])["id"]
    status, _headers, out = claim(front, room)
    assert status == 409 and code(out) == "room_not_pool"
    assert front.api.count(r".*/lifetime") == 0


def test_a_claim_of_a_room_with_no_receipt_this_boot_is_stale(front) -> None:
    status, _headers, out = claim(front, "sbx_unknown")
    assert status == 409 and code(out) == "pool_room_stale"


def test_a_claim_after_a_front_restart_is_stale(tmp_path, monkeypatch, front) -> None:
    room = pool_room(front)
    ledger = rr.Ledger("room-b", str(tmp_path / "second"))
    server = rr.Server(("127.0.0.1", 0), ledger, front.api.server.server_address[1], 1, KEY, "/nonexistent.sock")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
        c.request("POST", f"/v1/sandboxes/{room}/claim", body=json.dumps({"cathedral_sandbox_id": CID, "lifetime_seconds": 60}),
                  headers={"Authorization": "Bearer " + KEY.decode()})
        r = c.getresponse()
        assert r.status == 409 and code(r.read()) == "pool_room_stale"
    finally:
        server.shutdown()
        server.server_close()
    assert front.api.count(r".*/lifetime") == 0


def test_a_claim_after_the_room_ended_is_gone(front) -> None:
    room = pool_room(front)
    front.api.rooms.discard(room)
    front.server.look_all()
    status, _headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_room_gone"
    assert room not in front.ledger.pool


def test_a_claim_after_a_delete_is_gone(front) -> None:
    room = pool_room(front)
    front.delete(room)
    assert code(claim(front, room)[2]) == "pool_room_gone"


def test_a_claim_of_a_room_whose_list_is_longer_than_the_create_is_refused(front) -> None:
    room = pool_room(front)
    front.api.reply(rf"DELETE /v1/sandboxes/{room}", 500, {"error": {"code": "boom"}})
    assert front.delete(room)[0] == 500
    status, _headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_room_used"
    assert front.api.count(r".*/lifetime") == 0


def test_a_claim_within_five_minutes_of_the_limit_is_refused(front) -> None:
    front.api.expires_in = 240  # a create that took 11 minutes to answer, with ttl_seconds 900
    room = pool_room(front, ttl_seconds=900)
    status, _headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_room_expiring"
    assert front.api.count(r".*/lifetime") == 0
    assert front.delete(room)[0] == 200


@pytest.mark.parametrize("body", [
    {}, {"cathedral_sandbox_id": CID}, {"lifetime_seconds": 60},
    {"cathedral_sandbox_id": CID.upper(), "lifetime_seconds": 60},
    {"cathedral_sandbox_id": "not-a-uuid", "lifetime_seconds": 60},
    {"cathedral_sandbox_id": CID, "lifetime_seconds": 0},
    {"cathedral_sandbox_id": CID, "lifetime_seconds": 172801},
    {"cathedral_sandbox_id": CID, "lifetime_seconds": "60"},
    {"cathedral_sandbox_id": CID, "lifetime_seconds": True},
    {"cathedral_sandbox_id": CID, "lifetime_seconds": 60, "extra": 1},
    [1], "x",
])
def test_a_malformed_claim_is_refused_unsent(front, body) -> None:
    room = pool_room(front)
    status, _headers, out = front.call("POST", f"/v1/sandboxes/{room}/claim", json.dumps(body).encode())
    assert status == 400 and code(out) == "claim_request_invalid"
    assert front.api.count(r".*/lifetime") == 0
    assert room in front.ledger.pool
    assert_idle(front.ledger)


def test_a_claim_needs_post(front) -> None:
    room = json.loads(front.create()[2])["id"]
    status, headers, _out = front.call("GET", f"/v1/sandboxes/{room}/claim")
    assert status == 405 and headers["Allow"] == "POST"


def test_a_failed_lifetime_call_signs_the_claim_and_breaks_the_room_for_good(front) -> None:
    room = pool_room(front)
    front.api.reply(rf"POST /v1/sandboxes/{room}/lifetime", 500, {"error": {"code": "boom"}})
    status, headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_claim_failed"
    statement = receipt_of(headers)["statement"]
    assert statement["action"] == "claim" and statement["status"] == 500
    assert room in front.ledger.broken
    status, _headers, out = claim(front, room)  # one try per room
    assert status == 409 and code(out) == "room_broken"
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 1
    assert front.exec(room)[0] == 409
    assert front.delete(room)[0] == 200
    assert room not in front.ledger.broken and room not in front.ledger.pool
    assert_idle(front.ledger)


def test_a_lifetime_call_with_no_answer_signs_502_and_breaks_the_room(front) -> None:
    room = pool_room(front)
    front.api.drop(rf"POST /v1/sandboxes/{room}/lifetime")
    status, headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_claim_failed"
    assert receipt_of(headers)["statement"]["status"] == 502
    assert room in front.ledger.broken
    assert code(claim(front, room, OTHER)[2]) == "room_broken"
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 1
    assert_idle(front.ledger)


def test_a_claim_that_cannot_be_signed_breaks_the_room(front) -> None:
    room = pool_room(front)
    real = front.ledger.key

    class Failing:
        def sign(self, *_a):
            raise RuntimeError("no signature")

    front.ledger.key = Failing()
    status, _headers, out = claim(front, room)
    front.ledger.key = real
    assert status == 409 and code(out) == "pool_claim_failed"
    assert room in front.ledger.broken and front.exec(room)[0] == 409
    assert_idle(front.ledger)


# ---------------------------------------------------------------- claim against delete, and two claims

def test_a_delete_during_a_claim_is_refused_busy_and_unsent(front) -> None:
    room = pool_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/lifetime")
    t, box = in_thread(claim, front, room)
    held.wait_entered()
    status, headers, out = front.delete(room)
    assert status == 409 and code(out) == "room_busy" and "X-Room-Receipt" not in headers
    assert front.api.count(rf"DELETE /v1/sandboxes/{room}") == 0
    held.release.set()
    assert finish(t, box)[0] == 200
    assert front.delete(room)[0] == 200  # sent again by its caller
    assert_idle(front.ledger)


def test_a_claim_during_a_delete_is_refused_busy(front) -> None:
    room = pool_room(front)
    held = front.api.hold(rf"DELETE /v1/sandboxes/{room}")
    t, box = in_thread(front.delete, room)
    held.wait_entered()
    status, _headers, out = claim(front, room)
    assert status == 409 and code(out) == "room_busy"
    held.release.set()
    assert finish(t, box)[0] == 200
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 0
    assert_idle(front.ledger)


def test_two_claims_at_once_give_one_claim_receipt(front) -> None:
    room = pool_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/lifetime")
    a, abox = in_thread(claim, front, room, CID)
    held.wait_entered()
    status, _headers, out = claim(front, room, OTHER)
    assert status == 409 and code(out) == "room_busy"
    held.release.set()
    assert finish(a, abox)[0] == 200
    again = claim(front, room, CID)
    assert again[0] == 200
    assert code(claim(front, room, OTHER)[2]) == "pool_room_claimed"
    assert len([s for s in front.statements(room) if s["action"] == "claim"]) == 1
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 1
    assert_idle(front.ledger)


def test_a_claim_in_flight_keeps_a_room_end_out(front) -> None:
    room = pool_room(front)
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/lifetime")
    t, box = in_thread(claim, front, room)
    held.wait_entered()
    front.api.rooms.discard(room)
    front.server.look_all()
    assert not [s for s in front.statements(room) if s["action"] == "room_end"]
    held.release.set()
    finish(t, box)
    assert_idle(front.ledger)


def test_a_claimed_room_runs_two_execs_at_once(front) -> None:
    room = pool_room(front)
    assert claim(front, room)[0] == 200
    held = front.api.hold(rf"POST /v1/sandboxes/{room}/exec")
    a, abox = in_thread(front.exec, room, "a")
    b, bbox = in_thread(front.exec, room, "b")
    deadline = time.time() + 10
    while front.api.count(rf"POST /v1/sandboxes/{room}/exec") < 2 and time.time() < deadline:
        time.sleep(0.01)
    assert front.api.count(rf"POST /v1/sandboxes/{room}/exec") == 2
    held.release.set()
    assert finish(a, abox)[0] == 200 and finish(b, bbox)[0] == 200
    assert_idle(front.ledger)


def test_receipts_of_a_pool_room_pass_the_rules_a_checker_applies(front) -> None:
    room = pool_room(front)
    claim(front, room)
    front.exec(room)
    receipts = front.room_receipts(room)["receipts"]
    s = [r["statement"] for r in receipts]
    assert s[0]["action"] == "create" and s[0]["pool"] is True and s[0]["room_sequence"] == 1
    assert s[1]["action"] == "claim" and s[1]["room_sequence"] == 2 and s[1]["pooled_from"] == receipts[0]["receipt_sha256"]
    assert not any("pool" in x for x in s[1:]) and not any("pooled_from" in x for x in s if x["action"] != "claim")
    assert [x["room_sequence"] for x in s] == [1, 2, 3]


def test_the_sealed_env_handler_is_refused_on_an_unclaimed_room_and_reaches_the_handler_once_claimed(front) -> None:
    room = pool_room(front)
    seen = len(front.api.seen)
    for method in ("POST", "GET"):
        status, headers, out = front.call(method, f"/v1/sandboxes/{room}/sealed-env", b"{}" if method == "POST" else None)
        assert status == 409 and code(out) == "pool_room_unclaimed" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == seen
    assert claim(front, room)[0] == 200
    # Claimed: an ordinary room, so the request reaches the handler (this hotel has the feature off).
    assert front.call("GET", f"/v1/sandboxes/{room}/sealed-env")[0] == 403
    assert_idle(front.ledger)


# ---------------------------------------------------------------- the exact shape, a write before the flag, the claim method

@pytest.mark.parametrize("missing", ["image", "resources", "network", "ttl_seconds"])
def test_a_pool_create_with_any_other_key_missing_is_refused_unsent(front, missing) -> None:
    body = {k: v for k, v in POOL.items() if k != missing}
    status, headers, out = front.create(body)
    assert status == 400 and code(out) == "pool_create_invalid" and "X-Room-Receipt" not in headers
    assert front.api.seen == [] and front.ledger.chain == []


@pytest.mark.parametrize("changes", [
    {"resources": {}}, {"resources": []}, {"resources": None}, {"resources": "big"},
    {"ttl_seconds": 0}, {"ttl_seconds": -5}, {"ttl_seconds": True}, {"ttl_seconds": False}, {"ttl_seconds": 1.5},
    {"ttl_seconds": None}, {"ttl_seconds": "900"},
    {"image": None}, {"image": ["x"]}, {"network": []},
])
def test_a_pool_create_with_a_wrong_value_is_refused_unsent(front, changes) -> None:
    status, _headers, out = front.create({**POOL, **changes})
    assert status == 400 and code(out) == "pool_create_invalid"
    assert front.api.seen == []


def test_a_pool_create_with_all_five_keys_right_is_flagged(front) -> None:
    assert pool_room(front, ttl_seconds=1, resources={"cpu": 1}) in front.ledger.pool


def test_an_unsigned_write_before_the_pool_create_is_signed_withholds_the_flag(front) -> None:
    front.api.new_ids = ["sbx_t"]
    hold = front.api.hold(r"POST /v1/sandboxes")
    t, box = in_thread(front.create, POOL)
    hold.wait_entered()
    assert front.call("PUT", "/v1/sandboxes/sbx_t/tar?path=/work", b"tar-bytes")[0] == 200
    hold.release.set()
    status, headers, _out = finish(t, box)
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    assert "sbx_t" not in front.ledger.pool
    assert_idle(front.ledger)


def test_a_read_before_the_pool_create_is_signed_keeps_the_flag(front) -> None:
    front.api.new_ids = ["sbx_t"]
    front.api.rooms.add("sbx_t")
    hold = front.api.hold(r"POST /v1/sandboxes")
    t, box = in_thread(front.create, POOL)
    hold.wait_entered()
    assert front.call("GET", "/v1/sandboxes/sbx_t")[0] == 200
    hold.release.set()
    assert receipt_of(finish(t, box)[1])["statement"]["pool"] is True
    assert_idle(front.ledger)


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_a_claim_route_answers_405_for_any_method_but_post_even_on_an_unclaimed_room(front, method) -> None:
    room = pool_room(front)
    status, headers, out = front.call(method, f"/v1/sandboxes/{room}/claim")
    assert status == 405 and headers["Allow"] == "POST" and code(out) == "method_not_allowed"
    assert room in front.ledger.pool
    assert_idle(front.ledger)


def test_a_write_in_flight_before_the_pool_create_that_ends_before_it_is_signed_withholds_the_flag(front) -> None:
    front.api.new_ids = ["sbx_x"]
    request_hold = front.api.hold(r"PUT /v1/sandboxes/sbx_x/tar")
    r, rbox = in_thread(front.call, "PUT", "/v1/sandboxes/sbx_x/tar?path=/work", b"tar")
    request_hold.wait_entered()
    create_hold = front.api.hold(r"POST /v1/sandboxes")
    c, cbox = in_thread(front.create, POOL)
    create_hold.wait_entered()
    request_hold.release.set()
    finish(r, rbox)
    create_hold.release.set()
    status, headers, _out = finish(c, cbox)
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    assert "sbx_x" not in front.ledger.pool
    assert_idle(front.ledger)


def test_a_bulk_delete_that_removes_the_room_while_its_pool_create_is_unsigned_withholds_the_flag(front) -> None:
    front.api.new_ids = ["sbx_x"]
    answer = front.api.hold_create_answers()
    pool_body = {**POOL, "labels": {"cathedral_pool": "1", "team": "a"}}
    c, cbox = in_thread(front.create, pool_body)
    answer.wait_entered()
    assert front.call("DELETE", "/v1/sandboxes?label=team%3Da")[0] == 200
    assert "sbx_x" not in front.api.rooms
    answer.release.set()
    status, headers, _out = finish(c, cbox)
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    assert "sbx_x" not in front.ledger.pool
    assert_idle(front.ledger)


def test_a_bulk_delete_that_ended_before_the_pool_create_was_sent_leaves_the_flag(front) -> None:
    assert front.call("DELETE", "/v1/sandboxes?label=team%3Da")[0] == 200
    assert pool_room(front) in front.ledger.pool
    assert_idle(front.ledger)


# ---------------------------------------------------------------- each bulk guard alone, and a bulk delete during a claim

POOL_TEAM = {**POOL, "labels": {"cathedral_pool": "1", "team": "a"}}
BULK = "/v1/sandboxes?label=team%3Da"


def test_a_pool_create_signed_while_an_earlier_bulk_delete_is_still_pending_gets_no_flag(front) -> None:
    bulk_hold = front.api.hold(r"DELETE /v1/sandboxes")
    b, bbox = in_thread(front.call, "DELETE", BULK)
    bulk_hold.wait_entered()
    status, headers, _out = front.create(POOL_TEAM)
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    bulk_hold.release.set()
    finish(b, bbox)
    assert_idle(front.ledger)


def test_a_pool_create_signed_while_a_later_bulk_delete_is_still_pending_gets_no_flag(front) -> None:
    answer = front.api.hold_create_answers()
    c, cbox = in_thread(front.create, POOL_TEAM)
    answer.wait_entered()
    bulk_hold = front.api.hold(r"DELETE /v1/sandboxes")
    b, bbox = in_thread(front.call, "DELETE", BULK)
    bulk_hold.wait_entered()
    answer.release.set()
    status, headers, _out = finish(c, cbox)
    assert status == 200 and "pool" not in receipt_of(headers)["statement"]
    bulk_hold.release.set()
    finish(b, bbox)
    assert_idle(front.ledger)


def _claim_with_lifetime_held(front: Front):
    """Hold the claim's lifetime call so another request can race it."""
    front.api.new_ids = ["sbx_x"]
    assert front.create(POOL_TEAM)[0] == 200
    held = front.api.hold(rf"POST /v1/sandboxes/sbx_x/lifetime")
    t, box = in_thread(claim, front, "sbx_x")
    held.wait_entered()
    return held, t, box


def test_bulk_delete_cannot_remove_a_room_during_its_claim(front) -> None:
    held, t, box = _claim_with_lifetime_held(front)
    status, headers, out = front.call("DELETE", BULK)
    assert status == 409 and code(out) == "bulk_delete_claim_busy"
    assert "X-Room-Receipt" not in headers
    assert "sbx_x" in front.api.rooms
    held.release.set()
    status, headers, out = finish(t, box)
    assert status == 200 and json.loads(out)["status"] == "claimed"
    assert receipt_of(headers)["statement"]["status"] == 200
    assert "sbx_x" not in front.ledger.broken
    assert_idle(front.ledger)


def test_claim_refuses_while_a_bulk_delete_is_in_flight(front) -> None:
    room = pool_room(front, labels={"cathedral_pool": "1", "team": "a"})
    held = front.api.hold(r"DELETE /v1/sandboxes")
    t, box = in_thread(front.call, "DELETE", BULK)
    held.wait_entered()
    status, headers, out = claim(front, room)
    assert status == 409 and code(out) == "pool_bulk_delete_busy"
    assert "X-Room-Receipt" not in headers
    assert front.api.count(rf"POST /v1/sandboxes/{room}/lifetime") == 0
    held.release.set()
    assert finish(t, box)[0] == 200
    assert room not in front.api.rooms
    assert_idle(front.ledger)


def test_a_failed_lifetime_call_is_signed_and_breaks_the_pool_room(front) -> None:
    front.api.reply(r"POST /v1/sandboxes/sbx_x/lifetime", 404, {"error": {"code": "sandbox_not_found"}})
    held, t, box = _claim_with_lifetime_held(front)
    held.release.set()
    status, headers, out = finish(t, box)
    assert status == 409 and code(out) == "pool_claim_failed"
    assert receipt_of(headers)["statement"]["status"] == 404
    assert "sbx_x" in front.ledger.broken
    assert_idle(front.ledger)


def test_a_claim_whose_lifetime_answer_is_lost_is_signed_502_and_breaks_the_room(front) -> None:
    front.api.drop(r"POST /v1/sandboxes/sbx_x/lifetime")
    held, t, box = _claim_with_lifetime_held(front)
    held.release.set()
    status, headers, out = finish(t, box)
    assert status == 409 and code(out) == "pool_claim_failed"
    assert receipt_of(headers)["statement"]["status"] == 502
    assert "sbx_x" in front.ledger.broken
    assert_idle(front.ledger)


def test_a_params_suffix_on_the_path_is_read_as_the_api_reads_it_by_the_claim_and_the_pool_gate(front) -> None:
    room = pool_room(front)
    base = f"/v1/sandboxes/{room}"
    # The gate sees the same route the API would run, so a suffix does not reach an unclaimed room.
    status, _headers, out = front.call("POST", base + "/exec;x", {"cmd": ["true"]})
    assert status == 409 and code(out) == "pool_room_unclaimed"
    status, headers, _out = front.call("GET", base + "/claim;x")
    assert status == 405 and headers["Allow"] == "POST"
    assert front.api.count(r".*/exec") == 0
    status, headers, out = front.call("POST", base + "/claim;x", {"cathedral_sandbox_id": CID, "lifetime_seconds": 60})
    assert status == 200 and json.loads(out)["status"] == "claimed"
    statement = receipt_of(headers)["statement"]
    assert statement["action"] == "claim" and statement["target"] == f"POST {base}/claim"
    assert room not in front.ledger.pool
    assert_idle(front.ledger)
