"""AB#604 CS-3: snapshot and fork on the receipts front.

Machine routes: `POST /v1/sandboxes/{id}/snapshot` (the machine answers 202 with
`{"operation_id", "status", "result": {"snapshot_id", "size_bytes", "committed_image_id",
"work_archive_sha256", ...}}`), `DELETE /v1/snapshots/{id}`, and a fork is
`POST /v1/sandboxes` with `snapshot_id`. Plan section 2 gives the receipt rules; each test
below is named after the rule it covers. The tests drive the real front with the shared
fake room API (tests/room_front_support.py).

Where the plan is silent the tests pin the choice made here, and say so:
- a 2xx snapshot answer whose fields are missing or malformed is answered 502
  `snapshot_unsigned`, signed with status 502 and none of the snapshot members, and the
  snapshot is not remembered, so no fork of it is accepted;
- `snapshot_receipt_sha256` is the chain's own `receipt_sha256` (sha256 of the canonical
  statement, the value every room link in this file uses), not a hash of the header bytes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from room_front_support import Front, assert_idle, finish, in_thread, receipt_of, rr

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "snapshot_fork_v1"
FIXTURE = FIXTURES / "snapshot_fork_v1.json"
GENERATOR = FIXTURES / "generate.py"
# sha256 of snapshot_fork_v1.json. Filled in when the generator exists (step two of CS-3).
FIXTURE_SHA256 = "4b57e2329e5a7588f9869e9e63a4ccd58e35c13e4dc4b15b1746f9ed542483b0"
# sha256 of the receipts a fixed scripted run of the old actions makes on main (see scripted_old_actions).
OLD_ACTIONS_SHA256 = "1bbacb44f99c04319eff0ff209c64ee4d483c8536740408c2ecd7c4ee7d4d103"

SERIAL = {"image": "repo/app:1", "labels": {"cathedral_serial": "1"}}
SNAP_MEMBERS = ["snapshot_id", "snapshot_image_id", "snapshot_work_archive_sha256", "snapshot_size_bytes",
                "snapshot_content_sha256"]
FORK_MEMBERS = ["snapshot_id", "snapshot_content_sha256", "snapshot_receipt_sha256", "snapshot_source_sandbox_id"]


def h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


IMAGE_ID = "sha256:" + h("image 1")
ARCHIVE = h("archive 1")
SNAP = "snap_0123456789ab"


def content_sha(image_id: str = IMAGE_ID, archive: str = ARCHIVE) -> str:
    """Recomputed here with no help from the front: the plan's canonical document."""
    doc = {"schema": "cathedral_snapshot_content_v1", "image_id": image_id, "work_archive_sha256": archive}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def answer(snap: str = SNAP, **over) -> dict:
    result = {"snapshot_id": snap, "size_bytes": 4096, "committed_image_id": IMAGE_ID, "work_archive_sha256": ARCHIVE}
    result.update(over)
    return {"operation_id": "op_1", "status": "done", "result": result}


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def room(front: Front, body: dict | None = None) -> str:
    status, _h, out = front.create(body)
    assert status == 200, out
    return json.loads(out)["id"]


def machine_says(front: Front, status: int, body, route: str = r"POST /v1/sandboxes/[^/]+/snapshot") -> None:
    front.api.replies.clear()
    front.api.reply(route, status, body if isinstance(body, bytes) else json.dumps(body).encode())


def snapshot(front: Front, source: str, snap: str = SNAP, body: dict | None = None, **over):
    machine_says(front, 202, answer(snap, **over))
    return front.call("POST", f"/v1/sandboxes/{source}/snapshot", body if body is not None else {})


def snapshot_ok(front: Front, source: str, snap: str = SNAP, **over) -> dict:
    status, headers, out = snapshot(front, source, snap, **over)
    assert status == 202, out
    return receipt_of(headers)


def fork(front: Front, snap: str = SNAP, **extra):
    return front.call("POST", "/v1/sandboxes", {"snapshot_id": snap, **extra})


def snapshot_delete(front: Front, snap: str = SNAP, status: int = 200, body=None):
    front.api.replies.clear()
    front.api.reply(r"DELETE /v1/snapshots/[^/]+", status, {"deleted": True} if body is None else body)
    return front.call("DELETE", f"/v1/snapshots/{snap}")


def members(statement: dict) -> dict:
    return {k: v for k, v in statement.items() if k.startswith("snapshot_")}


def code(out: bytes) -> str:
    return json.loads(out)["error"]["code"]


def chain_actions(front: Front) -> list[str]:
    with front.ledger.lock:
        return [r["statement"]["action"] for r in front.ledger.chain]


# ---------------------------------------------------------------- the rows

def test_signed_table_has_a_snapshot_row_and_a_snapshot_delete_row() -> None:
    def action(method: str, path: str):
        return next((a for m, p, a in rr.SIGNED if m == method and p.match(path)), None)

    assert action("POST", "/v1/sandboxes/sbx_1/snapshot") == "snapshot"
    assert action("DELETE", "/v1/snapshots/snap_x") == "snapshot_delete"
    assert action("GET", "/v1/snapshots") is None  # a list changes nothing
    assert action("POST", "/v1/snapshots/snap_x/push") is None  # refused by the front, never signed


# ---------------------------------------------------------------- the snapshot receipt

def test_a_2xx_snapshot_receipt_carries_the_five_snapshot_members_with_these_types(front) -> None:
    a = room(front)
    st = snapshot_ok(front, a)["statement"]
    assert st["action"] == "snapshot" and st["sandbox_id"] == a and st["status"] == 202
    assert st["target"] == f"POST /v1/sandboxes/{a}/snapshot"
    assert st["command_sha256"] is None and st["image"] is None and st["image_digest"] is None
    assert members(st) == {
        "snapshot_id": SNAP, "snapshot_image_id": IMAGE_ID, "snapshot_work_archive_sha256": ARCHIVE,
        "snapshot_size_bytes": 4096, "snapshot_content_sha256": content_sha()}
    assert type(st["snapshot_size_bytes"]) is int


def test_the_content_hash_is_computed_by_the_front_from_the_two_parts_not_copied_from_the_machine(front) -> None:
    a = room(front)
    # a machine that sent its own "content_sha256" must not be believed
    st = snapshot_ok(front, a, content_sha256="f" * 64, snapshot_content_sha256="e" * 64)["statement"]
    assert st["snapshot_content_sha256"] == content_sha()
    other = snapshot_ok(front, a, "snap_0123456789ac", committed_image_id="sha256:" + h("image 2"))["statement"]
    assert other["snapshot_content_sha256"] == content_sha("sha256:" + h("image 2"))
    assert other["snapshot_content_sha256"] != st["snapshot_content_sha256"]


def test_the_snapshot_receipt_hashes_the_request_and_the_answer_the_caller_got(front) -> None:
    a = room(front)
    body = {"ttl_seconds": 600, "labels": {"k": "v"}}
    status, headers, out = snapshot(front, a, body=body)
    st = receipt_of(headers)["statement"]
    assert st["customer_request_sha256"] == rr.sha(json.dumps(body).encode()) and st["result_sha256"] == rr.sha(out)


@pytest.mark.parametrize("status", [400, 404, 409, 413, 422, 429, 500, 502, 503])
def test_a_machine_error_makes_a_receipt_with_no_snapshot_member_and_no_snapshot(front, status) -> None:
    a = room(front)
    machine_says(front, status, {"error": {"code": "snapshot_in_progress", "message": "x"}})
    got, headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    st = receipt_of(headers)["statement"]
    assert got == status and st["action"] == "snapshot" and st["status"] == status and members(st) == {}
    # nothing was remembered: a fork of the id the error might have named is refused
    assert fork(front)[0] == 404


def test_a_machine_error_that_still_carries_the_fields_gets_no_snapshot_member(front) -> None:
    a = room(front)
    machine_says(front, 409, answer())
    _status, headers, _out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    assert members(receipt_of(headers)["statement"]) == {}
    assert fork(front)[0] == 404


FIELD_BAD = {
    "image_id_missing": lambda r: r.pop("committed_image_id"),
    "archive_missing": lambda r: r.pop("work_archive_sha256"),
    "size_missing": lambda r: r.pop("size_bytes"),
    "snapshot_id_missing": lambda r: r.pop("snapshot_id"),
    "image_id_without_prefix": lambda r: r.update(committed_image_id=h("image 1")),
    "image_id_one_short": lambda r: r.update(committed_image_id="sha256:" + h("i")[:63]),
    "image_id_one_long": lambda r: r.update(committed_image_id="sha256:" + h("i") + "0"),
    "image_id_upper_case": lambda r: r.update(committed_image_id="sha256:" + h("i").upper()),
    "image_id_not_hex": lambda r: r.update(committed_image_id="sha256:" + "g" * 64),
    "image_id_int": lambda r: r.update(committed_image_id=5),
    "image_id_null": lambda r: r.update(committed_image_id=None),
    "archive_one_short": lambda r: r.update(work_archive_sha256=h("a")[:63]),
    "archive_one_long": lambda r: r.update(work_archive_sha256=h("a") + "0"),
    "archive_not_hex": lambda r: r.update(work_archive_sha256="z" * 64),
    "archive_with_prefix": lambda r: r.update(work_archive_sha256="sha256:" + h("a")),
    "archive_upper_case": lambda r: r.update(work_archive_sha256=h("a").upper()),
    "archive_int": lambda r: r.update(work_archive_sha256=7),
    "size_bool": lambda r: r.update(size_bytes=True),
    "size_negative": lambda r: r.update(size_bytes=-1),
    "size_string": lambda r: r.update(size_bytes="4096"),
    "size_float": lambda r: r.update(size_bytes=4096.5),
    "size_null": lambda r: r.update(size_bytes=None),
    "snapshot_id_int": lambda r: r.update(snapshot_id=3),
    "snapshot_id_empty": lambda r: r.update(snapshot_id=""),
    "snapshot_id_with_slash": lambda r: r.update(snapshot_id="snap_a/b"),
}


@pytest.mark.parametrize("name", sorted(FIELD_BAD))
def test_a_2xx_answer_with_a_missing_or_malformed_field_is_unsigned_502_and_not_remembered(front, name) -> None:
    a = room(front)
    doc = answer()
    FIELD_BAD[name](doc["result"])
    machine_says(front, 202, doc)
    status, headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    st = receipt_of(headers)["statement"]
    assert status == 502 and code(out) == "snapshot_unsigned"
    assert st["action"] == "snapshot" and st["status"] == 502 and members(st) == {}
    assert st["result_sha256"] == rr.sha(out)  # the receipt names the answer the caller got
    assert fork(front)[0] == 404


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'"x"', b"{}", b'{"result": null}', b'{"result": []}',
                                 b'{"committed_image_id": "x", "work_archive_sha256": "y", "snapshot_id": "snap_q"}'])
def test_a_2xx_answer_with_no_usable_result_object_is_unsigned_502(front, raw) -> None:
    a = room(front)
    machine_says(front, 202, raw)
    status, headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    assert status == 502 and code(out) == "snapshot_unsigned"
    assert members(receipt_of(headers)["statement"]) == {}


def test_a_snapshot_the_machine_never_answered_is_a_502_receipt_with_no_member_and_no_fork(front) -> None:
    # As for every lost answer on this front: 502 hotel_api_no_answer, and the receipt records the failure.
    a = room(front)
    machine_says(front, 202, answer())
    front.api.drop(rf"POST /v1/sandboxes/{a}/snapshot")
    status, headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    st = receipt_of(headers)["statement"]
    assert status == 502 and code(out) == "hotel_api_no_answer"
    assert st["action"] == "snapshot" and st["status"] == 502 and members(st) == {}
    assert fork(front)[0] == 404
    assert_idle(front.ledger)


def test_the_snapshot_receipt_is_signed_only_after_the_machine_answers(front) -> None:
    a = room(front)
    machine_says(front, 202, answer())
    held = front.api.hold(rf"POST /v1/sandboxes/{a}/snapshot")
    t, box = in_thread(front.call, "POST", f"/v1/sandboxes/{a}/snapshot", {})
    held.wait_entered()
    assert chain_actions(front) == ["create"]
    assert fork(front)[0] == 404  # not remembered while the machine is still saving
    held.release.set()
    status, headers, _out = finish(t, box)
    assert status == 202 and chain_actions(front) == ["create", "snapshot"]
    assert receipt_of(headers)["statement"]["sequence"] == 2


def test_a_result_source_sandbox_id_equal_to_the_path_room_is_signed(front) -> None:
    a = room(front)
    st = snapshot_ok(front, a, source_sandbox_id=a)["statement"]
    assert members(st)["snapshot_id"] == SNAP and "source_sandbox_id" not in st


def test_an_absent_result_source_sandbox_id_means_the_path_room_is_the_source(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    fst = receipt_of(fork(front)[1])["statement"]
    assert fst["snapshot_source_sandbox_id"] == a


@pytest.mark.parametrize("claimed", ["sbx_other", "", None, 7])
def test_a_result_source_sandbox_id_that_differs_from_the_path_room_is_unsigned_502(front, claimed) -> None:
    a = room(front)
    status, headers, out = snapshot(front, a, source_sandbox_id=claimed)
    assert status == 502 and code(out) == "snapshot_unsigned"
    assert members(receipt_of(headers)["statement"]) == {}
    assert fork(front)[0] == 404


def test_d9_a_tar_only_result_with_no_image_id_gets_no_members_and_502_never_a_tar_only_snapshot(front) -> None:
    a = room(front)
    doc = answer()
    del doc["result"]["committed_image_id"]  # the tar was written, the image was not committed
    machine_says(front, 202, doc)
    status, headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    assert status == 502 and code(out) == "snapshot_unsigned"
    assert members(receipt_of(headers)["statement"]) == {}
    assert fork(front)[0] == 404


def test_a_2xx_answer_for_a_held_snapshot_through_another_room_signs_nothing_and_keeps_the_entry(front) -> None:
    a, c = room(front), room(front)
    first = snapshot_ok(front, a)
    status, headers, out = snapshot(front, c)  # same id X, room C's path
    assert status == 502 and code(out) == "snapshot_unsigned" and members(receipt_of(headers)["statement"]) == {}
    fst = receipt_of(fork(front)[1])["statement"]
    assert fst["snapshot_source_sandbox_id"] == a and fst["snapshot_receipt_sha256"] == first["receipt_sha256"]


# ---------------------------------------------------------------- numbering

def test_the_snapshot_takes_room_as_next_room_number_and_links_to_the_receipt_before(front) -> None:
    a = room(front)
    front.exec(a)
    snap = snapshot_ok(front, a)
    st = snap["statement"]
    before = front.room_receipts(a)["receipts"][1]
    assert st["room_sequence"] == 3 and st["room_previous_receipt_sha256"] == before["receipt_sha256"]
    assert [s["room_sequence"] for s in front.statements(a)] == [1, 2, 3]


def test_repeated_snapshots_of_one_room_each_get_their_own_receipt_and_number(front) -> None:
    a = room(front)
    first = snapshot_ok(front, a, "snap_000000000001")["statement"]
    second = snapshot_ok(front, a, "snap_000000000002", committed_image_id="sha256:" + h("image 2"))["statement"]
    assert (first["room_sequence"], second["room_sequence"]) == (2, 3)
    assert second["room_previous_receipt_sha256"] == front.room_receipts(a)["receipts"][1]["receipt_sha256"]
    assert first["snapshot_content_sha256"] != second["snapshot_content_sha256"]
    assert first["operation_id"] != second["operation_id"]


def test_a_repeat_receipt_for_the_same_id_and_content_keeps_the_first_receipt_as_the_fork_source(front) -> None:
    # A named snapshot is get-or-create on the machine: the same id comes back.
    a = room(front)
    first = snapshot_ok(front, a)
    second = snapshot_ok(front, a)
    assert first["statement"]["room_sequence"] == 2 and second["statement"]["room_sequence"] == 3
    assert members(first["statement"]) == members(second["statement"])
    _status, headers, _out = fork(front)
    assert receipt_of(headers)["statement"]["snapshot_receipt_sha256"] == first["receipt_sha256"]


@pytest.mark.parametrize("change", ["content", "source room"])
def test_a_repeat_that_contradicts_the_first_receipt_is_unsigned_502_and_the_first_stays(front, change) -> None:
    a = room(front)
    first = snapshot_ok(front, a)
    if change == "content":
        status, headers, out = snapshot(front, a, committed_image_id="sha256:" + h("image 9"))
    else:
        b = room(front)
        status, headers, out = snapshot(front, b)
    st = receipt_of(headers)["statement"]
    assert status == 502 and code(out) == "snapshot_unsigned" and members(st) == {}
    _status, fork_headers, _out = fork(front)
    fst = receipt_of(fork_headers)["statement"]
    assert fst["snapshot_receipt_sha256"] == first["receipt_sha256"] and fst["snapshot_content_sha256"] == content_sha()


# ---------------------------------------------------------------- the fork receipt

def test_the_fork_create_receipt_names_its_source_with_the_front_s_own_values(front) -> None:
    a = room(front)
    snap = snapshot_ok(front, a)
    status, headers, out = fork(front)
    assert status == 200
    st = receipt_of(headers)["statement"]
    assert st["action"] == "create" and st["status"] == 200 and st["image"] is None
    assert members(st) == {"snapshot_id": SNAP, "snapshot_content_sha256": content_sha(),
                           "snapshot_receipt_sha256": snap["receipt_sha256"], "snapshot_source_sandbox_id": a}
    assert snap["receipt_sha256"] == rr.sha(rr.canonical(snap["statement"]))


def test_the_fork_values_come_from_the_front_not_from_the_request_or_the_answer(front) -> None:
    a = room(front)
    snap = snapshot_ok(front, a)
    front.api.create_answer = {"snapshot_content_sha256": "d" * 64, "snapshot_source_sandbox_id": "sbx_liar"}
    _status, headers, _out = fork(front, snapshot_receipt_sha256="c" * 64, snapshot_content_sha256="b" * 64)
    st = receipt_of(headers)["statement"]
    assert st["snapshot_content_sha256"] == content_sha() and st["snapshot_source_sandbox_id"] == a
    assert st["snapshot_receipt_sha256"] == snap["receipt_sha256"]


def test_the_fork_is_room_b_number_one_and_links_to_a_only_through_the_snapshot_receipt(front) -> None:
    a = room(front)
    snap = snapshot_ok(front, a)
    _status, headers, out = fork(front)
    b = json.loads(out)["id"]
    st = receipt_of(headers)["statement"]
    assert b != a and st["sandbox_id"] == b
    assert st["room_sequence"] == 1 and st["room_previous_receipt_sha256"] is None
    assert [s["room_sequence"] for s in front.statements(a)] == [1, 2]  # the fork took no number of A
    assert st["snapshot_receipt_sha256"] == snap["receipt_sha256"]


def test_two_forks_of_one_snapshot_each_name_the_same_snapshot_receipt(front) -> None:
    a = room(front)
    snap = snapshot_ok(front, a)
    got = [receipt_of(fork(front)[1])["statement"] for _ in range(2)]
    assert got[0]["sandbox_id"] != got[1]["sandbox_id"]
    assert {s["snapshot_receipt_sha256"] for s in got} == {snap["receipt_sha256"]}


def test_a_fork_of_a_snapshot_this_front_has_no_receipt_for_is_404_snapshot_not_found_unsent_unsigned(front) -> None:
    room(front)
    before = len(front.api.seen)
    status, headers, out = fork(front, "snap_ffffffffffff")
    assert status == 404 and code(out) == "snapshot_not_found" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == before and chain_actions(front) == ["create"]
    assert_idle(front.ledger)


def test_a_failed_fork_create_has_no_source_members(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    front.api.replies.clear()
    front.api.reply(r"POST /v1/sandboxes", 409, {"error": {"code": "snapshot_deleting", "message": "x"}})
    status, headers, _out = fork(front)
    st = receipt_of(headers)["statement"]
    assert status == 409 and st["action"] == "create" and st["status"] == 409 and members(st) == {}


@pytest.mark.parametrize("value", [None, 5, ["snap_a"], {"id": "snap_a"}, ""])
def test_a_create_with_no_usable_snapshot_id_is_forwarded_as_sent_and_has_no_source_members(front, value) -> None:
    # The real API: snapshot_id null is no source, so image alone is one source and the create is made (200);
    # any other value next to an image is two sources, or a blank or non-string id, and answers 422.
    if value is not None:
        front.api.reply(r"POST /v1/sandboxes", 422, {"error": {"code": "invalid_source", "message": "x"}})
    body = {"image": "repo/app:1", "snapshot_id": value}
    status, headers, _out = front.create(body)
    st = receipt_of(headers)["statement"]
    assert status == (200 if value is None else 422) and st["status"] == status and members(st) == {}
    assert json.loads(front.api.seen[-1][2]) == body  # forwarded as sent, never lost in the front
    assert front.api.count(r"POST /v1/sandboxes") == 1


def test_an_ordinary_create_carries_no_source_members(front) -> None:
    _status, headers, _out = front.create()
    assert members(receipt_of(headers)["statement"]) == {}


def test_a_fork_that_carries_the_pool_label_is_400_reserved_label_invalid_unsent_unsigned(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    before = len(front.api.seen)
    status, headers, out = fork(front, labels={"cathedral_pool": "1"})
    assert status == 400 and code(out) == "reserved_label_invalid" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == before
    # the same label on an ordinary create is not this rule's business: it passes as on main
    assert front.create({"image": "repo/app:1", "labels": {"cathedral_pool": "1"}})[0] == 200
    assert_idle(front.ledger)


# ---------------------------------------------------------------- snapshot_delete and push

def test_snapshot_delete_is_signed_with_a_null_sandbox_id_and_names_the_snapshot_and_its_source(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    status, headers, _out = snapshot_delete(front)
    st = receipt_of(headers)["statement"]
    assert status == 200 and st["action"] == "snapshot_delete" and st["status"] == 200
    assert st["target"] == f"DELETE /v1/snapshots/{SNAP}" and st["sandbox_id"] is None
    assert members(st) == {"snapshot_id": SNAP, "snapshot_source_sandbox_id": a}
    assert "room_sequence" not in st and "room_previous_receipt_sha256" not in st
    assert [s["action"] for s in front.statements(a)] == ["create", "snapshot"]  # not in room A's list
    assert chain_actions(front) == ["create", "snapshot", "snapshot_delete"]


def test_snapshot_delete_of_an_id_the_front_does_not_know_names_the_id_and_no_source(front) -> None:
    room(front)
    status, headers, _out = snapshot_delete(front, "snap_aaaaaaaaaaaa")
    st = receipt_of(headers)["statement"]
    assert status == 200 and st["sandbox_id"] is None and members(st) == {"snapshot_id": "snap_aaaaaaaaaaaa"}


def test_a_failed_snapshot_delete_is_signed_with_its_status_and_the_snapshot_stays_forkable(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    status, headers, _out = snapshot_delete(front, status=500, body={"error": {"code": "x", "message": "y"}})
    st = receipt_of(headers)["statement"]
    assert status == 500 and st["action"] == "snapshot_delete" and st["status"] == 500
    assert fork(front)[0] == 200


def test_snapshot_delete_then_fork_is_404_snapshot_not_found(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    assert snapshot_delete(front)[0] == 200
    before = len(front.api.seen)
    status, headers, out = fork(front)
    assert status == 404 and code(out) == "snapshot_not_found" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == before


def test_a_snapshot_that_is_snapshotted_again_after_its_delete_is_remembered_afresh(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    snapshot_delete(front)
    again = snapshot_ok(front, a)
    _status, headers, _out = fork(front)
    assert receipt_of(headers)["statement"]["snapshot_receipt_sha256"] == again["receipt_sha256"]


def test_pushing_a_snapshot_is_403_snapshot_push_refused_unsent_unsigned(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    before = len(front.api.seen)
    status, headers, out = front.call("POST", f"/v1/snapshots/{SNAP}/push", {"image": "evil.example/x:1"})
    assert status == 403 and code(out) == "snapshot_push_refused" and "X-Room-Receipt" not in headers
    assert len(front.api.seen) == before and chain_actions(front) == ["create", "snapshot"]


# ---------------------------------------------------------------- stale and terminal states

def test_a_front_restart_loses_the_map_so_a_fork_is_refused_but_a_delete_is_still_signed(front, tmp_path) -> None:
    a = room(front)
    snapshot_ok(front, a)
    assert fork(front)[0] == 200
    # The in-memory state is gone, as in a restart: a new ledger, a new key, an empty chain.
    front.server.ledger = rr.Ledger("room-a", str(tmp_path / "second-boot"))
    sent = front.api.count(r"POST /v1/sandboxes")
    status, headers, out = fork(front)
    assert front.api.count(r"POST /v1/sandboxes") == sent  # nothing was sent to the machine
    assert status == 404 and code(out) == "snapshot_not_found" and "X-Room-Receipt" not in headers
    status, headers, _out = snapshot_delete(front)
    st = receipt_of(headers)["statement"]
    assert status == 200 and st["action"] == "snapshot_delete" and members(st) == {"snapshot_id": SNAP}
    # a new snapshot of the same room under the new boot is remembered under the new chain
    assert len(front.server.ledger.chain) == 1


def test_a_fork_after_room_a_was_deleted_still_works_and_names_the_deleted_source(front) -> None:
    a = room(front)
    snap = snapshot_ok(front, a)
    assert front.delete(a)[0] == 200
    _status, headers, _out = fork(front)
    st = receipt_of(headers)["statement"]
    assert st["snapshot_source_sandbox_id"] == a and st["snapshot_receipt_sha256"] == snap["receipt_sha256"]
    assert st["room_sequence"] == 1


def test_a_snapshot_of_a_room_already_deleted_gets_the_machine_404_and_no_snapshot_member(front) -> None:
    a = room(front)
    front.delete(a)
    machine_says(front, 404, {"error": {"code": "sandbox_not_found", "message": "x"}})
    status, headers, _out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    st = receipt_of(headers)["statement"]
    assert status == 404 and members(st) == {} and st["room_sequence"] == 3
    assert fork(front)[0] == 404


# ---------------------------------------------------------------- concurrency

def _wait_for(count_fn, want: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline and count_fn() < want:
        time.sleep(0.01)
    assert count_fn() >= want


def test_two_snapshots_of_an_ordinary_room_at_once_both_reach_the_machine_and_get_distinct_numbers(front) -> None:
    # No front lock is held while the machine works: an ordinary room has no token, and the ledger lock is
    # taken only to number, sign and remember in one step (Ledger.sign), as for any other receipt.
    a = room(front)
    machine_says(front, 202, answer())
    held = front.api.hold(rf"POST /v1/sandboxes/{a}/snapshot")
    pair = [in_thread(front.call, "POST", f"/v1/sandboxes/{a}/snapshot", {}) for _ in range(2)]
    _wait_for(lambda: front.api.count(rf"POST /v1/sandboxes/{a}/snapshot"), 2)
    held.release.set()
    results = [finish(t, box) for t, box in pair]
    assert [r[0] for r in results] == [202, 202]
    statements = [receipt_of(r[1])["statement"] for r in results]
    assert sorted(s["room_sequence"] for s in statements) == [2, 3]
    assert [s["room_sequence"] for s in front.statements(a)] == [1, 2, 3]
    first = min(statements, key=lambda s: s["sequence"])
    _status, headers, _out = fork(front)
    assert receipt_of(headers)["statement"]["snapshot_receipt_sha256"] == rr.sha(rr.canonical(first))
    assert_idle(front.ledger)


def test_the_machine_s_own_409_snapshot_in_progress_is_passed_on_and_signed_with_no_member(front) -> None:
    a = room(front)
    machine_says(front, 409, {"error": {"code": "snapshot_in_progress", "message": "x"}})
    status, headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    st = receipt_of(headers)["statement"]
    assert status == 409 and code(out) == "snapshot_in_progress" and st["status"] == 409 and members(st) == {}


def test_a_fork_racing_a_snapshot_delete_the_fork_sent_before_the_delete_ended_names_its_source(front) -> None:
    # The map is read and changed only under the ledger lock, never across the machine call. A fork that
    # passed the lookup keeps what it read; a fork asked after the delete is signed is refused.
    a = room(front)
    snap = snapshot_ok(front, a)
    held = front.api.hold(r"POST /v1/sandboxes")
    t, box = in_thread(fork, front)
    held.wait_entered()
    assert snapshot_delete(front)[0] == 200
    assert fork(front)[0] == 404
    held.release.set()
    status, headers, _out = finish(t, box)
    st = receipt_of(headers)["statement"]
    assert status == 200 and st["snapshot_receipt_sha256"] == snap["receipt_sha256"]
    assert chain_actions(front) == ["create", "snapshot", "snapshot_delete", "create"]
    assert_idle(front.ledger)


def test_a_fork_racing_a_snapshot_delete_the_snapshot_is_forgotten_only_when_the_delete_is_answered(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    front.api.replies.clear()
    front.api.reply(r"DELETE /v1/snapshots/[^/]+", 200, {"deleted": True})
    held = front.api.hold(r"DELETE /v1/snapshots/[^/]+")
    t, box = in_thread(front.call, "DELETE", f"/v1/snapshots/{SNAP}")
    held.wait_entered()
    assert fork(front)[0] == 200  # the delete has not ended: the snapshot is still known
    held.release.set()
    assert finish(t, box)[0] == 200
    assert fork(front)[0] == 404
    assert_idle(front.ledger)


def test_a_capture_answer_that_arrives_after_its_snapshot_was_deleted_is_502_and_the_entry_stays_gone(front) -> None:
    # Schedule: capture of X sent, its answer delayed, DELETE X succeeds, the answer arrives.
    a = room(front)
    front.api.replies.clear()
    front.api.reply(rf"POST /v1/sandboxes/{a}/snapshot", 202, answer())
    front.api.reply(r"DELETE /v1/snapshots/[^/]+", 200, {"deleted": True})
    held = front.api.hold(rf"POST /v1/sandboxes/{a}/snapshot")
    t, box = in_thread(front.call, "POST", f"/v1/sandboxes/{a}/snapshot", {})
    held.wait_entered()
    assert front.call("DELETE", f"/v1/snapshots/{SNAP}")[0] == 200
    held.release.set()
    status, headers, out = finish(t, box)
    assert status == 502 and code(out) == "snapshot_unsigned" and members(receipt_of(headers)["statement"]) == {}
    before = front.api.count(r"POST /v1/sandboxes")
    status, headers, out = fork(front)
    assert status == 404 and code(out) == "snapshot_not_found" and "X-Room-Receipt" not in headers
    assert front.api.count(r"POST /v1/sandboxes") == before
    assert_idle(front.ledger)


def test_a_capture_begun_after_the_delete_is_remembered_even_though_the_id_was_deleted_before(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    snapshot_delete(front)
    again = snapshot_ok(front, a)
    assert receipt_of(fork(front)[1])["statement"]["snapshot_receipt_sha256"] == again["receipt_sha256"]


def test_the_map_caps_are_a_module_constant_of_4096() -> None:
    assert rr.SNAPSHOT_MAP_CAP == 4096


def test_the_snapshot_map_evicts_the_oldest_first_and_a_fork_of_an_evicted_one_is_refused_unsent(front, monkeypatch) -> None:
    monkeypatch.setattr(rr, "SNAPSHOT_MAP_CAP", 3)
    a = room(front)
    ids = [f"snap_00000000000{n}" for n in range(1, 6)]
    for sid in ids:
        snapshot_ok(front, a, sid)
    sent = front.api.count(r"POST /v1/sandboxes")
    status, headers, out = fork(front, ids[0])
    assert status == 404 and code(out) == "snapshot_not_found" and "X-Room-Receipt" not in headers
    assert fork(front, ids[1])[0] == 404
    assert front.api.count(r"POST /v1/sandboxes") == sent  # nothing was sent for the evicted two
    for sid in ids[2:]:  # the newest three are kept
        assert fork(front, sid)[0] == 200


def test_a_delete_during_a_capture_wins_however_many_other_deletes_follow(front, monkeypatch) -> None:
    # The in-flight capture is tracked directly, so no cap on anything can let the deleted id come back.
    monkeypatch.setattr(rr, "SNAPSHOT_MAP_CAP", 2)
    a, b = room(front), room(front)

    def machine(other: str) -> None:
        front.api.replies.clear()
        front.api.reply(rf"POST /v1/sandboxes/{a}/snapshot", 202, answer())
        front.api.reply(rf"POST /v1/sandboxes/{b}/snapshot", 202, answer(other))
        front.api.reply(r"DELETE /v1/snapshots/[^/]+", 200, {"deleted": True})

    machine("snap_00000000000f")
    held = front.api.hold(rf"POST /v1/sandboxes/{a}/snapshot")
    t, box = in_thread(front.call, "POST", f"/v1/sandboxes/{a}/snapshot", {})
    held.wait_entered()
    assert front.call("DELETE", f"/v1/snapshots/{SNAP}")[0] == 200
    for n in range(1, 6):  # five other captures and deletes: past a cap of 2
        other = f"snap_00000000000{n}"
        machine(other)
        assert front.call("POST", f"/v1/sandboxes/{b}/snapshot", {})[0] == 202
        assert front.call("DELETE", f"/v1/snapshots/{other}")[0] == 200
    held.release.set()
    status, headers, out = finish(t, box)
    assert status == 502 and code(out) == "snapshot_unsigned" and members(receipt_of(headers)["statement"]) == {}
    sent = front.api.count(r"POST /v1/sandboxes")
    assert fork(front)[0] == 404 and front.api.count(r"POST /v1/sandboxes") == sent
    assert_idle(front.ledger)


def test_a_delete_marks_every_capture_in_flight_and_only_those(front) -> None:
    a, b = room(front), room(front)
    front.api.replies.clear()
    front.api.reply(rf"POST /v1/sandboxes/{a}/snapshot", 202, answer())
    front.api.reply(rf"POST /v1/sandboxes/{b}/snapshot", 202, answer("snap_0000000000bb"))
    front.api.reply(r"DELETE /v1/snapshots/[^/]+", 200, {"deleted": True})
    held = front.api.hold(rf"POST /v1/sandboxes/{a}/snapshot")
    ta, boxa = in_thread(front.call, "POST", f"/v1/sandboxes/{a}/snapshot", {})
    held.wait_entered()
    assert front.call("DELETE", "/v1/snapshots/snap_0000000000bb")[0] == 200  # another id: A's capture is unmarked
    held.release.set()
    assert finish(ta, boxa)[0] == 202
    assert fork(front)[0] == 200


def test_a_late_not_found_does_not_remove_a_replacement_entry(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    held = front.api.hold(r"POST /v1/sandboxes")
    t, box = in_thread(fork, front)  # admitted against the first X
    held.wait_entered()
    assert snapshot_delete(front)[0] == 200
    replacement = snapshot_ok(front, a)  # a new X, a new receipt
    front.api.reply(r"POST /v1/sandboxes", 404, {"error": {"code": "snapshot_not_found", "message": "no snapshot"}})
    held.release.set()
    assert finish(t, box)[0] == 404  # the old fork's own answer
    front.api.replies.clear()
    held.release.set()
    status, headers, _out = fork(front)
    assert status == 200
    assert receipt_of(headers)["statement"]["snapshot_receipt_sha256"] == replacement["receipt_sha256"]
    assert_idle(front.ledger)


def test_a_machine_answer_snapshot_not_found_to_a_fork_drops_the_entry(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    front.api.replies.clear()
    front.api.reply(r"POST /v1/sandboxes", 404, {"error": {"code": "snapshot_not_found", "message": "no snapshot"}})
    status, headers, _out = fork(front)
    assert status == 404 and members(receipt_of(headers)["statement"]) == {}  # the failed create is signed
    front.api.replies.clear()
    sent = front.api.count(r"POST /v1/sandboxes")
    status, headers, out = fork(front)
    assert status == 404 and code(out) == "snapshot_not_found" and "X-Room-Receipt" not in headers
    assert front.api.count(r"POST /v1/sandboxes") == sent  # now refused by the front, unsent


@pytest.mark.parametrize("status,error", [(404, "sandbox_not_found"), (409, "snapshot_deleting"), (500, "boom"),
                                          (503, "snapshot_not_found")])
def test_any_other_machine_answer_to_a_fork_keeps_the_entry(front, status, error) -> None:
    a = room(front)
    snapshot_ok(front, a)
    front.api.replies.clear()
    front.api.reply(r"POST /v1/sandboxes", status, {"error": {"code": error, "message": "x"}})
    assert fork(front)[0] == status
    front.api.replies.clear()
    assert fork(front)[0] == 200


# ---------------------------------------------------------------- the exec result store (main's AB#536)

def _kept_exec(front: Front, room_id: str, handle: str = "cd" * 16) -> bytes:
    status, _h, _out = front.call("POST", f"/v1/sandboxes/{room_id}/exec", {"cmd": ["true"]},
                                  {"X-Room-Exec-Handle": handle})
    assert status == 200
    status, _h, out = front.call("GET", f"/v1/sandboxes/{room_id}/exec/result?handle={handle}")
    assert status == 200
    return out


def test_a_fork_starts_with_none_of_its_source_s_kept_exec_results(front) -> None:
    a = room(front)
    _kept_exec(front, a)
    snapshot_ok(front, a)
    _status, _headers, out = fork(front)
    b = json.loads(out)["id"]
    status, _headers, out = front.call("GET", f"/v1/sandboxes/{b}/exec/result?handle=" + "cd" * 16)
    assert status == 404 and code(out) == "exec_unknown"


def test_a_snapshot_of_a_room_leaves_that_room_s_kept_exec_results_as_they_were(front) -> None:
    a = room(front)
    before = _kept_exec(front, a)
    snapshot_ok(front, a)
    status, _headers, after = front.call("GET", f"/v1/sandboxes/{a}/exec/result?handle=" + "cd" * 16)
    assert status == 200 and after == before


# ---------------------------------------------------------------- serial rooms

def test_a_serial_room_takes_a_snapshot_as_a_signed_request_in_its_turn(front) -> None:
    a = room(front, SERIAL)
    st = snapshot_ok(front, a)["statement"]
    assert st["action"] == "snapshot" and st["room_sequence"] == 2 and members(st)["snapshot_id"] == SNAP
    assert front.exec(a)[0] == 200
    assert [s["room_sequence"] for s in front.statements(a)] == [1, 2, 3]
    assert_idle(front.ledger)


def test_a_serial_room_busy_with_a_snapshot_refuses_the_next_request_409_room_busy_unsent(front) -> None:
    a = room(front, SERIAL)
    machine_says(front, 202, answer())
    held = front.api.hold(rf"POST /v1/sandboxes/{a}/snapshot")
    t, box = in_thread(front.call, "POST", f"/v1/sandboxes/{a}/snapshot", {})
    held.wait_entered()
    status, headers, out = front.exec(a)
    assert status == 409 and code(out) == "room_busy" and "X-Room-Receipt" not in headers
    status, _headers, out = front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    assert status == 409 and code(out) == "room_busy"
    assert front.api.count(rf"POST /v1/sandboxes/{a}/snapshot") == 1
    held.release.set()
    assert finish(t, box)[0] == 202
    assert_idle(front.ledger)


def test_a_serial_room_that_loses_a_snapshot_answer_is_broken_until_it_is_deleted(front) -> None:
    a = room(front, SERIAL)
    machine_says(front, 202, answer())
    front.api.drop(rf"POST /v1/sandboxes/{a}/snapshot", 1)
    try:
        front.call("POST", f"/v1/sandboxes/{a}/snapshot", {})
    except Exception:  # noqa: BLE001 the connection closed with no answer
        pass
    status, _headers, out = front.exec(a)
    assert status == 409 and code(out) == "room_broken"
    assert front.delete(a)[0] == 200
    assert_idle(front.ledger)


def test_a_serial_room_snapshot_receipt_has_the_same_members_as_any_other(front) -> None:
    plain, serial = room(front), room(front, SERIAL)
    p = members(snapshot_ok(front, plain, "snap_00000000000a")["statement"])
    s = members(snapshot_ok(front, serial, "snap_00000000000b")["statement"])
    assert set(p) == set(s) == set(SNAP_MEMBERS)


def test_a_fork_is_never_serial_unless_it_asks_and_a_serial_fork_is_flagged_like_a_serial_create(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    assert "serial" not in receipt_of(fork(front)[1])["statement"]
    status, headers, _out = fork(front, labels={"cathedral_serial": "1"})
    st = receipt_of(headers)["statement"]
    assert status == 200 and st["serial"] is True and st["room_sequence"] == 1
    assert st["snapshot_source_sandbox_id"] == a


# ---------------------------------------------------------------- old callers

def scripted_old_actions(front: Front, monkeypatch) -> bytes:
    """A fixed run of old actions with a fixed key, clock and ids; the receipts' canonical bytes, one per line.

    Ordinary creates (no snapshot_id, null, blank, an unrelated member named snapshot_note), a failed action,
    exec, file put and get, a process start, a network change, a delete and a bulk delete.
    """
    led = front.ledger
    led.key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"snapshot-fork old-caller pin key").digest())
    led.hotel = "pin-hotel"
    led.binding_sha256 = h("old-caller pin binding")
    led.head = led.binding_sha256
    counter = itertools.count(1)
    monkeypatch.setattr(rr.uuid, "uuid4", lambda: uuid.UUID(int=next(counter)))
    monkeypatch.setattr(rr.time, "time", lambda: 1_700_000_000)
    monkeypatch.setattr(front.server, "image_digest", lambda ref: None)
    front.api.expires_at = "2023-11-14T22:13:20+00:00"
    front.api.new_ids = ["sbx_pin_1", "sbx_pin_2", "sbx_pin_3", "sbx_pin_4"]
    assert front.create({"image": "repo/app:1"})[0] == 200
    assert front.create({"image": "repo/other:2", "labels": {"k": "v"}})[0] == 200
    assert front.create({"image": "repo/app:1", "snapshot_id": None})[0] == 200
    assert front.create({"image": "repo/app:1", "snapshot_note": "x", "labels": {"snapshot_k": "v"}})[0] == 200
    front.api.reply(r"POST /v1/sandboxes", 422, {"error": {"code": "invalid_source", "message": "x"}})
    assert front.create({"image": "repo/app:1", "snapshot_id": ""})[0] == 422
    front.api.replies.clear()
    assert front.exec("sbx_pin_1", "echo hi")[0] == 200
    # An exec kept under a handle signs the same receipt; reading the kept answer is the front's own and signs nothing.
    assert front.call("POST", "/v1/sandboxes/sbx_pin_1/exec", {"cmd": ["true"]},
                      {"X-Room-Exec-Handle": "ab" * 16})[0] == 200
    assert front.call("GET", "/v1/sandboxes/sbx_pin_1/exec/result?handle=" + "ab" * 16)[0] == 200
    front.api.reply(r"POST /v1/sandboxes/sbx_pin_2/exec", 500, {"error": {"code": "boom", "message": "x"}})
    assert front.exec("sbx_pin_2", "false")[0] == 500
    front.api.replies.clear()
    assert front.put("sbx_pin_1", b"data")[0] == 200
    assert front.get_file("sbx_pin_1")[0] == 200
    assert front.call("POST", "/v1/sandboxes/sbx_pin_1/processes", {"cmd": ["sleep", "1"]})[0] == 200
    assert front.call("PUT", "/v1/sandboxes/sbx_pin_1/network", {"mode": "deny_all"})[0] == 200
    assert front.delete("sbx_pin_1")[0] == 200
    assert front.call("DELETE", "/v1/sandboxes?label=k%3Dv")[0] == 200
    return b"".join(rr.canonical(r) + b"\n" for r in led.chain)


def test_actions_other_than_snapshot_and_fork_make_the_same_bytes_as_main(front, monkeypatch) -> None:
    out = scripted_old_actions(front, monkeypatch)
    assert out.count(b"\n") == 14
    assert hashlib.sha256(out).hexdigest() == OLD_ACTIONS_SHA256


# The member names of each old receipt on main, for the same calls: nothing was added to any of them.
MAIN_MEMBERS = {'create': ['action',
            'binding_sha256',
            'command_sha256',
            'customer_request_sha256',
            'hotel',
            'image',
            'image_digest',
            'issued_at',
            'network_policy',
            'network_policy_sha256',
            'operation_id',
            'previous_receipt_sha256',
            'result_sha256',
            'room_previous_receipt_sha256',
            'room_sequence',
            'sandbox_id',
            'schema',
            'sequence',
            'start_command',
            'start_command_sha256',
            'status',
            'target'],
 'delete': ['action',
            'binding_sha256',
            'command_sha256',
            'customer_request_sha256',
            'hotel',
            'image',
            'image_digest',
            'issued_at',
            'operation_id',
            'previous_receipt_sha256',
            'result_sha256',
            'room_previous_receipt_sha256',
            'room_sequence',
            'sandbox_id',
            'schema',
            'sequence',
            'status',
            'target'],
 'exec': ['action',
          'binding_sha256',
          'command_sha256',
          'customer_request_sha256',
          'hotel',
          'image',
          'image_digest',
          'issued_at',
          'operation_id',
          'previous_receipt_sha256',
          'result_sha256',
          'room_previous_receipt_sha256',
          'room_sequence',
          'sandbox_id',
          'schema',
          'sequence',
          'status',
          'target'],
 'file_get': ['action',
              'binding_sha256',
              'command_sha256',
              'customer_request_sha256',
              'hotel',
              'image',
              'image_digest',
              'issued_at',
              'operation_id',
              'previous_receipt_sha256',
              'result_sha256',
              'room_previous_receipt_sha256',
              'room_sequence',
              'sandbox_id',
              'schema',
              'sequence',
              'status',
              'target'],
 'file_put': ['action',
              'binding_sha256',
              'command_sha256',
              'customer_request_sha256',
              'hotel',
              'image',
              'image_digest',
              'issued_at',
              'operation_id',
              'previous_receipt_sha256',
              'result_sha256',
              'room_previous_receipt_sha256',
              'room_sequence',
              'sandbox_id',
              'schema',
              'sequence',
              'status',
              'target']}


def test_an_old_action_receipt_has_exactly_the_members_main_gives_it(front) -> None:
    a = room(front)
    got = {}
    for name, (_status, headers, _out) in {"exec": front.exec(a), "file_put": front.put(a),
                                           "file_get": front.get_file(a), "delete": front.delete(a)}.items():
        got[name] = sorted(receipt_of(headers)["statement"])
    got["create"] = sorted(front.statements(a)[0])
    assert got == MAIN_MEMBERS


# ---------------------------------------------------------------- the fixture and its generator

def test_the_generator_check_rebuilds_the_fixture_byte_for_byte() -> None:
    run = subprocess.run([sys.executable, str(GENERATOR), "--check"], capture_output=True, text=True, timeout=300)
    assert run.returncode == 0, run.stdout + run.stderr


def _load_generator():
    spec = importlib.util.spec_from_file_location("snapshot_fork_v1_generate_t", GENERATOR)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_check_fails_when_the_front_stops_returning_the_receipt_header() -> None:
    gen = _load_generator()

    def strip_headers(rr_module) -> None:
        reply = rr_module.Handler.reply

        def without_receipt(self, status, out, extra=None, *args, **kwargs):
            extra = {k: v for k, v in (extra or {}).items() if k != "X-Room-Receipt"}
            return reply(self, status, out, extra, *args, **kwargs)

        rr_module.Handler.reply = without_receipt

    assert gen.check(None) == 0
    with pytest.raises(SystemExit) as raised:
        gen.check(strip_headers)
    assert "header" in str(raised.value)


def test_check_fails_when_a_returned_receipt_header_differs_from_the_chain() -> None:
    gen = _load_generator()

    def alter(rr_module) -> None:
        sign = rr_module.Ledger._sign_locked

        def other(self, fields, create=None):
            receipt = sign(self, fields, create)
            return {**receipt, "signature_b64": receipt["signature_b64"][::-1]} if fields.get("action") == "snapshot" else receipt

        rr_module.Ledger._sign_locked = other

    with pytest.raises(SystemExit):
        gen.check(alter)


def test_the_fixture_file_sha256_is_pinned() -> None:
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA256


def test_the_fixture_holds_the_attestation_and_the_four_receipts_linked_as_the_plan_says() -> None:
    doc = json.loads(FIXTURE.read_text())
    # The receipt_lists_v2 contract: pretty JSON, sorted keys, one space indent, one trailing newline;
    # the receipts file is {"receipts", "head"}; the case carries description, args and expect.
    assert FIXTURE.read_bytes() == (json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode()
    assert sorted(doc) == ["args", "attestation", "description", "expect", "head", "receipts", "trust"]
    assert doc["expect"] == {"exit_code": 0, "verdict": "PASS"}
    assert doc["args"][:4] == ["--attestation", "{dir}/attestation_doc.json", "--receipts", "{dir}/receipts.json"]
    trust = json.loads((FIXTURES.parent / "receipt_lists_v2" / "source" / "trust.json").read_text())
    assert doc["trust"] == trust and doc["attestation"]["binding_sha256"] == trust["binding_sha256"]
    assert doc["attestation"] == json.loads((FIXTURES.parent / "receipt_lists_v2" / "source" / "attestation_doc.json").read_text())
    assert doc["head"] == doc["receipts"][-1]["receipt_sha256"]
    create_a, snap, create_b, delete = doc["receipts"]
    assert [r["statement"]["action"] for r in doc["receipts"]] == ["create", "snapshot", "create", "snapshot_delete"]
    s = snap["statement"]
    assert s["snapshot_content_sha256"] == content_sha(s["snapshot_image_id"], s["snapshot_work_archive_sha256"])
    b = create_b["statement"]
    assert b["snapshot_receipt_sha256"] == snap["receipt_sha256"] and b["snapshot_content_sha256"] == s["snapshot_content_sha256"]
    assert b["snapshot_source_sandbox_id"] == create_a["statement"]["sandbox_id"] == s["sandbox_id"]
    assert b["room_sequence"] == 1 and s["room_sequence"] == 2
    assert delete["statement"]["sandbox_id"] is None and delete["statement"]["snapshot_id"] == s["snapshot_id"]
    assert [r["statement"]["sequence"] for r in doc["receipts"]] == [1, 2, 3, 4]
    for earlier, later in zip(doc["receipts"], doc["receipts"][1:]):
        assert later["statement"]["previous_receipt_sha256"] == earlier["receipt_sha256"]
    assert doc["receipts"][0]["statement"]["previous_receipt_sha256"] == doc["attestation"]["binding_sha256"]
