"""Per-room receipt numbers and one-room creates on the receipts front (AB#384).

Every statement with a room id carries `room_sequence` (1, 2, 3 for that id under
this boot's key) and `room_previous_receipt_sha256`. A room's receipt list says how
many receipts it holds (`count`) and the hash of the last one (`room_head`). A create
that asks for more than one room is refused before it reaches the API.
"""
from __future__ import annotations

import json

import pytest
from room_front_support import Front, receipt_of
from test_room_kit_sealed_secrets import _ledger as secrets_ledger
from test_room_kit_sealed_secrets import _room as secrets_room
from test_room_kit_sealed_secrets import _seal


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def _assert_chain(statements: list[dict]) -> None:
    """The numbers run 1..n and every link names the receipt before it."""
    assert [s["room_sequence"] for s in statements] == list(range(1, len(statements) + 1))
    assert statements[0]["room_previous_receipt_sha256"] is None


def _links(front: Front, room: str) -> None:
    receipts = front.room_receipts(room)["receipts"]
    for earlier, later in zip(receipts, receipts[1:]):
        assert later["statement"]["room_previous_receipt_sha256"] == earlier["receipt_sha256"]


def test_numbers_and_links_run_over_create_exec_put_and_delete(front) -> None:
    status, headers, out = front.create()
    room = json.loads(out)["id"]
    assert status == 200 and receipt_of(headers)["statement"]["room_sequence"] == 1
    assert front.exec(room)[0] == 200
    assert front.put(room)[0] == 200
    assert front.get_file(room)[0] == 200
    assert front.delete(room)[0] == 200
    statements = front.statements(room)
    assert [s["action"] for s in statements] == ["create", "exec", "file_put", "file_get", "delete"]
    _assert_chain(statements)
    _links(front, room)


def test_two_rooms_interleaved_each_have_their_own_numbers(front) -> None:
    a = json.loads(front.create()[2])["id"]
    b = json.loads(front.create()[2])["id"]
    for _ in range(2):
        front.exec(a)
        front.exec(b)
    front.exec(a)
    assert [s["room_sequence"] for s in front.statements(a)] == [1, 2, 3, 4]
    assert [s["room_sequence"] for s in front.statements(b)] == [1, 2, 3]
    _links(front, a)
    _links(front, b)
    # The chain's own sequence is not the room's.
    assert front.statements(b)[0]["sequence"] != front.statements(b)[0]["room_sequence"]


def test_a_reused_id_continues_its_numbers(front) -> None:
    front.api.new_ids = ["sbx_same", "sbx_same"]
    front.create()
    front.delete("sbx_same")
    status, headers, _ = front.create()
    assert status == 200
    assert receipt_of(headers)["statement"]["room_sequence"] == 3
    _assert_chain(front.statements("sbx_same"))
    _links(front, "sbx_same")


def test_a_bulk_delete_names_no_room_and_takes_no_number(front) -> None:
    room = json.loads(front.create()[2])["id"]
    status, headers, _ = front.call("DELETE", "/v1/sandboxes?label=a%3Db")
    assert status == 200
    statement = receipt_of(headers)["statement"]
    assert statement["action"] == "bulk_delete" and statement["sandbox_id"] is None
    assert "room_sequence" not in statement and "room_previous_receipt_sha256" not in statement
    assert [s["room_sequence"] for s in front.statements(room)] == [1]


def test_a_receipt_without_a_room_takes_no_number(front) -> None:
    receipt = front.ledger.sign({"action": "escape_nonce_plant", "sandbox_id": None, "status": 200})
    assert "room_sequence" not in receipt["statement"]
    receipt = front.ledger.sign({"action": "x", "sandbox_id": "", "status": 200})
    assert "room_sequence" not in receipt["statement"]


def test_a_retried_secret_returns_its_stored_receipt_and_takes_no_number(tmp_path, monkeypatch) -> None:
    ledger, _asked, root = secrets_ledger(tmp_path, monkeypatch)
    room = secrets_room(ledger, root)
    doc = _seal(ledger, room)
    _out, first = ledger.write_sealed_secret(room, doc)
    _out, again = ledger.write_sealed_secret(room, doc)
    assert again == first
    numbers = [ledger.chain[i]["statement"]["room_sequence"] for i in ledger.by_room[room]]
    assert numbers == [1, 2]  # the create and the one write


def test_the_room_list_says_its_count_and_its_head(front) -> None:
    room = json.loads(front.create()[2])["id"]
    empty = front.room_receipts("sbx_unknown")
    assert empty["count"] == 0 and empty["room_head"] is None and empty["receipts"] == []
    front.exec(room)
    listing = front.room_receipts(room)
    assert listing["count"] == 2 == len(listing["receipts"])
    assert listing["room_head"] == listing["receipts"][-1]["receipt_sha256"]
    front.exec(room)
    again = front.room_receipts(room)
    assert again["count"] == 3 and again["room_head"] != listing["room_head"]


@pytest.mark.parametrize("count", [2, 0, True, "2", 1.0, None, [1], -1])
def test_a_create_for_other_than_one_room_is_refused_unsent(front, count) -> None:
    status, headers, out = front.create({"image": "repo/app:1", "count": count})
    assert status == 400 and json.loads(out)["error"]["code"] == "create_count_refused"
    assert "X-Room-Receipt" not in headers
    assert front.api.seen == [] and front.ledger.chain == []


def test_a_create_for_one_room_goes_through(front) -> None:
    status, headers, _ = front.create({"image": "repo/app:1", "count": 1})
    assert status == 200 and "X-Room-Receipt" in headers
    assert front.create()[0] == 200  # no count at all


def test_the_count_refusal_applies_to_creates_only(front) -> None:
    room = json.loads(front.create()[2])["id"]
    assert front.call("POST", f"/v1/sandboxes/{room}/exec", {"cmd": ["true"], "count": 2})[0] == 200
    assert front.call("POST", "/v1/sandboxes", b"[1,2]")[0] == 200  # not an object: the API answers


def test_an_unauthorized_caller_cannot_read_the_room_list(front) -> None:
    assert front.call("GET", "/v1/sandboxes/sbx_1/receipts", auth=False)[0] == 401
