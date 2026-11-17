"""The offline checker against what the receipts front really signs for a pre-made room (AB#535).

Receipt 1 is the pool create, receipt 2 the claim that names it (pooled_from) and the customer's sandbox id.
verify_receipts.py (merged in #527) must accept that pair as the front signs it, refuse a pair that was changed,
and keep a claim made before a front restart under the binding that signed it.
"""

from __future__ import annotations

import copy
import http.client
import importlib.util
import json
import threading

import pytest
from room_front_support import KEY, KIT, Front, receipt_of, rr

_spec = importlib.util.spec_from_file_location("verify_receipts_pool_claim", KIT / "verify_receipts.py")
vr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vr)

CID = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
OTHER = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
POOL = {"image": "repo/app@sha256:" + "a" * 64, "resources": {"cpu": 1}, "network": {"mode": "deny_all", "allow": []},
        "labels": {"cathedral_pool": "1"}, "ttl_seconds": 900}


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def claimed_room(front: Front, cid: str = CID) -> tuple[str, list[dict]]:
    status, _h, out = front.create(POOL)
    assert status == 200, out
    room = json.loads(out)["id"]
    status, _h, out = front.call("POST", f"/v1/sandboxes/{room}/claim", {"cathedral_sandbox_id": cid, "lifetime_seconds": 600})
    assert status == 200, out
    receipts = front.room_receipts(room)["receipts"]
    assert [rc["statement"]["action"] for rc in receipts] == ["create", "claim"]
    return room, receipts


def resign(front: Front, statement: dict) -> dict:
    """A receipt over *statement* with the front's own key: the forger holds the key, so only the pair rules stop it."""
    return {"statement": statement, "signature_b64": rr.b64(front.ledger.key.sign(rr.canonical(statement))),
            "receipt_sha256": rr.sha(rr.canonical(statement))}


def test_the_pool_create_and_claim_the_front_signs_pass_the_checker(front) -> None:
    room, receipts = claimed_room(front)
    att = front.ledger.attestation()
    vr.verify_hotel_attestation(att)
    out = vr.verify_receipts(att, receipts)
    assert out["signatures_ok"] == 2
    create, claim = (rc["statement"] for rc in receipts)
    assert create["pool"] is True and "cathedral_sandbox_id" not in create
    assert claim["pooled_from"] == receipts[0]["receipt_sha256"] and claim["cathedral_sandbox_id"] == CID
    assert vr.pool_rooms(receipts) == {room: {"state": "claimed", "pooled_from": receipts[0]["receipt_sha256"],
                                              "shows": [vr.POOL_CLAIM_SHOWS]}}
    assert vr.room_links(receipts) == {room: CID}


def test_an_unsigned_edit_of_the_claim_is_refused_by_verify_receipts(front) -> None:
    _room, receipts = claimed_room(front)
    receipts = copy.deepcopy(receipts)
    receipts[1]["statement"]["cathedral_sandbox_id"] = OTHER
    with pytest.raises(vr.Fail, match="receipt_sha256 mismatch"):
        vr.verify_receipts(front.ledger.attestation(), receipts)


def test_a_resigned_claim_with_another_pooled_from_is_refused_by_pool_rooms(front) -> None:
    _room, receipts = claimed_room(front)
    claim = copy.deepcopy(receipts[1]["statement"])
    claim["pooled_from"] = "0" * 64
    forged = [receipts[0], resign(front, claim)]
    vr.verify_receipts(front.ledger.attestation(), forged)  # the signature is good
    with pytest.raises(vr.Fail, match="pooled_from is not the pool create's receipt hash"):
        vr.pool_rooms(forged)


def test_another_rooms_claim_spliced_onto_a_pool_create_is_refused_by_pool_rooms(front) -> None:
    room_a, receipts_a = claimed_room(front)
    _room_b, receipts_b = claimed_room(front, OTHER)
    claim = copy.deepcopy(receipts_b[1]["statement"])
    claim["sandbox_id"] = room_a
    claim["room_previous_receipt_sha256"] = receipts_a[0]["receipt_sha256"]
    claim["previous_receipt_sha256"] = receipts_a[0]["receipt_sha256"]
    forged = [receipts_a[0], resign(front, claim)]
    vr.verify_receipts(front.ledger.attestation(), forged)
    with pytest.raises(vr.Fail, match=f"the claim's target is not POST /v1/sandboxes/{room_a}/claim"):
        vr.pool_rooms(forged)


def test_a_claim_without_its_pool_create_is_refused_by_pool_rooms(front) -> None:
    _room, receipts = claimed_room(front)
    with pytest.raises(vr.Fail, match="a claim in a room that was not made as a pool room"):
        vr.pool_rooms([receipts[1]])


def test_a_claim_on_a_create_without_the_pool_flag_is_refused_by_pool_rooms(front) -> None:
    _room, receipts = claimed_room(front)
    create = copy.deepcopy(receipts[0]["statement"])
    del create["pool"]
    create_rc = resign(front, create)
    claim = copy.deepcopy(receipts[1]["statement"])
    claim["previous_receipt_sha256"] = create_rc["receipt_sha256"]
    claim["room_previous_receipt_sha256"] = create_rc["receipt_sha256"]
    claim["pooled_from"] = create_rc["receipt_sha256"]
    forged = [create_rc, resign(front, claim)]
    vr.verify_receipts(front.ledger.attestation(), forged)
    with pytest.raises(vr.Fail, match="a claim in a room that was not made as a pool room"):
        vr.pool_rooms(forged)


def test_a_claim_made_before_a_front_restart_stays_under_its_own_binding(tmp_path, front) -> None:
    room, before = claimed_room(front)  # receipts 1 and 2, kept by the caller at claim time
    att_a = front.ledger.attestation()
    ledger_b = rr.Ledger("room-b", str(tmp_path))
    server_b = rr.Server(("127.0.0.1", 0), ledger_b, front.api.server.server_address[1], 1, KEY, "/nonexistent.sock")
    threading.Thread(target=server_b.serve_forever, daemon=True).start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", server_b.server_address[1], timeout=10)
        c.request("POST", f"/v1/sandboxes/{room}/exec", body=b'{"cmd":["true"]}',
                  headers={"Authorization": "Bearer " + KEY.decode(), "Content-Type": "application/json"})
        r = c.getresponse()
        assert r.status == 200, r.read()
        after = receipt_of(dict(r.getheaders()))
        c.close()
        att_b = ledger_b.attestation()
    finally:
        server_b.shutdown()
        server_b.server_close()
        ledger_b.close()
    bsha_a, bsha_b = att_a["binding_sha256"], att_b["binding_sha256"]
    assert bsha_a != bsha_b and after["statement"]["binding_sha256"] == bsha_b
    combined = [*before, after]
    with pytest.raises(vr.Fail, match="names another binding"):
        vr.verify_receipts(att_b, combined)  # one binding per check: partition first
    by_binding = {bsha: [rc for rc in combined if rc["statement"]["binding_sha256"] == bsha] for bsha in (bsha_a, bsha_b)}
    assert vr.verify_receipts(att_a, by_binding[bsha_a])["signatures_ok"] == 2
    assert vr.verify_receipts(att_b, by_binding[bsha_b])["signatures_ok"] == 1
    assert after["statement"]["room_sequence"] == 1 and after["statement"]["action"] == "exec"
    pools = vr.pool_rooms(combined)
    assert pools == {f"{room}@{bsha_a[:12]}": {"state": "claimed", "pooled_from": before[0]["receipt_sha256"],
                                               "shows": [vr.POOL_CLAIM_SHOWS]}}
    assert vr.room_links(combined) == {room: CID}
