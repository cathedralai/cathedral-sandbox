"""The offline checker (#545) against the snapshot and fork receipts this front really signs (AB#604).

The merge gate for the receipts front: every chain the front signs for a snapshot, its forks and its delete must
pass verify_receipts.py, with each fork found as an edge to the first snapshot receipt of its id, and a forged
fork after the delete must not.
"""

from __future__ import annotations

import copy
import json
import importlib.util

import pytest
from room_front_support import KIT, Front, receipt_of, rr
from test_room_kit_signed_snapshots import SNAP, content_sha, fork, room, snapshot, snapshot_delete, snapshot_ok

_spec = importlib.util.spec_from_file_location("verify_receipts_snapshot_gate", KIT / "verify_receipts.py")
vr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vr)


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path, monkeypatch)
    yield f
    f.close()


def chain(front: Front) -> list[dict]:
    with front.ledger.lock:
        return copy.deepcopy(list(front.ledger.chain))


def check(front: Front, receipts: list[dict]) -> dict:
    att = front.ledger.attestation()
    vr.verify_hotel_attestation(att)
    out = vr.verify_receipts(att, receipts)
    assert out["signatures_ok"] == len(receipts)
    return vr.check_snapshot_edges(receipts)


def test_a_snapshot_a_repeat_two_forks_and_the_delete_the_front_signs_pass_the_checker(front) -> None:
    a = room(front)
    first = snapshot_ok(front, a)
    snapshot_ok(front, a)  # an agreeing repeat: forks still name the first
    forks = [receipt_of(fork(front)[1]) for _ in range(2)]
    status, _h, _out = snapshot_delete(front)
    assert status == 200
    receipts = chain(front)
    assert [rc["statement"]["action"] for rc in receipts] == ["create", "snapshot", "snapshot", "create", "create",
                                                               "snapshot_delete"]
    edges = check(front, receipts)
    assert [(e["room"], e["source_room"], e["snapshot_id"], e["in_list"]) for e in edges["forks"]] == [
        (rc["statement"]["sandbox_id"], a, SNAP, True) for rc in forks]
    assert {e["snapshot_content_sha256"] for e in edges["forks"]} == {content_sha()}
    assert {rc["statement"]["snapshot_receipt_sha256"] for rc in forks} == {first["receipt_sha256"]}


def test_a_fork_after_its_source_room_is_deleted_passes_the_checker(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    front.api.replies.clear()
    status, _h, _out = front.call("DELETE", f"/v1/sandboxes/{a}")
    assert status in (200, 204)
    status, _h, _out = fork(front)
    assert status == 200
    edges = check(front, chain(front))
    assert [e["source_room"] for e in edges["forks"]] == [a]


def test_a_fork_re_signed_after_the_delete_is_refused_by_the_checker(front) -> None:
    a = room(front)
    snapshot_ok(front, a)
    fork_rc = receipt_of(fork(front)[1])
    assert snapshot_delete(front)[0] == 200
    receipts = chain(front)
    check(front, receipts)
    # The key holder appends the same fork again after the delete, with the next sequence and chain link.
    late = copy.deepcopy(fork_rc["statement"])
    last = receipts[-1]["statement"]
    late["sequence"] = last["sequence"] + 1
    late["previous_receipt_sha256"] = receipts[-1]["receipt_sha256"]
    forged = receipts + [{"statement": late, "signature_b64": rr.b64(front.ledger.key.sign(rr.canonical(late))),
                          "receipt_sha256": rr.sha(rr.canonical(late))}]
    vr.verify_receipts(front.ledger.attestation(), forged)  # the signatures and the chain are good
    with pytest.raises(vr.Fail, match="deleted before it"):
        vr.check_snapshot_edges(forged)


def test_a_snapshot_whose_receipt_write_failed_is_never_signed_again_and_the_chain_passes(front) -> None:
    # The receipt is in the chain before its disk write. If that write fails, the front does not hold the
    # snapshot, so a repeat would be signed as if it were the first: the id is treated as deleted instead.
    a = room(front)
    real = front.ledger.store

    class FailOnce:
        def __init__(self) -> None:
            self.fail = True

        def write(self, data: bytes):
            if self.fail:
                self.fail = False
                raise OSError(28, "No space left on device")
            return real.write(data)

        def __getattr__(self, name):
            return getattr(real, name)

    front.ledger.store = FailOnce()
    status, headers, _out = snapshot(front, a)
    assert status == 202 and dict(headers).get("X-Room-Receipt-Error") == "OSError"
    with front.ledger.lock:
        assert SNAP in front.ledger.deleted_snapshots and SNAP not in front.ledger.snapshots
    status, headers, out = snapshot(front, a)  # the repeat: the machine's get-or-create answers the same id
    assert status == 502 and json.loads(out)["error"]["code"] == "snapshot_unsigned"
    sent = front.api.count(r"POST /v1/sandboxes")
    assert fork(front)[0] == 404 and front.api.count(r"POST /v1/sandboxes") == sent
    edges = check(front, chain(front))
    assert edges["forks"] == []
