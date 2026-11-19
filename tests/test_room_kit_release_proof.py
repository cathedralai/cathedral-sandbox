"""AB#392 guest freshness proof. Real HTTP/signatures; synthetic SNP evidence only."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import socket
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from room_front_support import Front, KEY, assert_idle, finish, in_thread, rr
from test_room_kit_sealed_secrets import _fake_report

CID = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
SECRET = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d"
PATH = "/room/release-proof"


@pytest.fixture
def front(tmp_path, monkeypatch):
    f = Front(tmp_path / "initial", monkeypatch)
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", _fake_report)
    f.ledger.close()
    f.ledger = rr.Ledger("room-a", str(tmp_path / "sealed"),
                         secrets=rr.SealedSecrets(str(tmp_path / "secrets")))
    f.server.ledger = f.ledger
    yield f
    f.close()


def create(front, **kw):
    status, _headers, out = front.create({
        "image": "repo/app@sha256:" + "a" * 64,
        "labels": {"cathedral_sandbox_id": CID}, **kw,
    })
    assert status == 200, out
    return json.loads(out)["id"]


def request(front, room):
    return {"sandbox_id": room, "challenge": {
        "schema": "cathedral_vault_release_challenge_v1",
        "nonce_b64": base64.b64encode(b"n" * 32).decode(),
        "hmac_b64": base64.b64encode(b"m" * 32).decode(),
        "issued_at": int(time.time()), "secret_id": SECRET, "sandbox_id": CID,
        "binding_sha256": front.ledger.binding_sha256,
        "room_create_receipt_sha256": front.ledger.room_incarnation(room),
    }}


def post(front, doc, **kw):
    return front.call("POST", PATH, doc, **kw)


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def test_proof_is_bound_and_verifiable_in_existing_chain(front):
    room = create(front)
    doc = request(front, room)
    before = front.ledger.head
    status, _headers, out = post(front, doc)
    assert status == 200, out
    receipt = json.loads(out)["receipt"]
    st = receipt["statement"]
    assert set(st) == {
        "schema", "binding_sha256", "hotel", "operation_id", "sequence",
        "previous_receipt_sha256", "issued_at", "room_sequence", "room_previous_receipt_sha256",
        "action", "purpose", "challenge_sha256", "sandbox_id", "room_create_receipt_sha256", "status",
    }
    assert st["action"] == "release_proof" and st["purpose"] == "cathedral.vault-release.v1"
    assert st["schema"] == rr.RECEIPT_SCHEMA and st["status"] == 200
    assert st["challenge_sha256"] == hashlib.sha256(canonical(doc["challenge"])).hexdigest()
    assert st["sandbox_id"] == room and st["room_create_receipt_sha256"] == before
    assert st["previous_receipt_sha256"] == before and st["room_sequence"] == 2
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(front.ledger.binding["receipt_key_ed25519_b64"]))
    pub.verify(base64.b64decode(receipt["signature_b64"]), canonical(st))
    assert receipt["receipt_sha256"] == hashlib.sha256(canonical(st)).hexdigest()
    verifier = Path(__file__).resolve().parents[1] / "room-kit/verify_receipts.py"
    spec = importlib.util.spec_from_file_location("release_proof_verifier", verifier)
    vr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vr)
    vr.check_receipt_shapes(front.ledger.chain)
    vr.verify_receipts(front.ledger.attestation(), front.ledger.chain, front.ledger.head)
    assert all(path != PATH for _, path, _ in front.api.seen)
    assert_idle(front.ledger)


@pytest.mark.parametrize("field,value", [
    ("schema", "other"), ("issued_at", True), ("issued_at", 1.5), ("issued_at", "1"),
    ("nonce_b64", "!" * 44), ("hmac_b64", "x" * 100), ("secret_id", "not-a-uuid"),
    ("binding_sha256", "AA" * 32), ("room_create_receipt_sha256", "ab"),
    ("action", "create"), ("purpose", "other"), ("extra", {"secret": "never signed"}),
])
def test_malformed_challenge_does_not_sign(front, field, value):
    room = create(front)
    doc = request(front, room)
    doc["challenge"][field] = value
    before = len(front.ledger.chain)
    assert post(front, doc)[0] == 400
    assert len(front.ledger.chain) == before
    assert_idle(front.ledger)


@pytest.mark.parametrize("change", ["binding", "incarnation", "customer", "expired", "future"])
def test_wrong_binding_incarnation_customer_or_time_is_refused(front, change):
    room = create(front)
    doc = request(front, room)
    field, value = {
        "binding": ("binding_sha256", "00" * 32),
        "incarnation": ("room_create_receipt_sha256", "00" * 32),
        "customer": ("sandbox_id", SECRET), "expired": ("issued_at", int(time.time()) - 61),
        "future": ("issued_at", int(time.time()) + 10),
    }[change]
    doc["challenge"][field] = value
    assert post(front, doc)[0] == 409
    assert len(front.ledger.chain) == 1
    assert_idle(front.ledger)


@pytest.mark.parametrize("body", [b"", b"[]", b"null", b"not-json", b'{"challenge":{},"challenge":{}}'])
def test_bad_json_has_no_signature(front, body):
    assert post(front, body)[0] == 400
    assert front.ledger.chain == []


def test_http_auth_method_and_size_guards(front):
    doc = request(front, create(front))
    assert post(front, doc, auth=False)[0] == 401
    assert post(front, doc, headers={"Authorization": "Bearer wrong"})[0] == 401
    assert front.call("GET", PATH)[0] == 405
    assert post(front, b"x" * (rr.RELEASE_PROOF_MAX_BYTES + 1))[0] == 413
    assert len(front.ledger.chain) == 1
    for length in ("-1", "invalid", "4097"):
        with socket.create_connection(("127.0.0.1", front.port), timeout=3) as conn:
            conn.sendall((f"POST {PATH} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "
                          f"{KEY.decode()}\r\nContent-Length: {length}\r\n\r\n").encode())
            status = conn.recv(1024).split(b"\r\n", 1)[0]
            assert b" 411 " in status or b" 413 " in status


@pytest.mark.parametrize("mode", ["unsealed", "secrets_off", "scan_pending", "plain_http"])
def test_proof_is_closed_when_guest_is_not_ready(front, mode):
    doc = request(front, create(front))
    if mode == "unsealed":
        front.ledger.sealed = False
    elif mode == "secrets_off":
        front.ledger.secrets = None
    elif mode == "scan_pending":
        front.server.pool_scan_ready = False
    else:
        front.server.attestation_only = True
    assert post(front, doc)[0] in (403, 503)
    assert len(front.ledger.chain) == 1


@pytest.mark.parametrize("status,body", [(404, {}), (409, {}), (500, {}), (200, {}), (200, {"id": "other"}), (200, b"invalid")])
def test_missing_or_uncertain_local_room_has_no_proof(front, status, body):
    room = create(front)
    front.api.get_replies[room] = (status, canonical(body) if isinstance(body, dict) else body)
    assert post(front, request(front, room))[0] == 409
    assert len(front.ledger.chain) == 1
    assert_idle(front.ledger)


def test_recreated_room_refuses_earlier_challenge(front):
    room = create(front)
    doc = request(front, room)
    assert front.call("DELETE", f"/v1/sandboxes/{room}")[0] == 200
    front.api.new_ids.append(room)
    assert create(front) == room
    assert post(front, doc)[0] == 409
    assert post(front, request(front, room))[0] == 200


def test_pool_needs_claim_and_checks_its_customer_link(front):
    room = create(front, labels={"cathedral_pool": "1"}, resources={"cpu": 1},
                  network={"mode": "deny_all", "allow": []}, ttl_seconds=900)
    doc = request(front, room)
    assert post(front, doc)[0] == 409
    assert front.call("POST", f"/v1/sandboxes/{room}/claim", {
        "cathedral_sandbox_id": CID, "lifetime_seconds": 600,
    })[0] == 200
    assert post(front, doc)[0] == 200
    doc["challenge"]["sandbox_id"] = SECRET
    assert post(front, doc)[0] == 409


@pytest.mark.parametrize("mark", ["broken", "unknown", "pool_stale", "bulk_pending"])
def test_uncertain_or_busy_room_is_closed(front, mark):
    room = create(front)
    if mark == "bulk_pending":
        front.ledger.bulk_pending = 1
    else:
        getattr(front.ledger, mark).add(room)
    assert post(front, request(front, room))[0] == 409
    assert len(front.ledger.chain) == 1


def test_delete_during_liveness_read_cannot_get_proof(front):
    room = create(front)
    doc = request(front, room)
    hold = front.api.hold(f"GET /v1/sandboxes/{room}")
    worker, result = in_thread(lambda: post(front, doc))
    hold.wait_entered()
    assert front.call("DELETE", f"/v1/sandboxes/{room}")[0] == 200
    hold.release.set()
    assert finish(worker, result)[0] == 409
    assert not any(s["action"] == "release_proof" for s in front.statements(room))
    assert_idle(front.ledger)


def test_serial_room_keeps_its_turn_until_proof_is_signed(front):
    room = create(front, labels={"cathedral_sandbox_id": CID, "cathedral_serial": "1"})
    assert room in front.ledger.serial
    doc = request(front, room)
    hold = front.api.hold(f"GET /v1/sandboxes/{room}")
    worker, result = in_thread(lambda: post(front, doc))
    hold.wait_entered()
    assert front.call("DELETE", f"/v1/sandboxes/{room}")[0] == 409
    hold.release.set()
    assert finish(worker, result)[0] == 200
    assert room not in front.ledger.broken
    assert_idle(front.ledger)


def test_expiry_is_rechecked_after_liveness_read(front, monkeypatch):
    room = create(front)
    doc = request(front, room)
    original = front.server.api_get
    def late(*args, **kw):
        got = original(*args, **kw)
        monkeypatch.setattr(rr.time, "time", lambda: doc["challenge"]["issued_at"] + 61)
        return got
    monkeypatch.setattr(front.server, "api_get", late)
    assert post(front, doc)[0] == 409
    assert len(front.ledger.chain) == 1


def test_signing_failure_returns_no_proof_and_releases_turn(front, monkeypatch):
    room = create(front)
    def fail(_fields):
        raise OSError("synthetic signing failure")
    monkeypatch.setattr(front.ledger, "_sign_locked", fail)
    assert post(front, request(front, room))[0] == 503
    assert_idle(front.ledger)


def test_guest_commits_mac_but_does_not_authenticate_the_service(front):
    room = create(front)
    doc = request(front, room)
    first = json.loads(post(front, doc)[2])["receipt"]["statement"]
    doc["challenge"]["hmac_b64"] = base64.b64encode(b"different, still unauthenticated!"[:32].ljust(32, b"x")).decode()
    status, _headers, out = post(front, doc)
    assert status == 200
    second = json.loads(out)["receipt"]["statement"]
    assert first["challenge_sha256"] != second["challenge_sha256"]
    # No secret or challenge plaintext is stored in the receipt chain.
    assert SECRET not in json.dumps(front.ledger.chain)


def test_room_without_signed_customer_link_cannot_get_proof(front):
    room = create(front, labels={})
    assert post(front, request(front, room))[0] == 409
    assert len(front.ledger.chain) == 1


def test_challenge_cannot_add_statement_fields_or_duplicate_members(front):
    doc = request(front, create(front))
    assert post(front, {**doc, "action": "create"})[0] == 400
    raw = json.dumps(doc).replace('"challenge": {', '"challenge": {"issued_at":0,')
    assert post(front, raw.encode())[0] == 400
    assert len(front.ledger.chain) == 1


def test_slow_liveness_lookup_has_total_deadline(front, monkeypatch):
    room = create(front)
    front.api.trickle(f"GET /v1/sandboxes/{room}", 0.1)
    monkeypatch.setattr(rr, "RELEASE_PROOF_LOOKUP_SECONDS", 0.15)
    started = time.monotonic()
    assert post(front, request(front, room))[0] == 409
    assert time.monotonic() - started < 2
    assert len(front.ledger.chain) == 1
    assert_idle(front.ledger)
