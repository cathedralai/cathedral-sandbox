"""AB#683 fresh guest evidence on the receipts front: signed escape_fresh on create and plant.

Contract: polariscomputer docs/AB683_FRESH_EVIDENCE.md. The front signs the API's assignment into the
create it performed, and admits one plant only for that assignment, room incarnation and create receipt.
"""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_escape_fresh_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
NONCE = "control-plane-nonce-1"
IMAGE = "ghcr.io/cathedral/escape-room:1"
# The guest's SNP REPORT_ID (ATTESTATION_REPORT 0x140): the launch every fresh create here must name.
LAUNCH = "5e" * 32
OTHER_LAUNCH = "6f" * 32
FRESH = {
    "schema": "cathedral.escape.fresh_evidence/v1",
    "attempt_id": "attempt-1",
    "report_id": LAUNCH,
    "request_sha256": "a" * 64,
}


def _fake_report() -> bytes:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x08:0x10] = (0x30000).to_bytes(8, "little")
    report[0x90:0xC0] = bytes.fromhex("ab" * 48)
    report[0xC0:0xE0] = bytes.fromhex("cd" * 32)
    report[0x140:0x160] = bytes.fromhex(LAUNCH)
    report[0x180:0x188] = bytes.fromhex("01" * 8)
    report[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
    return bytes(report)


# Every Front starts two servers; each test must close them, or the listening sockets and
# keep-alive threads leak into later tests (the full suite then passes select()'s 1024 fd limit).
_SERVERS: list[ThreadingHTTPServer] = []


@pytest.fixture(autouse=True)
def _close_servers():
    yield
    while _SERVERS:
        srv = _SERVERS.pop()
        srv.shutdown()
        srv.server_close()


class Front:
    def __init__(self, tmp_path, monkeypatch, *, escape="1", sealed=True, plaintext=None, create_status=202):
        if escape is None:
            monkeypatch.delenv("ROOM_ESCAPE", raising=False)
        else:
            monkeypatch.setenv("ROOM_ESCAPE", escape)
        if plaintext is None:
            monkeypatch.delenv("ROOM_ESCAPE_ALLOW_PLAINTEXT", raising=False)
        else:
            monkeypatch.setenv("ROOM_ESCAPE_ALLOW_PLAINTEXT", plaintext)
        self.plant_dir = tmp_path / "escape-room"
        monkeypatch.setenv("ROOM_ESCAPE_NONCE_DIR", str(self.plant_dir))
        if sealed:
            monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
            monkeypatch.setattr(rr, "snp_report", lambda _data: _fake_report())
        else:
            monkeypatch.setattr(rr, "tsm_provider", lambda: None)
        self.ledger = rr.Ledger("room-a", str(tmp_path / "store"))
        self.calls: list[tuple[str, str, dict]] = []
        self.rooms = iter(f"room-{i}" for i in range(1, 100))
        front = self

        class Api(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _answer(self, status: int, doc: dict) -> None:
                out = json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                front.calls.append(("POST", self.path, dict(self.headers)))
                if self.path == "/v1/sandboxes" and create_status < 300:
                    return self._answer(create_status, {"id": next(front.rooms), "state": "creating"})
                return self._answer(create_status, {"error": {"code": "boom"}})

            def do_DELETE(self):  # noqa: N802
                front.calls.append(("DELETE", self.path, dict(self.headers)))
                return self._answer(200, {"ok": True})

        api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
        Thread(target=api.serve_forever, args=(0.05,), daemon=True).start()
        server = rr.Server(("127.0.0.1", 0), self.ledger, api.server_address[1], 1, KEY, "/nonexistent.sock",
                           pool_scan=False)
        Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
        _SERVERS.extend((api, server))
        self.port = server.server_address[1]

    def request(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Authorization": "Bearer " + KEY.decode()}
        if body is not None:
            h["Content-Type"] = "application/json"
        try:
            c.request(method, path, body=body, headers={**h, **(headers or {})})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def expected(self, fresh=FRESH, **change) -> dict:
        """The expected launch the API would send for *fresh*: this guest's launch and binding by default."""
        out = {"schema": "cathedral.escape.expected_launch/v1", "binding_sha256": self.ledger.binding_sha256,
               **{k: fresh[k] for k in ("attempt_id", "report_id", "request_sha256")}}
        return {**out, **change}

    def create(self, fresh=FRESH, headers=None, body=None, expected="auto"):
        extra = {} if fresh is None else {"X-Escape-Fresh": fresh if isinstance(fresh, str) else json.dumps(fresh)}
        if expected == "auto":
            expected = self.expected(fresh) if isinstance(fresh, dict) else None
        if expected is not None:
            extra["X-Escape-Expected-Launch"] = expected if isinstance(expected, str) else json.dumps(expected)
        return self.request("POST", "/v1/sandboxes", json.dumps(body or {"image": IMAGE}).encode(),
                            {**extra, **(headers or {})})

    def plant_env(self, window_id="win-1"):
        status, _h, key_body = self.request("GET", "/room/escape-plant-key")
        assert status == 200
        pub = X25519PublicKey.from_public_bytes(base64.b64decode(json.loads(key_body)["x25519_public_b64"]))
        env = rr.seal_plant_nonce(NONCE.encode(), pub, "room-a", window_id)
        env["window_id"] = window_id
        return env

    def plant(self, room, fresh, window_id="win-1", env=None):
        doc = {**(env or self.plant_env(window_id))}
        if room is not None:
            doc["sandbox_id"] = room
        if fresh is not None:
            doc["escape_fresh"] = fresh
        return self.request("POST", "/room/escape-nonce", json.dumps(doc).encode())

    def creates(self) -> int:
        return sum(1 for m, p, _ in self.calls if m == "POST" and p == "/v1/sandboxes")


def _receipt(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


def _verified(front: Front, receipt: dict) -> dict:
    st = receipt["statement"]
    front.ledger.key.public_key().verify(base64.b64decode(receipt["signature_b64"]), rr.canonical(st))
    assert receipt["receipt_sha256"] == rr.sha(rr.canonical(st))
    return st


def _created(front: Front, fresh=FRESH) -> tuple[str, dict]:
    status, headers, out = front.create(fresh)
    assert status == 202, out
    receipt = _receipt(headers)
    return receipt["statement"]["sandbox_id"], receipt


def test_create_and_plant_sign_the_assignment(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    room, create = _created(front)
    st = _verified(front, create)
    assert st["schema"] == rr.RECEIPT_SCHEMA and st["hotel"] == "room-a"
    assert st["binding_sha256"] == front.ledger.binding_sha256
    assert st["action"] == "create" and st["target"] == "POST /v1/sandboxes"
    assert st["sandbox_id"] == room == "room-1" and st["image"] == IMAGE
    assert st["escape_fresh"] == FRESH
    # The status is what the room API answered (202), never a constant.
    assert st["status"] == 202
    # The assignment is for this front: it is not sent on to the room API.
    assert all("X-Escape-Fresh" not in h and "x-escape-fresh" not in {k.lower() for k in h} for _m, _p, h in front.calls)

    want = {**FRESH, "create_receipt_sha256": create["receipt_sha256"]}
    status, headers, out = front.plant(room, want)
    assert status == 200, out
    pst = _verified(front, _receipt(headers))
    assert pst["action"] == rr.PLANT_ACTION and pst["target"] == "POST /room/escape-nonce" and pst["status"] == 200
    assert pst["sandbox_id"] == room
    assert pst["escape_fresh"] == want
    assert pst["window_id"] == "win-1" and pst["encrypted"] is True
    assert pst["nonce_sha256"] == rr.sha(NONCE.encode())
    assert pst["sequence"] > st["sequence"]
    assert NONCE not in json.dumps(pst)
    assert (front.plant_dir / "win-1" / "nonce").read_bytes() == (NONCE + "\n").encode()


@pytest.mark.parametrize("second", [
    FRESH,
    {**FRESH, "attempt_id": "attempt-2"},
])
def test_attempt_and_launch_are_single_use(tmp_path, monkeypatch, second) -> None:
    front = Front(tmp_path, monkeypatch)
    _created(front)
    chain = len(front.ledger.chain)
    status, headers, out = front.create(second)
    assert status == 409 and b"escape_fresh_consumed" in out
    assert "X-Room-Receipt" not in headers
    assert front.creates() == 1 and len(front.ledger.chain) == chain


def test_a_failed_create_still_consumes_and_never_plants(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch, create_status=500)
    status, headers, _out = front.create()
    assert status == 500
    st = _verified(front, _receipt(headers))
    assert st["escape_fresh"] == FRESH and st["status"] == 500
    status, _h, out = front.create()
    assert status == 409 and b"escape_fresh_consumed" in out
    assert front.creates() == 1
    status, _h, out = front.plant("room-1", {**FRESH, "create_receipt_sha256": "0" * 64})
    assert status == 409 and not front.plant_dir.exists()


@pytest.mark.parametrize("header", [
    json.dumps({**FRESH, "schema": "cathedral.escape.fresh_evidence/v0"}),
    json.dumps({**FRESH, "owner_id": "o"}),
    json.dumps({k: v for k, v in FRESH.items() if k != "request_sha256"}),
    json.dumps({**FRESH, "request_sha256": "A" * 64}),
    json.dumps({**FRESH, "request_sha256": "a" * 63}),
    json.dumps({**FRESH, "attempt_id": ""}),
    json.dumps({**FRESH, "attempt_id": 7}),
    json.dumps({**FRESH, "report_id": "x/y"}),
    '{"schema":"cathedral.escape.fresh_evidence/v1","attempt_id":"a","attempt_id":"b","report_id":"r",'
    '"request_sha256":"' + "a" * 64 + '"}',
    "not json",
    json.dumps([FRESH]),
])
def test_malformed_assignment_is_refused_unsent(tmp_path, monkeypatch, header) -> None:
    front = Front(tmp_path, monkeypatch)
    status, headers, out = front.create(header, expected=front.expected())
    assert status == 400 and b"escape_fresh_invalid" in out
    assert "X-Room-Receipt" not in headers
    assert front.creates() == 0 and front.ledger.chain == [] and front.ledger.fresh_used == set()


def test_two_assignment_headers_are_refused(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    c = http.client.HTTPConnection("127.0.0.1", front.port, timeout=10)
    body = json.dumps({"image": IMAGE}).encode()
    c.putrequest("POST", "/v1/sandboxes")
    for k, v in (("Authorization", "Bearer " + KEY.decode()), ("Content-Type", "application/json"),
                 ("Content-Length", str(len(body))), ("X-Escape-Fresh", json.dumps(FRESH)),
                 ("X-Escape-Fresh", json.dumps({**FRESH, "attempt_id": "attempt-2"}))):
        c.putheader(k, v)
    c.endheaders(body)
    r = c.getresponse()
    assert r.status == 400 and b"escape_fresh_invalid" in r.read()
    assert front.creates() == 0


@pytest.mark.parametrize("escape,sealed", [(None, True), ("0", True), ("1", False)])
def test_fresh_create_needs_a_sealed_escape_hotel(tmp_path, monkeypatch, escape, sealed) -> None:
    front = Front(tmp_path, monkeypatch, escape=escape, sealed=sealed)
    status, _h, out = front.create()
    assert status == 403 and b"escape_fresh_disabled" in out
    assert front.creates() == 0 and front.ledger.chain == []


def test_fresh_create_needs_the_hotel_key(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    status, _h, _out = front.create(headers={"Authorization": "Bearer " + "w" * 32})
    assert status == 401
    assert front.creates() == 0 and front.ledger.fresh_used == set()


@pytest.mark.parametrize("headers,body,code", [
    ({"Idempotency-Key": "k1"}, None, b"escape_fresh_idempotency_refused"),
    (None, {"image": IMAGE, "labels": {rr.SERIAL_LABEL: "1"}}, b"escape_fresh_plain_create_required"),
    (None, {"image": IMAGE, "snapshot_id": "snap-1"}, b"escape_fresh_plain_create_required"),
])
def test_fresh_create_is_one_plain_create(tmp_path, monkeypatch, headers, body, code) -> None:
    front = Front(tmp_path, monkeypatch)
    status, _h, out = front.create(headers=headers, body=body)
    assert status == 400 and code in out
    assert front.creates() == 0 and front.ledger.fresh_used == set()


def test_assignment_header_only_rides_on_a_create(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    status, _h, out = front.request("POST", "/v1/sandboxes/room-1/exec", b'{"cmd":["true"]}',
                                    {"X-Escape-Fresh": json.dumps(FRESH)})
    assert status == 400 and b"escape_fresh_refused" in out
    assert front.calls == []


@pytest.mark.parametrize("change", [
    {"attempt_id": "attempt-2"},
    {"report_id": "launch-2"},
    {"request_sha256": "b" * 64},
    {"schema": "cathedral.escape.fresh_evidence/v0"},
    {"create_receipt_sha256": "0" * 64},
    {"extra": "x"},
    "drop:create_receipt_sha256",
    "drop:request_sha256",
    "room:room-9",
    "room:../room-1",
    "room:none",
    "fresh:none",
    "fresh:list",
])
def test_mismatched_plant_writes_nothing(tmp_path, monkeypatch, change) -> None:
    front = Front(tmp_path, monkeypatch)
    room, create = _created(front)
    fresh: object = {**FRESH, "create_receipt_sha256": create["receipt_sha256"]}
    if isinstance(change, dict):
        fresh = {**fresh, **change}
    elif change.startswith("drop:"):
        fresh = {k: v for k, v in fresh.items() if k != change[5:]}
    elif change == "room:none":
        room = None
    elif change.startswith("room:"):
        room = change[5:]
    elif change == "fresh:none":
        fresh = None
    elif change == "fresh:list":
        fresh = [fresh]
    chain = len(front.ledger.chain)
    status, headers, out = front.plant(room, fresh)
    assert status == 409 and b"escape_fresh_mismatch" in out
    assert "X-Room-Receipt" not in headers
    assert len(front.ledger.chain) == chain
    assert not front.plant_dir.exists()
    # A refused plant does not use up the attempt's one plant.
    status, _h, out = front.plant("room-1", {**FRESH, "create_receipt_sha256": create["receipt_sha256"]})
    assert status == 200, out


def test_second_plant_is_refused_even_when_identical(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    room, create = _created(front)
    want = {**FRESH, "create_receipt_sha256": create["receipt_sha256"]}
    assert front.plant(room, want)[0] == 200
    chain = len(front.ledger.chain)
    for window in ("win-1", "win-2"):
        status, _h, out = front.plant(room, want, window_id=window)
        assert status == 409 and b"escape_fresh_mismatch" in out
    assert len(front.ledger.chain) == chain
    assert not (front.plant_dir / "win-2").exists()


def test_room_not_made_by_a_fresh_create_cannot_take_a_fresh_plant(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    status, headers, _out = front.create(fresh=None)
    assert status == 202
    create = _receipt(headers)
    assert "escape_fresh" not in create["statement"]
    status, _h, out = front.plant(create["statement"]["sandbox_id"],
                                  {**FRESH, "create_receipt_sha256": create["receipt_sha256"]})
    assert status == 409 and b"escape_fresh_mismatch" in out
    assert not front.plant_dir.exists()


def test_plant_after_the_room_is_deleted_is_refused(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    room, create = _created(front)
    status, _h, _out = front.request("DELETE", f"/v1/sandboxes/{room}")
    assert status == 200
    status, _h, out = front.plant(room, {**FRESH, "create_receipt_sha256": create["receipt_sha256"]})
    assert status == 409 and b"escape_fresh_mismatch" in out
    assert not front.plant_dir.exists()


def test_fresh_plant_must_be_encrypted_even_when_plaintext_is_flagged(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch, plaintext="1")
    room, create = _created(front)
    doc = {"window_id": "win-1", "nonce": NONCE, "sandbox_id": room,
           "escape_fresh": {**FRESH, "create_receipt_sha256": create["receipt_sha256"]}}
    status, _h, out = front.request("POST", "/room/escape-nonce", json.dumps(doc).encode())
    assert status == 409 and b"escape_fresh_mismatch" in out
    assert not front.plant_dir.exists()
    assert "attempt-1" not in front.ledger.fresh_planted


def test_legacy_plant_is_unchanged(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    status, headers, out = front.plant(None, None)
    assert status == 200, out
    st = _verified(front, _receipt(headers))
    assert st["sandbox_id"] is None and "escape_fresh" not in st


def test_plant_after_the_room_id_is_answered_again_is_refused(tmp_path, monkeypatch) -> None:
    # A later create the API answers with the same room id moves the incarnation: the old create
    # receipt no longer names the room that would hold the nonce.
    front = Front(tmp_path, monkeypatch)
    front.rooms = iter(["room-1", "room-1"])
    room, create = _created(front)
    status, headers, _out = front.create(fresh=None)
    assert status == 202 and _receipt(headers)["statement"]["sandbox_id"] == room
    status, _h, out = front.plant(room, {**FRESH, "create_receipt_sha256": create["receipt_sha256"]})
    assert status == 409 and b"escape_fresh_mismatch" in out
    assert not front.plant_dir.exists()


@pytest.mark.parametrize("lifecycle", ["delete", "room_end", "replacement_create"])
def test_lifecycle_change_after_admission_refuses_the_plant(tmp_path, monkeypatch, lifecycle) -> None:
    # discussion_r4657456482: the incarnation moves after admit_fresh_plant() but before the nonce is
    # written and signed. prune_escape_windows() runs in that interval, outside the ledger lock.
    front = Front(tmp_path, monkeypatch)
    front.rooms = iter(["room-1", "room-1"])
    room, create = _created(front)
    real_prune = rr.prune_escape_windows

    def racing_prune(*args, **kwargs):
        if lifecycle == "delete":
            assert front.request("DELETE", f"/v1/sandboxes/{room}")[0] == 200
        elif lifecycle == "room_end":
            assert front.ledger.end_room(room, create["receipt_sha256"], 200, "exited", "0" * 64) is not None
        else:
            status, headers, _out = front.create(fresh=None)
            assert status == 202 and _receipt(headers)["statement"]["sandbox_id"] == room
        return real_prune(*args, **kwargs)

    monkeypatch.setattr(rr, "prune_escape_windows", racing_prune)
    status, headers, out = front.plant(room, {**FRESH, "create_receipt_sha256": create["receipt_sha256"]})
    assert status == 409 and b"escape_fresh_mismatch" in out
    assert "X-Room-Receipt" not in headers and "X-Room-Receipt-Error" not in headers
    actions = [front.ledger.chain[i]["statement"]["action"] for i in front.ledger.by_room[room]]
    assert actions == ["create", {"delete": "delete", "room_end": "room_end"}.get(lifecycle, "create")]
    assert rr.PLANT_ACTION not in [r["statement"]["action"] for r in front.ledger.chain]
    assert not (front.plant_dir / "win-1" / "nonce").exists()


def test_plant_write_failure_signs_nothing(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    room, create = _created(front)

    def failing_write(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(rr, "write_escape_nonce", failing_write)
    chain = len(front.ledger.chain)
    status, headers, out = front.plant(room, {**FRESH, "create_receipt_sha256": create["receipt_sha256"]})
    assert status == 500 and b"plant_failed" in out
    assert "X-Room-Receipt" not in headers
    assert len(front.ledger.chain) == chain


# ---- AB#683 durable launch reservation and expected launch (SpockChaser producer-contract observations) ----

def _reservations(tmp_path) -> list[str]:
    d = tmp_path / "store" / getattr(rr, "ESCAPE_FRESH_RESERVATION_DIR", "escape-fresh")
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def test_observation1_idempotency_key_is_still_refused_and_reserves_nothing(tmp_path, monkeypatch) -> None:
    # Chaser observation 1: a fresh create never carries an Idempotency-Key, with or without the expected
    # launch, and the refusal leaves the launch unreserved, so the one correct create still runs.
    front = Front(tmp_path, monkeypatch)
    status, headers, out = front.create(headers={"Idempotency-Key": "escape-fresh-attempt-1"})
    assert status == 400 and b"escape_fresh_idempotency_refused" in out
    assert "X-Room-Receipt" not in headers and front.creates() == 0
    assert _reservations(tmp_path) == []
    assert front.create()[0] == 202
    assert front.creates() == 1
    assert len(_reservations(tmp_path)) == 2


def test_observation2_consumption_survives_a_new_front_on_the_same_store(tmp_path, monkeypatch) -> None:
    # Chaser observation 2: on main a second front on the same store accepted the consumed attempt (202).
    first = Front(tmp_path, monkeypatch)
    assert first.create()[0] == 202
    assert first.create()[0] == 409
    first.ledger.store.close()
    second = Front(tmp_path, monkeypatch)
    # A receipt-front restart is a new key and binding on the same launch.
    assert second.ledger.binding_sha256 != first.ledger.binding_sha256
    for fresh in (FRESH, {**FRESH, "attempt_id": "attempt-2"}, {**FRESH, "request_sha256": "b" * 64}):
        status, headers, out = second.create(fresh)
        assert status == 409 and b"escape_fresh_consumed" in out, out
        assert "X-Room-Receipt" not in headers
    assert second.creates() == 0 and second.ledger.chain == []
    assert second.ledger.launch_report_id() == LAUNCH


def test_observation3_report_id_other_than_this_launch_is_refused_unsent(tmp_path, monkeypatch) -> None:
    # Chaser observation 3: on main a well formed arbitrary report_id was sent and signed (202).
    front = Front(tmp_path, monkeypatch)
    for report_id in ("not-the-admitted-launch", OTHER_LAUNCH):
        supplied = {**FRESH, "report_id": report_id}
        status, headers, out = front.create(supplied)
        assert status == 409 and b"escape_expected_launch_mismatch" in out, out
        assert "X-Room-Receipt" not in headers
    assert front.creates() == 0 and front.ledger.chain == [] and _reservations(tmp_path) == []
    # The guest's own launch was not used up by the refusals.
    status, headers, _out = front.create()
    assert status == 202 and _receipt(headers)["statement"]["escape_fresh"] == FRESH


@pytest.mark.parametrize("change", [
    {"binding_sha256": "0" * 64},  # an earlier receipt key on this launch, or another guest
    {"attempt_id": "attempt-2"},
    {"report_id": OTHER_LAUNCH},
    {"request_sha256": "b" * 64},
])
def test_expected_launch_must_match_the_assignment_and_this_guest(tmp_path, monkeypatch, change) -> None:
    front = Front(tmp_path, monkeypatch)
    status, headers, out = front.create(expected=front.expected(**change))
    assert status == 409 and b"escape_expected_launch_mismatch" in out
    assert "X-Room-Receipt" not in headers
    assert front.creates() == 0 and front.ledger.fresh_used == set() and _reservations(tmp_path) == []


def test_expected_launch_from_before_a_key_restart_is_refused(tmp_path, monkeypatch) -> None:
    first = Front(tmp_path, monkeypatch)
    old_binding = first.ledger.binding_sha256
    first.ledger.store.close()
    second = Front(tmp_path, monkeypatch)
    status, _h, out = second.create(expected=second.expected(binding_sha256=old_binding))
    assert status == 409 and b"escape_expected_launch_mismatch" in out
    assert second.creates() == 0


@pytest.mark.parametrize("expected", [
    None,
    "not json",
    json.dumps({"schema": "cathedral.escape.expected_launch/v0"}),
    "extra",
    "drop",
    "short_binding",
])
def test_fresh_create_without_a_well_formed_expected_launch_is_refused(tmp_path, monkeypatch, expected) -> None:
    front = Front(tmp_path, monkeypatch)
    if expected == "extra":
        expected = {**front.expected(), "owner": "o"}
    elif expected == "drop":
        expected = {k: v for k, v in front.expected().items() if k != "binding_sha256"}
    elif expected == "short_binding":
        expected = front.expected(binding_sha256="a" * 63)
    status, headers, out = front.create(expected=expected)
    assert status == 400 and b"escape_expected_launch_invalid" in out
    assert "X-Room-Receipt" not in headers
    assert front.creates() == 0 and front.ledger.fresh_used == set()


def test_expected_launch_without_the_assignment_is_refused(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    status, _h, out = front.create(fresh=None, expected=front.expected())
    assert status == 400 and b"escape_fresh_refused" in out
    status, _h, out = front.request("POST", "/v1/sandboxes/room-1/exec", b'{"cmd":["true"]}',
                                    {"X-Escape-Expected-Launch": json.dumps(front.expected())})
    assert status == 400 and b"escape_fresh_refused" in out
    assert front.calls == []


def test_guest_without_a_launch_report_id_refuses(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    front.ledger.report = front.ledger.report[:0x140] + bytes(32) + front.ledger.report[0x160:]
    assert front.ledger.launch_report_id() is None
    status, _h, out = front.create()
    assert status == 409 and b"escape_expected_launch_mismatch" in out
    assert front.creates() == 0


def test_expected_launch_is_not_sent_on_to_the_room_api(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    assert front.create()[0] == 202
    assert all("x-escape-expected-launch" not in {k.lower() for k in h} for _m, _p, h in front.calls)


def test_reservation_that_cannot_be_saved_sends_nothing(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    real_link, broken = rr.os.link, [True]

    def failing_link(*args, **kwargs):
        if broken[0]:
            raise OSError("disk full")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(rr.os, "link", failing_link)
    status, headers, out = front.create()
    assert status == 503 and b"escape_fresh_reservation_failed" in out
    assert "X-Room-Receipt" not in headers and front.creates() == 0
    broken[0] = False
    # Unknown save outcome: the attempt and launch stay used in this process.
    status, _h, out = front.create()
    assert status == 409 and b"escape_fresh_consumed" in out
    assert front.creates() == 0
    # No temporary file is left behind.
    assert _reservations(tmp_path) == []


def test_reservation_is_written_before_the_create_is_sent(tmp_path, monkeypatch) -> None:
    front = Front(tmp_path, monkeypatch)
    seen = []
    real = front.ledger.consume_fresh

    def watching(fresh):
        assert front.creates() == 0
        ok = real(fresh)
        seen.append(len(_reservations(tmp_path)))
        return ok

    monkeypatch.setattr(front.ledger, "consume_fresh", watching)
    assert front.create()[0] == 202
    assert seen == [2]
    for name in _reservations(tmp_path):
        record = json.loads((tmp_path / "store" / rr.ESCAPE_FRESH_RESERVATION_DIR / name).read_bytes())
        assert record == {"attempt_id": "attempt-1", "report_id": LAUNCH, "request_sha256": "a" * 64,
                          "binding_sha256": front.ledger.binding_sha256}


def test_attempt_stays_reserved_when_its_launch_was_taken(tmp_path, monkeypatch) -> None:
    first = Front(tmp_path, monkeypatch)
    assert first.create()[0] == 202
    first.ledger.store.close()
    second = Front(tmp_path, monkeypatch)
    late = {**FRESH, "attempt_id": "attempt-9"}
    assert second.create(late)[0] == 409
    assert len(_reservations(tmp_path)) == 3
    third = Front(tmp_path, monkeypatch)
    assert third.create(late)[0] == 409
    assert third.creates() == 0
