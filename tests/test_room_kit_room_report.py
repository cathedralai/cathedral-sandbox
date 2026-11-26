"""The in-room SNP report call on the receipts front (AB#1001, docs/IN_ROOM_REPORT_CALL.md).

A room on a sealed dedicated hotel posts its own 64 bytes to /run/cathedral/attest.sock. The front
answers with a fresh report over SHA-512(domain || statement) and the statement signed by the
receipt key. These tests drive the real socket with a fake TSM and a fake room API.
"""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from cathedral.verify.snp import REPORT_DATA_OFFSET, parse_snp_report

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_room_report_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
MEASUREMENT = bytes(range(48))
ROOM, OTHER = "sbx_roomaaaa", "sbx_roombbbb"
NONCE = bytes(range(64))


def _fake_report(report_data: bytes) -> bytes:
    rep = bytearray(1184)
    rep[0:4] = (2).to_bytes(4, "little")
    rep[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64] = report_data
    rep[0x90:0xC0] = MEASUREMENT
    rep[0x140:0x160] = b"\x07" * 32  # REPORT_ID
    rep[0x2A0:0x2A0 + 512] = b"\x01" * 512
    return bytes(rep)


class FakeTsm:
    """configfs-tsm stand-in. *during* runs inside each non-boot read, as a report in flight would."""

    def __init__(self):
        self.inputs: list[bytes] = []
        self.during = None

    def __call__(self, report_data: bytes, want_aux: bool = False):
        self.inputs.append(report_data)
        if report_data != bytes(64) and self.during is not None:
            self.during()
        return "sev_guest", _fake_report(report_data), b""


class FakeApi:
    def __init__(self):
        self.states: dict[str, str | None] = {}
        self.down = False
        self.calls: list[str] = []

    def __call__(self, path: str, timeout: float, total: float | None = None):
        self.calls.append(path)
        if self.down:
            return None
        state = self.states.get(path.rsplit("/", 1)[-1])
        if state is None:
            return 404, b'{"error":"not_found"}'
        return 200, json.dumps({"state": state}).encode()


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 10):
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


@pytest.fixture
def hotel(tmp_path, monkeypatch):
    monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    monkeypatch.delenv("ROOM_ALLOW_TUN", raising=False)
    tsm = FakeTsm()
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "_read_tsm_aux", tsm)
    monkeypatch.setattr(rr, "read", lambda path, default="": "boot-1" if "boot_id" in path else default)
    ledger = rr.Ledger("sealed-dedicated-1", str(tmp_path / "store"))
    # Unix socket paths are short (104 bytes on macOS): keep the root out of pytest's long tmp path.
    root = Path(tempfile.mkdtemp(prefix="rra", dir="/tmp"))
    api = FakeApi()
    reports = rr.RoomReports(str(root), ledger)
    ledger.room_reports = reports
    yield ledger, reports, root, api, tsm
    reports.stop()
    shutil.rmtree(root, ignore_errors=True)


def make_room(ledger, root: Path, api: FakeApi, room: str = ROOM) -> str:
    """What a create through the front leaves: the API's directory, a running record and a create receipt."""
    (root / room).mkdir(mode=0o755, exist_ok=True)
    api.states[room] = "running"
    return ledger.sign({"action": "create", "sandbox_id": room, "status": 201})["receipt_sha256"]


def sock(root: Path, room: str = ROOM) -> str:
    return str(root / room / rr.ROOM_REPORT_SOCKET)


def post(path: str, body, conn: UnixHTTPConnection | None = None):
    c = conn or UnixHTTPConnection(path)
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    c.request("POST", "/v1/report", body=raw, headers={"Content-Type": "application/json"})
    r = c.getresponse()
    out = r.read()
    return r.status, dict(r.getheaders()), (json.loads(out) if out else None)


def started(hotel, *rooms: str):
    ledger, reports, root, api, tsm = hotel
    incarnations = {room: make_room(ledger, root, api, room) for room in (rooms or (ROOM,))}
    reports.start(api, scan_seconds=None)
    return incarnations


# -- the answer


def test_room_gets_a_report_bound_to_a_statement_signed_by_the_receipt_key(hotel) -> None:
    ledger, _reports, root, _api, tsm = hotel
    incarnation = started(hotel)[ROOM]
    assert stat.S_IMODE(os.stat(sock(root)).st_mode) == 0o666  # a non-root room user can connect
    status, _h, doc = post(sock(root), {"report_data_hex": NONCE.hex().upper()})
    assert status == 200, doc
    statement = doc["statement"]
    assert statement == {"schema": "cathedral.room.report/v1", "hotel": "sealed-dedicated-1",
                         "binding_sha256": ledger.binding_sha256, "sandbox_id": ROOM, "incarnation": incarnation,
                         "caller_report_data_hex": NONCE.hex(), "requested_at": statement["requested_at"]}
    expected = rr.room_report_data(statement)
    assert tsm.inputs[-1] == expected  # the chip got SHA-512(domain || statement), not the room's bytes
    assert parse_snp_report(base64.b64decode(doc["report_b64"])).report_data == expected
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(ledger.binding["receipt_key_ed25519_b64"]))
    key.verify(base64.b64decode(doc["statement_sig_b64"]), rr.canonical(statement))  # raises if wrong
    assert doc["statement_sha256"] == rr.sha(rr.canonical(statement))
    assert doc["create_receipt"]["receipt_sha256"] == incarnation
    assert doc["create_receipt"]["statement"]["sandbox_id"] == ROOM
    assert doc["attestation"] == json.loads(rr.canonical(ledger.attestation()))
    assert doc["cert_chain"] is None and doc["chip_id"] and doc["reported_tcb"]


def test_two_rooms_with_the_same_bytes_get_different_reports(hotel) -> None:
    _ledger, _reports, root, _api, tsm = hotel
    started(hotel, ROOM, OTHER)
    a = post(sock(root, ROOM), {"report_data_hex": NONCE.hex()})[2]
    b = post(sock(root, OTHER), {"report_data_hex": NONCE.hex()})[2]
    assert a["statement"]["sandbox_id"] == ROOM and b["statement"]["sandbox_id"] == OTHER
    assert tsm.inputs[-1] != tsm.inputs[-2]


def test_the_domain_keeps_room_reports_off_every_hotel_shape(hotel) -> None:
    # A room never chooses REPORT_DATA: the boot binding shape (32 zero bytes at the end) cannot come out.
    _ledger, _reports, root, _api, tsm = hotel
    started(hotel)
    shaped = bytes(32) + bytes(32)
    status, _h, _doc = post(sock(root), {"report_data_hex": shaped.hex()})
    assert status == 200 and tsm.inputs[-1] != shaped and tsm.inputs[-1][32:] != bytes(32)


# -- which rooms have a socket


def test_a_directory_with_no_signed_create_gets_no_socket(hotel) -> None:
    ledger, reports, root, api, _tsm = hotel
    (root / "sbx_nocreate1").mkdir()
    api.states["sbx_nocreate1"] = "running"
    reports.start(api, scan_seconds=None)
    assert not os.path.exists(sock(root, "sbx_nocreate1"))


def test_a_link_is_never_a_room_directory(hotel) -> None:
    ledger, reports, root, api, _tsm = hotel
    elsewhere = root / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, root / ROOM)
    api.states[ROOM] = "running"
    ledger.sign({"action": "create", "sandbox_id": ROOM, "status": 201})
    reports.start(api, scan_seconds=None)
    assert not os.path.exists(elsewhere / rr.ROOM_REPORT_SOCKET)


def test_front_restart_clears_old_sockets_and_reopens_none(hotel) -> None:
    _ledger, reports, root, api, _tsm = hotel
    (root / ROOM).mkdir()
    (root / ROOM / rr.ROOM_REPORT_SOCKET).write_text("left by the earlier front")
    api.states[ROOM] = "running"  # the container survived; this front signed no create for it
    reports.start(api, scan_seconds=None)
    assert not os.path.exists(sock(root))
    assert ROOM not in reports.listeners


# -- liveness


def test_delete_closes_the_socket_and_an_open_connection(hotel) -> None:
    ledger, _reports, root, _api, _tsm = hotel
    started(hotel)
    conn = UnixHTTPConnection(sock(root))
    assert post(sock(root), {"report_data_hex": NONCE.hex()}, conn)[0] == 200  # keep-alive stays open
    ledger.sign({"action": "delete", "sandbox_id": ROOM, "status": 204})
    rr.retire_room(ledger, ROOM)
    assert not os.path.exists(sock(root))
    with pytest.raises((OSError, http.client.HTTPException)):
        post(sock(root), {"report_data_hex": NONCE.hex()}, conn)


def test_a_room_the_api_retires_during_its_report_gets_no_statement(hotel) -> None:
    _ledger, _reports, root, api, tsm = hotel
    started(hotel)
    tsm.during = lambda: api.states.__setitem__(ROOM, "deleting")  # retired on its own; container lingers
    status, _h, doc = post(sock(root), {"report_data_hex": NONCE.hex()})
    assert status == 410 and doc == {"error": "room_gone"}
    deadline = time.monotonic() + 5
    while os.path.exists(sock(root)) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not os.path.exists(sock(root))


def test_api_404_is_gone(hotel) -> None:
    _ledger, _reports, root, api, _tsm = hotel
    started(hotel)
    del api.states[ROOM]
    assert post(sock(root), {"report_data_hex": NONCE.hex()})[0] == 410


@pytest.mark.parametrize("cause", ["reaping", "broken", "api_down", "frozen", "creating"])
def test_a_temporary_state_is_503_and_keeps_the_socket(hotel, cause) -> None:
    ledger, _reports, root, api, tsm = hotel
    started(hotel)
    before = len(tsm.inputs)
    if cause in ("reaping", "broken"):
        getattr(ledger, cause).add(ROOM)
    elif cause == "api_down":
        api.down = True
    else:
        api.states[ROOM] = cause
    status, headers, doc = post(sock(root), {"report_data_hex": NONCE.hex()})
    assert status == 503 and doc == {"error": "room_not_ready"} and headers.get("Retry-After")
    assert len(tsm.inputs) == before  # no chip work for a room that is not ready
    time.sleep(0.1)
    assert os.path.exists(sock(root))


def test_a_create_replayed_during_the_report_is_409(hotel) -> None:
    ledger, _reports, root, _api, tsm = hotel
    started(hotel)
    tsm.during = lambda: ledger.sign({"action": "create", "sandbox_id": ROOM, "status": 201})
    status, _h, doc = post(sock(root), {"report_data_hex": NONCE.hex()})
    assert status == 409 and doc["error"] == "retry"
    tsm.during = None
    status, _h, doc = post(sock(root), {"report_data_hex": NONCE.hex()})
    assert status == 200 and doc["statement"]["incarnation"] == doc["create_receipt"]["receipt_sha256"]


# -- the chip


def test_scheduler_serves_a_waiting_broker_check_before_a_waiting_room() -> None:
    sched = rr.ReportScheduler()
    with sched.cond:
        sched.waiting[sched.BROKER] = 1  # a broker check is waiting; the slot itself is free
    got = threading.Event()

    def room() -> None:
        sched.acquire(sched.ROOM)
        got.set()

    threading.Thread(target=room, daemon=True).start()
    assert not got.wait(0.3)  # the free slot goes to no room while the broker waits
    with sched.cond:
        sched.waiting[sched.BROKER] = 0
        sched.cond.notify_all()
    assert got.wait(5)
    sched.release()


def test_a_stalled_read_keeps_the_chip_slot_past_the_rooms_answer(hotel, monkeypatch) -> None:
    _ledger, reports, root, _api, tsm = hotel
    monkeypatch.setattr(rr, "ROOM_REPORT_DEADLINE_SECONDS", 0.3)
    started(hotel)
    release = threading.Event()
    tsm.during = lambda: release.wait(10)
    status, _h, doc = post(sock(root), {"report_data_hex": NONCE.hex()})
    assert status == 503 and doc == {"error": "room_report_slow"}
    assert reports.scheduler.busy  # the read still runs: no second in-room read can start
    assert post(sock(root), {"report_data_hex": NONCE.hex()})[0] == 429  # the room already has one
    release.set()
    deadline = time.monotonic() + 5
    while (reports.scheduler.busy or ROOM in reports.active) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not reports.scheduler.busy and ROOM not in reports.active


def test_hotel_attest_route_takes_the_scheduler_with_broker_first(hotel, monkeypatch) -> None:
    ledger, reports, _root, _api, _tsm = hotel
    seen: list[int] = []
    real = reports.scheduler.acquire
    monkeypatch.setattr(reports.scheduler, "acquire", lambda p: (seen.append(p), real(p))[1])
    key = b"k" * 32
    server = rr.Server(("127.0.0.1", 0), ledger, 1, 1, key, "/nonexistent.sock")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for guest in ("_broker_fresh", "guest-a"):
            c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
            c.request("POST", "/room/attest", body=json.dumps({"report_data_hex": "01" * 64}),
                      headers={"Authorization": "Bearer " + key.decode(), "X-Cathedral-Guest": guest})
            assert c.getresponse().status == 200
        assert seen == [rr.ReportScheduler.BROKER, rr.ReportScheduler.HOTEL]
        assert not reports.scheduler.busy
    finally:
        server.shutdown()


# -- the request


@pytest.mark.parametrize("body,status", [
    ({"report_data_hex": "ab" * 63}, 400),
    ({"report_data_hex": "zz" * 64}, 400),
    ({"report_data": "ab" * 64}, 400),
    (b"not json", 400),
    (b"x" * 2048, 413),
])
def test_bad_requests_do_no_chip_work(hotel, body, status) -> None:
    _ledger, _reports, root, _api, tsm = hotel
    started(hotel)
    before = len(tsm.inputs)
    assert post(sock(root), body)[0] == status
    assert len(tsm.inputs) == before


def test_other_routes_and_methods(hotel) -> None:
    _ledger, _reports, root, _api, _tsm = hotel
    started(hotel)
    c = UnixHTTPConnection(sock(root))
    c.request("GET", "/v1/report")
    r = c.getresponse()
    r.read()
    assert r.status == 405
    c.request("POST", "/room/attest", body=b"{}", headers={"Content-Length": "2"})
    r = c.getresponse()
    r.read()
    assert r.status == 404


def test_at_most_four_connections_per_room(hotel) -> None:
    _ledger, _reports, root, _api, _tsm = hotel
    started(hotel)
    held = []
    for _ in range(rr.ROOM_REPORT_CONNECTIONS):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock(root))
        held.append(s)
    time.sleep(0.2)
    extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    extra.settimeout(5)
    extra.connect(sock(root))
    assert extra.recv(1) == b""  # closed at once
    for s in held + [extra]:
        s.close()
