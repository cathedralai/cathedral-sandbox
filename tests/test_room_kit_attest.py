"""POST /room/attest on the receipt front: a fresh SNP report over caller REPORT_DATA."""
from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import threading
import uuid
from pathlib import Path

import pytest

from cathedral.verify.snp import REPORT_DATA_OFFSET, parse_snp_report

KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_attest_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)
KEY = b"k" * 32
MEASUREMENT = bytes(range(48))


def _fake_report(report_data: bytes) -> bytes:
    """1184 bytes, the SNP layout's REPORT_DATA and MEASUREMENT filled in."""
    rep = bytearray(1184)
    rep[0:4] = (2).to_bytes(4, "little")
    rep[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET + 64] = report_data
    rep[0x90:0xC0] = MEASUREMENT
    rep[0x2A0:0x2A0 + 512] = b"\x01" * 512  # a nonempty (unverified) signature
    return bytes(rep)


def _cert_table(certs: dict[str, bytes], le: bool = True) -> bytes:
    entries, blobs = [], []
    off = 24 * (len(certs) + 1)
    for name, der in certs.items():
        u = uuid.UUID(rr._CERT_GUIDS[name])
        entries.append((u.bytes_le if le else u.bytes) + off.to_bytes(4, "little") + len(der).to_bytes(4, "little"))
        blobs.append(der)
        off += len(der)
    return b"".join(entries) + bytes(24) + b"".join(blobs)


class FakeTsm:
    def __init__(self, provider: str = "sev_guest", aux: bytes = b""):
        self.provider, self.aux, self.inputs = provider, aux, []

    def __call__(self, report_data: bytes, want_aux: bool = False):
        self.inputs.append(report_data)
        return self.provider, _fake_report(report_data), (self.aux if want_aux else b"")


def _start(tmp_path, monkeypatch, tsm: FakeTsm | None, per_minute: int = 30):
    if tsm is None:
        monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    else:
        monkeypatch.setattr(rr, "tsm_provider", lambda: tsm.provider)
        monkeypatch.setattr(rr, "_read_tsm_aux", tsm)
    monkeypatch.setattr(rr, "read", lambda path, default="": "boot-1" if "boot_id" in path else default)
    ledger = rr.Ledger("sealed-1", str(tmp_path))
    server = rr.Server(("127.0.0.1", 0), ledger, 1, 1, KEY, "/nonexistent.sock", attest_per_minute=per_minute)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, ledger


@pytest.fixture
def sealed(tmp_path, monkeypatch):
    tsm = FakeTsm()
    server, ledger = _start(tmp_path, monkeypatch, tsm)
    yield server.server_address[1], ledger, tsm
    server.shutdown()


def _attest(port: int, body, key: bytes | None = KEY, method: str = "POST"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["Authorization"] = "Bearer " + key.decode()
    c.request(method, "/room/attest", body=raw, headers=headers)
    r = c.getresponse()
    out = r.read()
    return r.status, dict(r.getheaders()), (json.loads(out) if out else None)


def test_report_data_is_the_callers_bytes_verbatim(sealed) -> None:
    port, ledger, tsm = sealed
    rd = hashlib.sha512(b"gittensor challenge run 42").digest()
    status, _h, doc = _attest(port, {"report_data_hex": rd.hex()})
    assert status == 200, doc
    report = base64.b64decode(doc["report_b64"])
    assert parse_snp_report(report).report_data == rd
    assert tsm.inputs[-1] == rd  # the TSM got the 64 bytes, not a hash of them
    assert doc["binding_sha256"] == ledger.binding_sha256
    assert doc["measurement"] == MEASUREMENT.hex() == ledger.binding["measurement"]
    assert isinstance(doc["generated_at"], int)
    assert doc["cert_chain_b64"] is None  # no host certificate table


def test_uppercase_hex_is_accepted(sealed) -> None:
    port, _ledger, tsm = sealed
    rd = bytes(range(64))
    status, _h, _doc = _attest(port, {"report_data_hex": rd.hex().upper()})
    assert status == 200 and tsm.inputs[-1] == rd


@pytest.mark.parametrize("body", [
    {"report_data_hex": "ab" * 63},
    {"report_data_hex": "ab" * 65},
    {"report_data_hex": "zz" * 64},
    {"report_data_hex": "ab" * 64 + "\n"},
    {"report_data_hex": " " + "ab" * 63 + "a"},
    {"report_data_hex": 12},
    {"report_data": "ab" * 64},
    ["ab" * 64],
    b"not json",
    b"",
])
def test_bad_report_data_is_a_400(sealed, body) -> None:
    port, _ledger, tsm = sealed
    before = len(tsm.inputs)
    status, _h, _doc = _attest(port, body)
    assert status == 400
    assert len(tsm.inputs) == before


@pytest.mark.parametrize("key", [None, b"wrong-key"])
def test_attest_needs_the_hotel_key(sealed, key) -> None:
    port, _ledger, tsm = sealed
    before = len(tsm.inputs)
    status, _h, _doc = _attest(port, {"report_data_hex": "00" * 64}, key=key)
    assert status == 401 and len(tsm.inputs) == before


def test_get_is_not_allowed(sealed) -> None:
    port, _ledger, _tsm = sealed
    status, _h, _doc = _attest(port, b"", method="GET")
    assert status == 405


def test_an_unsealed_hotel_answers_503_not_sealed(tmp_path, monkeypatch) -> None:
    server, _ledger = _start(tmp_path, monkeypatch, None)
    try:
        status, _h, doc = _attest(server.server_address[1], {"report_data_hex": "00" * 64})
        assert status == 503 and doc == {"error": "not_sealed"}
    finally:
        server.shutdown()


def test_reports_over_the_limit_get_429(tmp_path, monkeypatch) -> None:
    tsm = FakeTsm()
    server, _ledger = _start(tmp_path, monkeypatch, tsm, per_minute=3)
    port = server.server_address[1]
    try:
        for i in range(3):
            assert _attest(port, {"report_data_hex": f"{i:02x}" * 64})[0] == 200
        status, headers, doc = _attest(port, {"report_data_hex": "ff" * 64})
        assert status == 429 and doc == {"error": "attest_rate_limit"}
        assert 1 <= int(headers["Retry-After"]) <= 61
        # Bad requests do not spend a slot, and the limit holds for them too.
        assert _attest(port, {"report_data_hex": "x"})[0] == 400
    finally:
        server.shutdown()


def test_cert_chain_from_the_host_table(tmp_path, monkeypatch) -> None:
    certs = {"vcek": b"VCEK-DER", "ask": b"ASK-DER", "ark": b"ARK-DER"}
    tsm = FakeTsm(aux=_cert_table(certs))
    server, _ledger = _start(tmp_path, monkeypatch, tsm)
    try:
        status, _h, doc = _attest(server.server_address[1], {"report_data_hex": "11" * 64})
        assert status == 200
        assert doc["cert_chain_b64"] == {k: base64.b64encode(v).decode() for k, v in certs.items()}
    finally:
        server.shutdown()


def test_cert_chain_parser() -> None:
    certs = {"vcek": b"V" * 10, "ask": b"A" * 5, "ark": b"R" * 7}
    assert rr.cert_chain(_cert_table(certs, le=False))["ask"] == base64.b64encode(b"A" * 5).decode()
    assert rr.cert_chain(_cert_table({"vcek": b"V"})) is None  # partial: not a chain
    assert rr.cert_chain(b"") is None
    broken = bytearray(_cert_table(certs))
    broken[16:20] = (10_000).to_bytes(4, "little")  # vcek offset out of range
    assert rr.cert_chain(bytes(broken)) is None


def test_a_changed_measurement_is_refused(sealed, monkeypatch) -> None:
    port, _ledger, tsm = sealed

    def other(report_data, want_aux=False):
        rep = bytearray(_fake_report(report_data))
        rep[0x90:0xC0] = bytes(48)
        return "sev_guest", bytes(rep), b""

    monkeypatch.setattr(rr, "_read_tsm_aux", other)
    status, _h, doc = _attest(port, {"report_data_hex": "22" * 64})
    assert status == 500 and doc["error"] == "attest_failed"
