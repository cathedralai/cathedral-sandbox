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
    assert doc["cert_chain"] is None  # no host certificate table


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
    status, _h, _doc = _attest(port, {"report_data_hex": "01" * 64}, key=key)
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
            assert _attest(port, {"report_data_hex": f"{i + 1:02x}" * 64})[0] == 200
        status, headers, doc = _attest(port, {"report_data_hex": "ff" * 64})
        assert status == 429 and doc == {"error": "attest_rate_limit"}
        assert 1 <= int(headers["Retry-After"]) <= 61
        # Bad requests do not spend a slot, and the limit holds for them too.
        assert _attest(port, {"report_data_hex": "x"})[0] == 400
    finally:
        server.shutdown()


def test_attest_rate_limit_is_per_guest(tmp_path, monkeypatch) -> None:
    tsm = FakeTsm()
    server, _ledger = _start(tmp_path, monkeypatch, tsm, per_minute=2)
    port = server.server_address[1]

    def attest_as(guest: str, nibble: int) -> int:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + KEY.decode(),
            "X-Cathedral-Guest": guest,
        }
        c.request(
            "POST",
            "/room/attest",
            body=json.dumps({"report_data_hex": f"{nibble:02x}" * 64}).encode(),
            headers=headers,
        )
        return c.getresponse().status

    try:
        assert attest_as("g1", 1) == 200 and attest_as("g1", 2) == 200
        assert attest_as("g1", 3) == 429
        # Another guest still has its own budget on the same hotel.
        assert attest_as("g2", 4) == 200 and attest_as("g2", 5) == 200
        assert attest_as("g2", 6) == 429
    finally:
        server.shutdown()


def test_cert_chain_from_the_host_table(tmp_path, monkeypatch) -> None:
    certs = {"vcek": b"VCEK-DER", "ask": b"ASK-DER", "ark": b"ARK-DER"}
    tsm = FakeTsm(aux=_cert_table(certs))
    server, _ledger = _start(tmp_path, monkeypatch, tsm)
    try:
        status, _h, doc = _attest(server.server_address[1], {"report_data_hex": "11" * 64})
        assert status == 200
        assert doc["cert_chain"] == {k: base64.b64encode(v).decode() for k, v in certs.items()}
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


@pytest.mark.parametrize("head", [bytes(32), hashlib.sha256(b"a forged binding").digest()])
def test_binding_shaped_report_data_is_refused(sealed, head) -> None:
    """sha256(binding) || 32 zero bytes is the boot binding's shape: never signed on request (AB#392)."""
    port, ledger, tsm = sealed
    before = len(tsm.inputs)
    status, _h, doc = _attest(port, {"report_data_hex": (head + bytes(32)).hex()})
    assert status == 400 and doc["error"] == "report_data_reserved"
    assert len(tsm.inputs) == before
    with pytest.raises(ValueError):
        ledger.attest(head + bytes(32))
    assert len(tsm.inputs) == before


def test_one_nonzero_byte_in_the_tail_is_accepted(sealed) -> None:
    port, _ledger, tsm = sealed
    rd = hashlib.sha256(b"x").digest() + bytes(31) + b"\x01"
    status, _h, _doc = _attest(port, {"report_data_hex": rd.hex()})
    assert status == 200 and tsm.inputs[-1] == rd


# An Escape challenge receipt v1.1 (gt-challenge-sealed-sandbox receipt.py, binding rd-claims-v1) as the API
# builds it (polariscomputer services/cathedral_challenge_capacity.py build_attestation): REPORT_DATA is
# sha256(CLAIMS_DOMAIN || canonical(claims)) || 32 zero bytes, the boot binding's shape (AB#392 HOLD on #597).
ESCAPE_CLAIMS = {
    "attestation_digest": "57a6c7a63bcdefcf402fccf67bf04920c450f1c114950cfc603b8c0d31c3f005",
    "challenge": {
        "challenge_id": "sealed-sandbox-tti",
        "config_sha256": "d30988eb540a12f821dcaa8544fe9219f9010c8ad60ecc7ca0be075937c5f60c",
        "main_commit": "7316dbf0eb94d7b1e211c5fe161ef73072edf9f7",
        "module": "gt_challenge_sealed_sandbox",
        "package": "gt-challenge-sealed-sandbox @ git+https://github.com/cathedralai/gt-challenge-sealed-sandbox"
                   "@7316dbf0eb94d7b1e211c5fe161ef73072edf9f7",
        "repo": "cathedralai/gt-challenge-sealed-sandbox",
        "seeds": 25,
        "tier": "standard",
    },
    "evaluator": {
        "cpu_model": "AMD EPYC 9354P 32-Core Processor",
        "egress": "none",
        "entrypoint": ["polaris.services.cathedral_challenge_capacity"],
        "image": "ghcr.io/cathedralai/gt-challenge-sealed-sandbox@sha256:" + "cd" * 32,
        "machine": "snp:c46-sealed",
        "memory_mib": 4096,
        "runner": "polaris-api-in-process",
        "solver_cpus": 2,
        "vcpus": 2,
    },
    "outputs": {
        "challenger_valid": 25,
        "crown": True,
        "king_valid": 25,
        "result_sha256": "4f19161b97b0a9afc92760d1d28de29ab79f5e309e5143c5df225b8fa732fdf7",
        "seed_log_sha256": "335fd79cd238341abc4392bbd6a6cb9c6cd32e5755ed61e26bf5fa7222f7edaa",
    },
    "run": {
        "attempt": 1,
        "exit_code": 0,
        "finished_at": "2026-11-19T12:37:45.677975Z",
        "network": "finney",
        "run_id": "21a01c84-887b-4c52-8cc1-14a46fb0dad2",
        "run_nonce": "ebb552bcf6faee8841154b0d90376b35",
        "seed_block": 4242424,
        "seed_block_hash": "ab" * 32,
        "seed_policy": "latest_finalized_at_accept",
        "started_at": "2026-11-19T12:31:02.565323Z",
        "wall_seconds": 403,
    },
    "submission": {
        "challenger_path": "solvers/bateesatobi/1",
        "challenger_tree_sha": "e3cfef0c92fa19ff775960921d9b3e2857ae5e88",
        "github_id": 1234567,
        "github_login": "bateesatobi",
        "hotkey": "5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX",
        "hotkey_signature": "0x" + "9f" * 64,
        "king_path": "baselines/default",
        "king_tree_sha": "b83b51c14925903cc4d36716ba81ef5606304d97",
    },
}
# gt-challenge-sealed-sandbox receipt.py CLAIMS_DOMAIN and canonical(): kept literal so a drift fails here.
GT_CLAIMS_DOMAIN = b"cathedral-challenge-receipt-v1/claims\0"


def _escape_report_data(claims: dict) -> tuple[bytes, bytes]:
    canon = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(GT_CLAIMS_DOMAIN + canon).digest() + bytes(32), canon


def test_escape_rd_claims_v1_report_is_signed_with_its_claims(sealed) -> None:
    """The HOLD on #597: an Escape v1.1 receipt still gets its report, so receipts keep verifying after the roll."""
    port, ledger, tsm = sealed
    assert rr.ESCAPE_CLAIMS_DOMAIN == GT_CLAIMS_DOMAIN
    rd, canon = _escape_report_data(ESCAPE_CLAIMS)
    assert rr.binding_shaped(rd)
    body = {"report_data_hex": rd.hex(), "escape_claims_b64": base64.b64encode(canon).decode()}
    # The broker caps the attest body (broker/main.go hotelAttestBodyMax, 20480): a real body fits with room.
    assert len(json.dumps(body)) < 8192
    status, _h, doc = _attest(port, body)
    assert status == 200 and tsm.inputs[-1] == rd
    report = base64.b64decode(doc["report_b64"])
    # What gt-challenge's _check_snp compares: REPORT_DATA == expected_report_data('rd-claims-v1', claims).
    assert parse_snp_report(report).report_data == rd
    assert ledger.attest(rd, canon)["report_b64"]
    # Without its claims the same bytes stay reserved.
    before = len(tsm.inputs)
    status, _h, doc = _attest(port, {"report_data_hex": rd.hex()})
    assert status == 400 and doc["error"] == "report_data_reserved" and len(tsm.inputs) == before


def test_escape_claims_cannot_carry_a_forged_binding(sealed) -> None:
    """The exemption needs the Escape domain preimage, so it never yields sha256(canonical(binding)) || 0."""
    port, ledger, tsm = sealed
    before = len(tsm.inputs)
    forged = json.dumps({"receipt_pubkey": "ab" * 32, "measurement": "cd" * 48}, sort_keys=True,
                        separators=(",", ":")).encode()
    rd = hashlib.sha256(forged).digest() + bytes(32)
    # The binding bytes themselves, or the binding with the domain glued on, do not match its digest.
    for claims in (forged, GT_CLAIMS_DOMAIN + forged):
        status, _h, doc = _attest(port, {"report_data_hex": rd.hex(), "escape_claims_b64": base64.b64encode(claims).decode()})
        assert status == 400 and doc["error"] == "escape_claims_mismatch"
        with pytest.raises(ValueError):
            ledger.attest(rd, claims)
    # Real Escape claims next to someone else's digest are a mismatch too.
    _rd, canon = _escape_report_data(ESCAPE_CLAIMS)
    status, _h, doc = _attest(port, {"report_data_hex": rd.hex(), "escape_claims_b64": base64.b64encode(canon).decode()})
    assert status == 400 and doc["error"] == "escape_claims_mismatch"
    assert len(tsm.inputs) == before


@pytest.mark.parametrize("value", [7, "not base64!", base64.b64encode(b"x" * (12 * 1024 + 1)).decode(), ""])
def test_bad_escape_claims_are_a_400(sealed, value) -> None:
    port, _ledger, tsm = sealed
    before = len(tsm.inputs)
    rd, _canon = _escape_report_data(ESCAPE_CLAIMS)
    status, _h, doc = _attest(port, {"report_data_hex": rd.hex(), "escape_claims_b64": value})
    assert status == 400 and len(tsm.inputs) == before
