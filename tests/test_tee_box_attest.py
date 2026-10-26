"""attest.report: POST /v1/box/attest, a fresh SEV-SNP report over caller REPORT_DATA."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from pathlib import Path

import pytest
from test_tee_box_service import (
    CALLER,
    OTHER,
    _api,
    _binding,
    _handle,
    _push_revocations,
    fake_snp_report,
)

from cathedral.attest import TsmReport, read_configfs_tsm_report
from cathedral.tee_box.attest import (
    AttestRateLimited,
    AttestUnavailable,
    GuestAttestor,
    cert_chain,
)
from cathedral.verify.snp import parse_snp_report

MEASUREMENT = bytes(range(48))


class _Entry:
    """One configfs-tsm report directory: writing inblob makes outblob, as the kernel does."""

    def __init__(self, tsm: _FakeTsm, name: str) -> None:
        self.tsm, self.name = tsm, name

    def __truediv__(self, leaf: str) -> _File:
        return _File(self, leaf)

    def mkdir(self, mode: int = 0o777, exist_ok: bool = False) -> None:
        assert self.name not in self.tsm.entries and not exist_ok
        self.tsm.entries[self.name] = {}

    def rmdir(self) -> None:
        del self.tsm.entries[self.name]


class _File:
    def __init__(self, entry: _Entry, leaf: str) -> None:
        self.entry, self.leaf = entry, leaf

    def _files(self) -> dict:
        return self.entry.tsm.entries[self.entry.name]

    def write_bytes(self, data: bytes) -> None:
        assert self.leaf == "inblob"
        self.entry.tsm.inputs.append(bytes(data))
        files = self._files()
        files["outblob"] = self.entry.tsm.make(bytes(data))
        files["provider"] = self.entry.tsm.provider.encode() + b"\n"
        if self.entry.tsm.aux is not None:
            files["auxblob"] = self.entry.tsm.aux

    def read_bytes(self) -> bytes:
        files = self._files()
        if self.leaf not in files:
            raise FileNotFoundError(self.leaf)
        return files[self.leaf]

    def read_text(self) -> str:
        return self.read_bytes().decode()


class _FakeTsm:
    """Stands in for /sys/kernel/config/tsm/report."""

    def __init__(self, provider="sev_guest", aux=None, make=None) -> None:
        self.provider, self.aux = provider, aux
        self.make = make or (lambda data: fake_snp_report(data, MEASUREMENT))
        self.entries: dict[str, dict] = {}
        self.inputs: list[bytes] = []

    def exists(self) -> bool:
        return True

    def __truediv__(self, name: str) -> _Entry:
        return _Entry(self, name)


class _Monotonic:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


def _attestor(tsm: _FakeTsm, **kwargs) -> GuestAttestor:
    return GuestAttestor(reader=lambda data: read_configfs_tsm_report(data, root=tsm), **kwargs)


def _attest(api, body, caller=CALLER):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    response = api.handle("POST", "/v1/box/attest", caller, raw)
    return response.status, json.loads(response.body)


def _cert_table(certs: dict[str, bytes], little_endian: bool = True) -> bytes:
    from cathedral.tee_box.attest import _CERT_GUIDS

    entries, blobs = [], []
    offset = 24 * (len(certs) + 1)
    for name, der in certs.items():
        guid = uuid.UUID(_CERT_GUIDS[name])
        raw = guid.bytes_le if little_endian else guid.bytes
        entries.append(raw + offset.to_bytes(4, "little") + len(der).to_bytes(4, "little"))
        blobs.append(der)
        offset += len(der)
    return b"".join(entries) + bytes(24) + b"".join(blobs)


# -- the route -----------------------------------------------------------------------------


def test_report_data_is_the_callers_64_bytes_verbatim(tmp_path: Path):
    tsm = _FakeTsm()
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tsm))
    report_data = hashlib.sha512(b"gittensor run 42 claims").digest()
    status, doc = _attest(api, {"report_data_hex": report_data.hex()})
    assert status == 200, doc
    assert tsm.inputs == [report_data]  # the kernel got the bytes, not a hash of them
    report = base64.b64decode(doc["report_b64"])
    parsed = parse_snp_report(report)
    assert parsed.report_data == report_data
    assert doc["measurement"] == MEASUREMENT.hex() == parsed.measurement
    assert doc["chip_id"] == "c1" * 64 == parsed.chip_id
    assert isinstance(doc["generated_at"], int)
    assert doc["cert_chain_b64"] is None
    assert set(doc) == {
        "report_b64",
        "cert_chain_b64",
        "measurement",
        "chip_id",
        "reported_tcb",
        "generated_at",
    }
    assert tsm.entries == {}  # the report directory is removed


def test_uppercase_hex_is_the_same_bytes(tmp_path: Path):
    tsm = _FakeTsm()
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tsm))
    data = bytes(range(64))
    assert _attest(api, {"report_data_hex": data.hex().upper()})[0] == 200
    assert tsm.inputs == [data]


def test_no_lease_is_needed_but_a_revocation_list_is(tmp_path: Path):
    tsm = _FakeTsm()
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tsm), ready=False)
    body = {"report_data_hex": "00" * 64}
    status, doc = _attest(api, body)
    assert status == 409 and doc["reason"] == "revocation_list_required"
    _push_revocations(api)
    assert _attest(api, body)[0] == 200
    # Another caller holding the lease does not stop a report.
    assert _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 600})[0] == 200
    assert _attest(api, body)[0] == 200


@pytest.mark.parametrize(
    "body",
    [
        {"report_data_hex": "ab" * 63},
        {"report_data_hex": "ab" * 65},
        {"report_data_hex": "zz" * 64},
        {"report_data_hex": "ab" * 64 + "\n"},
        {"report_data_hex": " " + "ab" * 63 + "a"},
        {"report_data_hex": 12},
        {"report_data_hex": "ab" * 64, "extra": 1},
        {"report_data": "ab" * 64},
        b"not json",
        b"",
        b"[]",
    ],
)
def test_bad_bodies_are_400_and_never_reach_the_tsm(tmp_path: Path, body):
    tsm = _FakeTsm()
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tsm, per_minute=1))
    assert _attest(api, body)[0] == 400
    assert tsm.inputs == []
    assert _attest(api, {"report_data_hex": "00" * 64})[0] == 200  # no slot was used


def test_rate_limit_answers_429_with_a_wait(tmp_path: Path):
    tsm, clock = _FakeTsm(), _Monotonic()
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tsm, per_minute=2, monotonic=clock))
    body = {"report_data_hex": "11" * 64}
    assert _attest(api, body)[0] == 200
    clock.value += 10
    assert _attest(api, body)[0] == 200
    status, doc = _attest(api, body)
    assert status == 429 and doc["reason"] == "attest_rate_limit"
    assert doc["retry_after_seconds"] == 51
    assert len(tsm.inputs) == 2
    clock.value += 50.5
    assert _attest(api, body)[0] == 200


def test_a_box_that_is_not_an_snp_guest_answers_503(tmp_path: Path):
    tdx = _FakeTsm(provider="tdx_guest", make=lambda data: b"\x04\x00" + bytes(2000))
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tdx))
    status, doc = _attest(api, {"report_data_hex": "00" * 64})
    assert status == 503 and doc["reason"] == "attest_unavailable"
    assert "tdx_guest" in doc["error"]
    api, _ = _api(tmp_path, _binding())
    api._attestor = None
    assert _attest(api, {"report_data_hex": "00" * 64})[1]["reason"] == "attest_unavailable"


def test_no_configfs_tsm_answers_503(tmp_path: Path):
    attestor = GuestAttestor(root=tmp_path / "missing")
    api, _ = _api(tmp_path, _binding(), attestor=attestor)
    status, doc = _attest(api, {"report_data_hex": "00" * 64})
    assert status == 503 and doc["reason"] == "attest_unavailable"


@pytest.mark.parametrize(
    "make",
    [
        lambda data: fake_snp_report(bytes(64)),  # REPORT_DATA is not what was asked for
        lambda data: fake_snp_report(data)[:1000],  # short
        lambda data: fake_snp_report(data)[:0x2A0] + bytes(1184 - 0x2A0),  # no signature
    ],
)
def test_a_report_that_does_not_carry_the_bytes_is_never_returned(tmp_path: Path, make):
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(_FakeTsm(make=make)))
    status, doc = _attest(api, {"report_data_hex": "ab" * 64})
    assert status == 503 and doc["reason"] == "attest_unavailable"
    assert "report_b64" not in doc


# -- the certificate table -----------------------------------------------------------------


@pytest.mark.parametrize("little_endian", [True, False])
def test_the_host_certificate_table_comes_back_as_the_chain(tmp_path: Path, little_endian):
    certs = {"vcek": b"VCEK-DER", "ask": b"ASK-DER", "ark": b"ARK-DER"}
    tsm = _FakeTsm(aux=_cert_table(certs, little_endian))
    api, _ = _api(tmp_path, _binding(), attestor=_attestor(tsm))
    status, doc = _attest(api, {"report_data_hex": "22" * 64})
    assert status == 200
    assert doc["cert_chain_b64"] == {k: base64.b64encode(v).decode() for k, v in certs.items()}


def test_a_partial_or_broken_table_is_no_chain():
    assert cert_chain(b"") is None
    assert cert_chain(_cert_table({"vcek": b"V", "ask": b"A"})) is None
    table = bytearray(_cert_table({"vcek": b"V", "ask": b"A", "ark": b"R"}))
    table[20:24] = (10_000).to_bytes(4, "little")  # vcek length past the end
    assert cert_chain(bytes(table)) is None


# -- the attestor and the reader -----------------------------------------------------------


def test_the_reader_wants_exactly_64_bytes():
    tsm = _FakeTsm()
    for size in (0, 32, 63, 65):
        with pytest.raises(ValueError):
            read_configfs_tsm_report(bytes(size), root=tsm)
    assert tsm.inputs == []
    report = read_configfs_tsm_report(bytes(64), root=tsm)
    assert isinstance(report, TsmReport) and report.provider == "sev_guest"


def test_the_attestor_refuses_a_bad_rate_and_raises_typed_errors():
    for rate in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            GuestAttestor(reader=lambda data: None, per_minute=rate)
    clock = _Monotonic()
    attestor = _attestor(_FakeTsm(provider="none"), per_minute=1, monotonic=clock)
    with pytest.raises(AttestUnavailable):
        attestor.report(bytes(64))
    with pytest.raises(AttestRateLimited) as caught:
        attestor.report(bytes(64))
    assert caught.value.retry_after == 61
