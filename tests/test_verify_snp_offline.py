"""Offline replay tests. Real fixture rejection is an intentional policy finding."""
import json
import os
import socket
import struct
from contextlib import nullcontext
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cathedral.common import Policy
import cathedral.verify.snp as snp

FIXTURE = Path(__file__).parent / "fixtures" / "snp"
REPORT = (FIXTURE / "attestation-report.bin").read_bytes()
DATA = (FIXTURE / "request-data.bin").read_bytes()


def chain():
    return snp.SnpCertificateChain(**{name: (FIXTURE / "offline" / (name + ".der")).read_bytes()
                                     for name in ("vcek", "ask", "ark")})


def policy(report=REPORT):
    parsed = snp.parse_snp_report(report)
    return Policy(allowed_measurements={parsed.measurement}, min_tcb=parsed.tcb.reported)


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("outbound network is denied during offline tests")
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)


def test_real_fixture_rejected_by_unchanged_admission_policy():
    parsed = snp.parse_snp_report(REPORT)
    assert parsed.version == 5
    assert parsed.vmpl == 1
    assert parsed.platform_info & (1 << 6)
    certs = chain()
    assert snp.verify_snp_offline(REPORT, DATA, policy(), vcek_der=certs.vcek,
                                  ask_der=certs.ask, ark_der=certs.ark) is None


def test_offline_uses_only_private_der_files_and_verify_commands(monkeypatch):
    certs = chain()
    calls = []
    def run(command, **kwargs):
        calls.append(command[1:3])
        assert command[1] == "verify"
        directory = Path(command[3])
        assert directory.parent.stat().st_mode & 0o077 == 0
        for name in ("vcek", "ask", "ark"):
            assert (directory / (name + ".der")).read_bytes() == getattr(certs, name)
    monkeypatch.setattr(snp.subprocess, "run", run)
    assert snp._verify_chain_with_snpguest(REPORT, snpguest_path="/test/snpguest",
                                          certs_dir=None, certificate_chain=certs)
    assert calls == [["verify", "certs"], ["verify", "attestation"]]


@pytest.mark.parametrize("part", ["vcek", "ask", "ark"])
def test_truncated_der_is_rejected(part):
    certs = chain()
    values = {name + "_der": getattr(certs, name) for name in ("vcek", "ask", "ark")}
    values[part + "_der"] = values[part + "_der"][:-1]
    assert snp.verify_snp_offline(REPORT, DATA, policy(), **values) is None


def test_wrong_ark_fails_real_spki_pin_before_vendor_process(monkeypatch):
    certs = chain()
    # A valid DER certificate with a different public key is not the pinned ARK.
    wrong = snp.SnpCertificateChain(certs.vcek, certs.ask, certs.ask)
    monkeypatch.setattr(snp.subprocess, "run", lambda *a, **k: pytest.fail("untrusted root executed"))
    assert not snp._verify_chain_with_snpguest(REPORT, snpguest_path="/test/snpguest",
                                              certs_dir=None, certificate_chain=wrong)


def test_private_der_does_not_reenable_external_directories(tmp_path):
    assert not snp._verify_chain_with_snpguest(REPORT, snpguest_path="/test/snpguest",
                                              certs_dir=tmp_path, certificate_chain=chain())


@pytest.mark.parametrize("offset,value", [(0, 2), (0, 6), (0x30, 1)])
def test_offline_preserves_version_and_vmpl_policy(offset, value, monkeypatch):
    report = bytearray(REPORT)
    struct.pack_into("<I", report, offset, value)
    certs = chain()
    monkeypatch.setattr(snp, "_pinned_snpguest", lambda *a: pytest.fail("policy failure reached vendor"))
    assert snp.verify_snp_offline(bytes(report), DATA, policy(), vcek_der=certs.vcek,
                                  ask_der=certs.ask, ark_der=certs.ark) is None


@pytest.mark.parametrize("kind", ["debug", "migration", "tcb_floor", "nonce", "reserved"])
def test_offline_preserves_remaining_policy_checks(kind, monkeypatch):
    report = bytearray(REPORT)
    struct.pack_into("<I", report, 0x30, 0)
    struct.pack_into("<Q", report, 0x40, 0x25)
    expected = DATA
    required = policy()
    if kind in {"debug", "migration"}:
        guest = struct.unpack_from("<Q", report, 8)[0]
        struct.pack_into("<Q", report, 8, guest | (1 << (19 if kind == "debug" else 18)))
    elif kind == "tcb_floor":
        required = Policy(allowed_measurements=required.allowed_measurements, min_tcb=required.min_tcb + 1)
    elif kind == "nonce":
        expected = b"x" * 64
    else:
        report[0x208] = 1
    monkeypatch.setattr(snp, "_pinned_snpguest", lambda *a: pytest.fail("policy failure reached vendor"))
    certs = chain()
    assert snp.verify_snp_offline(bytes(report), expected, required, vcek_der=certs.vcek,
                                  ask_der=certs.ask, ark_der=certs.ark) is None


def test_online_capture_persists_report_and_verified_chain(monkeypatch, tmp_path):
    certs = chain()
    def run(command, **kwargs):
        if command[1] == "fetch":
            directory = Path(command[4])
            for name in ("vcek", "ask", "ark"):
                (directory / (name + ".der")).write_bytes(getattr(certs, name))
    monkeypatch.setattr(snp.subprocess, "run", run)
    captures = []
    assert snp._verify_chain_with_snpguest(REPORT, snpguest_path="/test/snpguest", certs_dir=None,
        capture=lambda raw, certs: captures.append(snp.persist_snp_capture(raw, certs, tmp_path)))
    assert len(captures) == 1
    saved = json.loads(captures[0].read_text())
    assert saved["schema"] == "cathedral_snp_capture_v1"
    assert captures[0].stat().st_mode & 0o077 == 0
    assert set(saved["certificates"]) == {"vcek_base64", "ask_base64", "ark_base64"}


def test_invalid_chain_is_never_captured(monkeypatch):
    def fail(command, **kwargs):
        raise snp.subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(snp.subprocess, "run", fail)
    assert not snp._verify_chain_with_snpguest(REPORT, snpguest_path="/test/snpguest", certs_dir=None,
        certificate_chain=chain(), capture=lambda *args: pytest.fail("captured invalid chain"))


def test_real_fixture_vendor_chain_with_pinned_binary():
    # This test concerns vendor crypto only. The complete admission path rejects
    # this historical report, as the unconditional policy test above records.
    if not os.environ.get("CATHEDRAL_SNPGUEST"):
        pytest.skip("pinned Linux snpguest is unavailable; real offline vendor execution is unproven")
    with snp._pinned_snpguest(None) as binary:
        assert binary is not None, "configured snpguest failed the unchanged digest pin"
        assert snp._verify_chain_with_snpguest(REPORT, snpguest_path=binary, certs_dir=None,
                                              certificate_chain=chain())


def test_real_fixture_signatures_with_openssl_while_python_network_is_denied(tmp_path):
    """Supplemental fixture authenticity proof, not snpguest admission proof."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    captured = chain()
    ark = x509.load_der_x509_certificate(captured.ark)
    ask = x509.load_der_x509_certificate(captured.ask)
    vcek = x509.load_der_x509_certificate(captured.vcek)
    (tmp_path / "ark.der").write_bytes(captured.ark)
    assert snp._amd_ark_is_pinned(tmp_path, "turin")
    ark.verify_directly_issued_by(ark)
    ask.verify_directly_issued_by(ark)
    vcek.verify_directly_issued_by(ask)
    r = int.from_bytes(REPORT[0x2A0:0x2D0], "little")
    s = int.from_bytes(REPORT[0x2E8:0x318], "little")
    public_key = vcek.public_key()
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert isinstance(public_key.curve, ec.SECP384R1)
    public_key.verify(utils.encode_dss_signature(r, s), REPORT[:0x2A0], ec.ECDSA(hashes.SHA384()))
    from cryptography.exceptions import InvalidSignature
    changed = bytearray(REPORT[:0x2A0])
    changed[0x1A0] ^= 1
    with pytest.raises(InvalidSignature):
        public_key.verify(utils.encode_dss_signature(r, s), bytes(changed), ec.ECDSA(hashes.SHA384()))
