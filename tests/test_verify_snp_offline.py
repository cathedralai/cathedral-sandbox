"""Offline replay tests. Real fixture rejection is an intentional policy finding."""

import json
import os
import socket
import struct
from contextlib import nullcontext
from pathlib import Path

import pytest
from cryptography import x509

from cathedral.common import Policy
import cathedral.verify.snp as snp

FIXTURE = Path(__file__).parent / "fixtures" / "snp"
REPORT = (FIXTURE / "attestation-report.bin").read_bytes()
DATA = (FIXTURE / "request-data.bin").read_bytes()


def chain():
    return snp.SnpCertificateChain(
        **{
            name: (FIXTURE / "offline" / (name + ".der")).read_bytes()
            for name in ("vcek", "ask", "ark")
        }
    )


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
    assert (
        snp.verify_snp_offline(
            REPORT, DATA, policy(), vcek_der=certs.vcek, ask_der=certs.ask, ark_der=certs.ark
        )
        is None
    )


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
    assert snp._verify_chain_with_snpguest(
        REPORT, snpguest_path="/test/snpguest", certs_dir=None, certificate_chain=certs
    )
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
    monkeypatch.setattr(
        snp.subprocess, "run", lambda *a, **k: pytest.fail("untrusted root executed")
    )
    assert not snp._verify_chain_with_snpguest(
        REPORT, snpguest_path="/test/snpguest", certs_dir=None, certificate_chain=wrong
    )


def test_private_der_does_not_reenable_external_directories(tmp_path):
    assert not snp._verify_chain_with_snpguest(
        REPORT, snpguest_path="/test/snpguest", certs_dir=tmp_path, certificate_chain=chain()
    )


@pytest.mark.parametrize("offset,value", [(0, 2), (0, 6), (0x30, 1)])
def test_offline_preserves_version_and_vmpl_policy(offset, value, monkeypatch):
    report = bytearray(REPORT)
    struct.pack_into("<I", report, offset, value)
    certs = chain()
    monkeypatch.setattr(
        snp, "_pinned_snpguest", lambda *a: pytest.fail("policy failure reached vendor")
    )
    assert (
        snp.verify_snp_offline(
            bytes(report), DATA, policy(), vcek_der=certs.vcek, ask_der=certs.ask, ark_der=certs.ark
        )
        is None
    )


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
        required = Policy(
            allowed_measurements=required.allowed_measurements, min_tcb=required.min_tcb + 1
        )
    elif kind == "nonce":
        expected = b"x" * 64
    else:
        report[0x208] = 1
    monkeypatch.setattr(
        snp, "_pinned_snpguest", lambda *a: pytest.fail("policy failure reached vendor")
    )
    certs = chain()
    assert (
        snp.verify_snp_offline(
            bytes(report),
            expected,
            required,
            vcek_der=certs.vcek,
            ask_der=certs.ask,
            ark_der=certs.ark,
        )
        is None
    )


def test_online_verification_hands_back_the_verified_chain(monkeypatch):
    certs = chain()

    def run(command, **kwargs):
        if command[1] == "fetch":
            directory = Path(command[4])
            for name in ("vcek", "ask", "ark"):
                (directory / (name + ".der")).write_bytes(getattr(certs, name))

    monkeypatch.setattr(snp.subprocess, "run", run)
    verified = []
    assert snp._verify_chain_with_snpguest(
        REPORT, snpguest_path="/test/snpguest", certs_dir=None, verified_chain_out=verified
    )
    assert verified == [{name: getattr(certs, name) for name in ("vcek", "ask", "ark")}]


def test_unreadable_verified_chain_keeps_the_verdict(monkeypatch):
    certs = chain()

    def run(command, **kwargs):
        if command[1] == "fetch":
            # The pinned root is present, but the VCEK file vanishes before capture.
            (Path(command[4]) / "ark.der").write_bytes(certs.ark)

    monkeypatch.setattr(snp.subprocess, "run", run)
    verified = []
    assert snp._verify_chain_with_snpguest(
        REPORT, snpguest_path="/test/snpguest", certs_dir=None, verified_chain_out=verified
    )
    assert verified == []


def test_invalid_chain_is_never_captured(monkeypatch):
    def fail(command, **kwargs):
        raise snp.subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(snp.subprocess, "run", fail)
    verified = []
    assert not snp._verify_chain_with_snpguest(
        REPORT,
        snpguest_path="/test/snpguest",
        certs_dir=None,
        certificate_chain=chain(),
        verified_chain_out=verified,
    )
    assert verified == []


def _admissible_report():
    report = bytearray(REPORT)
    struct.pack_into("<I", report, 0x30, 0)
    struct.pack_into("<Q", report, 0x40, struct.unpack_from("<Q", report, 0x40)[0] & ~(1 << 6))
    return bytes(report)


class _OnlineVendor:
    """Stands in for snpguest: fetches the fixture chain and accepts it."""

    def __init__(self, monkeypatch, vcek=None, reject_attestation=False):
        certs = chain()
        self.files = {"vcek": vcek or certs.vcek, "ask": certs.ask, "ark": certs.ark}
        self.reject_attestation = reject_attestation
        self.calls = []
        monkeypatch.setattr(snp, "_pinned_snpguest", lambda _path: nullcontext("/test/snpguest"))
        monkeypatch.setattr(snp.subprocess, "run", self)
        monkeypatch.setattr(snp.time, "sleep", lambda _s: pytest.fail("verification was retried"))

    def __call__(self, command, **kwargs):
        self.calls.append(tuple(command[1:3]))
        if command[1] == "fetch":
            for name, data in self.files.items():
                (Path(command[4]) / (name + ".der")).write_bytes(data)
        if self.reject_attestation and command[1:3] == ["verify", "attestation"]:
            raise snp.subprocess.CalledProcessError(1, command)


ONLINE_CALLS = [("fetch", "vcek"), ("fetch", "ca"), ("verify", "certs"), ("verify", "attestation")]


def test_capture_runs_once_after_verification_with_metadata(monkeypatch, tmp_path):
    report = _admissible_report()
    vendor = _OnlineVendor(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_SNP_CAPTURE_DIR", str(tmp_path / "captures"))
    verdict = snp.verify_snp_report_data(
        report,
        DATA,
        policy(report),
        raise_on_verifier_unavailable=True,
        capture_nonce=b"n" * 32,
        capture_box_id="box-7",
    )
    assert verdict is not None and verdict.chain_verified
    assert vendor.calls == ONLINE_CALLS
    captures = sorted((tmp_path / "captures").iterdir())
    assert [path.name.endswith(".meta.json") for path in captures].count(True) == 1
    capture = next(path for path in captures if not path.name.endswith(".meta.json"))
    saved = json.loads(capture.read_text())
    assert saved["schema"] == "cathedral_snp_capture_v1"
    assert set(saved["certificates"]) == {"vcek_base64", "ask_base64", "ark_base64"}
    assert capture.stat().st_mode & 0o077 == 0
    metadata_path = capture.with_name(capture.stem + ".meta.json")
    metadata = json.loads(metadata_path.read_text())
    assert metadata["capture"] == capture.name
    assert metadata["admission_nonce_hex"] == (b"n" * 32).hex()
    assert metadata["box_id"] == "box-7"
    assert metadata["captured_at"].endswith("Z")
    assert metadata_path.stat().st_mode & 0o077 == 0


def test_admission_entry_point_records_nonce_and_box_id(monkeypatch, tmp_path):
    from cathedral.common import Evidence, EvidenceKind
    from cathedral.verify import verify

    report = _admissible_report()
    _OnlineVendor(monkeypatch)
    monkeypatch.setattr(snp, "evidence_report_data", lambda _evidence, _nonce: DATA)
    monkeypatch.setenv("CATHEDRAL_SNP_CAPTURE_DIR", str(tmp_path))
    nonce = b"q" * 32
    evidence = Evidence(kind=EvidenceKind.SEV_SNP, quote=report, nonce=nonce, miner_hotkey="hk")
    assert verify(evidence, nonce, policy(report), capture_box_id="box-3") is not None
    (sidecar,) = tmp_path.glob("*.meta.json")
    metadata = json.loads(sidecar.read_text())
    assert metadata["admission_nonce_hex"] == nonce.hex()
    assert metadata["box_id"] == "box-3"


def test_capture_write_failure_neither_fails_nor_repeats_verification(
    monkeypatch, tmp_path, caplog
):
    report = _admissible_report()
    vendor = _OnlineVendor(monkeypatch)
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("occupied")
    monkeypatch.setenv("CATHEDRAL_SNP_CAPTURE_DIR", str(blocker / "captures"))
    with caplog.at_level("WARNING", logger=snp.__name__):
        verdict = snp.verify_snp_report_data(
            report, DATA, policy(report), raise_on_verifier_unavailable=True
        )
    assert verdict is not None and verdict.chain_verified
    assert vendor.calls == ONLINE_CALLS
    assert "capture failed" in caplog.text
    assert isinstance(caplog.records[-1].exc_info[1], snp.SnpCaptureError)
    assert isinstance(caplog.records[-1].exc_info[1].__cause__, OSError)


def test_unparseable_verified_chain_is_a_capture_error(monkeypatch, tmp_path, caplog):
    with pytest.raises(snp.SnpCaptureError) as error:
        snp._capture_verified_snp(
            REPORT,
            {"vcek": b"not der", "ask": chain().ask, "ark": chain().ark},
            tmp_path,
            admission_nonce=None,
            box_id=None,
        )
    assert isinstance(error.value.__cause__, ValueError)
    assert list(tmp_path.iterdir()) == []

    report = _admissible_report()
    vendor = _OnlineVendor(monkeypatch, vcek=chain().vcek + b"\x00")
    monkeypatch.setenv("CATHEDRAL_SNP_CAPTURE_DIR", str(tmp_path / "captures"))
    with caplog.at_level("WARNING", logger=snp.__name__):
        verdict = snp.verify_snp_report_data(
            report, DATA, policy(report), raise_on_verifier_unavailable=True
        )
    assert verdict is not None and verdict.chain_verified
    assert vendor.calls == ONLINE_CALLS
    assert not (tmp_path / "captures").exists()
    assert isinstance(caplog.records[-1].exc_info[1].__cause__, ValueError)


def test_rejected_reports_are_never_captured(monkeypatch, tmp_path):
    report = _admissible_report()
    monkeypatch.setenv("CATHEDRAL_SNP_CAPTURE_DIR", str(tmp_path / "captures"))
    vendor = _OnlineVendor(monkeypatch, reject_attestation=True)
    assert snp.verify_snp_report_data(report, DATA, policy(report)) is None
    assert vendor.calls[-1] == ("verify", "attestation")
    vendor.reject_attestation = False
    assert snp.verify_snp_report_data(report, b"x" * 64, policy(report)) is None
    assert not (tmp_path / "captures").exists()


def test_offline_replay_is_never_recaptured(monkeypatch, tmp_path):
    report = _admissible_report()
    vendor = _OnlineVendor(monkeypatch)
    monkeypatch.setenv("CATHEDRAL_SNP_CAPTURE_DIR", str(tmp_path / "captures"))
    certs = chain()
    verdict = snp.verify_snp_offline(
        report, DATA, policy(report), vcek_der=certs.vcek, ask_der=certs.ask, ark_der=certs.ark
    )
    assert verdict is not None
    assert vendor.calls == [("verify", "certs"), ("verify", "attestation")]
    assert not (tmp_path / "captures").exists()


def test_real_fixture_vendor_chain_with_pinned_binary():
    # This test concerns vendor crypto only. The complete admission path rejects
    # this historical report, as the unconditional policy test above records.
    if not os.environ.get("CATHEDRAL_SNPGUEST"):
        pytest.skip(
            "pinned Linux snpguest is unavailable; real offline vendor execution is unproven"
        )
    with snp._pinned_snpguest(None) as binary:
        assert binary is not None, "configured snpguest failed the unchanged digest pin"
        assert snp._verify_chain_with_snpguest(
            REPORT, snpguest_path=binary, certs_dir=None, certificate_chain=chain()
        )


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
        public_key.verify(
            utils.encode_dss_signature(r, s), bytes(changed), ec.ECDSA(hashes.SHA384())
        )
