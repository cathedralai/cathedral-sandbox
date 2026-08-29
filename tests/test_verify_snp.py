"""Contract: hardware-free AMD SEV-SNP report parsing and binding checks."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from cathedral.assurance import ClaimStatus
from cathedral.common import Policy
import cathedral.verify.snp as snp_module
from cathedral.verify.snp import (
    STRUCTURE_OK_CHAIN_UNVERIFIED,
    VERIFIED,
    REPORT_DATA_OFFSET,
    parse_snp_report,
    verify_snp_report_data,
)


FIXTURES = Path(__file__).parent / "fixtures" / "snp"
REPORT = FIXTURES / "attestation-report.bin"
REQUEST_DATA = FIXTURES / "request-data.bin"


def _policy_for(report: bytes) -> Policy:
    parsed = parse_snp_report(report)
    return Policy(allowed_measurements={parsed.measurement}, min_tcb=parsed.tcb.reported)


def _admissible_fixture() -> bytes:
    """Normalize the historical snpguest-default VMPL 1 fixture to VMPL 0.

    Diagnostic tests do not vendor-verify this modified fixture. The live
    hardware suite obtains a fresh, signed VMPL 0 report.
    """

    report = bytearray(REPORT.read_bytes())
    struct.pack_into("<I", report, 0x30, 0)
    return bytes(report)


def test_parses_real_report_data_fixture_byte_for_byte():
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()

    parsed = parse_snp_report(report)

    assert len(report) == 1184
    assert len(request_data) == 64
    assert parsed.report_data == request_data
    assert parsed.version == 5
    assert parsed.measurement
    assert parsed.chip_id
    assert parsed.tcb.reported > 0


def test_rejects_tampered_report_data():
    report = bytearray(REPORT.read_bytes())
    request_data = REQUEST_DATA.read_bytes()
    report[REPORT_DATA_OFFSET] ^= 0x01

    assert verify_snp_report_data(bytes(report), request_data, _policy_for(bytes(report))) is None


def test_rejects_wrong_nonce_binding():
    report = REPORT.read_bytes()
    wrong_request_data = b"\x00" * 64

    assert verify_snp_report_data(report, wrong_request_data, _policy_for(report)) is None


def test_chain_unavailable_rejects_by_default():
    """The admission path fails closed: no vendor chain means no Attested.

    A structurally valid report with a forged signature must never become an
    admission ticket on a box that happens to lack snpguest.
    """
    report = REPORT.read_bytes()
    request_data = REQUEST_DATA.read_bytes()

    verdict = verify_snp_report_data(
        report,
        request_data,
        _policy_for(report),
        snpguest_path="/definitely/not/snpguest",
    )

    assert verdict is None


def test_chain_unavailable_diagnostic_status_via_opt_in():
    report = _admissible_fixture()
    request_data = REQUEST_DATA.read_bytes()

    verdict = verify_snp_report_data(
        report,
        request_data,
        _policy_for(report),
        snpguest_path="/definitely/not/snpguest",
        require_chain=False,
    )

    assert verdict is not None
    assert verdict.verification_status == STRUCTURE_OK_CHAIN_UNVERIFIED
    assert verdict.verification_status != VERIFIED
    assert verdict.chain_verified is False
    assert verdict.assurance is not None
    assert verdict.assurance.hardware.status is ClaimStatus.FAILED
    assert verdict.assurance.software.status is ClaimStatus.NOT_EVALUATED


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: struct.pack_into("<I", report, 0x00, 1),
        lambda report: struct.pack_into("<I", report, 0x00, 2),
        lambda report: struct.pack_into("<I", report, 0x00, 6),
        lambda report: struct.pack_into("<I", report, 0x00, 7),
        lambda report: struct.pack_into("<I", report, 0x30, 1),
        lambda report: struct.pack_into("<I", report, 0x34, 0),
        lambda report: struct.pack_into(
            "<Q", report, 0x08, struct.unpack_from("<Q", report, 0x08)[0] | (1 << 19)
        ),
        lambda report: struct.pack_into(
            "<Q", report, 0x08, struct.unpack_from("<Q", report, 0x08)[0] | (1 << 18)
        ),
        lambda report: struct.pack_into(
            "<Q", report, 0x08, struct.unpack_from("<Q", report, 0x08)[0] & ~(1 << 17)
        ),
        lambda report: struct.pack_into("<I", report, 0x48, 1 << 1),
        lambda report: struct.pack_into("<I", report, 0x48, 1 << 2),
        lambda report: struct.pack_into("<I", report, 0x48, 1 << 5),
        lambda report: struct.pack_into(
            "<Q", report, 0x08, struct.unpack_from("<Q", report, 0x08)[0] | (1 << 26)
        ),
        lambda report: report.__setitem__(0x41, 1),
        lambda report: report.__setitem__(0x4C, 1),
        lambda report: report.__setitem__(0x18B, 1),
        lambda report: report.__setitem__(0x1EB, 1),
        lambda report: report.__setitem__(0x1EF, 1),
        lambda report: report.__setitem__(0x208, 1),
        lambda report: report.__setitem__(0x2D0, 1),
        lambda report: report.__setitem__(0x318, 1),
        lambda report: report.__setitem__(0x330, 1),
        lambda report: report.__setitem__(0x3C, 1),
        lambda report: report.__setitem__(slice(0x188, 0x18A), bytes([0x19, 0xAF])),
        lambda report: report.__setitem__(slice(0x1A0, 0x1E0), b"\x00" * 64),
        lambda report: report.__setitem__(slice(0x90, 0xC0), b"\x00" * 48),
        lambda report: struct.pack_into("<Q", report, 0x180, 0),
    ],
)
def test_diagnostic_path_rejects_reports_outside_worker_identity_profile(mutate):
    report = bytearray(_admissible_fixture())
    mutate(report)
    encoded = bytes(report)

    assert (
        verify_snp_report_data(
            encoded,
            REQUEST_DATA.read_bytes(),
            _policy_for(encoded),
            snpguest_path="/definitely/not/snpguest",
            require_chain=False,
        )
        is None
    )


@pytest.mark.parametrize("version", [3, 4, 5])
def test_diagnostic_path_accepts_only_reviewed_report_versions(version):
    report = bytearray(_admissible_fixture())
    struct.pack_into("<I", report, 0x00, version)
    if version in {3, 4}:
        report[0x1F8:0x208] = b"\x00" * 16
    encoded = bytes(report)

    verdict = verify_snp_report_data(
        encoded,
        REQUEST_DATA.read_bytes(),
        _policy_for(encoded),
        snpguest_path="/definitely/not/snpguest",
        require_chain=False,
    )

    assert verdict is not None
    assert verdict.verification_status == STRUCTURE_OK_CHAIN_UNVERIFIED


def test_tcb_minimum_is_componentwise_not_packed_integer_order():
    report = bytearray(_admissible_fixture())
    assert report[0x188] == 0x1A  # checked-in fixture uses the Turin TCB layout
    required = int.from_bytes(bytes([5, 5, 5, 5, 0, 0, 0, 5]), "little")
    candidate = int.from_bytes(bytes([4, 5, 5, 5, 0, 0, 0, 6]), "little")
    assert candidate > required  # scalar ordering would hide the FMC downgrade
    struct.pack_into("<Q", report, 0x180, candidate)
    encoded = bytes(report)
    policy = Policy(
        allowed_measurements={parse_snp_report(encoded).measurement},
        min_tcb=required,
    )

    assert (
        verify_snp_report_data(
            encoded,
            REQUEST_DATA.read_bytes(),
            policy,
            snpguest_path="/definitely/not/snpguest",
            require_chain=False,
        )
        is None
    )


def test_vendor_verifier_commands_are_bounded_and_use_current_ca_order(monkeypatch, tmp_path):
    calls: list[tuple[list[str], float | None]] = []

    def fake_run(command, **kwargs):
        calls.append((list(command), kwargs.get("timeout")))
        return None

    monkeypatch.setenv("CATHEDRAL_SNPGUEST_TIMEOUT", "17")
    monkeypatch.setattr(snp_module.subprocess, "run", fake_run)

    assert snp_module._verify_chain_with_snpguest(
        _admissible_fixture(),
        snpguest_path="/test/snpguest",
        certs_dir=tmp_path / "certs",
    )
    assert calls
    assert all(timeout == 17.0 for _, timeout in calls)
    assert calls[1][0][1:] == [
        "fetch",
        "ca",
        "DER",
        str(tmp_path / "certs"),
        "--report",
        calls[1][0][-1],
    ]


def test_invalid_attestation_is_a_terminal_rejection_not_a_kds_retry(monkeypatch, tmp_path):
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        encoded = list(command)
        calls.append(encoded)
        if encoded[1:3] == ["verify", "attestation"]:
            raise snp_module.subprocess.CalledProcessError(1, encoded)

    monkeypatch.setattr(snp_module.subprocess, "run", fake_run)

    assert not snp_module._verify_chain_with_snpguest(
        _admissible_fixture(),
        snpguest_path="/test/snpguest",
        certs_dir=tmp_path / "certs",
    )
    assert sum(command[1:3] == ["fetch", "vcek"] for command in calls) == 1
    assert sum(command[1:3] == ["verify", "attestation"] for command in calls) == 2
