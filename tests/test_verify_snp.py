"""Contract: hardware-free AMD SEV-SNP report parsing and binding checks."""

from __future__ import annotations

import hashlib
import struct
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

import pytest

from cathedral.assurance import ClaimStatus
from cathedral.common import Policy
import cathedral.verify.snp as snp_module
from cathedral.verify.snp import (
    SnpVerifierUnavailable,
    STRUCTURE_OK_CHAIN_UNVERIFIED,
    VERIFIED,
    REPORT_DATA_OFFSET,
    parse_snp_report,
    verify_snp_report_data,
)


FIXTURES = Path(__file__).parent / "fixtures" / "snp"
REPORT = FIXTURES / "attestation-report.bin"
REQUEST_DATA = FIXTURES / "request-data.bin"


def test_verifier_unavailable_has_stable_infrastructure_category():
    assert SnpVerifierUnavailable.category == "verifier_infrastructure_unavailable"


def _policy_for(report: bytes) -> Policy:
    parsed = parse_snp_report(report)
    return Policy(allowed_measurements={parsed.measurement}, min_tcb=parsed.tcb.reported)


def _admissible_fixture() -> bytes:
    """Normalize historical fixture fields outside the reviewed policy.

    Diagnostic tests do not vendor-verify this modified fixture. The live
    hardware suite obtains a fresh, signed report with VMPL 0 and every
    generation-specific reserved bit clear.
    """

    report = bytearray(REPORT.read_bytes())
    struct.pack_into("<I", report, 0x30, 0)
    struct.pack_into(
        "<Q",
        report,
        0x40,
        struct.unpack_from("<Q", report, 0x40)[0] & ~(1 << 6),
    )
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


def test_public_generation_classifier_is_exact_and_fail_closed():
    parsed = parse_snp_report(REPORT.read_bytes())

    assert snp_module.snp_generation(parsed) == "turin"
    assert (
        snp_module.snp_generation(replace(parsed, cpuid_family=0x19, cpuid_model=0x01)) == "milan"
    )
    assert (
        snp_module.snp_generation(replace(parsed, cpuid_family=0x19, cpuid_model=0x11)) == "genoa"
    )
    assert (
        snp_module.snp_generation(replace(parsed, cpuid_family=0x19, cpuid_model=0xAF)) == "genoa"
    )
    assert snp_module.snp_generation(replace(parsed, cpuid_family=0xFF, cpuid_model=0xFF)) is None
    assert snp_module.snp_generation(object()) is None


def test_platform_info_sev_tio_bit_is_allowed_only_in_report_v5():
    report = bytearray(_admissible_fixture())
    struct.pack_into("<Q", report, 0x40, 1 << 7)
    version_five = parse_snp_report(bytes(report))
    assert snp_module._raw_report_reserved_fields_are_zero(  # noqa: SLF001
        bytes(report), version_five, "turin"
    )

    struct.pack_into("<I", report, 0x00, 4)
    version_four = parse_snp_report(bytes(report))
    assert not snp_module._raw_report_reserved_fields_are_zero(  # noqa: SLF001
        bytes(report), version_four, "turin"
    )


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


def test_exit_zero_stub_cannot_impersonate_the_pinned_vendor_verifier(
    monkeypatch, tmp_path: Path
) -> None:
    stub = tmp_path / "snpguest"
    stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub.chmod(0o500)
    report = _admissible_fixture()

    def refuse_subprocess(*_args, **_kwargs):
        pytest.fail("an unpinned verifier must never execute")

    monkeypatch.setattr(snp_module.subprocess, "run", refuse_subprocess)

    verdict = verify_snp_report_data(
        report,
        REQUEST_DATA.read_bytes(),
        _policy_for(report),
        snpguest_path=stub,
    )

    assert verdict is None


def test_diagnostic_caller_can_distinguish_unavailable_verifier(tmp_path: Path) -> None:
    missing = tmp_path / "missing-snpguest"
    report = _admissible_fixture()

    with pytest.raises(SnpVerifierUnavailable, match="verifier is unavailable"):
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path=missing,
            raise_on_verifier_unavailable=True,
        )


def test_pinned_verifier_executes_a_private_copy_not_a_replaced_path(
    monkeypatch, tmp_path: Path
) -> None:
    source = tmp_path / "snpguest"
    original = b"#!/bin/sh\nexit 7\n"
    source.write_bytes(original)
    source.chmod(0o500)
    monkeypatch.setattr(
        snp_module,
        "PINNED_SNPGUEST_SHA256",
        hashlib.sha256(original).hexdigest(),
    )
    observed: dict[str, object] = {}

    def verify_private_copy(_report, *, snpguest_path, certs_dir):
        replacement = tmp_path / "replacement"
        replacement.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        replacement.chmod(0o500)
        replacement.replace(source)
        executed = Path(snpguest_path)
        observed["path"] = executed
        observed["bytes"] = executed.read_bytes()
        observed["certs_dir"] = certs_dir
        return True

    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", verify_private_copy)
    report = _admissible_fixture()

    verdict = verify_snp_report_data(
        report,
        REQUEST_DATA.read_bytes(),
        _policy_for(report),
        snpguest_path=source,
    )

    assert verdict is not None
    assert observed["path"] != source
    assert observed["bytes"] == original


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
        lambda report: struct.pack_into(
            "<Q", report, 0x40, struct.unpack_from("<Q", report, 0x40)[0] | (1 << 21)
        ),
        lambda report: struct.pack_into(
            "<Q", report, 0x40, struct.unpack_from("<Q", report, 0x40)[0] | (1 << 6)
        ),
        lambda report: report.__setitem__(0x4C, 1),
        lambda report: report.__setitem__(0x18B, 1),
        lambda report: report.__setitem__(0x1EB, 1),
        lambda report: report.__setitem__(0x1EF, 1),
        lambda report: report.__setitem__(0x208, 1),
        lambda report: report.__setitem__(0x2D0, 1),
        lambda report: report.__setitem__(0x318, 1),
        lambda report: report.__setitem__(0x330, 1),
        lambda report: report.__setitem__(0x3C, 1),
        lambda report: report.__setitem__(slice(0x188, 0x18A), bytes([0x19, 0xB0])),
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


def test_diagnostic_path_accepts_the_amd_single_socket_guest_policy_bit():
    report = bytearray(_admissible_fixture())
    struct.pack_into("<Q", report, 0x08, struct.unpack_from("<Q", report, 0x08)[0] | (1 << 20))
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


def test_vendor_verifier_commands_are_bounded_and_use_current_ca_order(monkeypatch):
    calls: list[tuple[list[str], float | None]] = []

    def fake_run(command, **kwargs):
        calls.append((list(command), kwargs.get("timeout")))
        return None

    monkeypatch.setenv("CATHEDRAL_SNPGUEST_TIMEOUT", "17")
    monkeypatch.setattr(snp_module.subprocess, "run", fake_run)
    monkeypatch.setattr(snp_module, "_amd_ark_is_pinned", lambda *_args: True)

    assert snp_module._verify_chain_with_snpguest(
        _admissible_fixture(),
        snpguest_path="/test/snpguest",
        certs_dir=None,
    )
    assert calls
    assert all(timeout == 17.0 for _, timeout in calls)
    certs_path = calls[0][0][4]
    assert calls[1][0][1:] == [
        "fetch",
        "ca",
        "DER",
        certs_path,
        "--report",
        calls[1][0][-1],
    ]


def test_invalid_attestation_is_a_terminal_rejection_not_a_kds_retry(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        encoded = list(command)
        calls.append(encoded)
        if encoded[1:3] == ["verify", "attestation"]:
            raise snp_module.subprocess.CalledProcessError(1, encoded)

    monkeypatch.setattr(snp_module.subprocess, "run", fake_run)
    monkeypatch.setattr(snp_module, "_amd_ark_is_pinned", lambda *_args: True)

    assert not snp_module._verify_chain_with_snpguest(
        _admissible_fixture(),
        snpguest_path="/test/snpguest",
        certs_dir=None,
    )
    assert sum(command[1:3] == ["fetch", "vcek"] for command in calls) == 1
    assert sum(command[1:3] == ["verify", "attestation"] for command in calls) == 2


def test_kds_4xx_is_invalid_evidence_not_a_validator_outage(monkeypatch):
    attempts = 0

    def reject_certificate_request(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        command = ["/test/snpguest", "fetch", "vcek"]
        raise snp_module.subprocess.CalledProcessError(
            1,
            command,
            stderr="ERROR: Unable to fetch VCEK from URL: 400 Bad Request",
        )

    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext("/test/snpguest"),
    )
    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", reject_certificate_request)

    report = _admissible_fixture()
    assert (
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path="/test/snpguest",
            raise_on_verifier_unavailable=True,
        )
        is None
    )
    assert attempts == 1


def test_malformed_report_rejected_by_snpguest_is_invalid_evidence(monkeypatch):
    attempts = 0

    def reject_malformed_report(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        command = ["/test/snpguest", "fetch", "vcek"]
        raise snp_module.subprocess.CalledProcessError(
            1,
            command,
            stderr=(
                "ERROR: Could not open attestation report\n"
                "because: Failed to build report from the raw bytes. "
                "Report could be malformed."
            ),
        )

    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext("/test/snpguest"),
    )
    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", reject_malformed_report)

    report = _admissible_fixture()
    assert (
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path="/test/snpguest",
            raise_on_verifier_unavailable=True,
        )
        is None
    )
    assert attempts == 1


def test_unknown_fetch_failure_is_not_misreported_as_amd_outage(monkeypatch):
    attempts = 0

    def reject_bad_local_command(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        command = ["/test/snpguest", "fetch", "ca"]
        raise snp_module.subprocess.CalledProcessError(
            2,
            command,
            stderr="error: unexpected argument '--wrong-flag' found\nUsage: snpguest fetch ca",
        )

    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext("/test/snpguest"),
    )
    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", reject_bad_local_command)

    report = _admissible_fixture()
    assert (
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path="/test/snpguest",
            raise_on_verifier_unavailable=True,
        )
        is None
    )
    assert attempts == 1


def test_kds_5xx_blocks_the_validator_write_as_infrastructure(monkeypatch):
    attempts = 0

    def fail_during_kds_outage(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        command = ["/test/snpguest", "fetch", "ca"]
        raise snp_module.subprocess.CalledProcessError(
            1,
            command,
            stderr="ERROR: Unable to fetch certificate: 503 Service Unavailable",
        )

    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext("/test/snpguest"),
    )
    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", fail_during_kds_outage)
    monkeypatch.setattr(snp_module.time, "sleep", lambda _seconds: None)

    report = _admissible_fixture()
    with pytest.raises(SnpVerifierUnavailable, match="infrastructure is unavailable") as error:
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path="/test/snpguest",
            raise_on_verifier_unavailable=True,
        )

    assert attempts == 3
    assert isinstance(error.value.__cause__, snp_module.subprocess.CalledProcessError)


def test_kds_transport_failure_blocks_the_validator_write(monkeypatch):
    attempts = 0

    def fail_to_reach_kds(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        command = ["/test/snpguest", "fetch", "vcek"]
        raise snp_module.subprocess.CalledProcessError(
            1,
            command,
            stderr=(
                "ERROR: Unable to send request for VCEK\n"
                "because: error sending request for url\n"
                "because: connection refused"
            ),
        )

    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext("/test/snpguest"),
    )
    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", fail_to_reach_kds)
    monkeypatch.setattr(snp_module.time, "sleep", lambda _seconds: None)

    report = _admissible_fixture()
    with pytest.raises(SnpVerifierUnavailable, match="infrastructure is unavailable"):
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path="/test/snpguest",
            raise_on_verifier_unavailable=True,
        )

    assert attempts == 3


def test_snpguest_timeout_blocks_the_validator_write(monkeypatch):
    attempts = 0

    def time_out(*_args, **_kwargs):
        nonlocal attempts
        attempts += 1
        raise snp_module.subprocess.TimeoutExpired("snpguest", 5)

    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext("/test/snpguest"),
    )
    monkeypatch.setattr(snp_module, "_verify_chain_with_snpguest", time_out)
    monkeypatch.setattr(snp_module.time, "sleep", lambda _seconds: None)

    report = _admissible_fixture()
    with pytest.raises(SnpVerifierUnavailable, match="infrastructure is unavailable"):
        verify_snp_report_data(
            report,
            REQUEST_DATA.read_bytes(),
            _policy_for(report),
            snpguest_path="/test/snpguest",
            raise_on_verifier_unavailable=True,
        )

    assert attempts == 3


def test_external_certificate_directory_is_refused_before_execution(monkeypatch, tmp_path):
    called = False

    def fake_run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(snp_module.subprocess, "run", fake_run)

    assert not snp_module._verify_chain_with_snpguest(
        _admissible_fixture(),
        snpguest_path="/test/snpguest",
        certs_dir=tmp_path / "shared-certs",
    )
    assert called is False


def test_snpguest_subprocess_timeout_never_exceeds_the_validator_deadline(
    monkeypatch,
):
    monkeypatch.setenv("CATHEDRAL_SNPGUEST_TIMEOUT", "30")
    monkeypatch.setattr(snp_module.time, "monotonic", lambda: 100.0)
    assert snp_module._snpguest_command_timeout(105.0) == 5.0
    with pytest.raises(snp_module.subprocess.TimeoutExpired):
        snp_module._snpguest_command_timeout(100.0)


def test_amd_ark_requires_the_reviewed_generation_spki(monkeypatch, tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from datetime import UTC, datetime, timedelta

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ark")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA384())
    )
    encoded = certificate.public_bytes(serialization.Encoding.DER)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    certs = tmp_path / "certs"
    certs.mkdir()
    ark = certs / "ark.der"
    ark.write_bytes(encoded)
    ark.chmod(0o600)

    assert not snp_module._amd_ark_is_pinned(certs, "milan")

    monkeypatch.setitem(
        snp_module.PINNED_AMD_ARK_SPKI_SHA256,
        "milan",
        hashlib.sha256(spki).hexdigest(),
    )
    assert snp_module._amd_ark_is_pinned(certs, "milan")
