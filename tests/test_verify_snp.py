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
    assert len(parsed.host_data) == 32
    assert parsed.host_data == report[0xC0:0xE0]
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


def test_amd_ark_pin_holds_for_certificates_fetched_under_a_permissive_umask(monkeypatch, tmp_path):
    """The pin must accept an authentic ARK that snpguest wrote under umask 0002.

    The stand-in verifier is a real executable that creates the certificates by
    shell redirection, so their mode comes from the umask the child inherits,
    as it does for snpguest. Without an owner-only umask for that child the ARK
    is group-writable and _read_amd_ark refuses it.
    """

    import os
    import shlex
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

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
    source_ark = tmp_path / "source-ark.der"
    source_ark.write_bytes(certificate.public_bytes(serialization.Encoding.DER))
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    report = _admissible_fixture()
    generation = snp_module._snp_generation(snp_module.parse_snp_report(report))
    assert generation is not None
    monkeypatch.setitem(
        snp_module.PINNED_AMD_ARK_SPKI_SHA256,
        generation,
        hashlib.sha256(spki).hexdigest(),
    )

    # Both fetch forms name the certificate directory as the fourth argument.
    # Every verify command succeeds; this test isolates the root pin.
    stand_in = tmp_path / "snpguest"
    stand_in.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        '  "fetch vcek") : > "$4/vcek.der" ;;\n'
        f'  "fetch ca") cat {shlex.quote(str(source_ark))} > "$4/ark.der"; : > "$4/ask.der" ;;\n'
        "esac\n"
    )
    stand_in.chmod(0o700)

    previous = os.umask(0o002)
    try:
        assert snp_module._verify_chain_with_snpguest(
            report,
            snpguest_path=str(stand_in),
            certs_dir=None,
        )
    finally:
        os.umask(previous)


# AMD certificate cache and KDS backoff ---------------------------------------


@pytest.fixture(autouse=True)
def _empty_certificate_cache():
    snp_module.clear_snp_certificate_cache()
    yield
    snp_module.clear_snp_certificate_cache()


def _test_certificate(common_name: str) -> tuple[bytes, str]:
    """Return a self-signed DER certificate and the SHA-256 of its SPKI."""

    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return (
        certificate.public_bytes(serialization.Encoding.DER),
        hashlib.sha256(spki).hexdigest(),
    )


_STAND_IN_BODY = r"""
import json
import stat
import sys

state = json.loads(STATE.read_text())
action = " ".join(sys.argv[1:3])
state["calls"].append(action)
if action == "verify certs":
    state["seen"].append(
        {
            entry.name: [stat.S_IMODE(entry.lstat().st_mode), entry.read_bytes().hex()]
            for entry in Path(sys.argv[3]).iterdir()
        }
    )
message = None
if state["fail"].get(action):
    message = state["fail"][action].pop(0)
elif action in state["always_fail"]:
    message = state["always_fail"][action]
elif action == "verify attestation":
    import hashlib

    report = next(Path(arg) for arg in sys.argv[3:5] if Path(arg).is_file())
    if hashlib.sha256(report.read_bytes()).hexdigest() in state["reject_reports"]:
        message = "stand-in: the attestation report signature does not verify"
STATE.write_text(json.dumps(state))
if message is not None:
    sys.stderr.write(message + "\n")
    sys.exit(1)
names = {"fetch vcek": ["vcek.der"], "fetch ca": ["ark.der", "ask.der"]}.get(action, [])
files = {name: state["certs"][name] for name in names}
files.update(state["extra"].get(action, {}))
for name, body in files.items():
    path = Path(sys.argv[4], name)
    path.write_bytes(bytes.fromhex(body))
    if name in state["modes"]:
        path.chmod(state["modes"][name])
"""

_KDS_429 = "ERROR: Unable to fetch VCEK from URL: 429 Too Many Requests"


class _StandInSnpguest:
    """A real executable that plays snpguest v0.10.0 for one test.

    Both fetch forms name the certificate directory as their fourth argument.
    The stand-in writes the configured DER certificates there with the umask it
    inherits, records every command and what each ``verify certs`` saw, and
    fails a command when the test asks it to. ``verify attestation`` also
    fails, in either argument order, for a report the test marks as forged.
    """

    def __init__(self, directory: Path, *, ark: bytes, ask: bytes, vcek: bytes) -> None:
        import sys

        self.path = directory / "snpguest"
        self._state_path = directory / "snpguest-state.json"
        self._save(
            {
                "calls": [],
                "seen": [],
                "certs": {"ark.der": ark.hex(), "ask.der": ask.hex(), "vcek.der": vcek.hex()},
                "fail": {},
                "always_fail": {},
                "extra": {},
                "modes": {},
                "reject_reports": [],
            }
        )
        self.path.write_text(
            f"#!{sys.executable} -I\n"
            "from pathlib import Path\n"
            f"STATE = Path({str(self._state_path)!r})\n" + _STAND_IN_BODY
        )
        self.path.chmod(0o700)

    def _load(self) -> dict:
        import json

        return json.loads(self._state_path.read_text())

    def _save(self, state: dict) -> None:
        import json

        self._state_path.write_text(json.dumps(state))

    def configure(self, field: str, key: str, value) -> None:
        state = self._load()
        state[field][key] = value
        self._save(state)

    def clear(self, field: str) -> None:
        state = self._load()
        state[field] = {}
        self._save(state)

    def reject_report(self, report: bytes) -> None:
        state = self._load()
        state["reject_reports"].append(hashlib.sha256(report).hexdigest())
        self._save(state)

    def serve(self, name: str, body: bytes) -> None:
        self.configure("certs", name, body.hex())

    def count(self, action: str) -> int:
        return self._load()["calls"].count(action)

    @property
    def seen(self) -> list[dict[str, list]]:
        return self._load()["seen"]


@pytest.fixture
def chain(monkeypatch, tmp_path):
    """A stand-in snpguest serving a test chain whose ARK is pinned for Turin."""

    ark, ark_spki = _test_certificate("test-ark")
    ask, _ = _test_certificate("test-ask")
    vcek, _ = _test_certificate("test-vcek")
    monkeypatch.setitem(snp_module.PINNED_AMD_ARK_SPKI_SHA256, "turin", ark_spki)
    stand_in = _StandInSnpguest(tmp_path, ark=ark, ask=ask, vcek=vcek)
    stand_in.ark, stand_in.ask, stand_in.vcek = ark, ask, vcek
    return stand_in


def _check(stand_in: _StandInSnpguest, report: bytes | None = None) -> bool:
    return snp_module._verify_chain_with_snpguest(
        _admissible_fixture() if report is None else report,
        snpguest_path=str(stand_in.path),
        certs_dir=None,
    )


def _verify_through_public_api(monkeypatch, stand_in, **kwargs):
    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext(str(stand_in.path)),
    )
    report = _admissible_fixture()
    return verify_snp_report_data(
        report,
        REQUEST_DATA.read_bytes(),
        _policy_for(report),
        snpguest_path=stand_in.path,
        **kwargs,
    )


def _record_sleeps(monkeypatch) -> list[float]:
    sleeps: list[float] = []
    monkeypatch.setattr(snp_module, "_kds_backoff_sleep", sleeps.append)
    return sleeps


def _with_chip_id(report: bytes, chip_id: bytes) -> bytes:
    changed = bytearray(report)
    changed[snp_module.CHIP_ID_OFFSET : snp_module.CHIP_ID_OFFSET + 64] = chip_id
    return bytes(changed)


def test_repeated_checks_of_one_chip_fetch_the_vcek_and_ca_once(monkeypatch, chain):
    for _ in range(4):
        verdict = _verify_through_public_api(monkeypatch, chain)
        assert verdict is not None
        assert verdict.chain_verified is True

    assert chain.count("fetch vcek") == 1
    assert chain.count("fetch ca") == 1
    # A cached certificate never skips verification.
    assert chain.count("verify certs") == 4
    assert chain.count("verify attestation") == 4
    expected = {
        "ark.der": [0o600, chain.ark.hex()],
        "ask.der": [0o600, chain.ask.hex()],
        "vcek.der": [0o600, chain.vcek.hex()],
    }
    assert chain.seen == [expected] * 4


def test_kds_429_is_retried_after_a_jittered_backoff(monkeypatch, chain):
    sleeps = _record_sleeps(monkeypatch)
    chain.configure("fail", "fetch vcek", [_KDS_429])

    verdict = _verify_through_public_api(monkeypatch, chain, raise_on_verifier_unavailable=True)

    assert verdict is not None
    assert verdict.chain_verified is True
    assert chain.count("fetch vcek") == 2
    assert len(sleeps) == 1
    assert 1.5 <= sleeps[0] <= 2.5


def test_persistent_kds_429_is_verifier_infrastructure_not_invalid_evidence(monkeypatch, chain):
    sleeps = _record_sleeps(monkeypatch)
    chain.configure("always_fail", "fetch vcek", _KDS_429)

    with pytest.raises(SnpVerifierUnavailable, match="infrastructure is unavailable") as error:
        _verify_through_public_api(monkeypatch, chain, raise_on_verifier_unavailable=True)

    assert error.value.category == "verifier_infrastructure_unavailable"
    assert isinstance(error.value.__cause__, snp_module.subprocess.CalledProcessError)
    assert chain.count("fetch vcek") == 3
    assert len(sleeps) == 2
    assert 1.5 <= sleeps[0] <= 2.5
    assert 3.75 <= sleeps[1] <= 6.25
    assert len(snp_module._CERTIFICATE_CACHE) == 0


def test_kds_backoff_never_sleeps_past_the_validator_deadline(monkeypatch, chain):
    sleeps = _record_sleeps(monkeypatch)
    chain.configure("always_fail", "fetch vcek", _KDS_429)

    with pytest.raises(SnpVerifierUnavailable, match="deadline expired"):
        _verify_through_public_api(
            monkeypatch,
            chain,
            raise_on_verifier_unavailable=True,
            deadline_monotonic=snp_module.time.monotonic() + 1.0,
        )

    assert sleeps == []
    assert chain.count("fetch vcek") == 1


def test_kds_backoff_grows_and_is_jittered():
    first = [snp_module._kds_backoff_seconds(0) for _ in range(200)]
    second = [snp_module._kds_backoff_seconds(1) for _ in range(200)]

    assert all(1.5 <= delay <= 2.5 for delay in first)
    assert all(3.75 <= delay <= 6.25 for delay in second)
    assert len(set(first)) > 1
    assert max(first) < min(second)


def test_cached_ark_that_no_longer_matches_the_pin_is_refused_and_refetched(monkeypatch, chain):
    assert _check(chain)
    rotated_ark, rotated_spki = _test_certificate("rotated-ark")
    monkeypatch.setitem(snp_module.PINNED_AMD_ARK_SPKI_SHA256, "turin", rotated_spki)

    # KDS still serves the old root: the cached copy and the refetch both fail
    # the pin, and neither reaches snpguest's verification.
    assert not _check(chain)
    assert chain.count("fetch ca") == 2
    assert chain.count("verify certs") == 1
    assert snp_module._CERTIFICATE_CACHE.get(("ca", "turin")) is None

    chain.serve("ark.der", rotated_ark)
    assert _check(chain)
    assert chain.count("fetch ca") == 3
    assert snp_module._CERTIFICATE_CACHE.get(("ca", "turin")) == (
        ("ark.der", rotated_ark),
        ("ask.der", chain.ask),
    )


def test_tampered_cache_entry_is_evicted_and_the_chain_refetched(chain):
    other_ark, _ = _test_certificate("not-the-pinned-ark")
    snp_module._CERTIFICATE_CACHE.put(
        ("ca", "turin"), (("ark.der", other_ark), ("ask.der", chain.ask))
    )

    assert _check(chain)
    assert chain.count("fetch ca") == 1
    assert chain.count("verify certs") == 1
    assert snp_module._CERTIFICATE_CACHE.get(("ca", "turin")) == (
        ("ark.der", chain.ark),
        ("ask.der", chain.ask),
    )


def test_cache_hit_refused_by_verify_certs_is_evicted_and_refetched_once(chain):
    assert _check(chain)

    # verify certs refuses the cached chain once: drop it, fetch fresh, verify.
    chain.configure("fail", "verify certs", ["stand-in rejects the cached chain"])
    assert _check(chain)
    assert chain.count("fetch vcek") == 2
    assert chain.count("fetch ca") == 2

    assert _check(chain)
    assert chain.count("fetch vcek") == 2

    # A chain refused with the cache and without it is refused, after exactly
    # one refetch, and leaves nothing cached.
    chain.configure("always_fail", "verify certs", "stand-in rejects every chain")
    assert not _check(chain)
    assert chain.count("fetch vcek") == 3
    assert chain.count("fetch ca") == 3
    assert len(snp_module._CERTIFICATE_CACHE) == 0


def test_report_refused_only_by_verify_attestation_keeps_the_cache(chain):
    assert _check(chain)
    chain.configure("always_fail", "verify attestation", "stand-in rejects the report")

    assert not _check(chain)
    # The cached chain was still pinned and verified, and nothing was refetched.
    assert chain.count("verify certs") == 2
    assert chain.count("fetch vcek") == 1
    assert chain.count("fetch ca") == 1
    assert len(snp_module._CERTIFICATE_CACHE) == 2

    chain.clear("always_fail")
    assert _check(chain)
    assert chain.count("fetch vcek") == 1


def test_friend_probe_sequence_fetches_each_certificate_once(monkeypatch, chain):
    """An authentic report, a tampered signature for the same chip, then a
    second authentic report, as ``cathedral-snp-friend-probe`` verifies them."""

    first = _admissible_fixture()
    tampered = bytearray(first)
    tampered[snp_module.SIGNATURE_OFFSET] ^= 0x01
    second_data = bytes(range(64))
    second = bytearray(first)
    second[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + 64] = second_data
    chain.reject_report(bytes(tampered))
    monkeypatch.setattr(
        snp_module,
        "_pinned_snpguest",
        lambda _path: nullcontext(str(chain.path)),
    )
    policy = _policy_for(first)

    def verify(report: bytes, expected: bytes):
        return verify_snp_report_data(
            report,
            expected,
            policy,
            snpguest_path=chain.path,
            raise_on_verifier_unavailable=True,
        )

    first_verdict = verify(first, REQUEST_DATA.read_bytes())
    tampered_verdict = verify(bytes(tampered), REQUEST_DATA.read_bytes())
    second_verdict = verify(bytes(second), second_data)

    assert first_verdict is not None and first_verdict.chain_verified is True
    assert tampered_verdict is None
    assert second_verdict is not None and second_verdict.chain_verified is True
    assert chain.count("fetch vcek") == 1
    assert chain.count("fetch ca") == 1
    assert chain.count("verify certs") == 3
    assert chain.count("verify attestation") == 4  # both orders for the tampered one


def test_different_chip_or_tcb_values_are_separate_cache_entries(monkeypatch, chain):
    base = _admissible_fixture()
    other_chip = _with_chip_id(base, bytes(range(1, 65)))
    other_tcb = bytearray(base)
    other_tcb[0x180] ^= 0x01
    milan = bytearray(base)
    milan[0x188:0x18A] = bytes([0x19, 0x01])
    monkeypatch.setitem(
        snp_module.PINNED_AMD_ARK_SPKI_SHA256,
        "milan",
        snp_module.PINNED_AMD_ARK_SPKI_SHA256["turin"],
    )
    reports = [base, other_chip, bytes(other_tcb), bytes(milan)]

    for report in reports:
        assert _check(chain, report)
    assert chain.count("fetch vcek") == 4
    assert chain.count("fetch ca") == 2
    assert len(snp_module._CERTIFICATE_CACHE) == 6

    for report in reports:
        assert _check(chain, report)
    assert chain.count("fetch vcek") == 4
    assert chain.count("fetch ca") == 2


@pytest.mark.parametrize("failure", ["pin", "verify certs", "verify attestation"])
def test_failed_verification_never_populates_the_cache(monkeypatch, chain, failure):
    if failure == "pin":
        _, other_spki = _test_certificate("other-root")
        monkeypatch.setitem(snp_module.PINNED_AMD_ARK_SPKI_SHA256, "turin", other_spki)
    else:
        chain.configure("always_fail", failure, "stand-in rejects the chain")

    assert not _check(chain)
    assert len(snp_module._CERTIFICATE_CACHE) == 0

    monkeypatch.setitem(
        snp_module.PINNED_AMD_ARK_SPKI_SHA256,
        "turin",
        _spki_sha256(chain.ark),
    )
    chain.clear("always_fail")
    assert _check(chain)
    assert chain.count("fetch vcek") == 2
    assert chain.count("fetch ca") == 2


def _spki_sha256(der: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    spki = (
        x509.load_der_x509_certificate(der)
        .public_key()
        .public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return hashlib.sha256(spki).hexdigest()


@pytest.mark.parametrize("oddity", ["extra file", "group-writable vcek"])
def test_unexpected_certificate_files_are_never_cached(chain, oddity):
    if oddity == "extra file":
        chain.configure("extra", "fetch ca", {"ark.pem": chain.ark.hex()})
    else:
        chain.configure("modes", "vcek.der", 0o664)

    assert _check(chain)
    assert len(snp_module._CERTIFICATE_CACHE) == 0


def test_certificate_cache_bound_and_age_limit_hold():
    now = [1000.0]
    cache = snp_module._SnpCertificateCache(max_entries=3, ttl_seconds=10.0, clock=lambda: now[0])
    entries = {key: ((f"{key}.der", key.encode()),) for key in ("a", "b", "c", "d")}

    for key in ("a", "b", "c"):
        cache.put((key,), entries[key])
    assert cache.get(("a",)) == entries["a"]  # "a" is now the most recently used
    cache.put(("d",), entries["d"])
    assert len(cache) == 3
    assert cache.get(("b",)) is None
    assert cache.get(("a",)) == entries["a"]

    now[0] += 10.0
    assert cache.get(("a",)) is None
    assert len(cache) == 2

    cache.clear()
    assert len(cache) == 0
    for bad in ({"max_entries": 0}, {"max_entries": True}, {"ttl_seconds": 0.0}):
        with pytest.raises(ValueError):
            snp_module._SnpCertificateCache(**bad)


def test_cache_age_runs_from_the_fetch_not_the_last_use(monkeypatch, chain):
    now = [0.0]
    monkeypatch.setattr(
        snp_module,
        "_CERTIFICATE_CACHE",
        snp_module._SnpCertificateCache(ttl_seconds=100.0, clock=lambda: now[0]),
    )

    assert _check(chain)
    now[0] = 60.0
    assert _check(chain)
    assert chain.count("fetch vcek") == 1
    now[0] = 100.0
    assert _check(chain)
    assert chain.count("fetch vcek") == 2
    assert chain.count("fetch ca") == 2


def test_process_cache_bound_holds_across_many_chips(monkeypatch, chain):
    monkeypatch.setattr(
        snp_module, "_CERTIFICATE_CACHE", snp_module._SnpCertificateCache(max_entries=2)
    )
    base = _admissible_fixture()

    for index in range(1, 4):
        assert _check(chain, _with_chip_id(base, bytes([index]) * 64))
    assert len(snp_module._CERTIFICATE_CACHE) == 2


def test_eviction_spares_an_entry_a_concurrent_check_replaced():
    cache = snp_module._SnpCertificateCache()
    stale = (("vcek.der", b"stale"),)
    fresh = (("vcek.der", b"fresh"),)
    cache.put(("vcek",), stale)
    cache.put(("vcek",), fresh)

    cache.evict(("vcek",), stale)
    assert cache.get(("vcek",)) is fresh
    cache.evict(("vcek",), fresh)
    assert cache.get(("vcek",)) is None
