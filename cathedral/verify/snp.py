"""AMD SEV-SNP attestation report parsing and verification.

The verifier owns Cathedral policy and nonce binding. AMD owns the signature
chain: when ``snpguest`` is available, this module shells out to it instead of
hand-rolling vendor crypto. See docs/DESIGN.md §6 and docs/history/HANDOFF.md §4.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from cathedral.assurance import ClaimStatus, ReasonCategory, attestation_claims
from cathedral.common import Attested, Evidence, Policy, Tier, evidence_report_data


SNP_REPORT_SIZE = 1184
REPORT_DATA_OFFSET = 0x50
REPORT_DATA_SIZE = 64
MEASUREMENT_OFFSET = 0x90
MEASUREMENT_SIZE = 48
CHIP_ID_OFFSET = 0x1A0
CHIP_ID_SIZE = 64
SIGNATURE_OFFSET = 0x2A0
SIGNATURE_SIZE = 512

# Keep the friend self-test profile inside the processor auto-detection contract of
# the pinned snpguest v0.10.0 verifier. It cannot reliably select the AMD CA for
# report versions below 3, and it predates the current version 6 ABI. Expanding
# this set requires a separately reviewed verifier/toolchain update.
_SUPPORTED_REPORT_VERSIONS = frozenset({3, 4, 5})
_ECDSA_P384_SHA384 = 1
_GUEST_POLICY_RESERVED_ONE = 1 << 17
_GUEST_POLICY_MIGRATE_MA = 1 << 18
_GUEST_POLICY_DEBUG = 1 << 19
_SIGNER_INFO_MASK_CHIP_KEY = 1 << 1
_SIGNER_INFO_SIGNING_KEY_SHIFT = 2
_SIGNER_INFO_SIGNING_KEY_MASK = 0b111
_GENERATION_MILAN = "milan"
_GENERATION_GENOA = "genoa"
_GENERATION_TURIN = "turin"

VERIFIED = "VERIFIED"
STRUCTURE_OK_CHAIN_UNVERIFIED = "STRUCTURE_OK_CHAIN_UNVERIFIED"


@dataclass(frozen=True)
class SnpTcb:
    """Raw TCB values carried by the SNP report."""

    current: int
    reported: int
    committed: int
    launch: int


@dataclass(frozen=True)
class SnpReport:
    """Parsed fields Cathedral needs from an AMD SEV-SNP attestation report."""

    version: int
    guest_svn: int
    guest_policy: int
    vmpl: int
    signature_algo: int
    platform_info: int
    signer_info: int
    cpuid_family: int
    cpuid_model: int
    cpuid_step: int
    report_data: bytes
    measurement: str
    chip_id: str
    tcb: SnpTcb
    signature: bytes


def parse_snp_report(report: bytes) -> SnpReport:
    """Parse the fixed 1184-byte AMD SEV-SNP attestation report layout."""

    if len(report) != SNP_REPORT_SIZE:
        raise ValueError(f"SNP report must be {SNP_REPORT_SIZE} bytes, got {len(report)}")

    version = struct.unpack_from("<I", report, 0x00)[0]
    guest_svn = struct.unpack_from("<I", report, 0x04)[0]
    guest_policy = struct.unpack_from("<Q", report, 0x08)[0]
    vmpl = struct.unpack_from("<I", report, 0x30)[0]
    signature_algo = struct.unpack_from("<I", report, 0x34)[0]
    current_tcb = struct.unpack_from("<Q", report, 0x38)[0]
    platform_info = struct.unpack_from("<Q", report, 0x40)[0]
    signer_info = struct.unpack_from("<I", report, 0x48)[0]
    reported_tcb = struct.unpack_from("<Q", report, 0x180)[0]
    cpuid_family = report[0x188]
    cpuid_model = report[0x189]
    cpuid_step = report[0x18A]
    committed_tcb = struct.unpack_from("<Q", report, 0x1E0)[0]
    launch_tcb = struct.unpack_from("<Q", report, 0x1F0)[0]

    report_data = report[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE]
    measurement = report[MEASUREMENT_OFFSET : MEASUREMENT_OFFSET + MEASUREMENT_SIZE].hex()
    chip_id = report[CHIP_ID_OFFSET : CHIP_ID_OFFSET + CHIP_ID_SIZE].hex()
    signature = report[SIGNATURE_OFFSET : SIGNATURE_OFFSET + SIGNATURE_SIZE]

    if not any(signature):
        raise ValueError("SNP report signature is empty")

    return SnpReport(
        version=version,
        guest_svn=guest_svn,
        guest_policy=guest_policy,
        vmpl=vmpl,
        signature_algo=signature_algo,
        platform_info=platform_info,
        signer_info=signer_info,
        cpuid_family=cpuid_family,
        cpuid_model=cpuid_model,
        cpuid_step=cpuid_step,
        report_data=report_data,
        measurement=measurement,
        chip_id=chip_id,
        tcb=SnpTcb(
            current=current_tcb,
            reported=reported_tcb,
            committed=committed_tcb,
            launch=launch_tcb,
        ),
        signature=signature,
    )


def _resolve_snpguest(snpguest_path: str | os.PathLike[str] | None) -> str | None:
    if snpguest_path is not None:
        path = os.fspath(snpguest_path)
        return path if Path(path).is_file() and os.access(path, os.X_OK) else None
    env_path = os.environ.get("CATHEDRAL_SNPGUEST")
    if env_path:
        return env_path if Path(env_path).is_file() and os.access(env_path, os.X_OK) else None
    return shutil.which("snpguest")


def _snpguest_timeout() -> float:
    """Bound every external verifier action, including AMD KDS access."""

    try:
        return min(300.0, max(1.0, float(os.environ.get("CATHEDRAL_SNPGUEST_TIMEOUT", "30"))))
    except (TypeError, ValueError):
        return 30.0


def _snp_generation(parsed: SnpReport) -> str | None:
    """Match the processor families understood by pinned snpguest v0.10.0."""

    if parsed.cpuid_family == 0x19:
        if 0x00 <= parsed.cpuid_model <= 0x0F:
            return _GENERATION_MILAN
        if 0x10 <= parsed.cpuid_model <= 0x1F or 0xA0 <= parsed.cpuid_model < 0xAF:
            return _GENERATION_GENOA
    if parsed.cpuid_family == 0x1A and 0x00 <= parsed.cpuid_model <= 0x11:
        return _GENERATION_TURIN
    return None


def _all_zero(report: bytes, start: int, end: int) -> bool:
    return not any(report[start:end])


def _raw_report_reserved_fields_are_zero(
    report: bytes,
    parsed: SnpReport,
    generation: str,
) -> bool:
    """Reject raw bytes that snpguest v0.10.0 would discard on re-encoding.

    That verifier parses and re-encodes a report before hashing it. Checking
    every AMD MBZ field first makes the reconstructed signed region identical
    to the received version 3, 4, or 5 report instead of accepting a quote with
    attacker-modified reserved bytes.
    """

    if parsed.guest_policy & ~((1 << 26) - 1):
        return False
    if parsed.platform_info & ~0xFF:
        return False
    if parsed.signer_info & ~0x1F:
        return False

    ranges = [
        (0x4C, 0x50),
        (0x18B, 0x1A0),
        (0x1EB, 0x1EC),
        (0x1EF, 0x1F0),
        (0x2D0, 0x2E8),  # zero extension of the 48-byte P-384 R value
        (0x318, 0x330),  # zero extension of the 48-byte P-384 S value
        (0x330, 0x4A0),  # signature structure padding
    ]
    ranges.append((0x1F8, 0x2A0) if parsed.version in {3, 4} else (0x208, 0x2A0))

    tcb_reserved = (2, 6) if generation in {_GENERATION_MILAN, _GENERATION_GENOA} else (4, 7)
    for base in (0x38, 0x180, 0x1E0, 0x1F0):
        ranges.append((base + tcb_reserved[0], base + tcb_reserved[1]))
    return all(_all_zero(report, start, end) for start, end in ranges)


def _tcb_meets_minimum(candidate: int, required: int, generation: str) -> bool:
    """Compare AMD TCB component SVNs instead of treating their bytes as a scalar."""

    if not 0 <= required < 1 << 64:
        return False
    candidate_bytes = candidate.to_bytes(8, "little")
    required_bytes = required.to_bytes(8, "little")
    if generation in {_GENERATION_MILAN, _GENERATION_GENOA}:
        component_indices = (0, 1, 6, 7)  # bootloader, TEE, SNP, microcode
        reserved_indices = range(2, 6)
    else:
        component_indices = (0, 1, 2, 3, 7)  # FMC, bootloader, TEE, SNP, microcode
        reserved_indices = range(4, 7)
    if any(required_bytes[index] for index in reserved_indices):
        return False
    return all(candidate_bytes[index] >= required_bytes[index] for index in component_indices)


def _snp_report_is_admissible(report: bytes, parsed: SnpReport) -> bool:
    """Apply Cathedral's fail-closed SEV-SNP friend self-test profile.

    The vendor signature check proves report authenticity. These checks decide
    whether the authentic report satisfies this bounded verifier contract.
    Production admission and durable one-machine deduplication remain disabled.
    """

    generation = _snp_generation(parsed)
    signing_key = (
        parsed.signer_info >> _SIGNER_INFO_SIGNING_KEY_SHIFT
    ) & _SIGNER_INFO_SIGNING_KEY_MASK
    return (
        parsed.version in _SUPPORTED_REPORT_VERSIONS
        and generation is not None
        and _raw_report_reserved_fields_are_zero(report, parsed, generation)
        and parsed.vmpl == 0
        and parsed.signature_algo == _ECDSA_P384_SHA384
        and bool(parsed.guest_policy & _GUEST_POLICY_RESERVED_ONE)
        and not bool(parsed.guest_policy & _GUEST_POLICY_DEBUG)
        and not bool(parsed.guest_policy & _GUEST_POLICY_MIGRATE_MA)
        and not bool(parsed.signer_info & _SIGNER_INFO_MASK_CHIP_KEY)
        and signing_key == 0  # legacy VCEK, the chain fetched below
        and parsed.chip_id != "00" * CHIP_ID_SIZE
        and parsed.measurement != "00" * MEASUREMENT_SIZE
        and any(parsed.tcb.reported.to_bytes(8, "little"))
    )


def _verify_chain_with_snpguest(
    report: bytes,
    *,
    snpguest_path: str,
    certs_dir: str | os.PathLike[str] | None,
) -> bool:
    """Ask snpguest to fetch AMD certs and verify the report signature chain."""

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        report_path = work / "attestation-report.bin"
        report_path.write_bytes(report)
        certs_path = Path(certs_dir) if certs_dir is not None else work / "certs"
        certs_path.mkdir(parents=True, exist_ok=True)

        timeout = _snpguest_timeout()
        subprocess.run(
            [snpguest_path, "fetch", "vcek", "DER", str(certs_path), str(report_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        ca_fetch_orders = [
            [
                snpguest_path,
                "fetch",
                "ca",
                "DER",
                str(certs_path),
                "--report",
                str(report_path),
            ],
            [snpguest_path, "fetch", "ca", "--report", str(report_path), "DER", str(certs_path)],
            [snpguest_path, "fetch", "ca", "DER", str(certs_path), str(report_path)],
        ]
        last_error: subprocess.CalledProcessError | subprocess.TimeoutExpired | None = None
        for cmd in ca_fetch_orders:
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                last_error = exc
        else:
            if last_error is not None:
                raise last_error

        try:
            subprocess.run(
                [snpguest_path, "verify", "certs", str(certs_path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.CalledProcessError:
            return False

        verify_orders = [
            [snpguest_path, "verify", "attestation", str(certs_path), str(report_path)],
            [snpguest_path, "verify", "attestation", str(report_path), str(certs_path)],
        ]
        for cmd in verify_orders:
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                return True
            except subprocess.CalledProcessError:
                continue
    return False


def verify_snp_report_data(
    report: bytes,
    expected_report_data: bytes,
    policy: Policy,
    *,
    snpguest_path: str | os.PathLike[str] | None = None,
    certs_dir: str | os.PathLike[str] | None = None,
    require_chain: bool = True,
) -> Attested | None:
    """Verify a raw SNP report against explicit 64-byte REPORT_DATA.

    Fail-closed by default: every existing caller treats ANY ``Attested`` as an
    admission ticket, so without a vendor-verified signature chain the default
    verdict is ``None``. Diagnostic/shadow tooling that wants the parsed report
    with an explicit ``STRUCTURE_OK_CHAIN_UNVERIFIED`` status can opt in with
    ``require_chain=False`` — that verdict must never be used for admission.
    """

    if len(expected_report_data) != REPORT_DATA_SIZE:
        raise ValueError("expected REPORT_DATA must be exactly 64 bytes")

    parsed = parse_snp_report(report)
    if not _snp_report_is_admissible(report, parsed):
        return None
    if parsed.report_data != expected_report_data:
        return None
    if parsed.measurement not in policy.allowed_measurements:
        return None
    generation = _snp_generation(parsed)
    if generation is None or not _tcb_meets_minimum(
        parsed.tcb.reported,
        policy.min_tcb,
        generation,
    ):
        return None

    snpguest = _resolve_snpguest(snpguest_path)
    chain_verified = False
    if snpguest is not None:
        for attempt in range(3):
            try:
                chain_verified = _verify_chain_with_snpguest(
                    report,
                    snpguest_path=snpguest,
                    certs_dir=certs_dir,
                )
                break
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if attempt == 2:
                    return None
                time.sleep(1)

    if require_chain and not chain_verified:
        return None

    status = VERIFIED if chain_verified else STRUCTURE_OK_CHAIN_UNVERIFIED
    assurance = attestation_claims(
        report,
        policy,
        hardware_status=ClaimStatus.PASSED if chain_verified else ClaimStatus.FAILED,
        hardware_reason=None if chain_verified else ReasonCategory.EVIDENCE_INVALID,
        software_status=(ClaimStatus.PASSED if chain_verified else ClaimStatus.NOT_EVALUATED),
    )
    return Attested(
        tier=Tier.CC_CPU_SNP,
        chip_id=parsed.chip_id,
        measurement=parsed.measurement,
        tcb=parsed.tcb.reported,
        verification_status=status,
        chain_verified=chain_verified,
        assurance=assurance,
    )


def verify_snp(
    evidence: Evidence,
    nonce: bytes,
    policy: Policy,
    *,
    snpguest_path: str | os.PathLike[str] | None = None,
    certs_dir: str | os.PathLike[str] | None = None,
) -> Attested | None:
    """Verify SNP evidence using the existing Cathedral nonce/hotkey binding."""

    expected = evidence_report_data(evidence, nonce)
    return verify_snp_report_data(
        evidence.quote,
        expected,
        policy,
        snpguest_path=snpguest_path,
        certs_dir=certs_dir,
    )
