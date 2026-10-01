"""AMD SEV-SNP attestation report parsing and verification.

The verifier owns Cathedral policy and nonce binding. AMD owns the signature
chain: when ``snpguest`` is available, this module shells out to it instead of
hand-rolling vendor crypto. See docs/DESIGN.md §6 and the AMD friend-test guide.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
PINNED_SNPGUEST_VERSION = "0.10.0"
PINNED_SNPGUEST_SHA256 = "70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0"
MAX_SNPGUEST_BYTES = 64 * 1024 * 1024
MAX_AMD_CERTIFICATE_BYTES = 64 * 1024
MAX_AMD_ARK_BYTES = MAX_AMD_CERTIFICATE_BYTES
PINNED_AMD_ARK_SPKI_SHA256 = {
    "milan": "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9",
    "genoa": "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831",
    "turin": "4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08",
}

# Keep the production admission profile inside the processor auto-detection
# contract of the pinned snpguest v0.10.0 verifier. It cannot reliably select
# the AMD CA for report versions below 3, and it predates the current version 6
# ABI. Expanding this set requires a separately reviewed verifier/toolchain
# update.
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

# snpguest v0.10.0 prints KDS response codes in these two exact error
# messages. Keep the patterns narrow so digits in a URL, CHIP_ID, or TCB value
# cannot be mistaken for an HTTP status.
_KDS_HTTP_STATUS_PATTERNS = (
    re.compile(r"Unable to fetch VCEK from URL:\s*([45][0-9]{2})\b", re.IGNORECASE),
    re.compile(r"Unable to fetch certificate:\s*([45][0-9]{2})\b", re.IGNORECASE),
)
_TRANSIENT_KDS_CLIENT_STATUSES = frozenset({408, 425, 429})
_INVALID_REPORT_ERROR_MARKERS = (
    "failed to build report from the raw bytes",
    "report could be malformed",
    "hardware id is 0s on attestation report",
    "processor family not supported",
    "processor model not supported",
    "missing cpu family id",
    "missing cpu model id",
    "a turin processor must have a fmc value",
)
_KDS_TRANSPORT_ERROR_MARKERS = (
    "error sending request for url",
    "connection refused",
    "connection reset",
    "connection timed out",
    "operation timed out",
    "dns error",
    "failed to lookup address information",
    "temporary failure in name resolution",
    "tls error",
    "certificate verify failed",
)

# AMD KDS throttles per VCEK. Retry a transient failure at most twice, about
# 2 s and then about 5 s later, each wait spread by +/-25% so verifiers that
# were throttled together do not come back in lockstep.
_KDS_ATTEMPTS = 3
_KDS_BACKOFF_BASE_SECONDS = 2.0
_KDS_BACKOFF_FACTOR = 2.5
_KDS_BACKOFF_JITTER = 0.25

# Fetched AMD certificates are cached in memory for this process only. The
# bound and age limit keep the cache small and pick up a reissued or revoked
# certificate within a day. The file names are the ones the pinned snpguest
# v0.10.0 writes for DER output with the default VCEK endorser.
CERTIFICATE_CACHE_MAX_ENTRIES = 256
CERTIFICATE_CACHE_TTL_SECONDS = 24 * 60 * 60
_VCEK_CERTIFICATE_FILES = ("vcek.der",)
_CA_CERTIFICATE_FILES = ("ark.der", "ask.der")

VERIFIED = "VERIFIED"
STRUCTURE_OK_CHAIN_UNVERIFIED = "STRUCTURE_OK_CHAIN_UNVERIFIED"


class SnpVerifierUnavailable(RuntimeError):
    """The pinned local verifier or its AMD certificate path was unavailable."""

    category = "verifier_infrastructure_unavailable"


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


@contextmanager
def _pinned_snpguest(
    snpguest_path: str | os.PathLike[str] | None,
) -> Iterator[str | None]:
    """Copy one pinned verifier inode, then execute only the private copy.

    Hashing a pathname and later executing the pathname leaves a replacement
    race. Open the configured inode without following a symlink, copy and hash
    those bytes into an owner-only directory, and keep that directory alive for
    the complete vendor-chain check.
    """

    candidate = (
        os.fspath(snpguest_path)
        if snpguest_path is not None
        else (os.environ.get("CATHEDRAL_SNPGUEST") or shutil.which("snpguest"))
    )
    if not candidate:
        yield None
        return
    path = Path(os.path.abspath(candidate))
    if not hasattr(os, "O_NOFOLLOW"):
        yield None
        return
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        source_fd = os.open(path, flags)
    except OSError:
        yield None
        return
    try:
        try:
            metadata = os.fstat(source_fd)
        except OSError:
            yield None
            return
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_SNPGUEST_BYTES
            or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or metadata.st_uid not in {0, os.geteuid()}
        ):
            yield None
            return
        with tempfile.TemporaryDirectory(prefix="cathedral-snpguest-") as td:
            try:
                private_dir = Path(td)
                private_dir.chmod(0o700)
                private_path = private_dir / "snpguest"
                output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_CLOEXEC"):
                    output_flags |= os.O_CLOEXEC
                output_fd = os.open(private_path, output_flags, 0o500)
                digest = hashlib.sha256()
                copied = 0
                try:
                    while True:
                        chunk = os.read(source_fd, 1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > MAX_SNPGUEST_BYTES:
                            raise OSError("private verifier copy exceeds its bound")
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            written = os.write(output_fd, view)
                            if written <= 0:
                                raise OSError("private verifier copy made no progress")
                            view = view[written:]
                    os.fsync(output_fd)
                finally:
                    os.close(output_fd)
                private_path.chmod(0o500)
            except OSError:
                yield None
                return
            if copied != metadata.st_size or digest.hexdigest() != PINNED_SNPGUEST_SHA256:
                yield None
                return
            yield str(private_path)
    finally:
        os.close(source_fd)


def _snpguest_timeout() -> float:
    """Bound every external verifier action, including AMD KDS access."""

    try:
        return min(300.0, max(1.0, float(os.environ.get("CATHEDRAL_SNPGUEST_TIMEOUT", "30"))))
    except (TypeError, ValueError):
        return 30.0


def _snpguest_command_timeout(deadline_monotonic: float | None) -> float:
    """Bound one subprocess by both the local cap and the caller's cycle."""

    maximum = _snpguest_timeout()
    if deadline_monotonic is None:
        return maximum
    if (
        isinstance(deadline_monotonic, bool)
        or not isinstance(deadline_monotonic, (int, float))
        or not math.isfinite(float(deadline_monotonic))
    ):
        raise ValueError("SNP verifier deadline must be a finite monotonic time")
    remaining = float(deadline_monotonic) - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired("snpguest", 0)
    return min(maximum, remaining)


def _snp_generation(parsed: SnpReport) -> str | None:
    """Match the processor families understood by pinned snpguest v0.10.0."""

    if parsed.cpuid_family == 0x19:
        if 0x00 <= parsed.cpuid_model <= 0x0F:
            return _GENERATION_MILAN
        if 0x10 <= parsed.cpuid_model <= 0x1F or 0xA0 <= parsed.cpuid_model <= 0xAF:
            return _GENERATION_GENOA
    if parsed.cpuid_family == 0x1A and 0x00 <= parsed.cpuid_model <= 0x11:
        return _GENERATION_TURIN
    return None


def snp_generation(parsed: SnpReport) -> str | None:
    """Return the reviewed AMD product generation for a parsed SNP report."""

    if not isinstance(parsed, SnpReport):
        return None
    return _snp_generation(parsed)


def _read_amd_ark(path: Path) -> bytes | None:
    return _read_amd_certificate(path)


def _read_amd_certificate(path: Path) -> bytes | None:
    """Read one bounded, owner-controlled certificate file without following links."""

    if not hasattr(os, "O_NOFOLLOW"):
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in {0, os.geteuid()}
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= before.st_size <= MAX_AMD_CERTIFICATE_BYTES
        ):
            return None
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(16 * 1024, MAX_AMD_CERTIFICATE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_AMD_CERTIFICATE_BYTES:
                return None
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
        ):
            return None
        body = b"".join(chunks)
        return body if len(body) == before.st_size else None
    except OSError:
        return None
    finally:
        os.close(descriptor)


def _amd_ark_is_pinned(certs_path: Path, generation: str) -> bool:
    expected = PINNED_AMD_ARK_SPKI_SHA256.get(generation)
    encoded = _read_amd_ark(certs_path / "ark.der")
    if expected is None or encoded is None:
        return False
    try:
        certificate = x509.load_der_x509_certificate(encoded)
        spki = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError):
        return False
    return hashlib.sha256(spki).hexdigest() == expected


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
    # AMD assigns bits 0..5. SEV-TIO at bit 7 exists only from report v5.
    # Bit 6 and every other bit remain reserved until a reviewed ABI update.
    platform_info_mask = 0xBF if parsed.version == 5 else 0x3F
    if parsed.platform_info & ~platform_info_mask:
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
    """Apply Cathedral's fail-closed SEV-SNP production profile.

    The vendor signature check proves report authenticity. These checks decide
    whether the authentic report satisfies this bounded verifier contract.
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


def _called_process_output(exc: subprocess.CalledProcessError) -> str:
    """Return bounded diagnostic text emitted by one pinned snpguest command."""

    chunks: list[str] = []
    for value in (exc.stderr, exc.output):
        if value is None:
            continue
        if isinstance(value, bytes):
            chunks.append(value[:16_384].decode("utf-8", errors="replace"))
        else:
            chunks.append(str(value)[:16_384])
    return "\n".join(chunks)


def _snpguest_fetch_failure_is_unavailable(
    exc: subprocess.CalledProcessError,
) -> bool:
    """Classify a failed KDS fetch without turning outages into miner faults.

    snpguest v0.10.0 reports both KDS HTTP failures and local report parsing as
    a non-zero exit. A deterministic 4xx response (other than request timeout,
    Too Early, or rate limiting) is a terminal rejection of this certificate
    request. A 5xx response, transient 4xx response, or recognized network
    client error is verifier infrastructure and must suspend a write when the
    caller requests outage reporting. An unknown failure is never labelled an
    AMD outage because it can be a local verifier or command defect.

    Non-fetch failures are cryptographic or certificate verification failures
    and therefore invalid evidence.
    """

    command = tuple(os.fspath(part) for part in exc.cmd) if not isinstance(exc.cmd, str) else ()
    if len(command) < 3 or command[1] != "fetch" or command[2] not in {"vcek", "ca"}:
        return False

    diagnostic = _called_process_output(exc)
    for pattern in _KDS_HTTP_STATUS_PATTERNS:
        match = pattern.search(diagnostic)
        if match is None:
            continue
        status = int(match.group(1))
        if 500 <= status <= 599 or status in _TRANSIENT_KDS_CLIENT_STATUSES:
            return True
        return False

    lowered = diagnostic.casefold()
    if any(marker in lowered for marker in _INVALID_REPORT_ERROR_MARKERS):
        return False

    return any(marker in lowered for marker in _KDS_TRANSPORT_ERROR_MARKERS)


_CachedCertificates = tuple[tuple[str, bytes], ...]
_CacheKey = tuple[object, ...]


class _SnpCertificateCache:
    """Bounded, thread-safe, process-local LRU of AMD certificate bytes.

    An entry only replaces one KDS fetch. Every verification that uses it still
    writes the bytes into a fresh private directory and runs the ARK pin,
    ``verify certs`` and ``verify attestation``. Nothing is written to disk
    outside that directory, and no entry outlives the process.
    """

    def __init__(
        self,
        *,
        max_entries: int = CERTIFICATE_CACHE_MAX_ENTRIES,
        ttl_seconds: float | None = CERTIFICATE_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("certificate cache bound must be a positive integer")
        if ttl_seconds is not None and not (math.isfinite(ttl_seconds) and ttl_seconds > 0):
            raise ValueError("certificate cache TTL must be positive and finite")
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[_CacheKey, tuple[float, _CachedCertificates]] = OrderedDict()

    def get(self, key: _CacheKey) -> _CachedCertificates | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, certificates = entry
            if self._ttl_seconds is not None and self._clock() - stored_at >= self._ttl_seconds:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return certificates

    def put(self, key: _CacheKey, certificates: _CachedCertificates) -> None:
        with self._lock:
            self._entries[key] = (self._clock(), certificates)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def evict(self, key: _CacheKey, certificates: _CachedCertificates) -> None:
        """Drop ``key`` only while it still holds the entry the caller used."""

        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry[1] is certificates:
                del self._entries[key]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


_CERTIFICATE_CACHE = _SnpCertificateCache()


def clear_snp_certificate_cache() -> None:
    """Forget every cached AMD certificate, so the next check fetches from KDS."""

    _CERTIFICATE_CACHE.clear()


def _vcek_cache_key(generation: str, parsed: SnpReport) -> _CacheKey:
    # KDS serves the VCEK for one product, hardware ID, and reported TCB.
    return ("vcek", generation, parsed.chip_id, parsed.tcb.reported)


def _ca_cache_key(generation: str) -> _CacheKey:
    return ("ca", generation)


def _write_cached_certificates(certs_path: Path, certificates: _CachedCertificates) -> None:
    """Recreate cached certificates as new owner-only files in a private directory."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    for name, body in certificates:
        descriptor = os.open(certs_path / name, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(body)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("cached certificate write made no progress")
                view = view[written:]
        finally:
            os.close(descriptor)


def _remember_fetched_certificates(
    cache: _SnpCertificateCache,
    certs_path: Path,
    fetched: dict[_CacheKey, tuple[str, ...]],
) -> None:
    """Cache what KDS returned, after the whole chain verified.

    The directory must hold exactly the files the verifier used, and each one
    must pass the same strict read as the pinned ARK. Anything else is simply
    not cached; the verdict is already decided.
    """

    if not fetched:
        return
    try:
        present = sorted(os.listdir(certs_path))
    except OSError:
        return
    if present != sorted(_VCEK_CERTIFICATE_FILES + _CA_CERTIFICATE_FILES):
        return
    entries: dict[_CacheKey, _CachedCertificates] = {}
    for key, names in fetched.items():
        certificates: list[tuple[str, bytes]] = []
        for name in names:
            body = _read_amd_certificate(certs_path / name)
            if body is None:
                return
            certificates.append((name, body))
        entries[key] = tuple(certificates)
    for key, certificates in entries.items():
        cache.put(key, certificates)


def _verify_chain_once(
    report: bytes,
    generation: str,
    *,
    vcek_key: _CacheKey,
    ca_key: _CacheKey,
    cached: dict[_CacheKey, _CachedCertificates],
    cache: _SnpCertificateCache,
    snpguest_path: str,
    deadline_monotonic: float | None,
) -> bool:
    """Run one complete chain check, taking certificates from ``cached`` or KDS."""

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        report_path = work / "attestation-report.bin"
        report_path.write_bytes(report)
        certs_path = work / "certs"
        certs_path.mkdir(mode=0o700)

        def run(command: list[str]) -> None:
            # snpguest creates the fetched certificates with the inherited
            # umask. Under the common 0002 the ARK comes out group-writable and
            # _read_amd_ark refuses it, so the root pin fails closed for an
            # authentic chain. Owner-only files keep that strict check intact.
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=_snpguest_command_timeout(deadline_monotonic),
                umask=0o077,
            )

        fetched: dict[_CacheKey, tuple[str, ...]] = {}
        vcek = cached.get(vcek_key)
        if vcek is None:
            run([snpguest_path, "fetch", "vcek", "DER", str(certs_path), str(report_path)])
            fetched[vcek_key] = _VCEK_CERTIFICATE_FILES
        else:
            _write_cached_certificates(certs_path, vcek)

        ca = cached.get(ca_key)
        if ca is None:
            # This is the exact v0.10.0 interface documented at
            # https://github.com/virtee/snpguest/blob/v0.10.0/README.md#4-fetch.
            # Trying legacy orders after a real KDS 5xx would replace the outage
            # diagnostic with a local CLI parse error and incorrectly blame the
            # miner.
            run(
                [
                    snpguest_path,
                    "fetch",
                    "ca",
                    "DER",
                    str(certs_path),
                    "--report",
                    str(report_path),
                ]
            )
            fetched[ca_key] = _CA_CERTIFICATE_FILES
        else:
            _write_cached_certificates(certs_path, ca)

        # A cached ARK is pinned and verified exactly like a fetched one.
        if not _amd_ark_is_pinned(certs_path, generation):
            return False

        try:
            run([snpguest_path, "verify", "certs", str(certs_path)])
        except subprocess.CalledProcessError:
            return False

        verify_orders = [
            [snpguest_path, "verify", "attestation", str(certs_path), str(report_path)],
            [snpguest_path, "verify", "attestation", str(report_path), str(certs_path)],
        ]
        for cmd in verify_orders:
            try:
                run(cmd)
            except subprocess.CalledProcessError:
                continue
            _remember_fetched_certificates(cache, certs_path, fetched)
            return True
    return False


def _verify_chain_with_snpguest(
    report: bytes,
    *,
    snpguest_path: str,
    certs_dir: str | os.PathLike[str] | None,
    deadline_monotonic: float | None = None,
) -> bool:
    """Ask snpguest to verify the report signature chain to the pinned AMD root.

    Certificates come from AMD KDS or, after an earlier fully verified check of
    the same chip and TCB, from the in-memory cache. A cached certificate only
    skips its fetch: the pin and both snpguest verifications always run. If a
    check that used the cache fails, the entries it used are dropped and the
    chain is checked once more from fresh KDS fetches, so a stale entry can
    never make an authentic report fail.
    """

    # An external directory lets another process swap ARK/ASK/VCEK pathnames
    # after the root pin check but before snpguest reopens them. Keep the
    # argument for fail-closed API compatibility, but never verify from it.
    if certs_dir is not None:
        return False
    parsed = parse_snp_report(report)
    generation = _snp_generation(parsed)
    if generation is None:
        return False

    cache = _CERTIFICATE_CACHE
    vcek_key = _vcek_cache_key(generation, parsed)
    ca_key = _ca_cache_key(generation)
    cached: dict[_CacheKey, _CachedCertificates] = {}
    for key in (vcek_key, ca_key):
        certificates = cache.get(key)
        if certificates is not None:
            cached[key] = certificates

    def attempt(certificates: dict[_CacheKey, _CachedCertificates]) -> bool:
        return _verify_chain_once(
            report,
            generation,
            vcek_key=vcek_key,
            ca_key=ca_key,
            cached=certificates,
            cache=cache,
            snpguest_path=snpguest_path,
            deadline_monotonic=deadline_monotonic,
        )

    if attempt(cached):
        return True
    if not cached:
        return False
    for key, certificates in cached.items():
        cache.evict(key, certificates)
    return attempt({})


def _kds_backoff_seconds(retry: int) -> float:
    """Return the jittered wait before KDS retry ``retry`` (0 is the first retry)."""

    nominal = _KDS_BACKOFF_BASE_SECONDS * _KDS_BACKOFF_FACTOR**retry
    return nominal * random.uniform(1.0 - _KDS_BACKOFF_JITTER, 1.0 + _KDS_BACKOFF_JITTER)


def _kds_backoff_sleep(seconds: float) -> None:
    """Wait before a KDS retry. Tests replace this hook to observe the backoff."""

    time.sleep(seconds)


def verify_snp_report_data(
    report: bytes,
    expected_report_data: bytes,
    policy: Policy,
    *,
    snpguest_path: str | os.PathLike[str] | None = None,
    certs_dir: str | os.PathLike[str] | None = None,
    require_chain: bool = True,
    raise_on_verifier_unavailable: bool = False,
    deadline_monotonic: float | None = None,
) -> Attested | None:
    """Verify a raw SNP report against explicit 64-byte REPORT_DATA.

    Fail-closed by default: every existing caller treats ANY ``Attested`` as an
    admission ticket, so without a vendor-verified signature chain the default
    verdict is ``None``. Diagnostic/shadow tooling that wants the parsed report
    with an explicit ``STRUCTURE_OK_CHAIN_UNVERIFIED`` status can opt in with
    ``require_chain=False`` — that verdict must never be used for admission.

    ``certs_dir`` remains in the compatibility signature but any non-``None``
    value is refused. Vendor certificates must stay in the verifier's private
    temporary tree so their pathnames cannot be replaced between root pinning
    and signature verification.

    A transient AMD KDS failure (5xx, 408, 425, 429, or a network error) is
    retried at most twice, after a jittered wait of about 2 s and then about
    5 s, never past ``deadline_monotonic``. Fetched certificates are reused
    from a bounded in-memory cache, but every check still pins and verifies
    the full chain.
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

    chain_verified = False
    with _pinned_snpguest(snpguest_path) as snpguest:
        if snpguest is None and raise_on_verifier_unavailable:
            raise SnpVerifierUnavailable("pinned SNP verifier is unavailable")
        if snpguest is not None:
            for attempt in range(_KDS_ATTEMPTS):
                unavailable_error: BaseException
                try:
                    verify_kwargs = {
                        "snpguest_path": snpguest,
                        "certs_dir": certs_dir,
                    }
                    if deadline_monotonic is not None:
                        verify_kwargs["deadline_monotonic"] = deadline_monotonic
                    chain_verified = _verify_chain_with_snpguest(report, **verify_kwargs)
                    break
                except subprocess.CalledProcessError as exc:
                    if not _snpguest_fetch_failure_is_unavailable(exc):
                        return None
                    unavailable_error = exc
                except (OSError, subprocess.TimeoutExpired) as exc:
                    unavailable_error = exc

                if attempt == _KDS_ATTEMPTS - 1:
                    if raise_on_verifier_unavailable:
                        raise SnpVerifierUnavailable(
                            "AMD certificate or verifier infrastructure is unavailable"
                        ) from unavailable_error
                    return None
                delay = _kds_backoff_seconds(attempt)
                if deadline_monotonic is not None:
                    # Stop now rather than sleep into a deadline that would
                    # leave the retry no time to reach KDS.
                    remaining = float(deadline_monotonic) - time.monotonic()
                    if remaining <= delay:
                        if raise_on_verifier_unavailable:
                            raise SnpVerifierUnavailable(
                                "AMD verifier deadline expired"
                            ) from unavailable_error
                        return None
                _kds_backoff_sleep(delay)

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
    raise_on_verifier_unavailable: bool = False,
    deadline_monotonic: float | None = None,
) -> Attested | None:
    """Verify SNP evidence using the existing Cathedral nonce/hotkey binding."""

    expected = evidence_report_data(evidence, nonce)
    return verify_snp_report_data(
        evidence.quote,
        expected,
        policy,
        snpguest_path=snpguest_path,
        certs_dir=certs_dir,
        raise_on_verifier_unavailable=raise_on_verifier_unavailable,
        deadline_monotonic=deadline_monotonic,
    )
