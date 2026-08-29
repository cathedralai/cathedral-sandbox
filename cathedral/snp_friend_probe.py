"""One-shot friend-owned AMD SEV-SNP local self-test transcript.

The probe runs inside a native Linux SEV-SNP guest with ``/dev/sev-guest``.
It starts the real Cathedral HTTPS worker on loopback, requests fresh v2
evidence through the real remote client, verifies the AMD VCEK chain, rejects
five counterexamples, observes whether two reports from the same guest carry a
matching platform pseudonym after hotkey and TLS-key rotation, and completes
one canonical SAT challenge. The two-report observation is not durable machine
deduplication proof.

The redacted JSON is a local test transcript, not independently replayable
hardware evidence. A reviewer must supply the challenge and observe the run on
the native guest before treating ``LOCAL_PASS`` as live proof.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Sequence

import cathedral as cathedral_package

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from cathedral.attest import collect_snp
from cathedral.channel import tls_spki_binding
from cathedral.common import ChannelBinding, Policy, Tier, issue_nonce
from cathedral.lanes.sat import SatLane
from cathedral.remote import RemoteMiner
from cathedral.verify import verify
from cathedral.verify.snp import (
    MAX_SNPGUEST_BYTES,
    PINNED_SNPGUEST_SHA256,
    PINNED_SNPGUEST_VERSION,
    parse_snp_report,
)
from cathedral.worker import WorkerServer


TRANSCRIPT_SCHEMA = "cathedral_amd_sev_snp_friend_transcript_v1"
HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
SECOND_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
DEFAULT_SEV_GUEST_DEVICE = Path("/dev/sev-guest")
PROBE_TIMEOUT_SECONDS = 120.0
FRIEND_SNPGUEST_TIMEOUT_SECONDS = 15.0


class ProbeError(RuntimeError):
    """The hardware self-test did not satisfy its contract."""


def _resolve_snpguest(private_directory: Path) -> tuple[Path, str, str]:
    configured = os.environ.get("CATHEDRAL_SNPGUEST")
    candidate = configured or shutil.which("snpguest")
    if not candidate:
        raise ProbeError("snpguest is missing; install the pinned v0.10.0 release")
    source = Path(os.path.abspath(candidate))
    private_directory.chmod(0o700)
    binary = private_directory / "snpguest"
    read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    copied = 0
    source_descriptor = -1
    destination_descriptor = -1
    try:
        source_descriptor = os.open(source, read_flags)
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ProbeError("CATHEDRAL_SNPGUEST must be a regular file, not a link or device")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SNPGUEST_BYTES:
            raise ProbeError("CATHEDRAL_SNPGUEST has an invalid size")
        destination_descriptor = os.open(binary, write_flags, 0o500)
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_SNPGUEST_BYTES:
                raise ProbeError("CATHEDRAL_SNPGUEST exceeds the size limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise ProbeError("failed to copy the pinned snpguest binary")
                view = view[written:]
        os.fsync(destination_descriptor)
        os.fchmod(destination_descriptor, 0o500)
    except OSError as exc:
        raise ProbeError("CATHEDRAL_SNPGUEST could not be copied safely") from exc
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
    actual_digest = digest.hexdigest()
    if actual_digest != PINNED_SNPGUEST_SHA256:
        binary.unlink(missing_ok=True)
        raise ProbeError("snpguest binary digest does not match the reviewed v0.10.0 release")
    private_digest = hashlib.sha256()
    verification_descriptor = -1
    try:
        verification_descriptor = os.open(binary, read_flags)
        while True:
            chunk = os.read(verification_descriptor, 1024 * 1024)
            if not chunk:
                break
            private_digest.update(chunk)
    except OSError as exc:
        raise ProbeError("the private snpguest copy could not be verified") from exc
    finally:
        if verification_descriptor >= 0:
            os.close(verification_descriptor)
    if private_digest.hexdigest() != PINNED_SNPGUEST_SHA256:
        binary.unlink(missing_ok=True)
        raise ProbeError("the private snpguest copy failed its digest check")
    completed = subprocess.run(
        [str(binary), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10.0,
    )
    version_text = " ".join((completed.stdout, completed.stderr)).strip()
    if re.search(r"(?<![0-9.])0\.10\.0(?![0-9.])", version_text) is None:
        raise ProbeError(f"snpguest {PINNED_SNPGUEST_VERSION} is required")
    return binary, version_text, actual_digest


def _preflight(private_directory: Path) -> tuple[Path, str, str, Path]:
    if not sys.platform.startswith("linux"):
        raise ProbeError("the hardware probe must run inside a Linux SEV-SNP guest")
    device = Path(os.environ.get("CATHEDRAL_SEV_GUEST_DEV", DEFAULT_SEV_GUEST_DEVICE))
    try:
        metadata = device.stat()
    except OSError as exc:
        raise ProbeError(
            "/dev/sev-guest is unavailable; this is not the supported native SNP path"
        ) from exc
    if not stat.S_ISCHR(metadata.st_mode):
        raise ProbeError("the configured SEV guest device is not a character device")
    binary, version, digest = _resolve_snpguest(private_directory)
    return binary, version, digest, device


def _tls_material(directory: Path, name: str = "worker") -> tuple[Path, Path, bytes]:
    private_key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(private_key, algorithm=None)
    )
    key_path = directory / f"{name}.key.pem"
    cert_path = directory / f"{name}.cert.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.chmod(0o600)
    cert_path.chmod(0o600)
    return cert_path, key_path, certificate.public_bytes(serialization.Encoding.DER)


def _source_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _package_file() -> Path:
    return Path(cathedral_package.__file__).resolve()


def _source_commit() -> str:
    root = _source_root()
    try:
        _package_file().relative_to(root)
    except ValueError as exc:
        raise ProbeError(
            "the executing Cathedral package is outside the reviewed source tree"
        ) from exc
    git = ["git", "-c", f"safe.directory={root}", "-C", str(root)]
    try:
        completed = subprocess.run(
            [*git, "rev-parse", "--verify", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        status = subprocess.run(
            [*git, "status", "--porcelain=v1", "--untracked-files=all"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
    except (OSError, subprocess.SubprocessError):
        raise ProbeError("the executing source tree is not a readable Git checkout") from None
    commit = completed.stdout.strip().lower()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ProbeError("the executing source tree has no full 40-character commit")
    if status.stdout:
        raise ProbeError("the executing source tree is not clean")
    return commit


def _parse_review_challenge(value: str) -> bytes:
    normalized = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        raise argparse.ArgumentTypeError("challenge must be exactly 32 bytes encoded as 64 hex")
    challenge = bytes.fromhex(normalized)
    if not any(challenge):
        raise argparse.ArgumentTypeError("challenge must not be all zero")
    return challenge


def run_probe(review_challenge: bytes) -> dict[str, Any]:
    if len(review_challenge) != 32 or not any(review_challenge):
        raise ProbeError("a nonzero 32-byte reviewer challenge is required")
    source_commit = _source_commit()
    verifier_directory = tempfile.TemporaryDirectory(prefix="cathedral-snp-verifier-")
    try:
        snpguest, snpguest_version, snpguest_digest, _device = _preflight(
            Path(verifier_directory.name)
        )
    except Exception:
        verifier_directory.cleanup()
        raise
    previous_snpguest = os.environ.get("CATHEDRAL_SNPGUEST")
    previous_timeout = os.environ.get("CATHEDRAL_SNPGUEST_TIMEOUT")
    os.environ["CATHEDRAL_SNPGUEST"] = str(snpguest)
    os.environ["CATHEDRAL_SNPGUEST_TIMEOUT"] = str(FRIEND_SNPGUEST_TIMEOUT_SECONDS)
    try:
        with tempfile.TemporaryDirectory(prefix="cathedral-snp-transcript-") as td:
            cert_path, key_path, certificate_der = _tls_material(Path(td))
            binding = tls_spki_binding(certificate_der)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context.load_cert_chain(cert_path, key_path)
            client_context = ssl.create_default_context(cafile=str(cert_path))
            with WorkerServer(
                "127.0.0.1",
                0,
                configured_hotkey=HOTKEY,
                evidence_collector=collect_snp,
                channel_binding=binding,
                tls_context=server_context,
                timeout=PROBE_TIMEOUT_SECONDS,
            ) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                remote = RemoteMiner(
                    server.base_url,
                    HOTKEY,
                    timeout=PROBE_TIMEOUT_SECONDS,
                    ssl_context=client_context,
                )
                # The reviewer-provided value is the exact first report nonce,
                # so REPORT_DATA v2 binds the observed run to that challenge.
                nonce = review_challenge
                evidence = remote.fetch_evidence(nonce)
                parsed = parse_snp_report(evidence.quote)
                policy = Policy(
                    allowed_measurements={parsed.measurement},
                    min_tcb=parsed.tcb.reported,
                )
                attested = verify(evidence, nonce, policy)
                if attested is None or not attested.chain_verified:
                    raise ProbeError("AMD VCEK chain or Cathedral SNP policy verification failed")
                if attested.tier is not Tier.CC_CPU_SNP:
                    raise ProbeError("the verifier returned the wrong hardware tier")

                checks = {
                    "native_sev_guest_device": True,
                    "amd_vcek_chain_verified": True,
                    "report_data_v2_bound": evidence.report_data_version == 2,
                    "tls_spki_bound": evidence.channel_binding == binding,
                    "vmpl_zero": parsed.vmpl == 0,
                    "debug_disabled": not bool(parsed.guest_policy & (1 << 19)),
                    "migration_agent_disabled": not bool(parsed.guest_policy & (1 << 18)),
                    "wrong_nonce_rejected": verify(evidence, issue_nonce(), policy) is None,
                    "wrong_hotkey_rejected": verify(
                        replace(evidence, miner_hotkey=HOTKEY[:-1] + "x"), nonce, policy
                    )
                    is None,
                    "wrong_channel_key_rejected": verify(
                        replace(
                            evidence,
                            channel_binding=ChannelBinding(
                                binding.binding_type,
                                bytes((binding.digest[0] ^ 1,)) + binding.digest[1:],
                            ),
                        ),
                        nonce,
                        policy,
                    )
                    is None,
                    "wrong_measurement_rejected": verify(
                        evidence,
                        nonce,
                        Policy(allowed_measurements={"00" * 48}, min_tcb=0),
                    )
                    is None,
                }
                tampered_quote = bytearray(evidence.quote)
                tampered_quote[0x2A0] ^= 1
                checks["tampered_signature_rejected"] = (
                    verify(replace(evidence, quote=bytes(tampered_quote)), nonce, policy) is None
                )
                remote.confirm_channel_binding(evidence)
                lane = SatLane(namespace="amd-sev-snp-friend-transcript")
                item = lane.dispatch(HOTKEY, budget=0)
                certificate = remote.do_sat_work(item)
                checks["canonical_sat_verified"] = lane.verify(item, certificate) is not None
                if not all(checks.values()):
                    failed = sorted(name for name, passed in checks.items() if not passed)
                    raise ProbeError("self-test checks failed: " + ", ".join(failed))
            thread.join(timeout=5.0)
            if thread.is_alive():
                raise ProbeError("the first HTTPS worker did not stop cleanly")

            # Observe whether two reports from this guest use the same
            # vendor-signed hardware pseudonym after hotkey and TLS-key
            # rotation. This is not a durable dedup guarantee: SINGLE_SOCKET=0
            # permits a guest on multiple sockets, each with its own CHIP_ID.
            cert_path_2, key_path_2, certificate_der_2 = _tls_material(Path(td), "worker-2")
            binding_2 = tls_spki_binding(certificate_der_2)
            server_context_2 = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context_2.minimum_version = ssl.TLSVersion.TLSv1_2
            server_context_2.load_cert_chain(cert_path_2, key_path_2)
            client_context_2 = ssl.create_default_context(cafile=str(cert_path_2))
            with WorkerServer(
                "127.0.0.1",
                0,
                configured_hotkey=SECOND_HOTKEY,
                evidence_collector=collect_snp,
                channel_binding=binding_2,
                tls_context=server_context_2,
                timeout=PROBE_TIMEOUT_SECONDS,
            ) as server_2:
                thread_2 = threading.Thread(target=server_2.serve_forever, daemon=True)
                thread_2.start()
                remote_2 = RemoteMiner(
                    server_2.base_url,
                    SECOND_HOTKEY,
                    timeout=PROBE_TIMEOUT_SECONDS,
                    ssl_context=client_context_2,
                )
                nonce_2 = hashlib.sha256(
                    b"cathedral.amd-sev-snp.friend-transcript.v1.second\x00" + review_challenge
                ).digest()
                evidence_2 = remote_2.fetch_evidence(nonce_2)
                parsed_2 = parse_snp_report(evidence_2.quote)
                attested_2 = verify(
                    evidence_2,
                    nonce_2,
                    Policy(
                        allowed_measurements={parsed_2.measurement},
                        min_tcb=parsed_2.tcb.reported,
                    ),
                )
                checks["second_amd_vcek_chain_verified"] = bool(
                    attested_2 is not None and attested_2.chain_verified
                )
                checks["tls_key_rotation_observed"] = binding_2 != binding
                checks["two_report_platform_pseudonym_match_observed"] = bool(
                    attested_2 is not None and attested_2.chip_id == attested.chip_id
                )
                checks["same_guest_measurement_stable"] = parsed_2.measurement == parsed.measurement
                if not all(checks.values()):
                    failed = sorted(name for name, passed in checks.items() if not passed)
                    raise ProbeError("self-test checks failed: " + ", ".join(failed))
            thread_2.join(timeout=5.0)
            if thread_2.is_alive():
                raise ProbeError("the second HTTPS worker did not stop cleanly")
    finally:
        if previous_snpguest is None:
            os.environ.pop("CATHEDRAL_SNPGUEST", None)
        else:
            os.environ["CATHEDRAL_SNPGUEST"] = previous_snpguest
        if previous_timeout is None:
            os.environ.pop("CATHEDRAL_SNPGUEST_TIMEOUT", None)
        else:
            os.environ["CATHEDRAL_SNPGUEST_TIMEOUT"] = previous_timeout
        verifier_directory.cleanup()

    return {
        "schema": TRANSCRIPT_SCHEMA,
        "status": "LOCAL_PASS",
        "tested_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_commit": source_commit,
        "review": {
            "challenge_hex": review_challenge.hex(),
            "observer_required_for_live_proof": True,
            "independently_replayable": False,
        },
        "snpguest": {
            "version": snpguest_version,
            "sha256": snpguest_digest,
        },
        "report": {
            "version": parsed.version,
            "vmpl": parsed.vmpl,
            "signature_algorithm": parsed.signature_algo,
            "guest_policy_hex": f"0x{parsed.guest_policy:016x}",
            "measurement": parsed.measurement,
            "review_scoped_platform_pseudonym": "hmac-sha256:"
            + hmac.new(
                review_challenge,
                b"cathedral.amd-sev-snp.platform.v1\x00" + bytes.fromhex(parsed.chip_id),
                hashlib.sha256,
            ).hexdigest(),
            "reported_tcb_hex": f"0x{parsed.tcb.reported:016x}",
        },
        "channel": {
            "binding_type": binding.binding_type.value,
            "binding_digest": "sha256:" + binding.digest.hex(),
        },
        "checks": checks,
        "production_activation": {
            "validator_weights_enabled": False,
            "customer_receipts_enabled": False,
            "managed_provisioning_enabled": False,
            "durable_machine_dedup_proven": False,
        },
    }


def _write_new(path: Path, document: dict[str, Any]) -> None:
    payload = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run one bounded AMD SEV-SNP local self-test transcript"
    )
    parser.add_argument(
        "--challenge",
        type=_parse_review_challenge,
        required=True,
        help="reviewer-supplied nonzero 32-byte challenge as 64 hex",
    )
    parser.add_argument("--output", type=Path, required=True, help="new JSON transcript path")
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.challenge)
        _write_new(args.output, result)
    except Exception as exc:  # noqa: BLE001 - one sanitized CLI failure boundary
        failure = {
            "schema": TRANSCRIPT_SCHEMA,
            "status": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema": TRANSCRIPT_SCHEMA,
                "status": result["status"],
                "source_commit": result["source_commit"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
