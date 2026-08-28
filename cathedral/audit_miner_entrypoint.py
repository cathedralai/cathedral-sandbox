"""Fixed entrypoint for the independent SN39 audit-miner image.

The container accepts one deployment input: a public Bittensor hotkey. It
generates its TLS identity inside the guest and supplies an unexported random
bearer only because the general-purpose worker CLI keeps non-audit routes
authenticated. The independent evidence and canonical SAT routes remain
credential-free.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NoReturn

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

HOTKEY_ENV = "CATHEDRAL_MINER_HOTKEY"
WORKER_BEARER_ENV = "CATHEDRAL_WORKER_BEARER_TOKEN"
TLS_DIRECTORY = Path("/run/cathedral-audit-miner")
TLS_CERTIFICATE = "worker.crt"
TLS_PRIVATE_KEY = "worker.key"
WORKER_HOST = "0.0.0.0"
WORKER_PORT = 8081
WORKER_TEE = "tdx"

_ALLOWED_CATHEDRAL_INPUTS = frozenset({HOTKEY_ENV})
_CHILD_PATH = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {character: index for index, character in enumerate(_BASE58_ALPHABET)}
_SS58_PREFIX = b"SS58PRE"
_BITTENSOR_SS58_FORMAT = 42
_PUBLIC_KEY_BYTES = 32
_CHECKSUM_BYTES = 2


class EntrypointError(ValueError):
    """The fixed image contract was not satisfied."""


@dataclass(frozen=True)
class TLSMaterial:
    certificate: Path
    private_key: Path


def _decode_base58(value: str) -> bytes:
    number = 0
    try:
        for character in value:
            number = number * 58 + _BASE58_INDEX[character]
    except KeyError as exc:
        raise EntrypointError("the miner hotkey is not base58") from exc
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + encoded


def validate_public_hotkey(value: object) -> str:
    """Accept one canonical Bittensor AccountId32 SS58 address."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise EntrypointError(f"{HOTKEY_ENV} must be a canonical public SS58 hotkey")
    if not value.isascii() or len(value) != 48:
        raise EntrypointError(f"{HOTKEY_ENV} must be a canonical public SS58 hotkey")
    decoded = _decode_base58(value)
    expected_size = 1 + _PUBLIC_KEY_BYTES + _CHECKSUM_BYTES
    if len(decoded) != expected_size or decoded[0] != _BITTENSOR_SS58_FORMAT:
        raise EntrypointError(f"{HOTKEY_ENV} must use Bittensor SS58 format 42")
    payload = decoded[:-_CHECKSUM_BYTES]
    checksum = decoded[-_CHECKSUM_BYTES:]
    expected = hashlib.blake2b(_SS58_PREFIX + payload, digest_size=64).digest()[:2]
    if not hmac.compare_digest(checksum, expected):
        raise EntrypointError(f"{HOTKEY_ENV} has an invalid SS58 checksum")
    return value


def validate_environment(environ: Mapping[str, str]) -> str:
    """Read only the public-hotkey input from the Cathedral namespace."""

    unknown = {
        name
        for name in environ
        if name.startswith("CATHEDRAL_") and name not in _ALLOWED_CATHEDRAL_INPUTS
    }
    if unknown:
        raise EntrypointError(f"only {HOTKEY_ENV} is accepted as a CATHEDRAL_* environment input")
    return validate_public_hotkey(environ.get(HOTKEY_ENV))


def _secure_directory(directory: Path) -> None:
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        directory.mkdir(parents=True, mode=0o700)
        metadata = directory.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise EntrypointError("the runtime TLS path must be a real directory")
    if metadata.st_uid != os.geteuid():
        raise EntrypointError("the runtime TLS directory must be owned by this process")
    directory.chmod(0o700)


def _atomic_owner_only_write(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def generate_tls_material(
    directory: Path = TLS_DIRECTORY,
    *,
    now: datetime | None = None,
) -> TLSMaterial:
    """Generate a fresh owner-only key and self-signed leaf certificate."""

    try:
        _secure_directory(directory)
        private_key = Ed25519PrivateKey.generate()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cathedral-sn39-audit-miner")])
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(current - timedelta(minutes=5))
            .not_valid_after(current + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("cathedral-sn39-audit-miner")]),
                critical=False,
            )
            .sign(private_key, algorithm=None)
        )
        private_key_path = directory / TLS_PRIVATE_KEY
        certificate_path = directory / TLS_CERTIFICATE
        _atomic_owner_only_write(
            private_key_path,
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _atomic_owner_only_write(
            certificate_path,
            certificate.public_bytes(serialization.Encoding.PEM),
        )
    except EntrypointError:
        raise
    except (OSError, ValueError) as exc:
        raise EntrypointError("could not generate owner-only runtime TLS material") from exc
    return TLSMaterial(certificate=certificate_path, private_key=private_key_path)


def worker_command(hotkey: str, material: TLSMaterial) -> list[str]:
    """Return the immutable audit-worker command."""

    return [
        sys.executable,
        "-I",
        "-u",
        "-B",
        "-m",
        "cathedral.cli",
        "worker",
        "serve",
        "--hotkey",
        hotkey,
        "--host",
        WORKER_HOST,
        "--port",
        str(WORKER_PORT),
        "--tls-certificate",
        str(material.certificate),
        "--tls-private-key",
        str(material.private_key),
        "--tee",
        WORKER_TEE,
    ]


def _child_environment() -> dict[str, str]:
    child = {"PATH": _CHILD_PATH}
    # The general worker CLI requires a bearer even when only its public audit
    # routes are used. Keep that guard random, local to this process, and
    # unavailable as a deployment input. Noncanonical SAT remains disabled.
    child[WORKER_BEARER_ENV] = secrets.token_hex(32)
    return child


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    tls_directory: Path = TLS_DIRECTORY,
    execvpe: Callable[[str, Sequence[str], Mapping[str, str]], NoReturn] = os.execvpe,
) -> NoReturn:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        raise EntrypointError("the audit-miner image accepts no command arguments")
    source_environment = os.environ if environ is None else environ
    hotkey = validate_environment(source_environment)
    material = generate_tls_material(tls_directory)
    command = worker_command(hotkey, material)
    execvpe(command[0], command, _child_environment())
    raise EntrypointError("worker exec returned unexpectedly")


if __name__ == "__main__":
    try:
        main()
    except EntrypointError as exc:
        print(f"audit miner refused to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
