"""One small Ed25519 signing interface with a local file and an AWS KMS backend.

The backend is selected by a JSON config file so the move from a local
interim key to AWS KMS is a config change plus a key rotation, not a code
change in each caller. Config shape (one entry per purpose):

    {
      "sealed_hotels": {
        "backend": "local_file",
        "key_id": "sealed-hotels-local-1",
        "path": "/root/.../sealed-hotels-local-1.pem",
        "passphrase_path": "/root/.../sealed-hotels-local-1.passphrase"
      },
      "miner_canary": {
        "backend": "aws_kms",
        "key_id": "miner-canary-kms-1",
        "key_arn": "arn:aws:kms:...",
        "region": "us-east-1",
        "public_key_hex": "<64 hex, optional pin>"
      }
    }

Both backends refuse a message over MAX_MESSAGE_BYTES, the AWS KMS ``Sign``
limit for ``MessageType=RAW``, so a document that would fail after the move to
KMS fails now. No backend ever logs or returns private key bytes.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_MESSAGE_BYTES = 4096
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
BACKENDS = frozenset({"local_file", "aws_kms"})
_LOCAL_FILE_KEYS = frozenset({"backend", "key_id", "path", "passphrase_path"})
_AWS_KMS_KEYS = frozenset({"backend", "key_id", "key_arn", "region"})
# An aws_kms entry may also pin its expected raw public key in the config.
_AWS_KMS_OPTIONAL_KEYS = frozenset({"public_key_hex"})
# DER SubjectPublicKeyInfo prefix for an Ed25519 key; KMS GetPublicKey returns
# this followed by the 32 raw public key bytes.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SignerError(ValueError):
    """A signer could not be built or refused to sign."""


@runtime_checkable
class Signer(Protocol):
    """Pure Ed25519 signer for one key."""

    @property
    def key_id(self) -> str: ...

    def public_key_raw(self) -> bytes:
        """The 32-byte raw Ed25519 public key."""
        ...

    def sign(self, message: bytes) -> bytes:
        """A 64-byte pure Ed25519 signature over ``message``."""
        ...


def _check_message(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise SignerError("message must be bytes")
    if len(message) > MAX_MESSAGE_BYTES:
        raise SignerError(
            f"message is {len(message)} bytes; the signing limit is {MAX_MESSAGE_BYTES}"
            " (AWS KMS Sign RAW); a larger document needs a reviewed new format version"
        )
    return bytes(message)


def _check_key_id(key_id: object) -> str:
    if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
        raise SignerError("key_id must be a non-empty string of at most 128 characters")
    return key_id


def _read_private_file(path: Path, what: str) -> bytes:
    """Read a secret file only if the running user owns it and nobody else can read it."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise SignerError(f"the {what} cannot be read: {exc.strerror}") from None
    if stat.S_ISLNK(info.st_mode):
        raise SignerError(f"the {what} is a symlink")
    if not stat.S_ISREG(info.st_mode):
        raise SignerError(f"the {what} is not a regular file")
    if info.st_uid != os.geteuid():
        raise SignerError(f"the {what} is not owned by the running user")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077:
        raise SignerError(f"the {what} is group or world accessible (mode {mode:04o})")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SignerError(f"the {what} cannot be read: {exc.strerror}") from None
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SignerError(f"the {what} changed while it was opened")
        return handle.read()


def _raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


class LocalFileSigner:
    """Ed25519 key in an encrypted PKCS#8 PEM, passphrase in a separate file.

    Refuses an unencrypted PEM, a key or passphrase file not owned by the
    running user, and any group or other permission bit on either file. This
    guards copies of the PEM alone; root on the host can still sign.
    """

    def __init__(self, key_id: str, path: str | os.PathLike[str], passphrase_path: str | os.PathLike[str]) -> None:
        self._key_id = _check_key_id(key_id)
        pem = _read_private_file(Path(path), "private key")
        try:
            serialization.load_pem_private_key(pem, password=None)
        except TypeError:
            pass  # encrypted, as required
        except ValueError:
            raise SignerError("the private key is not a loadable PEM") from None
        else:
            raise SignerError("the private key is not encrypted; signing keys are stored encrypted at rest")
        passphrase = _read_private_file(Path(passphrase_path), "passphrase file").rstrip(b"\r\n")
        if not passphrase:
            raise SignerError("the passphrase file is empty")
        try:
            key = serialization.load_pem_private_key(pem, password=passphrase)
        except (TypeError, ValueError):
            raise SignerError("the private key could not be decrypted with the passphrase file") from None
        finally:
            del passphrase
        if not isinstance(key, Ed25519PrivateKey):
            raise SignerError("the private key is not Ed25519")
        self._key = key
        self._public = _raw_public(key.public_key())

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_raw(self) -> bytes:
        return self._public

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(_check_message(message))

    def __repr__(self) -> str:
        return f"LocalFileSigner(key_id={self._key_id!r})"


class AwsKmsSigner:
    """Ed25519 signing through AWS KMS ``Sign`` (``ED25519_SHA_512``, ``RAW``).

    ``pinned_public_key`` is the 32-byte raw key the caller trusts (for example
    from ``docs/keys/``). Before the first signature the KMS public key must
    equal it, so a mistyped ARN or a swapped key cannot sign. boto3 is imported
    only when a client is first needed.
    """

    def __init__(
        self,
        key_id: str,
        key_arn: str,
        region: str,
        *,
        pinned_public_key: bytes | None = None,
        client_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self._key_id = _check_key_id(key_id)
        if not isinstance(key_arn, str) or not key_arn:
            raise SignerError("key_arn must be a non-empty string")
        if not isinstance(region, str) or not region:
            raise SignerError("region must be a non-empty string")
        if pinned_public_key is not None and (
            not isinstance(pinned_public_key, (bytes, bytearray))
            or len(pinned_public_key) != PUBLIC_KEY_BYTES
        ):
            raise SignerError("pinned_public_key must be 32 raw bytes")
        self._key_arn = key_arn
        self._region = region
        self._pinned = bytes(pinned_public_key) if pinned_public_key is not None else None
        self._client_factory = client_factory
        self._client: Any = None
        self._public: bytes | None = None

    @property
    def key_id(self) -> str:
        return self._key_id

    def _kms(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory(self._region)
            else:
                try:
                    import boto3  # noqa: PLC0415 - optional, only for the KMS backend
                except ImportError:
                    raise SignerError("the aws_kms backend needs boto3 installed") from None
                self._client = boto3.client("kms", region_name=self._region)
        return self._client

    def public_key_raw(self) -> bytes:
        if self._public is None:
            response = self._kms().GetPublicKey(KeyId=self._key_arn)
            if response.get("KeySpec") != "ECC_NIST_EDWARDS25519":
                raise SignerError("the KMS key spec is not ECC_NIST_EDWARDS25519")
            if response.get("KeyUsage") != "SIGN_VERIFY":
                raise SignerError("the KMS key usage is not SIGN_VERIFY")
            der = bytes(response.get("PublicKey") or b"")
            if len(der) != len(_ED25519_SPKI_PREFIX) + PUBLIC_KEY_BYTES or not der.startswith(
                _ED25519_SPKI_PREFIX
            ):
                raise SignerError("the KMS public key is not an Ed25519 SubjectPublicKeyInfo")
            raw = der[len(_ED25519_SPKI_PREFIX) :]
            if self._pinned is not None and raw != self._pinned:
                raise SignerError("the KMS public key does not equal the pinned public key")
            self._public = raw
        return self._public

    def sign(self, message: bytes) -> bytes:
        message = _check_message(message)
        if self._pinned is None:
            raise SignerError("the aws_kms backend needs a pinned public key before it signs")
        public = self.public_key_raw()
        response = self._kms().Sign(
            KeyId=self._key_arn,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="ED25519_SHA_512",
        )
        signature = bytes(response.get("Signature") or b"")
        if len(signature) != SIGNATURE_BYTES:
            raise SignerError("KMS returned a signature that is not 64 bytes")
        # A signature that does not verify under the pinned key must never leave here.
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        except Exception:
            raise SignerError("the KMS signature does not verify under the pinned public key") from None
        return signature

    def __repr__(self) -> str:
        return f"AwsKmsSigner(key_id={self._key_id!r}, region={self._region!r})"


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SignerError(f"duplicate key {key!r} in the signer config")
        result[key] = value
    return result


def signer_from_config(
    path: str | os.PathLike[str],
    purpose: str,
    *,
    pinned_public_key: bytes | None = None,
    kms_client_factory: Callable[[str], Any] | None = None,
) -> Signer:
    """Build the signer configured for ``purpose``. Unknown purpose or backend refuses.

    The ``aws_kms`` backend needs a pinned public key before it signs: either
    ``pinned_public_key`` here or ``public_key_hex`` in its config entry (both
    given must agree). When given for a ``local_file`` entry the local key must
    equal it.
    """
    if not isinstance(purpose, str) or not purpose:
        raise SignerError("purpose must be a non-empty string")
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SignerError(f"the signer config cannot be read: {exc}") from None
    try:
        config = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError:
        raise SignerError("the signer config is not valid JSON") from None
    if not isinstance(config, dict):
        raise SignerError("the signer config must be a JSON object")
    entry = config.get(purpose)
    if entry is None:
        raise SignerError(f"no signer is configured for purpose {purpose!r}")
    if not isinstance(entry, dict):
        raise SignerError(f"the signer entry for {purpose!r} must be an object")
    backend = entry.get("backend")
    if backend not in BACKENDS:
        raise SignerError(f"unknown signer backend {backend!r} for purpose {purpose!r}")
    expected = _LOCAL_FILE_KEYS if backend == "local_file" else _AWS_KMS_KEYS
    optional = frozenset() if backend == "local_file" else _AWS_KMS_OPTIONAL_KEYS
    if not expected <= set(entry) <= expected | optional:
        raise SignerError(
            f"the {backend} signer entry for {purpose!r} must have exactly {sorted(expected)}"
            + (f" plus optional {sorted(optional)}" if optional else "")
        )
    if pinned_public_key is not None and (
        not isinstance(pinned_public_key, (bytes, bytearray))
        or len(pinned_public_key) != PUBLIC_KEY_BYTES
    ):
        raise SignerError("pinned_public_key must be 32 raw bytes")
    if "public_key_hex" in entry:
        configured = entry["public_key_hex"]
        if (
            not isinstance(configured, str)
            or len(configured) != 2 * PUBLIC_KEY_BYTES
            or any(c not in "0123456789abcdef" for c in configured)
        ):
            raise SignerError(f"public_key_hex for purpose {purpose!r} must be 64 lowercase hex")
        if pinned_public_key is not None and bytes(pinned_public_key) != bytes.fromhex(configured):
            raise SignerError("the configured public_key_hex does not equal the pinned public key")
        pinned_public_key = bytes.fromhex(configured)
    for name in expected:
        if not isinstance(entry[name], str) or not entry[name]:
            raise SignerError(f"{name} for purpose {purpose!r} must be a non-empty string")
    signer: Signer
    if backend == "local_file":
        signer = LocalFileSigner(entry["key_id"], entry["path"], entry["passphrase_path"])
        if pinned_public_key is not None and signer.public_key_raw() != bytes(pinned_public_key):
            raise SignerError("the local key does not equal the pinned public key")
    else:
        signer = AwsKmsSigner(
            entry["key_id"],
            entry["key_arn"],
            entry["region"],
            pinned_public_key=pinned_public_key,
            client_factory=kms_client_factory,
        )
    return signer


__all__ = [
    "AwsKmsSigner",
    "BACKENDS",
    "LocalFileSigner",
    "MAX_MESSAGE_BYTES",
    "Signer",
    "SignerError",
    "signer_from_config",
]
