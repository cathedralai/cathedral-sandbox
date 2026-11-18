"""cathedral.signer: local encrypted PEM and mocked AWS KMS Ed25519 backends.

Every key here is a throwaway generated in the test.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.signer import (
    MAX_MESSAGE_BYTES,
    AwsKmsSigner,
    LocalFileSigner,
    Signer,
    SignerError,
    signer_from_config,
)

PASSPHRASE = b"throwaway-test-passphrase"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _write(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    path.chmod(mode)
    return path


@pytest.fixture
def local_key(tmp_path: Path) -> tuple[Ed25519PrivateKey, Path, Path]:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSPHRASE),
    )
    return key, _write(tmp_path / "k.pem", pem), _write(tmp_path / "k.pass", PASSPHRASE + b"\n")


def test_local_signer_signs_pure_ed25519(local_key) -> None:
    key, pem, passphrase = local_key
    signer = LocalFileSigner("test-key-1", pem, passphrase)
    assert isinstance(signer, Signer)
    assert signer.key_id == "test-key-1"
    assert signer.public_key_raw() == _raw(key)
    message = b"canonical bytes"
    signature = signer.sign(message)
    assert len(signature) == 64
    key.public_key().verify(signature, message)
    assert "PRIVATE" not in repr(signer) and PASSPHRASE.decode() not in repr(signer)


def test_local_signer_refuses_unencrypted_pem(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = _write(tmp_path / "plain.pem", pem)
    passphrase = _write(tmp_path / "p", PASSPHRASE)
    with pytest.raises(SignerError, match="not encrypted"):
        LocalFileSigner("k", path, passphrase)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_local_signer_refuses_loose_key_mode(local_key, mode: int) -> None:
    _, pem, passphrase = local_key
    pem.chmod(mode)
    with pytest.raises(SignerError, match="group or world"):
        LocalFileSigner("k", pem, passphrase)


def test_local_signer_refuses_loose_passphrase_mode(local_key) -> None:
    _, pem, passphrase = local_key
    passphrase.chmod(0o644)
    with pytest.raises(SignerError, match="passphrase file is group or world"):
        LocalFileSigner("k", pem, passphrase)


def test_local_signer_refuses_wrong_owner(local_key, monkeypatch) -> None:
    _, pem, passphrase = local_key
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(pem).st_uid + 1)
    with pytest.raises(SignerError, match="not owned by the running user"):
        LocalFileSigner("k", pem, passphrase)


def test_local_signer_refuses_symlink(local_key, tmp_path: Path) -> None:
    _, pem, passphrase = local_key
    link = tmp_path / "link.pem"
    link.symlink_to(pem)
    with pytest.raises(SignerError, match="symlink"):
        LocalFileSigner("k", link, passphrase)


def test_local_signer_refuses_wrong_passphrase(local_key) -> None:
    _, pem, passphrase = local_key
    passphrase.write_bytes(b"wrong")
    with pytest.raises(SignerError, match="could not be decrypted"):
        LocalFileSigner("k", pem, passphrase)


def test_local_signer_refuses_empty_passphrase(local_key) -> None:
    _, pem, passphrase = local_key
    passphrase.write_bytes(b"\n")
    with pytest.raises(SignerError, match="empty"):
        LocalFileSigner("k", pem, passphrase)


def test_local_signer_refuses_non_ed25519(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASSPHRASE),
    )
    with pytest.raises(SignerError, match="not Ed25519"):
        LocalFileSigner("k", _write(tmp_path / "ec.pem", pem), _write(tmp_path / "p", PASSPHRASE))


def test_local_signer_message_limit(local_key) -> None:
    key, pem, passphrase = local_key
    signer = LocalFileSigner("k", pem, passphrase)
    key.public_key().verify(signer.sign(b"x" * MAX_MESSAGE_BYTES), b"x" * MAX_MESSAGE_BYTES)
    with pytest.raises(SignerError, match="4096"):
        signer.sign(b"x" * (MAX_MESSAGE_BYTES + 1))


def test_local_signer_error_never_contains_key_material(local_key) -> None:
    _, pem, passphrase = local_key
    pem.chmod(0o644)
    with pytest.raises(SignerError) as raised:
        LocalFileSigner("k", pem, passphrase)
    text = str(raised.value)
    assert "PRIVATE KEY" not in text and PASSPHRASE.decode() not in text


class FakeKms:
    """Stands in for a boto3 KMS client backed by a throwaway local key."""

    def __init__(self, key: Ed25519PrivateKey, *, spec: str = "ECC_NIST_EDWARDS25519") -> None:
        self.key = key
        self.spec = spec
        self.calls: list[tuple[str, dict]] = []
        self.signature_override: bytes | None = None

    def GetPublicKey(self, **kwargs):  # noqa: N802 - boto3 method name
        self.calls.append(("GetPublicKey", kwargs))
        return {
            "KeySpec": self.spec,
            "KeyUsage": "SIGN_VERIFY",
            "PublicKey": SPKI_PREFIX + _raw(self.key),
        }

    def Sign(self, **kwargs):  # noqa: N802 - boto3 method name
        self.calls.append(("Sign", kwargs))
        if self.signature_override is not None:
            return {"Signature": self.signature_override}
        return {"Signature": self.key.sign(kwargs["Message"])}


ARN = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000"


def test_kms_signer_signs_with_raw_ed25519_and_checks_pin() -> None:
    key = Ed25519PrivateKey.generate()
    fake = FakeKms(key)
    regions: list[str] = []

    def factory(region: str) -> FakeKms:
        regions.append(region)
        return fake

    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", pinned_public_key=_raw(key), client_factory=factory)
    assert isinstance(signer, Signer)
    assert fake.calls == []  # lazy
    signature = signer.sign(b"msg")
    key.public_key().verify(signature, b"msg")
    assert regions == ["us-east-1"]
    assert [name for name, _ in fake.calls] == ["GetPublicKey", "Sign"]
    sign_args = fake.calls[1][1]
    assert sign_args == {
        "KeyId": ARN,
        "Message": b"msg",
        "MessageType": "RAW",
        "SigningAlgorithm": "ED25519_SHA_512",
    }
    signer.sign(b"again")
    assert [name for name, _ in fake.calls].count("GetPublicKey") == 1


def test_kms_signer_refuses_public_key_mismatch_before_signing() -> None:
    fake = FakeKms(Ed25519PrivateKey.generate())
    other = _raw(Ed25519PrivateKey.generate())
    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", pinned_public_key=other, client_factory=lambda _: fake)
    with pytest.raises(SignerError, match="pinned"):
        signer.sign(b"msg")
    assert all(name != "Sign" for name, _ in fake.calls)


def test_kms_signer_refuses_without_pin() -> None:
    fake = FakeKms(Ed25519PrivateKey.generate())
    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", client_factory=lambda _: fake)
    with pytest.raises(SignerError, match="pinned public key"):
        signer.sign(b"msg")
    assert fake.calls == []


def test_kms_signer_refuses_wrong_key_spec() -> None:
    key = Ed25519PrivateKey.generate()
    fake = FakeKms(key, spec="ECC_NIST_P256")
    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", pinned_public_key=_raw(key), client_factory=lambda _: fake)
    with pytest.raises(SignerError, match="ECC_NIST_EDWARDS25519"):
        signer.sign(b"msg")


def test_kms_signer_refuses_bad_signature_from_kms() -> None:
    key = Ed25519PrivateKey.generate()
    fake = FakeKms(key)
    fake.signature_override = bytes(64)
    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", pinned_public_key=_raw(key), client_factory=lambda _: fake)
    with pytest.raises(SignerError, match="does not verify"):
        signer.sign(b"msg")


def test_kms_signer_message_limit_before_any_call() -> None:
    key = Ed25519PrivateKey.generate()
    fake = FakeKms(key)
    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", pinned_public_key=_raw(key), client_factory=lambda _: fake)
    with pytest.raises(SignerError, match="4096"):
        signer.sign(b"x" * (MAX_MESSAGE_BYTES + 1))
    assert fake.calls == []


def test_kms_signer_imports_boto3_lazily(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def no_boto3(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_boto3)
    key = Ed25519PrivateKey.generate()
    signer = AwsKmsSigner("kms-1", ARN, "us-east-1", pinned_public_key=_raw(key))
    with pytest.raises(SignerError, match="boto3"):
        signer.sign(b"msg")


def _config(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "signers.json"
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    path.chmod(0o600)
    return path


def test_signer_from_config_local_file(tmp_path: Path, local_key) -> None:
    key, pem, passphrase = local_key
    config = _config(
        tmp_path,
        {
            "sealed_hotels": {
                "backend": "local_file",
                "key_id": "sealed-hotels-test-1",
                "path": str(pem),
                "passphrase_path": str(passphrase),
            }
        },
    )
    signer = signer_from_config(config, "sealed_hotels")
    assert isinstance(signer, LocalFileSigner)
    assert signer.key_id == "sealed-hotels-test-1"
    key.public_key().verify(signer.sign(b"m"), b"m")
    assert signer_from_config(config, "sealed_hotels", pinned_public_key=_raw(key)).key_id
    with pytest.raises(SignerError, match="pinned"):
        signer_from_config(
            config, "sealed_hotels", pinned_public_key=_raw(Ed25519PrivateKey.generate())
        )


def test_signer_from_config_aws_kms(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    fake = FakeKms(key)
    entry = {"backend": "aws_kms", "key_id": "sealed-hotels-kms-1", "key_arn": ARN, "region": "eu-west-1"}
    config = _config(tmp_path, {"sealed_hotels": entry})
    signer = signer_from_config(
        config, "sealed_hotels", pinned_public_key=_raw(key), kms_client_factory=lambda _: fake
    )
    assert isinstance(signer, AwsKmsSigner)
    key.public_key().verify(signer.sign(b"m"), b"m")

    pinned_in_config = _config(tmp_path, {"sealed_hotels": {**entry, "public_key_hex": _raw(key).hex()}})
    signer = signer_from_config(pinned_in_config, "sealed_hotels", kms_client_factory=lambda _: fake)
    key.public_key().verify(signer.sign(b"m"), b"m")
    with pytest.raises(SignerError, match="does not equal"):
        signer_from_config(
            pinned_in_config,
            "sealed_hotels",
            pinned_public_key=_raw(Ed25519PrivateKey.generate()),
            kms_client_factory=lambda _: fake,
        )


@pytest.mark.parametrize(
    "document, purpose, match",
    [
        ({"sealed_hotels": {"backend": "local_file"}}, "miner_canary", "no signer"),
        ({"sealed_hotels": {"backend": "gpg", "key_id": "k"}}, "sealed_hotels", "unknown signer backend"),
        ({"sealed_hotels": {"backend": "local_file", "key_id": "k", "path": "/x"}}, "sealed_hotels", "exactly"),
        (
            {"sealed_hotels": {"backend": "aws_kms", "key_id": "k", "key_arn": ARN, "region": "r", "extra": 1}},
            "sealed_hotels",
            "exactly",
        ),
        (
            {"sealed_hotels": {"backend": "aws_kms", "key_id": "k", "key_arn": ARN, "region": "r", "public_key_hex": "AB"}},
            "sealed_hotels",
            "64 lowercase hex",
        ),
        (
            {"sealed_hotels": {"backend": "aws_kms", "key_id": "", "key_arn": ARN, "region": "r"}},
            "sealed_hotels",
            "non-empty",
        ),
        ({"sealed_hotels": []}, "sealed_hotels", "must be an object"),
        ([], "sealed_hotels", "JSON object"),
        ('{"a": 1, "a": 2}', "a", "duplicate"),
        ("{not json", "sealed_hotels", "not valid JSON"),
    ],
)
def test_signer_from_config_refuses(tmp_path: Path, document, purpose: str, match: str) -> None:
    with pytest.raises(SignerError, match=match):
        signer_from_config(_config(tmp_path, document), purpose)


def test_signer_from_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SignerError, match="cannot be read"):
        signer_from_config(tmp_path / "absent.json", "sealed_hotels")


def test_signature_from_one_key_does_not_verify_under_another(local_key) -> None:
    _, pem, passphrase = local_key
    signature = LocalFileSigner("k", pem, passphrase).sign(b"m")
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(_raw(Ed25519PrivateKey.generate())).verify(signature, b"m")
