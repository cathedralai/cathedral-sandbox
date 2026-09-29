"""Delivery metadata signed by an executor and the allocation authority.

Signature validity is not TEE admission. The validator must separately verify
fresh, key-bound vendor evidence and an approved measurement before paying.
Capacity-probe receipts and Standard sandbox usage are not accepted here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "cathedral_delivery_receipt_v1"
MIN_RETENTION_SECONDS = 14 * 24 * 3600
MAX_BYTES = 32 * 1024
MAX_INTERVAL = 24 * 3600
MAX_UNIX_TIME = 253402300799
_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_HEX = re.compile(r"[0-9a-f]{64}")
_FIELDS = frozenset(
    {
        "schema",
        "netuid",
        "receipt_id",
        "attempt_id",
        "sandbox_id",
        "miner_hotkey",
        "hardware_id",
        "executor_key_id",
        "control_plane_key_id",
        "evidence_sha256",
        "measurement",
        "window_start",
        "window_end",
        "started_at",
        "ended_at",
        "vcpu",
        "memory_gib",
        "vcpu_seconds",
        "gib_seconds",
        "issued_at",
        "retention_until",
        "execution_class",
        "outcome",
        "admission_nonce",
        "admitted_at",
        "admission_expires_at",
    }
)
_DOMAIN = b"cathedral.delivery-receipt.v1\x00"


class DeliveryError(ValueError):
    """Invalid receipt, admission or accounting input. No eligibility implied."""


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (ValueError, TypeError, UnicodeError) as exc:
        raise DeliveryError("invalid canonical document") from exc


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeliveryError(f"invalid {name}")
    return value


def check_body(body: object) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != _FIELDS:
        raise DeliveryError("delivery body fields differ from v1")
    if body["schema"] != SCHEMA or type(body["netuid"]) is not int or body["netuid"] != 94:
        raise DeliveryError("delivery receipts are SN94 only")
    for field in (
        "receipt_id",
        "attempt_id",
        "sandbox_id",
        "miner_hotkey",
        "executor_key_id",
        "control_plane_key_id",
    ):
        if not isinstance(body[field], str) or not _ID.fullmatch(body[field]):
            raise DeliveryError(f"invalid {field}")
    for field in ("hardware_id", "evidence_sha256", "admission_nonce"):
        if not isinstance(body[field], str) or not _HEX.fullmatch(body[field]):
            raise DeliveryError(f"invalid {field}")
    if not isinstance(body["measurement"], str) or not re.fullmatch(
        r"tdx-measurement-sha256:[0-9a-f]{64}", body["measurement"]
    ):
        raise DeliveryError("invalid measurement")
    for field in (
        "window_start",
        "window_end",
        "started_at",
        "ended_at",
        "issued_at",
        "retention_until",
        "admitted_at",
        "admission_expires_at",
    ):
        _integer(body[field], field, 0, MAX_UNIX_TIME)
    if not (body["window_start"] <= body["started_at"] < body["ended_at"] <= body["window_end"]):
        raise DeliveryError("delivery interval must be within its accounting window")
    if not 1 <= body["window_end"] - body["window_start"] <= MAX_INTERVAL:
        raise DeliveryError("accounting window exceeds 24 hours")
    if not (
        body["admitted_at"] <= body["started_at"] < body["ended_at"] <= body["admission_expires_at"]
    ):
        raise DeliveryError("delivery is outside admitted lease")
    if not 1 <= body["admission_expires_at"] - body["admitted_at"] <= 48 * 3600:
        raise DeliveryError("admitted lease exceeds 48 hours")
    if body["admission_nonce"] == "00" * 32:
        raise DeliveryError("admission nonce must be fresh and nonzero")
    if body["issued_at"] < body["ended_at"]:
        raise DeliveryError("receipt precedes delivered interval")
    if body["retention_until"] - body["issued_at"] < MIN_RETENTION_SECONDS:
        raise DeliveryError("receipt retention is shorter than 14 days")
    vcpu = _integer(body["vcpu"], "vcpu", 1, 16)
    memory = _integer(body["memory_gib"], "memory_gib", 1, 64)
    seconds = body["ended_at"] - body["started_at"]
    for field, expected in (("vcpu_seconds", vcpu * seconds), ("gib_seconds", memory * seconds)):
        if type(body[field]) is not int or body[field] != expected:
            raise DeliveryError(f"{field} does not match allocation duration")
    if body["execution_class"] not in {"attested", "unattested"}:
        raise DeliveryError("invalid execution class")
    if body["outcome"] not in {"completed", "customer_error", "customer_timeout", "lost"}:
        raise DeliveryError("invalid terminal outcome")
    return dict(body)


@dataclass(frozen=True)
class VerifiedDelivery:
    body: Mapping[str, Any]
    digest: str

    @property
    def resource_seconds(self) -> int:
        if self.body["execution_class"] != "attested" or self.body["outcome"] == "lost":
            return 0
        return self.body["vcpu_seconds"] + self.body["gib_seconds"]


def signing_bytes(body: dict[str, Any]) -> bytes:
    return _DOMAIN + canonical_bytes(check_body(body))


def sign_receipt(
    body: dict[str, Any], *, executor_key: Ed25519PrivateKey, control_plane_key: Ed25519PrivateKey
) -> dict[str, Any]:
    """Used only after both authorities observed the same terminal allocation.

    Key arguments remain in memory. This utility does not claim lifecycle or
    TEE verification and does not write keys, command output, or environment.
    """
    checked = check_body(body)
    message = signing_bytes(checked)
    return {
        "body": checked,
        "signatures": {
            "executor": base64.b64encode(executor_key.sign(message)).decode("ascii"),
            "control_plane": base64.b64encode(control_plane_key.sign(message)).decode("ascii"),
        },
    }


def sign_executor(body: dict[str, Any], key: Ed25519PrivateKey) -> str:
    """Guest-side signature using its quoted Ed25519 TLS private key."""
    return base64.b64encode(key.sign(signing_bytes(body))).decode("ascii")


def countersign_receipt(
    body: dict[str, Any],
    *,
    executor_signature: str,
    executor_key: Ed25519PublicKey,
    control_plane_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Add the allocation authority signature after checking the guest's.

    The caller must first compare the body with its durable allocation and
    admitted key. This helper cannot establish lifecycle facts by itself.
    """
    checked = check_body(body)
    message = signing_bytes(checked)
    try:
        raw = base64.b64decode(executor_signature, validate=True)
        if base64.b64encode(raw).decode("ascii") != executor_signature:
            raise DeliveryError("noncanonical executor signature")
        executor_key.verify(raw, message)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise DeliveryError("executor signature rejected before countersigning") from exc
    return {
        "body": checked,
        "signatures": {
            "executor": executor_signature,
            "control_plane": base64.b64encode(control_plane_key.sign(message)).decode("ascii"),
        },
    }


def verify_receipt(
    receipt: object,
    *,
    executor_key: Ed25519PublicKey,
    control_plane_key: Ed25519PublicKey,
    now: int,
) -> VerifiedDelivery:
    """Verify both signatures and resource arithmetic, not hardware admission."""
    _integer(now, "now", 0, MAX_UNIX_TIME)
    if not isinstance(receipt, dict) or set(receipt) != {"body", "signatures"}:
        raise DeliveryError("invalid delivery envelope")
    body = check_body(receipt["body"])
    signatures = receipt["signatures"]
    if not isinstance(signatures, dict) or set(signatures) != {"executor", "control_plane"}:
        raise DeliveryError("both delivery signatures are required")
    if not body["issued_at"] <= now < body["retention_until"]:
        raise DeliveryError("receipt is from the future or past retention")
    message = signing_bytes(body)
    try:
        for role, key in (("executor", executor_key), ("control_plane", control_plane_key)):
            encoded = signatures[role]
            if not isinstance(encoded, str) or len(encoded) != 88:
                raise DeliveryError("invalid delivery signature encoding")
            signature = base64.b64decode(encoded, validate=True)
            if base64.b64encode(signature).decode("ascii") != encoded:
                raise DeliveryError("noncanonical signature encoding")
            key.verify(signature, message)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise DeliveryError("delivery signature rejected") from exc
    return VerifiedDelivery(
        MappingProxyType(body), hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    )


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_BYTES:
        raise DeliveryError("delivery input exceeds 32 KiB")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique,
            parse_constant=lambda _v: (_ for _ in ()).throw(DeliveryError("invalid JSON number")),
        )
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise DeliveryError("invalid delivery JSON") from exc
    if not isinstance(value, dict):
        raise DeliveryError("delivery input must be an object")
    return value


def cmd_check(_args: object) -> int:
    """Public-key/signature check only; it can never announce eligibility."""
    try:
        document = parse_json(sys.stdin.buffer.read(MAX_BYTES + 1))
        if set(document) != {"receipt", "executor_public_key", "control_plane_public_key"}:
            raise DeliveryError("invalid CLI input")
        keys = [
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(document[name]))
            for name in ("executor_public_key", "control_plane_public_key")
        ]
        result = verify_receipt(
            document["receipt"],
            executor_key=keys[0],
            control_plane_key=keys[1],
            now=int(time.time()),
        )
        print(
            json.dumps(
                {
                    "status": "SIGNATURES_VERIFIED",
                    "receipt_digest": result.digest,
                    "eligible": False,
                    "admission": "not_checked",
                    "retention_until": result.body["retention_until"],
                }
            )
        )
        return 0
    except (DeliveryError, ValueError, TypeError, KeyError):
        print(json.dumps({"code": "invalid_delivery_receipt", "eligible": False}))
        return 2


@dataclass(frozen=True)
class AdmittedDelivery:
    """Receipt and quote checked together. Instances are internal, not wire input."""

    receipt: VerifiedDelivery
    verifier_digest: str
    executor_key_sha256: str


def admit_delivery(
    receipt: VerifiedDelivery,
    *,
    quote: bytes,
    executor_key: Ed25519PublicKey,
    allowed_measurements: frozenset[str],
    verifier_path: str,
    verifier_sha256: str,
) -> AdmittedDelivery:
    """Independently verify the raw TDX quote under a digest-pinned verifier.

    The allocation authority's countersignature attests that admission_nonce
    was its fresh challenge and admitted_at was observed in its lease ledger.
    The quote independently proves that exact nonce, hotkey and signing key.
    No JSON `verified` flag or capacity-probe receipt can skip this check.
    """
    from pathlib import Path
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cathedral.common import (
        ChannelBinding,
        ChannelBindingType,
        Evidence,
        EvidenceKind,
        Policy,
        Tier,
        report_data_v2,
    )
    from cathedral.verify import replay_verify_tdx
    from cathedral.verify.tdx_quote import parse_tdx_quote

    if not isinstance(receipt, VerifiedDelivery) or receipt.resource_seconds <= 0:
        raise DeliveryError("unattested or lost work has no reward admission")
    body = receipt.body
    if (
        not isinstance(allowed_measurements, frozenset)
        or not allowed_measurements
        or body["measurement"] not in allowed_measurements
    ):
        raise DeliveryError("measurement is not approved")
    if not isinstance(quote, bytes) or not 1 <= len(quote) <= 65536:
        raise DeliveryError("invalid TDX quote size")
    if hashlib.sha256(quote).hexdigest() != body["evidence_sha256"]:
        raise DeliveryError("quote differs from signed receipt")
    if not isinstance(verifier_sha256, str) or not _HEX.fullmatch(verifier_sha256):
        raise DeliveryError("verifier needs an immutable sha256 pin")
    path = Path(verifier_path)
    try:
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise DeliveryError("verifier must be an absolute regular file")
        if path.stat().st_mode & 0o022:
            raise DeliveryError("verifier must not be group or world writable")
        if hashlib.sha256(path.read_bytes()).hexdigest() != verifier_sha256:
            raise DeliveryError("verifier digest differs from policy")
        parsed = parse_tdx_quote(quote)
    except (OSError, ValueError) as exc:
        raise DeliveryError("quote or pinned verifier is unavailable") from exc
    if parsed.measurement != body["measurement"]:
        raise DeliveryError("quote measurement differs from receipt")
    spki = executor_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key_digest = hashlib.sha256(spki).digest()
    nonce = bytes.fromhex(body["admission_nonce"])
    evidence = Evidence(
        kind=EvidenceKind.TDX,
        quote=quote,
        nonce=nonce,
        miner_hotkey=body["miner_hotkey"],
        report_data_version=2,
        channel_binding=ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, key_digest),
    )
    if parsed.debug_enabled or parsed.report_data != report_data_v2(
        nonce, body["miner_hotkey"], evidence.channel_binding
    ):
        raise DeliveryError("quote does not bind the admitted nonce and executor key")
    policy = Policy(allowed_measurements=allowed_measurements, tdx_strict=True)
    try:
        verdict = replay_verify_tdx(evidence, nonce, policy, [str(path)], timeout_override=30)
    except Exception as exc:
        raise DeliveryError("vendor verification unavailable") from exc
    if (
        verdict is None
        or verdict.tier is not Tier.CC_CPU_TDX
        or verdict.verification_status != "VERIFIED"
        or verdict.chain_verified is not True
        or verdict.debug_enabled is not False
        or verdict.collateral_current is not True
        or verdict.platform_identity_kind != "stable"
        or verdict.policy_mode != "strict"
        or verdict.measurement != body["measurement"]
        or not verdict.chip_id
    ):
        raise DeliveryError("vendor evidence was not fully verified")
    match = re.fullmatch(r"tdx-platform-sha256:([0-9a-f]{64})", verdict.chip_id)
    if match is None or match.group(1) == "00" * 32:
        raise DeliveryError("verifier has no stable hardware identity")
    # Identical to the capacity-admission contract, including domain separation.
    hardware_id = hashlib.sha256(
        b"cathedral.capacity.hardware_id.v1\x00tdx_platform\x00" + bytes.fromhex(match.group(1))
    ).hexdigest()
    if hardware_id != body["hardware_id"]:
        raise DeliveryError("quote hardware differs from signed receipt")
    return AdmittedDelivery(receipt, verifier_sha256, key_digest.hex())
