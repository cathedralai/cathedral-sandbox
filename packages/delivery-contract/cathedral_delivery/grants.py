"""Allocation authority contract for the bounded, measured SN94 guest.

This module authenticates allocation intent, not TEE admission or delivered work.
Both the guest and control plane must join it to their protected lifecycle state.
The initial executable offer is ten fixed-image, no-egress 1 CPU / 4 GiB slots.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import uuid
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cathedral_delivery import (
    MAX_BYTES, MAX_UNIX_TIME, DeliveryError, canonical_bytes, parse_json,
)

SCHEMA = "cathedral_executor_allocation_grant_v1"
DOMAIN = b"cathedral.executor-allocation.v1\x00"
_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_HEX = re.compile(r"[0-9a-f]{64}")
_GENERATION = re.compile(r"[A-Za-z0-9_-]{8,80}")
_FIELDS = frozenset({
    "schema", "grant_id", "admission_id", "boot_id", "project_id", "job_id", "attempt_id",
    "sandbox_id", "miner_hotkey", "hardware_id", "executor_key_id", "executor_spki_sha256",
    "control_plane_key_id", "evidence_sha256", "measurement", "admission_nonce", "admitted_at",
    "admission_expires_at", "issued_at", "expires_at", "slot_id", "slot_generation",
    "request_sha256", "vcpu", "memory_gib", "window_seconds",
})


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise DeliveryError(f"invalid {name}")
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise DeliveryError(f"invalid {name}")
    return value


def _slot(slot: object, generation: object) -> None:
    if not isinstance(slot, str) or slot not in {f"slot-{i:04d}" for i in range(1, 11)}:
        raise DeliveryError("invalid slot_id")
    if not isinstance(generation, str) or not _GENERATION.fullmatch(generation):
        raise DeliveryError("invalid slot_generation")


def check_grant(body: object) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != _FIELDS or body["schema"] != SCHEMA:
        raise DeliveryError("executor grant fields differ from v1")
    for field in ("grant_id", "admission_id", "project_id", "job_id", "attempt_id", "sandbox_id",
                  "miner_hotkey", "executor_key_id", "control_plane_key_id"):
        _identifier(body[field], field)
    try:
        if not isinstance(body["boot_id"], str) or str(uuid.UUID(body["boot_id"])) != body["boot_id"]:
            raise ValueError("noncanonical boot")
        if uuid.UUID(body["boot_id"]).int == 0:
            raise ValueError("zero boot")
    except (ValueError, AttributeError) as exc:
        raise DeliveryError("invalid boot_id") from exc
    for field in ("hardware_id", "executor_spki_sha256", "evidence_sha256", "admission_nonce",
                  "request_sha256"):
        if (not isinstance(body[field], str) or not _HEX.fullmatch(body[field])
                or body[field] == "00" * 32):
            raise DeliveryError(f"invalid {field}")
    if not isinstance(body["measurement"], str) or not re.fullmatch(
        r"tdx-measurement-sha256:[0-9a-f]{64}", body["measurement"]
    ):
        raise DeliveryError("invalid measurement")
    for field in ("admitted_at", "admission_expires_at", "issued_at", "expires_at"):
        _integer(body[field], field, 0, MAX_UNIX_TIME)
    if not (body["admitted_at"] <= body["issued_at"] < body["expires_at"]
            <= body["admission_expires_at"]):
        raise DeliveryError("grant exceeds admitted customer allocation interval")
    if not 1 <= body["admission_expires_at"] - body["admitted_at"] <= 48 * 3600:
        raise DeliveryError("admitted lease exceeds 48 hours")
    if type(body["vcpu"]) is not int or body["vcpu"] != 1:
        raise DeliveryError("initial executor offer requires 1 vCPU")
    if type(body["memory_gib"]) is not int or body["memory_gib"] != 4:
        raise DeliveryError("initial executor offer requires 4 GiB")
    if not _GENERATION.fullmatch(body["attempt_id"]):
        raise DeliveryError("invalid node operation_id")
    _slot(body["slot_id"], body["slot_generation"])
    _integer(body["window_seconds"], "window_seconds", 1, 86400)
    return dict(body)


def sign_grant(body: dict[str, Any], *, control_plane_key: Ed25519PrivateKey) -> dict[str, Any]:
    checked = check_grant(body)
    return {"body": checked, "signature": base64.b64encode(
        control_plane_key.sign(DOMAIN + canonical_bytes(checked))
    ).decode("ascii")}


def verify_grant(envelope: object, *, control_plane_key: Ed25519PublicKey,
                 now: int) -> dict[str, Any]:
    _integer(now, "now", 0, MAX_UNIX_TIME)
    if not isinstance(envelope, dict) or set(envelope) != {"body", "signature"}:
        raise DeliveryError("invalid executor grant envelope")
    checked = check_grant(envelope["body"])
    if not checked["issued_at"] <= now < checked["expires_at"]:
        raise DeliveryError("executor grant is not current")
    try:
        raw = base64.b64decode(envelope["signature"], validate=True)
        if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != envelope["signature"]:
            raise DeliveryError("noncanonical grant signature")
        control_plane_key.verify(raw, DOMAIN + canonical_bytes(checked))
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise DeliveryError("executor grant signature rejected") from exc
    return checked


def node_request_digest(body: object) -> str:
    """Hash only the exact existing Node create body; never normalize a retry."""
    if not isinstance(body, dict) or set(body) != {
        "operation_id", "ttl_seconds", "slot_id", "slot_generation"
    }:
        raise DeliveryError("invalid node create fields")
    if not isinstance(body["operation_id"], str) or not _GENERATION.fullmatch(body["operation_id"]):
        raise DeliveryError("invalid operation_id")
    _integer(body["ttl_seconds"], "ttl_seconds", 1, 3600)
    _slot(body["slot_id"], body["slot_generation"])
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def receipt_id_for_window(admission_id: str, attempt_id: str, window_start: int) -> str:
    _identifier(admission_id, "admission_id")
    _identifier(attempt_id, "attempt_id")
    _integer(window_start, "window_start", 0, MAX_UNIX_TIME)
    return "rcpt_" + hashlib.sha256(b"cathedral.delivery-window.v1\x00" + canonical_bytes(
        [admission_id, attempt_id, window_start]
    )).hexdigest()


def segment_for_window(started_at: int, ended_at: int, window_start: int,
                       window_seconds: int) -> tuple[int, int] | None:
    for value, name in ((started_at, "started_at"), (ended_at, "ended_at"),
                        (window_start, "window_start")):
        _integer(value, name, 0, MAX_UNIX_TIME)
    _integer(window_seconds, "window_seconds", 1, 86400)
    if started_at >= ended_at or window_start % window_seconds:
        raise DeliveryError("invalid interval or unaligned accounting window")
    if window_start + window_seconds > MAX_UNIX_TIME:
        raise DeliveryError("accounting window exceeds supported time")
    start, end = max(started_at, window_start), min(ended_at, window_start + window_seconds)
    return (start, end) if start < end else None


def cmd_check(_args: object) -> int:
    """Offline signature check. It can never grant TEE or reward eligibility."""
    try:
        document = parse_json(sys.stdin.buffer.read(MAX_BYTES + 1))
        if set(document) != {"grant", "control_plane_public_key", "now"}:
            raise DeliveryError("invalid CLI input")
        public = document["control_plane_public_key"]
        if not isinstance(public, str) or not _HEX.fullmatch(public):
            raise DeliveryError("invalid authority public key")
        body = verify_grant(document["grant"], now=document["now"],
                            control_plane_key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)))
        print(json.dumps({"status": "SIGNATURE_VERIFIED", "grant_id": body["grant_id"],
                          "eligible": False, "admission": "not_checked"}))
        return 0
    except (DeliveryError, ValueError, TypeError, KeyError):
        print(json.dumps({"code": "invalid_executor_grant", "eligible": False}))
        return 2
