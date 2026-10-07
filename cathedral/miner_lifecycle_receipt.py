"""Cathedral miner lifecycle receipt v1 — control-plane signed teardown proof.

Implements the draft in ``docs/MINER_TEARDOWN_EVIDENCE.md``. Verifies and
builds receipts; does **not** activate subnet rewards or relax the supply
boundary. Miner self-report is rejected by construction (signing key must be
a Cathedral-pinned control-plane key, never the miner hotkey alone).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.policy_registry import canonical_json

SCHEMA = "cathedral_miner_lifecycle_receipt_v1"
ALLOWED_ACTIONS = frozenset({"reclaim", "delete", "relaunch_observed_absent"})
ALLOWED_OBSERVATION_CLASSES = frozenset(
    {
        "central_guest_gone",
        "operator_host_reclaim",
        "seed_analog_runsc_absent",
    }
)
# Evidence classes that must never authorize PROVEN_ABSENT by themselves.
FORBIDDEN_SOLE_EVIDENCE = frozenset(
    {
        "miner_self_report",
        "sat_proof",
        "enrollment",
        "uptime",
    }
)


class MinerLifecycleReceiptError(ValueError):
    pass


@dataclass(frozen=True)
class VerifiedMinerLifecycleReceipt:
    provider_hotkey: str
    slot_id: str
    attempt_id: str
    assignment_digest: str
    action: str
    observed_at: str
    observation_class: str
    observation_digest: str
    signing_key_id: str
    body: Mapping[str, Any]


def _require_str(body: Mapping[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise MinerLifecycleReceiptError(f"missing_or_invalid:{key}")
    return value


def build_unsigned_receipt(
    *,
    provider_hotkey: str,
    slot_id: str,
    attempt_id: str,
    assignment_digest: str,
    action: str,
    observed_at: datetime | str,
    observation_class: str,
    observation_payload: Mapping[str, Any],
    signing_key_id: str,
    guest_boot_id: str | None = None,
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    if action not in ALLOWED_ACTIONS:
        raise MinerLifecycleReceiptError(f"invalid_action:{action}")
    if observation_class not in ALLOWED_OBSERVATION_CLASSES:
        raise MinerLifecycleReceiptError(
            f"invalid_observation_class:{observation_class}"
        )
    if isinstance(observed_at, datetime):
        stamp = observed_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    else:
        stamp = observed_at
    observation_digest = (
        "sha256:"
        + hashlib.sha256(canonical_json(dict(observation_payload))).hexdigest()
    )
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "provider_hotkey": provider_hotkey,
        "slot_id": slot_id,
        "attempt_id": attempt_id,
        "assignment_digest": assignment_digest,
        "action": action,
        "observed_at": stamp,
        "observation_class": observation_class,
        "observation_digest": observation_digest,
        "signing_key_id": signing_key_id,
        "evidence_refs": list(evidence_refs or []),
    }
    if guest_boot_id:
        body["guest_boot_id"] = guest_boot_id
    return body


def sign_receipt(
    unsigned: Mapping[str, Any],
    *,
    private_key: bytes,
) -> dict[str, Any]:
    if unsigned.get("schema") != SCHEMA:
        raise MinerLifecycleReceiptError("wrong_schema")
    payload = {k: v for k, v in unsigned.items() if k != "signature"}
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        canonical_json(payload)
    )
    body = dict(payload)
    body["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return body


def verify_receipt(
    receipt: Mapping[str, Any],
    *,
    public_keys_by_id: Mapping[str, bytes],
) -> VerifiedMinerLifecycleReceipt:
    if receipt.get("schema") != SCHEMA:
        raise MinerLifecycleReceiptError("wrong_schema")
    action = _require_str(receipt, "action")
    if action not in ALLOWED_ACTIONS:
        raise MinerLifecycleReceiptError(f"invalid_action:{action}")
    observation_class = _require_str(receipt, "observation_class")
    if observation_class not in ALLOWED_OBSERVATION_CLASSES:
        raise MinerLifecycleReceiptError(
            f"invalid_observation_class:{observation_class}"
        )
    for ref in receipt.get("evidence_refs") or []:
        if not isinstance(ref, str):
            raise MinerLifecycleReceiptError("invalid_evidence_ref")
        if any(bad in ref for bad in FORBIDDEN_SOLE_EVIDENCE):
            # Refs may mention context; sole-evidence ban is documented for
            # producers. Reject explicit self-report markers.
            if ref.startswith("miner_self_report:"):
                raise MinerLifecycleReceiptError("miner_self_report_rejected")
    signature = receipt.get("signature")
    if not isinstance(signature, dict):
        raise MinerLifecycleReceiptError("missing_signature")
    if signature.get("algorithm") != "ed25519":
        raise MinerLifecycleReceiptError("bad_signature_algorithm")
    key_id = _require_str(receipt, "signing_key_id")
    public_key = public_keys_by_id.get(key_id)
    if public_key is None:
        raise MinerLifecycleReceiptError("unknown_signing_key")
    try:
        sig_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise MinerLifecycleReceiptError("bad_signature_encoding") from exc
    unsigned = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            sig_bytes, canonical_json(unsigned)
        )
    except (InvalidSignature, ValueError) as exc:
        raise MinerLifecycleReceiptError("bad_signature") from exc
    return VerifiedMinerLifecycleReceipt(
        provider_hotkey=_require_str(receipt, "provider_hotkey"),
        slot_id=_require_str(receipt, "slot_id"),
        attempt_id=_require_str(receipt, "attempt_id"),
        assignment_digest=_require_str(receipt, "assignment_digest"),
        action=action,
        observed_at=_require_str(receipt, "observed_at"),
        observation_class=observation_class,
        observation_digest=_require_str(receipt, "observation_digest"),
        signing_key_id=key_id,
        body=dict(receipt),
    )


def receipt_json_bytes(receipt: Mapping[str, Any]) -> bytes:
    return canonical_json(dict(receipt))
