"""Authority grants bind exact customer allocations; signatures are not admission."""

import base64
import hashlib
import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral_delivery import DeliveryError, canonical_bytes, parse_json
from cathedral_delivery.grants import (
    SCHEMA,
    check_grant,
    node_request_digest,
    receipt_id_for_window,
    segment_for_window,
    sign_grant,
    verify_grant,
)


def body():
    request = {"operation_id": "attempt-1", "ttl_seconds": 60,
               "slot_id": "slot-0001", "slot_generation": "generation-1"}
    return {
        "schema": SCHEMA, "grant_id": "grant-1", "admission_id": "admit-1",
        "boot_id": "b5072b38-1cf4-4de2-b1fe-51b007002083", "project_id": "project-1",
        "job_id": "job-1", "attempt_id": "attempt-1", "sandbox_id": "sandbox-1",
        "miner_hotkey": "miner-1", "hardware_id": "11" * 32,
        "executor_key_id": "key-1", "executor_spki_sha256": "22" * 32,
        "control_plane_key_id": "cp-1", "evidence_sha256": "33" * 32,
        "measurement": "tdx-measurement-sha256:" + "44" * 32,
        "admission_nonce": "55" * 32, "admitted_at": 100,
        "admission_expires_at": 1000, "issued_at": 110, "expires_at": 170,
        "slot_id": "slot-0001", "slot_generation": "generation-1",
        "request_sha256": node_request_digest(request), "vcpu": 1, "memory_gib": 4,
        "window_seconds": 60,
    }


def test_signature_and_cli_are_not_admission():
    key = Ed25519PrivateKey.generate()
    envelope = sign_grant(body(), control_plane_key=key)
    assert verify_grant(envelope, control_plane_key=key.public_key(), now=120) == body()
    result = subprocess.run(
        [sys.executable, "-m", "cathedral.cli", "executor", "check-grant"],
        input=json.dumps({"grant": envelope, "now": 120, "control_plane_public_key":
                          key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}),
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "status": "SIGNATURE_VERIFIED", "grant_id": "grant-1", "eligible": False,
        "admission": "not_checked",
    }


@pytest.mark.parametrize("field,value", [
    ("extra", 1), ("schema", "other"), ("expires_at", 1001), ("expires_at", 110),
    ("admitted_at", 111), ("admission_expires_at", 200000), ("issued_at", True),
    ("admission_nonce", "00" * 32), ("executor_spki_sha256", "00" * 32),
    ("hardware_id", "00" * 32), ("vcpu", 2), ("memory_gib", 8),
    ("slot_id", "slot-0011"), ("slot_generation", "../bad"), ("boot_id", "not-a-boot"),
    ("window_seconds", 0), ("window_seconds", 86401), ("project_id", "secret\nvalue"),
    ("request_sha256", "x" * 64), ("job_id", None),
])
def test_bad_grants_reject(field, value):
    grant = body()
    grant[field] = value
    with pytest.raises(DeliveryError):
        check_grant(grant)


def test_missing_fields_wrong_signatures_and_deadlines():
    key = Ed25519PrivateKey.generate()
    grant = body()
    del grant["job_id"]
    with pytest.raises(DeliveryError):
        check_grant(grant)
    envelope = sign_grant(body(), control_plane_key=key)
    for now in (109, 170, True):
        with pytest.raises(DeliveryError):
            verify_grant(envelope, control_plane_key=key.public_key(), now=now)
    with pytest.raises(DeliveryError):
        verify_grant(envelope, control_plane_key=Ed25519PrivateKey.generate().public_key(), now=120)
    envelope["body"]["sandbox_id"] = "other"
    with pytest.raises(DeliveryError):
        verify_grant(envelope, control_plane_key=key.public_key(), now=120)
    envelope = sign_grant(body(), control_plane_key=key)
    envelope["signature"] = base64.b64encode(b"x" * 64).decode()
    with pytest.raises(DeliveryError):
        verify_grant(envelope, control_plane_key=key.public_key(), now=120)
    with pytest.raises(DeliveryError):
        parse_json(b'{"grant":{},"grant":{}}')


def test_request_digest_is_exact_and_validates_slot_contract():
    request = {"operation_id": "attempt-1", "ttl_seconds": 60,
               "slot_id": "slot-0001", "slot_generation": "generation-1"}
    assert node_request_digest(request) == hashlib.sha256(canonical_bytes(request)).hexdigest()
    for change in ({"ttl_seconds": 3601}, {"extra": 1}, {"slot_id": "slot-0011"},
                   {"ttl_seconds": True}, {"operation_id": "../bad"}):
        with pytest.raises(DeliveryError):
            node_request_digest({**request, **change})


def test_window_segments_and_ids_do_not_overlap_or_replay():
    assert segment_for_window(119, 181, 60, 60) == (119, 120)
    assert segment_for_window(119, 181, 120, 60) == (120, 180)
    assert segment_for_window(119, 181, 180, 60) == (180, 181)
    assert segment_for_window(119, 181, 240, 60) is None
    for args in ((119, 181, 61, 60), (181, 119, 60, 60), (1, 2, 0, 0)):
        with pytest.raises(DeliveryError):
            segment_for_window(*args)
    first = receipt_id_for_window("admit-1", "attempt-1", 60)
    assert first == receipt_id_for_window("admit-1", "attempt-1", 60)
    assert first != receipt_id_for_window("admit-1", "attempt-1", 120)
    assert first != receipt_id_for_window("admit-2", "attempt-1", 60)
