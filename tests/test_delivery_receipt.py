import hashlib
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.delivery import (
    MIN_RETENTION_SECONDS,
    DeliveryError,
    canonical_bytes,
    sign_receipt,
    verify_receipt,
)

NOW = 1_790_640_100


def body():
    return {
        "schema": "cathedral_delivery_receipt_v1",
        "netuid": 94,
        "receipt_id": "receipt-1",
        "attempt_id": "attempt-1",
        "sandbox_id": "sandbox-1",
        "miner_hotkey": "miner-1",
        "admission_nonce": "44" * 32,
        "admitted_at": 1_790_640_000,
        "admission_expires_at": 1_790_643_600,
        "hardware_id": "11" * 32,
        "executor_key_id": "executor-1",
        "control_plane_key_id": "central-1",
        "evidence_sha256": "22" * 32,
        "measurement": "tdx-measurement-sha256:" + "33" * 32,
        "window_start": 1_790_640_000,
        "window_end": 1_790_643_600,
        "started_at": 1_790_640_001,
        "ended_at": 1_790_640_061,
        "vcpu": 1,
        "memory_gib": 4,
        "vcpu_seconds": 60,
        "gib_seconds": 240,
        "issued_at": NOW,
        "retention_until": NOW + MIN_RETENTION_SECONDS,
        "execution_class": "attested",
        "outcome": "completed",
    }


def test_two_signatures_bind_same_body():
    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    receipt = sign_receipt(body(), executor_key=executor, control_plane_key=central)
    verified = verify_receipt(
        receipt, executor_key=executor.public_key(), control_plane_key=central.public_key(), now=NOW
    )
    assert verified.resource_seconds == 300
    assert verified.digest == hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    for field, value in [("vcpu_seconds", 61), ("miner_hotkey", "other"), ("retention_until", NOW)]:
        changed = deepcopy(receipt)
        changed["body"][field] = value
        with pytest.raises(DeliveryError):
            verify_receipt(
                changed,
                executor_key=executor.public_key(),
                control_plane_key=central.public_key(),
                now=NOW,
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("vcpu", True),
        ("memory_gib", 0),
        ("netuid", 39),
        ("ended_at", 1_790_640_000),
        ("vcpu_seconds", 999999),
        ("retention_until", NOW + 1),
    ],
)
def test_malformed_body_never_signed(field, value):
    value_body = body()
    value_body[field] = value
    with pytest.raises(DeliveryError):
        sign_receipt(
            value_body,
            executor_key=Ed25519PrivateKey.generate(),
            control_plane_key=Ed25519PrivateKey.generate(),
        )


def test_wrong_signer_and_expired_retention_rejected():
    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    receipt = sign_receipt(body(), executor_key=executor, control_plane_key=central)
    for key, now in [
        (Ed25519PrivateKey.generate().public_key(), NOW),
        (central.public_key(), NOW + MIN_RETENTION_SECONDS),
    ]:
        with pytest.raises(DeliveryError):
            verify_receipt(
                receipt, executor_key=executor.public_key(), control_plane_key=key, now=now
            )


def test_unattested_and_lost_receipts_are_never_reward_eligible():
    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    for field, value in [("execution_class", "unattested"), ("outcome", "lost")]:
        value_body = body()
        value_body[field] = value
        verified = verify_receipt(
            sign_receipt(value_body, executor_key=executor, control_plane_key=central),
            executor_key=executor.public_key(),
            control_plane_key=central.public_key(),
            now=NOW,
        )
        assert verified.resource_seconds == 0


def test_noncanonical_base64_signature_is_rejected():
    import base64

    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    receipt = sign_receipt(body(), executor_key=executor, control_plane_key=central)
    original = receipt["signatures"]["executor"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    altered = original[:-3] + alphabet[alphabet.index(original[-3]) + 1] + original[-2:]
    assert base64.b64decode(original) == base64.b64decode(altered)
    receipt["signatures"]["executor"] = altered
    with pytest.raises(DeliveryError):
        verify_receipt(
            receipt,
            executor_key=executor.public_key(),
            control_plane_key=central.public_key(),
            now=NOW,
        )


def test_admission_without_quote_or_approved_measurement_refuses(tmp_path):
    from cathedral.delivery import admit_delivery

    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    checked = verify_receipt(
        sign_receipt(body(), executor_key=executor, control_plane_key=central),
        executor_key=executor.public_key(),
        control_plane_key=central.public_key(),
        now=NOW,
    )
    with pytest.raises(DeliveryError):
        admit_delivery(
            checked,
            quote=b"not a quote",
            executor_key=executor.public_key(),
            allowed_measurements=frozenset(),
            verifier_path="/missing",
            verifier_sha256="aa" * 32,
        )


def test_authority_countersigns_only_exact_executor_body():
    from cathedral.delivery import countersign_receipt, sign_executor

    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    value = body()
    signature = sign_executor(value, executor)
    receipt = countersign_receipt(
        value,
        executor_signature=signature,
        executor_key=executor.public_key(),
        control_plane_key=central,
    )
    assert (
        verify_receipt(
            receipt,
            executor_key=executor.public_key(),
            control_plane_key=central.public_key(),
            now=NOW,
        ).resource_seconds
        == 300
    )
    value["sandbox_id"] = "different"
    with pytest.raises(DeliveryError):
        countersign_receipt(
            value,
            executor_signature=signature,
            executor_key=executor.public_key(),
            control_plane_key=central,
        )


def admitted_fixture(tmp_path, monkeypatch):
    """Synthetic quote plus substituted vendor result; never hardware proof."""
    from types import SimpleNamespace

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    import cathedral.verify
    from cathedral.common import ChannelBinding, ChannelBindingType, Tier, report_data_v2
    from cathedral.verify.tdx_quote import parse_tdx_quote
    from tests.tdx_quote_fixtures import synthetic_tdx_quote

    executor, central = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    value = body()
    spki = executor.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, hashlib.sha256(spki).digest())
    quote = synthetic_tdx_quote(
        report_data=report_data_v2(
            bytes.fromhex(value["admission_nonce"]), value["miner_hotkey"], binding
        )
    )
    measurement = parse_tdx_quote(quote).measurement
    value.update(
        measurement=measurement,
        evidence_sha256=hashlib.sha256(quote).hexdigest(),
        hardware_id=hashlib.sha256(
            b"cathedral.capacity.hardware_id.v1\0tdx_platform\0" + b"h" * 32
        ).hexdigest(),
    )
    verifier = tmp_path / "verifier"
    verifier.write_bytes(b"synthetic verifier pin, not executable")
    verifier.chmod(0o600)
    verdict = SimpleNamespace(
        tier=Tier.CC_CPU_TDX,
        verification_status="VERIFIED",
        chain_verified=True,
        debug_enabled=False,
        collateral_current=True,
        platform_identity_kind="stable",
        policy_mode="strict",
        measurement=measurement,
        chip_id="tdx-platform-sha256:" + (b"h" * 32).hex(),
    )
    monkeypatch.setattr(cathedral.verify, "replay_verify_tdx", lambda *a, **k: verdict)
    kwargs = {
        "quote": quote,
        "executor_key": executor.public_key(),
        "allowed_measurements": frozenset([measurement]),
        "verifier_path": str(verifier),
        "verifier_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
    }

    def receipt(changes=None):
        candidate = dict(value)
        candidate.update(changes or {})
        return verify_receipt(
            sign_receipt(candidate, executor_key=executor, control_plane_key=central),
            executor_key=executor.public_key(),
            control_plane_key=central.public_key(),
            now=NOW,
        )

    return receipt, kwargs, verdict


def test_admission_binds_raw_quote_key_nonce_hardware(tmp_path, monkeypatch):
    from cathedral.delivery import admit_delivery

    receipt, kwargs, _verdict = admitted_fixture(tmp_path, monkeypatch)
    admitted = admit_delivery(receipt(), **kwargs)
    assert admitted.receipt.resource_seconds == 300
    for change in (
        {"admission_nonce": "55" * 32},
        {"miner_hotkey": "other"},
        {"hardware_id": "66" * 32},
        {"evidence_sha256": "77" * 32},
    ):
        with pytest.raises(DeliveryError):
            admit_delivery(receipt(change), **kwargs)
    with pytest.raises(DeliveryError):
        admit_delivery(
            receipt(), **dict(kwargs, executor_key=Ed25519PrivateKey.generate().public_key())
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("chain_verified", False),
        ("debug_enabled", True),
        ("collateral_current", False),
        ("platform_identity_kind", "ephemeral"),
        ("policy_mode", "permissive"),
        ("verification_status", "NOT_PROVEN"),
        ("chip_id", "tdx-platform-sha256:" + "00" * 32),
    ],
)
def test_partial_vendor_verdict_cannot_admit(tmp_path, monkeypatch, field, value):
    from cathedral.delivery import admit_delivery

    receipt, kwargs, verdict = admitted_fixture(tmp_path, monkeypatch)
    setattr(verdict, field, value)
    with pytest.raises(DeliveryError):
        admit_delivery(receipt(), **kwargs)
