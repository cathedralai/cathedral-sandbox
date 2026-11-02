"""Miner lifecycle receipt v1 — build/verify; no reward activation."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.miner_lifecycle_receipt import (
    MinerLifecycleReceiptError,
    SCHEMA,
    build_unsigned_receipt,
    sign_receipt,
    verify_receipt,
)


def _keys():
    private = Ed25519PrivateKey.generate()
    priv = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def test_sign_and_verify_round_trip():
    priv, pub = _keys()
    unsigned = build_unsigned_receipt(
        provider_hotkey="5Hotkey",
        slot_id="slot-1",
        attempt_id="attempt-1",
        assignment_digest="sha256:" + "a" * 64,
        action="reclaim",
        observed_at=datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc),
        observation_class="central_guest_gone",
        observation_payload={"method": "central_pool_probe", "absent": True},
        signing_key_id="cp-root-1",
    )
    assert unsigned["schema"] == SCHEMA
    signed = sign_receipt(unsigned, private_key=priv)
    verified = verify_receipt(signed, public_keys_by_id={"cp-root-1": pub})
    assert verified.provider_hotkey == "5Hotkey"
    assert verified.observation_class == "central_guest_gone"


def test_rejects_miner_self_report_marker():
    priv, pub = _keys()
    unsigned = build_unsigned_receipt(
        provider_hotkey="5Hotkey",
        slot_id="slot-1",
        attempt_id="attempt-1",
        assignment_digest="sha256:" + "b" * 64,
        action="delete",
        observed_at="2026-10-07T12:00:00.000000Z",
        observation_class="operator_host_reclaim",
        observation_payload={"ok": True},
        signing_key_id="cp-root-1",
        evidence_refs=["miner_self_report:i-am-gone"],
    )
    signed = sign_receipt(unsigned, private_key=priv)
    with pytest.raises(MinerLifecycleReceiptError, match="miner_self_report"):
        verify_receipt(signed, public_keys_by_id={"cp-root-1": pub})


def test_rejects_bad_observation_class():
    with pytest.raises(MinerLifecycleReceiptError, match="invalid_observation_class"):
        build_unsigned_receipt(
            provider_hotkey="5Hotkey",
            slot_id="s",
            attempt_id="a",
            assignment_digest="sha256:" + "c" * 64,
            action="reclaim",
            observed_at="2026-10-07T12:00:00.000000Z",
            observation_class="miner_said_so",
            observation_payload={},
            signing_key_id="cp-root-1",
        )


def test_rejects_unknown_signing_key():
    priv, _pub = _keys()
    unsigned = build_unsigned_receipt(
        provider_hotkey="5Hotkey",
        slot_id="s",
        attempt_id="a",
        assignment_digest="sha256:" + "d" * 64,
        action="relaunch_observed_absent",
        observed_at="2026-10-07T12:00:00.000000Z",
        observation_class="seed_analog_runsc_absent",
        observation_payload={"runsc": "absent"},
        signing_key_id="cp-root-1",
    )
    signed = sign_receipt(unsigned, private_key=priv)
    with pytest.raises(MinerLifecycleReceiptError, match="unknown_signing_key"):
        verify_receipt(signed, public_keys_by_id={})
