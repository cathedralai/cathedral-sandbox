"""Unit tests for Confidential CVM reference lifecycle (Product C)."""

from __future__ import annotations

import time

import pytest

from cathedral.cvm_lifecycle import AttestationEvidence, CvmLifecycle
from cathedral.sandbox_api import MIN_RUNNING_SANDBOXES


def test_cvm_does_not_redefine_affline_quota() -> None:
    assert MIN_RUNNING_SANDBOXES == 500


def test_create_attest_admit_running() -> None:
    life = CvmLifecycle()
    inst = life.create()
    assert inst.state == "pending"
    life.begin_attest(inst.id)
    ev = CvmLifecycle.mint_reference_evidence(life.get(inst.id).nonce)
    out = life.submit_evidence(inst.id, ev)
    assert out.state == "running"
    doc = out.to_document()
    assert doc["attestation"] is False
    assert doc["attestation_kind"] == "reference"
    report = life.status_report()
    assert report["product"] == "cvm"
    assert report["attestation"] is False
    assert report["attestation_kind"] == "reference"
    assert "Affline" in report["note"]


def test_tdx_quote_rejected_without_verifier() -> None:
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    nonce = life.get(inst.id).nonce
    fake = AttestationEvidence(
        quote_b64="bm90LWEtcmVhbC10ZHgtcXVvdGU=",  # base64 "not-a-real-tdx-quote"
        measurement="m",
        nonce=nonce,
        issued_at=time.time(),
        tee="tdx",
    )
    out = life.submit_evidence(inst.id, fake)
    assert out.state == "rejected"
    assert out.reject_reason == "tee_verification_unavailable"


def test_tdx_invalid_quote_encoding_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_TDX_VERIFY_CMD", "true")
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    nonce = life.get(inst.id).nonce
    bad = AttestationEvidence(
        quote_b64="!!!not-base64!!!",
        measurement="m",
        nonce=nonce,
        issued_at=time.time(),
        tee="tdx",
    )
    out = life.submit_evidence(inst.id, bad)
    assert out.state == "rejected"
    assert out.reject_reason == "invalid_quote_encoding"


def test_fail_closed_nonce_mismatch() -> None:
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    bad = AttestationEvidence(
        quote_b64="ref.deadbeef",
        measurement="m",
        nonce="wrong",
        issued_at=time.time(),
        tee="reference",
    )
    out = life.submit_evidence(inst.id, bad)
    assert out.state == "rejected"
    assert out.reject_reason == "nonce_mismatch"


def test_fail_closed_replay() -> None:
    life = CvmLifecycle()
    a = life.create()
    life.begin_attest(a.id)
    ev = CvmLifecycle.mint_reference_evidence(life.get(a.id).nonce)
    assert life.submit_evidence(a.id, ev).state == "running"
    b = life.create()
    life.begin_attest(b.id)
    # reuse same nonce string from previous evidence
    replay = AttestationEvidence(
        quote_b64="ref.other",
        measurement="m",
        nonce=ev.nonce,
        issued_at=time.time(),
        tee="reference",
    )
    # also mismatch current challenge — expect nonce_mismatch first; force equal nonce
    life.get(b.id).nonce = ev.nonce
    out = life.submit_evidence(b.id, replay)
    assert out.state == "rejected"
    assert out.reject_reason == "nonce_replay"


def test_fail_closed_stale_evidence() -> None:
    life = CvmLifecycle(max_evidence_age_seconds=1.0)
    inst = life.create()
    life.begin_attest(inst.id)
    ev = CvmLifecycle.mint_reference_evidence(life.get(inst.id).nonce)
    stale = AttestationEvidence(
        quote_b64=ev.quote_b64,
        measurement=ev.measurement,
        nonce=ev.nonce,
        issued_at=time.time() - 10,
        tee="reference",
    )
    out = life.submit_evidence(inst.id, stale)
    assert out.state == "rejected"
    assert out.reject_reason == "stale_or_future_evidence"


def test_stop_and_delete() -> None:
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    life.submit_evidence(inst.id, CvmLifecycle.mint_reference_evidence(life.get(inst.id).nonce))
    assert life.stop(inst.id).state == "stopped"
    life.delete(inst.id)
    with pytest.raises(KeyError):
        life.get(inst.id)


def test_invalid_reference_quote_prefix() -> None:
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    nonce = life.get(inst.id).nonce
    bad = AttestationEvidence(
        quote_b64="hw.fake",
        measurement="m",
        nonce=nonce,
        issued_at=time.time(),
        tee="reference",
    )
    assert life.submit_evidence(inst.id, bad).reject_reason == "invalid_reference_quote"
