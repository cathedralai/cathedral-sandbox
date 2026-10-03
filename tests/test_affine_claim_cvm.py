"""CVM-gated Affine claim issuance — Affline sandboxes cannot mint skip-rerun."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import (
    AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
    AffineClaimError,
    parse_affine_claim_trusted_keys_json,
    verify_affine_claim,
)
from cathedral.affine_claim_cvm import (
    cvm_instance_from_running_document,
    issue_affine_claim_from_cvm,
)
from cathedral.cvm_lifecycle import AttestationEvidence, CvmLifecycle

ISSUED_AT = datetime(2026, 10, 3, 6, 0, tzinfo=UTC)
KEY_ID = "affine-cvm-test-1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
VERIFY_CODE = b"def verify(payload): return payload.startswith(b'AFFINE:')"
VERIFY_INPUTS = b'{"task":"tiny-affine-v1"}'


def _trusted():
    pub = PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return parse_affine_claim_trusted_keys_json(
        json.dumps(
            {
                "schema": AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
                "keys": {
                    KEY_ID: {
                        "algorithm": "ed25519",
                        "public_key_base64": base64.b64encode(pub).decode("ascii"),
                        "status": "active",
                        "valid_from": "2026-01-01T00:00:00.000000Z",
                        "valid_until": "2027-01-01T00:00:00.000000Z",
                    }
                },
            },
            sort_keys=True,
        ).encode("ascii")
    )


def _running_reference_cvm() -> tuple[CvmLifecycle, object]:
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    ev = CvmLifecycle.mint_reference_evidence(life.get(inst.id).nonce)
    out = life.submit_evidence(inst.id, ev)
    assert out.state == "running"
    return life, out


def test_reference_cvm_issues_binding_dev_not_skip_rerun():
    _, cvm = _running_reference_cvm()
    claim = issue_affine_claim_from_cvm(
        cvm=cvm,
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:42",
        issued_at=ISSUED_AT,
    )
    verified = verify_affine_claim(claim, _trusted())
    assert verified.document["attestation_class"] == "binding_dev"
    assert verified.document["execution_profile_id"] == "affine-cvm-reference-v1"
    assert verified.skip_rerun_authorized is False
    assert verified.document["affline_sandbox_tee_claimed"] is False


def test_reference_refused_when_allow_reference_false():
    _, cvm = _running_reference_cvm()
    with pytest.raises(AffineClaimError) as exc:
        issue_affine_claim_from_cvm(
            cvm=cvm,
            private_key=PRIVATE_KEY,
            signing_key_id=KEY_ID,
            verify_code=VERIFY_CODE,
            verify_inputs=VERIFY_INPUTS,
            miner_payload=b"AFFINE:1",
            allow_reference=False,
        )
    assert exc.value.category == "policy"


def test_affline_labeled_cvm_refused():
    _, cvm = _running_reference_cvm()
    cvm.labels["customer"] = "affline"
    with pytest.raises(AffineClaimError) as exc:
        issue_affine_claim_from_cvm(
            cvm=cvm,
            private_key=PRIVATE_KEY,
            signing_key_id=KEY_ID,
            verify_code=VERIFY_CODE,
            verify_inputs=VERIFY_INPUTS,
            miner_payload=b"AFFINE:1",
        )
    assert "Affline" in str(exc.value)


def test_tdx_without_verifier_cannot_issue_skip_rerun(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CATHEDRAL_TDX_VERIFY_CMD", raising=False)
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    nonce = life.get(inst.id).nonce
    # Force a running instance with tdx evidence as if someone bypassed admit —
    # issue path must still re-verify and refuse.
    inst.state = "running"
    inst.evidence = AttestationEvidence(
        quote_b64=base64.b64encode(b"not-real").decode("ascii"),
        measurement="m_tdx",
        nonce=nonce,
        issued_at=__import__("time").time(),
        tee="tdx",
    )
    with pytest.raises(AffineClaimError) as exc:
        issue_affine_claim_from_cvm(
            cvm=inst,
            private_key=PRIVATE_KEY,
            signing_key_id=KEY_ID,
            verify_code=VERIFY_CODE,
            verify_inputs=VERIFY_INPUTS,
            miner_payload=b"AFFINE:9",
            allow_reference=False,
        )
    assert "tee_verification_unavailable" in str(exc.value) or exc.value.category == "policy"


def test_hardware_path_issues_skip_rerun_when_verifier_admits(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "cathedral.cvm_attest.verify_hardware_evidence",
        lambda _evidence: None,
    )
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    nonce = life.get(inst.id).nonce
    inst.state = "running"
    inst.evidence = AttestationEvidence(
        quote_b64=base64.b64encode(b"admitted-quote").decode("ascii"),
        measurement="aabbccdd" * 8,
        nonce=nonce,
        issued_at=__import__("time").time(),
        tee="tdx",
    )
    claim = issue_affine_claim_from_cvm(
        cvm=inst,
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:100",
        issued_at=ISSUED_AT,
        allow_reference=False,
    )
    verified = verify_affine_claim(claim, _trusted())
    assert verified.document["attestation_class"] == "confidential_cpu"
    assert verified.document["execution_profile_id"] == "affine-cvm-tdx-v1"
    assert verified.skip_rerun_authorized is True


def test_failed_verify_outcome_never_skip_rerun(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "cathedral.cvm_attest.verify_hardware_evidence",
        lambda _evidence: None,
    )
    life = CvmLifecycle()
    inst = life.create()
    life.begin_attest(inst.id)
    inst.state = "running"
    inst.evidence = AttestationEvidence(
        quote_b64=base64.b64encode(b"admitted-quote").decode("ascii"),
        measurement="m1",
        nonce=life.get(inst.id).nonce,
        issued_at=__import__("time").time(),
        tee="snp",
    )
    claim = issue_affine_claim_from_cvm(
        cvm=inst,
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"BAD:1",
        issued_at=ISSUED_AT,
    )
    verified = verify_affine_claim(claim, _trusted())
    assert verified.document["verify_outcome"] == "failed"
    assert verified.skip_rerun_authorized is False


def test_cvm_instance_from_running_document_roundtrip():
    _, cvm = _running_reference_cvm()
    rebuilt = cvm_instance_from_running_document(cvm.to_document())
    claim = issue_affine_claim_from_cvm(
        cvm=rebuilt,
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:7",
        issued_at=ISSUED_AT,
    )
    assert verify_affine_claim(claim, _trusted()).document["attestation_class"] == "binding_dev"


def test_cli_issue_from_cvm_reference(tmp_path: Path, capsys):
    from cathedral.cli import main as cli_main

    _, cvm = _running_reference_cvm()
    cvm_path = tmp_path / "cvm.json"
    code_path = tmp_path / "verify.py"
    inputs_path = tmp_path / "inputs.json"
    payload_path = tmp_path / "payload.bin"
    key_path = tmp_path / "seed.key"
    out_path = tmp_path / "claim.json"
    cvm_path.write_text(json.dumps(cvm.to_document()), encoding="utf-8")
    code_path.write_bytes(VERIFY_CODE)
    inputs_path.write_bytes(VERIFY_INPUTS)
    payload_path.write_bytes(b"AFFINE:3")
    key_path.write_bytes(bytes(range(32)))

    rc = cli_main(
        [
            "affine-claim",
            "issue-from-cvm",
            "--cvm-document",
            str(cvm_path),
            "--verify-code",
            str(code_path),
            "--verify-inputs",
            str(inputs_path),
            "--miner-payload",
            str(payload_path),
            "--signing-key-file",
            str(key_path),
            "--signing-key-id",
            KEY_ID,
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["issued"] is True
    assert out["skip_rerun_authorized"] is False
    assert out_path.is_file()
    verified = verify_affine_claim(out_path.read_bytes(), _trusted())
    assert verified.skip_rerun_authorized is False
