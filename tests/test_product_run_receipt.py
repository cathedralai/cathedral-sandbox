"""Tests for cathedral_product_run_receipt_v1 (validator-aligned execution+evidence)."""

from datetime import datetime, timedelta, timezone

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.product_run_receipt import (
    PRODUCT_RUN_RECEIPT_POLICY_DIGEST,
    PRODUCT_RUN_RECEIPT_SCHEMA,
    PRODUCT_RUN_RECEIPT_TRUSTED_KEYS_SCHEMA,
    ProductRunReceiptError,
    build_affline_evidence,
    build_affline_execution,
    build_agent_evidence,
    build_agent_execution,
    build_cvm_evidence,
    build_cvm_execution,
    build_ditto_evidence,
    build_ditto_execution,
    build_reliquary_evidence,
    build_reliquary_execution,
    canonical_json,
    issue_product_run_receipt,
    sha256_hex,
    verify_product_run_receipt,
)

UTC = timezone.utc
ZERO = "0" * 64


def _trusted_keys(private: Ed25519PrivateKey, key_id: str = "demo-key") -> bytes:
    from cryptography.hazmat.primitives import serialization

    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    now = datetime.now(UTC)
    doc = {
        "schema": PRODUCT_RUN_RECEIPT_TRUSTED_KEYS_SCHEMA,
        "keys": {
            key_id: {
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "status": "active",
                "valid_from": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "valid_until": (now + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            }
        },
    }
    return canonical_json(doc)


def _ts(offset_s: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_affline_product_receipt_requires_full_rerun_action():
    private = Ed25519PrivateKey.generate()
    keys = _trusted_keys(private)
    evidence = build_affline_evidence()
    assert evidence["required_validator_action"] == "full_rerun"
    raw = issue_product_run_receipt(
        product="affline",
        surface="v1_sandboxes",
        run_id="harbor-rerun-required",
        request_bytes=b"req",
        result_bytes=b"res",
        outcome="succeeded",
        private_key=private,
        signing_key_id="demo-key",
        execution=build_affline_execution(
            sandbox_id="sbx_1",
            image="alpine:3.20",
            create_request_sha256=ZERO,
            exec_cmd_sha256=ZERO,
            exec_stdout_sha256=ZERO,
            exec_stderr_sha256=ZERO,
        ),
        evidence=evidence,
    )
    verified = verify_product_run_receipt(raw, trusted_keys=keys)
    assert verified.validator_view["required_validator_action"] == "full_rerun"
    assert verified.document["evidence"]["skip_rerun_authorized"] is False


def test_rejects_accept_receipt_on_product_receipt():
    private = Ed25519PrivateKey.generate()
    evidence = build_affline_evidence()
    evidence["required_validator_action"] = "accept_receipt"
    with pytest.raises(ProductRunReceiptError) as exc:
        issue_product_run_receipt(
            product="affline",
            surface="v1_sandboxes",
            run_id="bad-accept",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=build_affline_execution(
                sandbox_id="sbx_1",
                image="alpine:3.20",
                create_request_sha256=ZERO,
                exec_cmd_sha256=ZERO,
                exec_stdout_sha256=ZERO,
                exec_stderr_sha256=ZERO,
            ),
            evidence=evidence,
        )
    assert exc.value.category == "binding"


def test_affline_harbor_only_without_claim_digests():
    private = Ed25519PrivateKey.generate()
    keys = _trusted_keys(private)
    raw = issue_product_run_receipt(
        product="affline",
        surface="v1_sandboxes",
        run_id="harbor-trial-1",
        request_bytes=b'{"image":"alpine"}',
        result_bytes=b'{"exec_exit":0}',
        outcome="succeeded",
        private_key=private,
        signing_key_id="demo-key",
        note="Harbor-only; no Affine claim linked",
        execution=build_affline_execution(
            sandbox_id="sbx_affline_1",
            image="alpine:3.20",
            create_request_sha256=ZERO,
            exec_cmd_sha256=ZERO,
            exec_stdout_sha256=ZERO,
            exec_stderr_sha256=ZERO,
            verify_outcome="not_applicable",
        ),
        evidence=build_affline_evidence(),
    )
    verified = verify_product_run_receipt(raw, trusted_keys=keys)
    assert verified.validator_view["verify_outcome"] == "not_applicable"
    assert verified.validator_view["related_claim_schema"] is None
    assert verified.validator_view["skip_rerun_authorized"] is False
    assert verified.validator_view["required_validator_action"] == "full_rerun"


def test_rejects_affine_digests_without_claim():
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ProductRunReceiptError) as exc:
        issue_product_run_receipt(
            product="affline",
            surface="v1_sandboxes",
            run_id="bad-claim",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=build_affline_execution(
                sandbox_id="sbx_1",
                image="alpine:3.20",
                create_request_sha256=ZERO,
                exec_cmd_sha256=ZERO,
                exec_stdout_sha256=ZERO,
                exec_stderr_sha256=ZERO,
                affine_verify_code_sha256=ZERO,
                affine_verify_inputs_sha256=ZERO,
                miner_payload_sha256=ZERO,
                verify_result_sha256=ZERO,
                verify_outcome="passed",
            ),
            evidence=build_affline_evidence(),
        )
    assert exc.value.category == "binding"


def test_affline_with_linked_claim_digests():
    private = Ed25519PrivateKey.generate()
    keys = _trusted_keys(private)
    claim_id = "a" * 64
    raw = issue_product_run_receipt(
        product="affline",
        surface="v1_sandboxes",
        run_id="harbor-with-claim",
        request_bytes=b"req",
        result_bytes=b"res",
        outcome="succeeded",
        private_key=private,
        signing_key_id="demo-key",
        execution=build_affline_execution(
            sandbox_id="sbx_1",
            image="alpine:3.20",
            create_request_sha256=ZERO,
            exec_cmd_sha256=ZERO,
            exec_stdout_sha256=ZERO,
            exec_stderr_sha256=ZERO,
            affine_verify_code_sha256=ZERO,
            affine_verify_inputs_sha256=ZERO,
            miner_payload_sha256=ZERO,
            verify_result_sha256=ZERO,
            verify_outcome="passed",
        ),
        evidence=build_affline_evidence(
            affine_claim_id=claim_id,
            affine_claim_sha256=ZERO,
            claim_attestation_class="binding_dev",
            execution_profile_id="affine-cvm-reference-v1",
        ),
    )
    verified = verify_product_run_receipt(raw, trusted_keys=keys)
    assert verified.validator_view["affine_claim_id"] == claim_id
    assert verified.document["evidence"]["skip_rerun_authorized"] is False


def test_rejects_tee_claimed_true():
    private = Ed25519PrivateKey.generate()
    keys = _trusted_keys(private)
    execution = build_affline_execution(
        sandbox_id="sbx_bad",
        image="alpine:3.20",
        create_request_sha256=ZERO,
        exec_cmd_sha256=ZERO,
        exec_stdout_sha256=ZERO,
        exec_stderr_sha256=ZERO,
    )
    evidence = build_affline_evidence()
    issued = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    body = {
        "schema": PRODUCT_RUN_RECEIPT_SCHEMA,
        "issued_at": issued,
        "policy_digest": PRODUCT_RUN_RECEIPT_POLICY_DIGEST,
        "signing_key_id": "demo-key",
        "receipt_status": "ready",
        "product": "affline",
        "surface": "v1_sandboxes",
        "tee_claimed": True,
        "attestation_class": "none",
        "run_id": "bad",
        "request_sha256": sha256_hex(b"a"),
        "result_sha256": sha256_hex(b"b"),
        "outcome": "succeeded",
        "note": "",
        "execution": execution,
        "evidence": evidence,
    }
    receipt_id = sha256_hex(canonical_json(body))
    unsigned = {**body, "receipt_id": receipt_id}
    signature = private.sign(canonical_json(unsigned))
    signed = {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }
    with pytest.raises(ProductRunReceiptError) as exc:
        verify_product_run_receipt(canonical_json(signed), trusted_keys=keys)
    assert exc.value.category == "binding"


def test_ditto_ready_requires_expects_isolation():
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ProductRunReceiptError):
        issue_product_run_receipt(
            product="ditto",
            surface="v1_sandboxes",
            run_id="ditto-bad-tier",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=build_ditto_execution(
                sandbox_id="sbx_ditto",
                image="python:3.12-alpine",
                create_request_sha256=ZERO,
                score_cmd_sha256=ZERO,
                score_result_sha256=ZERO,
                score_stdout_sha256=ZERO,
                score_stderr_sha256=ZERO,
            ),
            evidence=build_ditto_evidence(tier="ditto-ready", expects_isolation="0"),
        )


def test_reliquary_parallel_matches_load_row():
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ProductRunReceiptError) as exc:
        issue_product_run_receipt(
            product="reliquary",
            surface="offline_pack",
            run_id="reliquary-bad-parallel",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=build_reliquary_execution(
                allocation_id="reliquary-offline-1",
                runtime_id="runsc-ref",
                image_id="sha256:" + ZERO,
                source_revision="0be0cda0c9a73dc3f08e3af2a07dda9407635aa7",
                summary_sha256=ZERO,
                load_row="32_of_50",
                parallel=50,
            ),
            evidence=build_reliquary_evidence(),
        )
    assert "parallel" in str(exc.value)


def test_reliquary_health_digest_binding():
    private = Ed25519PrivateKey.generate()
    keys = _trusted_keys(private)
    execution = build_reliquary_execution(
        allocation_id="reliquary-offline-1",
        runtime_id="runsc-ref",
        image_id="sha256:" + ZERO,
        source_revision="0be0cda0c9a73dc3f08e3af2a07dda9407635aa7",
        summary_sha256=ZERO,
        sandbox_platform="reference",
        load_row="32_of_50",
    )
    assert execution["load"]["parallel"] == 32
    assert execution["health"]["api"]["max_inflight"] == 50
    assert execution["health"]["pool"]["worker_reap_failures_total"] == 0
    raw = issue_product_run_receipt(
        product="reliquary",
        surface="offline_pack",
        run_id="reliquary-ok",
        request_bytes=b"req",
        result_bytes=b"res",
        outcome="succeeded",
        private_key=private,
        signing_key_id="demo-key",
        execution=execution,
        evidence=build_reliquary_evidence(),
    )
    verified = verify_product_run_receipt(raw, trusted_keys=keys)
    assert verified.validator_view["load_parallel"] == 32
    assert verified.validator_view["max_inflight"] == 50


def test_agent_requires_increasing_timestamps():
    private = Ed25519PrivateKey.generate()
    same = _ts(0)
    with pytest.raises(ProductRunReceiptError) as exc:
        issue_product_run_receipt(
            product="agent",
            surface="v1_sandboxes",
            run_id="agent-bad-ts",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=build_agent_execution(
                sandbox_id="sbx_agent",
                image="agent-ide:1",
                create_request_sha256=ZERO,
                lifecycle=[
                    {"state": "running", "at": same},
                    {"state": "frozen", "at": same},
                ],
            ),
            evidence=build_agent_evidence(),
        )
    assert exc.value.category == "binding"


def test_all_products_happy_path():
    private = Ed25519PrivateKey.generate()
    keys = _trusted_keys(private)
    now_unix = int(datetime.now(UTC).timestamp())
    specs = [
        (
            "ditto",
            "v1_sandboxes",
            build_ditto_execution(
                sandbox_id="sbx_ditto_1",
                image="python:3.12-alpine",
                create_request_sha256=ZERO,
                score_cmd_sha256=ZERO,
                score_result_sha256=ZERO,
                score_stdout_sha256=ZERO,
                score_stderr_sha256=ZERO,
                max_running=4,
                cap_trial_exercised=True,
                rejected_429=True,
                retry_after_seconds=5,
            ),
            build_ditto_evidence(tier="ditto-ready", expects_isolation="1"),
        ),
        (
            "reliquary",
            "offline_pack",
            build_reliquary_execution(
                allocation_id="reliquary-offline-1",
                runtime_id="runsc-reference-offline",
                image_id="sha256:" + ZERO,
                source_revision="0be0cda0c9a73dc3f08e3af2a07dda9407635aa7",
                summary_sha256=ZERO,
                sandbox_platform="reference",
            ),
            build_reliquary_evidence(tier="reliquary-workers-offline"),
        ),
        (
            "agent",
            "v1_sandboxes",
            build_agent_execution(
                sandbox_id="sbx_agent_1",
                image="agent-ide:1",
                create_request_sha256=ZERO,
                lifecycle=[
                    {"state": "running", "at": _ts(0)},
                    {"state": "frozen", "at": _ts(1)},
                    {"state": "running", "at": _ts(2)},
                ],
                terminals=[
                    {
                        "id": "term-1",
                        "cols": 120,
                        "rows": 40,
                        "exited": True,
                        "exit_code": 0,
                        "output_sha256": ZERO,
                        "started_at": _ts(0),
                        "connected": True,
                    }
                ],
                access_tickets=[
                    {"ttl_seconds": 60, "issued_at": _ts(0), "consumed": True}
                ],
            ),
            build_agent_evidence(),
        ),
        (
            "cvm",
            "cvm_lifecycle",
            build_cvm_execution(
                cvm_id="cvm_ref_1",
                state="running",
                nonce="deadbeef",
                issued_at_unix=now_unix,
                lifecycle=[
                    {"state": "pending", "at": _ts(0)},
                    {"state": "attesting", "at": _ts(1)},
                    {"state": "running", "at": _ts(2)},
                ],
            ),
            build_cvm_evidence(),
        ),
    ]
    for product, surface, execution, evidence in specs:
        raw = issue_product_run_receipt(
            product=product,
            surface=surface,
            run_id=f"{product}-run",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=execution,
            evidence=evidence,
        )
        verified = verify_product_run_receipt(raw, trusted_keys=keys)
        assert verified.product == product
        assert verified.tee_claimed is False


def test_cvm_running_requires_nonzero_attest_time():
    private = Ed25519PrivateKey.generate()
    with pytest.raises(ProductRunReceiptError) as exc:
        issue_product_run_receipt(
            product="cvm",
            surface="cvm_lifecycle",
            run_id="cvm-bad",
            request_bytes=b"req",
            result_bytes=b"res",
            outcome="succeeded",
            private_key=private,
            signing_key_id="demo-key",
            execution=build_cvm_execution(
                cvm_id="cvm_bad",
                state="running",
                nonce="n1",
                issued_at_unix=0,
                last_attest_at=0,
                lifecycle=[{"state": "running", "at": _ts(0)}],
            ),
            evidence=build_cvm_evidence(),
        )
    assert exc.value.category == "binding"
