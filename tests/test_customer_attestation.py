"""Receipt signatures are real. Vendor success stubs test composition only."""
import base64
import hashlib
import json
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import cathedral.customer_attestation as attestation
from cathedral.customer_receipt import (
    CUSTOMER_ATTESTATION_POLICY_DIGEST, CUSTOMER_ATTESTATION_RECEIPT_SCHEMA,
    CustomerReceiptError, parse_customer_receipt_trusted_keys_json, verify_customer_receipt,
)
from test_customer_receipt import _sign, _trusted_keys_bytes, _unsigned_cpu_document

FIXTURES = Path(__file__).parent / "fixtures"
REPORT = (FIXTURES / "snp" / "attestation-report.bin").read_bytes()
EXPECTED = (FIXTURES / "snp" / "request-data.bin").read_bytes()


def b64(value):
    return base64.b64encode(value).decode("ascii")


def receipt_document(report=REPORT):
    document = _unsigned_cpu_document()
    document.update(schema=CUSTOMER_ATTESTATION_RECEIPT_SCHEMA,
        policy_digest=CUSTOMER_ATTESTATION_POLICY_DIGEST, execution_class="snp_cpu",
        profile_id="attest.snp.v1", cpu_tee="amd_sev_snp", intel_verified=None,
        hardware_binding={"box_id": "box-fixture-snp", "quote_sha256": hashlib.sha256(report).hexdigest(),
                          "report_data_hex": EXPECTED.hex()})
    return document


def bundle(report=REPORT, document=None):
    return {"schema": attestation.BUNDLE_SCHEMA,
        "receipt_base64": b64(_sign(document or receipt_document(report))),
        "evidence": {"kind": "sev_snp", "quote_base64": b64(report),
            "collateral": {name + "_base64": b64((FIXTURES / "attestation" / (name + ".der")).read_bytes())
                           for name in ("vcek", "ask", "ark")}}}


def policy_bytes():
    parsed = attestation.parse_snp_report(REPORT)
    return json.dumps({"allowed_measurements": [parsed.measurement], "min_snp_tcb": parsed.tcb.reported}).encode()


def verify(value, **kwargs):
    return attestation.verify_attestation_bundle(json.dumps(value).encode(),
        parse_customer_receipt_trusted_keys_json(_trusted_keys_bytes()),
        attestation.parse_attestation_policy(policy_bytes()), **kwargs)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*a, **k):
        pytest.fail("offline bundle attempted network access")
    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)


def test_real_fixture_signed_receipt_passes_but_hardware_policy_fails():
    signed = _sign(receipt_document())
    assert verify_customer_receipt(signed, parse_customer_receipt_trusted_keys_json(_trusted_keys_bytes())).receipt_bytes == signed
    with pytest.raises(CustomerReceiptError, match="unchanged admission policy") as error:
        verify(bundle())
    assert error.value.category == "policy"


@pytest.mark.parametrize("mutation,category", [
    (lambda b: b["evidence"].update(quote_base64=b64(REPORT[:-1])), "binding"),
    (lambda b: b["evidence"].update(kind="tdx"), "binding"),
    (lambda b: b["evidence"]["collateral"].pop("ark_base64"), "vendor_chain"),
    (lambda b: b["evidence"]["collateral"].update(vcek_base64="broken"), "vendor_chain"),
    (lambda b: b.update(trusted_keys={}), "schema"),
])
def test_bundle_failures_remain_categorized(mutation, category):
    value = bundle()
    mutation(value)
    with pytest.raises(CustomerReceiptError) as error:
        verify(value)
    assert error.value.category == category


def test_wrong_box_and_receipt_tampering_are_rejected():
    with pytest.raises(CustomerReceiptError) as error:
        verify(bundle(), expected_box_id="box-other")
    assert error.value.category == "binding"
    value = bundle()
    receipt = json.loads(base64.b64decode(value["receipt_base64"]))
    receipt["hardware_binding"]["box_id"] = "box-other"
    from cathedral.customer_receipt import canonical_customer_receipt_json
    value["receipt_base64"] = b64(canonical_customer_receipt_json(receipt))
    with pytest.raises(CustomerReceiptError) as error:
        verify(value)
    assert error.value.category == "signature"


def test_legacy_receipt_cannot_claim_independent_verification():
    value = bundle()
    value["receipt_base64"] = b64(_sign(_unsigned_cpu_document()))
    with pytest.raises(CustomerReceiptError) as error:
        verify(value)
    assert error.value.category == "binding"


def test_missing_trusted_key_and_stale_receipt_fail_before_hardware():
    with pytest.raises(CustomerReceiptError) as error:
        attestation.verify_attestation_bundle(json.dumps(bundle()).encode(), {}, attestation.parse_attestation_policy(policy_bytes()))
    assert error.value.category == "key"
    with pytest.raises(CustomerReceiptError) as error:
        verify(bundle(), max_age_seconds=1, now=datetime(2026, 9, 9, tzinfo=UTC))
    assert error.value.category == "stale"


def test_success_boolean_requires_chain_verified_true(monkeypatch):
    # Policy-normalized bytes are not vendor-signed. Only composition is tested
    # here, and this test is never offered as real SNP signature evidence.
    report = bytearray(REPORT)
    struct.pack_into("<I", report, 0x30, 0)
    struct.pack_into("<Q", report, 0x40, 0x25)
    value = bundle(bytes(report))
    measurement = attestation.parse_snp_report(REPORT).measurement
    for verdict in (None, SimpleNamespace(chain_verified=False)):
        monkeypatch.setattr(attestation, "verify_snp_offline", lambda *a, _v=verdict, **k: _v)
        with pytest.raises(CustomerReceiptError) as error:
            verify(value)
        assert error.value.category == "vendor_chain"
    monkeypatch.setattr(attestation, "verify_snp_offline", lambda *a, **k: SimpleNamespace(chain_verified=True, measurement=measurement))
    result = verify(value)
    assert result["evidence_independently_verified"] is True
    assert result["verification_scope"] == "cathedral_receipt_and_vendor_hardware"
    assert result["collateral_current"] is False


@pytest.mark.parametrize("data", [b"null", b"[]", b'{"schema":1,"schema":2}', b'{"bad":NaN}'])
def test_malformed_bundle_fails_closed(data):
    with pytest.raises(CustomerReceiptError) as error:
        attestation.verify_attestation_bundle(data, {}, attestation.parse_attestation_policy(policy_bytes()))
    assert error.value.category == "schema"


def test_tdx_vendor_failure_does_not_flip_the_boolean(monkeypatch):
    document = _unsigned_cpu_document()
    document.update(schema=CUSTOMER_ATTESTATION_RECEIPT_SCHEMA, policy_digest=CUSTOMER_ATTESTATION_POLICY_DIGEST,
                    hardware_binding=receipt_document()["hardware_binding"])
    value = bundle(document=document)
    value["evidence"].update(kind="tdx", collateral=b64(b"{}"))
    monkeypatch.setattr(attestation, "verify_tdx_offline", lambda *a, **k: {})
    with pytest.raises(CustomerReceiptError) as error:
        verify(value, tdx_executable="/test/verifier", tdx_implementation_digest="sha256:" + "0" * 64)
    assert error.value.category == "vendor_chain"


def test_hardware_receipts_preserve_existing_task_policy_validation():
    document = receipt_document()
    document["task_policy"] = {"egress": "restricted", "egress_allowlist": [], "tls_pinning": True}
    with pytest.raises(CustomerReceiptError) as error:
        verify(bundle(document=document))
    assert error.value.category == "schema"
    document["task_policy"]["egress_allowlist"] = ["api.example.com"]
    with pytest.raises(CustomerReceiptError) as error:
        verify(bundle(document=document))
    assert error.value.category == "policy"  # task policy passed, real hardware remains inadmissible
