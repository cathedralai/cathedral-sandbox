"""Receipt signatures are real. Vendor success stubs test composition only."""

import base64
import hashlib
import json
import socket
import struct
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import cathedral.customer_attestation as attestation
from cathedral.customer_receipt import (
    CUSTOMER_ATTESTATION_POLICY_DIGEST,
    CUSTOMER_ATTESTATION_RECEIPT_SCHEMA,
    SNP_MACHINE_ID_PREFIX,
    CustomerReceiptError,
    canonical_customer_receipt_json,
    customer_attestation_report_data,
    parse_customer_receipt_trusted_keys_json,
    verify_customer_receipt,
)
from cathedral.verify.snp import REPORT_DATA_OFFSET, REPORT_DATA_SIZE
from test_customer_receipt import ISSUED_AT, _sign, _trusted_keys_bytes, _unsigned_cpu_document

FIXTURES = Path(__file__).parent / "fixtures"
REPORT = (FIXTURES / "snp" / "attestation-report.bin").read_bytes()
BOX = "box-fixture-snp"
RECEIPT_ID = "6de10d88-e554-4b68-a334-377e81744ee4"
OTHER_RECEIPT_ID = "0b6f3f55-2f55-4d1e-9d8e-2f7b8b2b9c11"
NONCE_SHA256 = "1" * 64
TDX_MACHINE = "tdx-platform-sha256:" + "ab" * 32
NOW = ISSUED_AT + timedelta(minutes=5)


def b64(value):
    return base64.b64encode(value).decode("ascii")


def snp_machine(report=REPORT):
    return SNP_MACHINE_ID_PREFIX + attestation.parse_snp_report(report).chip_id


def bound_report(receipt_id=RECEIPT_ID, box_id=BOX, nonce_sha256=NONCE_SHA256):
    """Policy-normalized fixture whose REPORT_DATA commits to one receipt.

    Rewriting fields breaks the AMD signature, so these reports only ever meet
    a stubbed vendor verifier. They test composition, never vendor proof.
    """
    report = bytearray(REPORT)
    struct.pack_into("<I", report, 0x30, 0)
    struct.pack_into("<Q", report, 0x40, 0x25)
    report[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_SIZE] = (
        customer_attestation_report_data(receipt_id, box_id, nonce_sha256)
    )
    return bytes(report)


def receipt_document(report=REPORT, *, receipt_id=RECEIPT_ID, box_id=BOX, machine_id=None):
    document = _unsigned_cpu_document()
    document.update(
        receipt_id=receipt_id,
        schema=CUSTOMER_ATTESTATION_RECEIPT_SCHEMA,
        policy_digest=CUSTOMER_ATTESTATION_POLICY_DIGEST,
        execution_class="snp_cpu",
        profile_id="attest.snp.v1",
        cpu_tee="amd_sev_snp",
        intel_verified=None,
        hardware_binding={
            "box_id": box_id,
            "machine_id": machine_id or snp_machine(report),
            "quote_sha256": hashlib.sha256(report).hexdigest(),
            "report_data_hex": customer_attestation_report_data(
                receipt_id, box_id, document["nonce_sha256"]
            ).hex(),
        },
    )
    return document


def tdx_receipt_document(quote, *, machine_id=TDX_MACHINE):
    document = _unsigned_cpu_document()
    document.update(
        schema=CUSTOMER_ATTESTATION_RECEIPT_SCHEMA,
        policy_digest=CUSTOMER_ATTESTATION_POLICY_DIGEST,
        hardware_binding={
            "box_id": BOX,
            "machine_id": machine_id,
            "quote_sha256": hashlib.sha256(quote).hexdigest(),
            "report_data_hex": customer_attestation_report_data(
                document["receipt_id"], BOX, document["nonce_sha256"]
            ).hex(),
        },
    )
    return document


def bundle(report=REPORT, document=None):
    return {
        "schema": attestation.BUNDLE_SCHEMA,
        "receipt_base64": b64(_sign(document or receipt_document(report))),
        "evidence": {
            "kind": "sev_snp",
            "quote_base64": b64(report),
            "collateral": {
                name + "_base64": b64((FIXTURES / "attestation" / (name + ".der")).read_bytes())
                for name in ("vcek", "ask", "ark")
            },
        },
    }


def tdx_bundle(quote=b"tdx quote bytes", document=None):
    value = bundle(document=document or tdx_receipt_document(quote))
    value["evidence"].update(kind="tdx", quote_base64=b64(quote), collateral=b64(b"{}"))
    return value


def policy_bytes():
    parsed = attestation.parse_snp_report(REPORT)
    return json.dumps(
        {"allowed_measurements": [parsed.measurement], "min_snp_tcb": parsed.tcb.reported}
    ).encode()


def keys():
    return parse_customer_receipt_trusted_keys_json(_trusted_keys_bytes())


def verify(value, **kwargs):
    arguments = {"expected_box_id": BOX, "max_age_seconds": 3600, "now": NOW, **kwargs}
    return attestation.verify_attestation_bundle(
        json.dumps(value).encode(),
        keys(),
        attestation.parse_attestation_policy(policy_bytes()),
        **arguments,
    )


def rejection(value, **kwargs):
    with pytest.raises(CustomerReceiptError) as error:
        verify(value, **kwargs)
    return error.value.category


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*a, **k):
        pytest.fail("offline bundle attempted network access")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)


@pytest.fixture
def vendor_accepts(monkeypatch):
    """Stubbed AMD success. Composition only, never vendor proof."""
    calls = []

    def accept(quote, expected, policy, **kwargs):
        calls.append(expected)
        parsed = attestation.parse_snp_report(quote)
        return SimpleNamespace(chain_verified=True, measurement=parsed.measurement)

    monkeypatch.setattr(attestation, "verify_snp_offline", accept)
    return calls


def test_real_fixture_report_cannot_commit_to_any_receipt():
    signed = _sign(receipt_document())
    assert verify_customer_receipt(signed, keys()).receipt_bytes == signed
    # The historical report predates the receipt binding, so its REPORT_DATA
    # cannot equal the receipt commitment (it also fails VMPL/reserved policy).
    assert rejection(bundle()) == "binding"


def test_checked_in_real_fixture_bundle_is_rejected():
    data = (FIXTURES / "attestation" / "snp-real-rejected-bundle.json").read_bytes()
    trusted = parse_customer_receipt_trusted_keys_json(
        (FIXTURES / "attestation" / "fixture-trusted-keys.json").read_bytes()
    )
    policy = attestation.parse_attestation_policy(
        (FIXTURES / "attestation" / "fixture-policy.json").read_bytes()
    )
    with pytest.raises(CustomerReceiptError) as error:
        attestation.verify_attestation_bundle(
            data, trusted, policy, expected_box_id=BOX, max_age_seconds=3600, now=NOW
        )
    assert error.value.category == "binding"


def test_bound_snp_evidence_composes_with_vendor_success(vendor_accepts):
    report = bound_report()
    result = verify(bundle(report))
    assert result["evidence_independently_verified"] is True
    assert result["verification_scope"] == "cathedral_receipt_and_vendor_hardware"
    assert result["collateral_current"] is False
    assert result["box_id"] == BOX
    assert result["machine_id"] == snp_machine(report)
    assert vendor_accepts == [customer_attestation_report_data(RECEIPT_ID, BOX, NONCE_SHA256)]


def test_one_quote_bound_to_two_receipts_fails_for_the_second(vendor_accepts):
    report = bound_report()
    assert verify(bundle(report))["receipt_id"] == RECEIPT_ID

    # Second receipt reuses the first receipt's signed binding verbatim.
    copied = receipt_document(report, receipt_id=OTHER_RECEIPT_ID)
    copied["hardware_binding"] = receipt_document(report)["hardware_binding"]
    assert rejection(bundle(report, copied)) == "binding"

    # Second receipt is internally consistent, but the quote commits to the first.
    consistent = receipt_document(report, receipt_id=OTHER_RECEIPT_ID)
    assert rejection(bundle(report, consistent)) == "binding"
    assert len(vendor_accepts) == 1


def test_snp_report_data_must_commit_to_the_receipt(vendor_accepts):
    # The quote digest is signed, but REPORT_DATA commits to another nonce.
    report = bound_report(nonce_sha256="4" * 64)
    assert rejection(bundle(report)) == "binding"
    assert vendor_accepts == []


def test_snp_chip_identity_must_match_the_signed_machine(vendor_accepts):
    report = bound_report()
    other_chip = SNP_MACHINE_ID_PREFIX + "cd" * 64
    assert rejection(bundle(report, receipt_document(report, machine_id=other_chip))) == "binding"
    assert vendor_accepts == []


def test_snp_evidence_cannot_satisfy_a_tdx_receipt(vendor_accepts):
    report = bound_report()
    document = tdx_receipt_document(report, machine_id=snp_machine(report))
    assert verify_customer_receipt(_sign(document), keys()).document["execution_class"] == "tdx_cpu"
    assert rejection(bundle(report, document)) == "binding"
    assert vendor_accepts == []


@pytest.mark.parametrize(
    "mutation,category",
    [
        (lambda b: b["evidence"].update(quote_base64=b64(REPORT[:-1])), "binding"),
        (lambda b: b["evidence"].update(kind="tdx"), "binding"),
        (lambda b: b["evidence"]["collateral"].pop("ark_base64"), "vendor_chain"),
        (lambda b: b["evidence"]["collateral"].update(vcek_base64="broken"), "vendor_chain"),
        (lambda b: b.update(trusted_keys={}), "schema"),
    ],
)
def test_bundle_failures_remain_categorized(mutation, category):
    value = bundle(bound_report())
    mutation(value)
    assert rejection(value) == category


def test_wrong_box_and_receipt_tampering_are_rejected():
    assert rejection(bundle(bound_report()), expected_box_id="box-other") == "binding"
    value = bundle(bound_report())
    receipt = json.loads(base64.b64decode(value["receipt_base64"]))
    receipt["hardware_binding"]["box_id"] = "box-other"
    value["receipt_base64"] = b64(canonical_customer_receipt_json(receipt))
    assert rejection(value) == "signature"


def test_box_and_age_bounds_are_required_keywords():
    data = json.dumps(bundle(bound_report())).encode()
    policy = attestation.parse_attestation_policy(policy_bytes())
    with pytest.raises(TypeError):
        attestation.verify_attestation_bundle(data, keys(), policy, max_age_seconds=3600)
    with pytest.raises(TypeError):
        attestation.verify_attestation_bundle(data, keys(), policy, expected_box_id=BOX)
    with pytest.raises(TypeError):
        attestation.verify_attestation_bundle(data, keys(), policy, BOX, 3600)
    for box in (None, ""):
        assert rejection(bundle(bound_report()), expected_box_id=box) == "binding"
    for age in (None, 0, -1, True):
        assert rejection(bundle(bound_report()), max_age_seconds=age) == "stale"


def test_legacy_receipt_cannot_claim_independent_verification():
    value = bundle(bound_report())
    value["receipt_base64"] = b64(_sign(_unsigned_cpu_document()))
    assert rejection(value) == "binding"


def test_missing_trusted_key_and_stale_receipt_fail_before_hardware():
    with pytest.raises(CustomerReceiptError) as error:
        attestation.verify_attestation_bundle(
            json.dumps(bundle(bound_report())).encode(),
            {},
            attestation.parse_attestation_policy(policy_bytes()),
            expected_box_id=BOX,
            max_age_seconds=3600,
            now=NOW,
        )
    assert error.value.category == "key"
    assert rejection(bundle(bound_report()), max_age_seconds=1) == "stale"


def test_success_boolean_requires_chain_verified_true(monkeypatch):
    value = bundle(bound_report())
    for verdict in (None, SimpleNamespace(chain_verified=False)):
        monkeypatch.setattr(attestation, "verify_snp_offline", lambda *a, _v=verdict, **k: _v)
        assert rejection(value) == "vendor_chain"


@pytest.mark.parametrize("data", [b"null", b"[]", b'{"schema":1,"schema":2}', b'{"bad":NaN}'])
def test_malformed_bundle_fails_closed(data):
    with pytest.raises(CustomerReceiptError) as error:
        attestation.verify_attestation_bundle(
            data,
            {},
            attestation.parse_attestation_policy(policy_bytes()),
            expected_box_id=BOX,
            max_age_seconds=3600,
        )
    assert error.value.category == "schema"


def _tdx_claims(**changes):
    parsed = attestation.parse_snp_report(REPORT)
    return {
        "measurement": parsed.measurement,
        "stable_platform_id": TDX_MACHINE,
        "collateral_current_reason": "offline replay",
        **changes,
    }


TDX_ARGS = {"tdx_executable": "/test/verifier", "tdx_implementation_digest": "sha256:" + "0" * 64}


def test_tdx_bound_evidence_composes_with_vendor_success(monkeypatch):
    seen = []
    monkeypatch.setattr(
        attestation,
        "verify_tdx_offline",
        lambda quote, expected, *a, **k: seen.append(expected) or _tdx_claims(),
    )
    result = verify(tdx_bundle(), **TDX_ARGS)
    assert result["hardware_kind"] == "tdx"
    assert result["machine_id"] == TDX_MACHINE
    assert seen == [customer_attestation_report_data(RECEIPT_ID, BOX, NONCE_SHA256)]


def test_tdx_vendor_failure_does_not_flip_the_boolean(monkeypatch):
    monkeypatch.setattr(attestation, "verify_tdx_offline", lambda *a, **k: {})
    assert rejection(tdx_bundle(), **TDX_ARGS) == "vendor_chain"


def test_tdx_measurement_outside_local_policy_is_rejected(monkeypatch):
    claims = _tdx_claims(measurement="00" * 48)
    monkeypatch.setattr(attestation, "verify_tdx_offline", lambda *a, **k: claims)
    assert rejection(tdx_bundle(), **TDX_ARGS) == "policy"


@pytest.mark.parametrize("platform", ["tdx-platform-sha256:" + "cd" * 32, None])
def test_tdx_platform_identity_must_match_the_signed_machine(monkeypatch, platform):
    claims = _tdx_claims(stable_platform_id=platform)
    monkeypatch.setattr(attestation, "verify_tdx_offline", lambda *a, **k: claims)
    assert rejection(tdx_bundle(), **TDX_ARGS) == "binding"


def test_hardware_receipts_preserve_existing_task_policy_validation(vendor_accepts):
    report = bound_report()
    document = receipt_document(report)
    document["task_policy"] = {"egress": "restricted", "egress_allowlist": [], "tls_pinning": True}
    assert rejection(bundle(report, document)) == "schema"
    document["task_policy"]["egress_allowlist"] = ["api.example.com"]
    assert verify(bundle(report, document))["ok"] is True


def _binding_variants():
    good = receipt_document(bound_report())["hardware_binding"]
    other = customer_attestation_report_data(OTHER_RECEIPT_ID, BOX, NONCE_SHA256).hex()
    return [
        ("extra field", {**good, "extra": 1}),
        ("missing machine", {k: v for k, v in good.items() if k != "machine_id"}),
        ("bad box", {**good, "box_id": "-box"}),
        ("bad machine", {**good, "machine_id": "chip:" + "ab" * 64}),
        ("short machine", {**good, "machine_id": SNP_MACHINE_ID_PREFIX + "ab" * 32}),
        ("bad quote digest", {**good, "quote_sha256": "Z" * 64}),
        ("uppercase report data", {**good, "report_data_hex": good["report_data_hex"].upper()}),
        ("report data of another receipt", {**good, "report_data_hex": other}),
        ("not an object", "binding"),
    ]


@pytest.mark.parametrize(
    "binding", [value for _, value in _binding_variants()], ids=[n for n, _ in _binding_variants()]
)
def test_signed_hardware_binding_is_validated(binding):
    document = receipt_document(bound_report())
    document["hardware_binding"] = binding
    with pytest.raises(CustomerReceiptError) as error:
        verify_customer_receipt(_sign(document), keys())
    assert error.value.category == "binding"


def test_report_data_commitment_is_unambiguous():
    base = customer_attestation_report_data(RECEIPT_ID, BOX, NONCE_SHA256)
    assert len(base) == 64
    assert base != customer_attestation_report_data(OTHER_RECEIPT_ID, BOX, NONCE_SHA256)
    assert base != customer_attestation_report_data(RECEIPT_ID, "box-other", NONCE_SHA256)
    assert base != customer_attestation_report_data(RECEIPT_ID, BOX, "4" * 64)
