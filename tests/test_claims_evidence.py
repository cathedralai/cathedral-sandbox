"""Claims evidence pack — unit tests (no Claims team, no live hotel)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.claims_evidence import (
    CLAIMS_EVIDENCE_POLICY_DIGEST,
    CLAIMS_EVIDENCE_SCHEMA,
    CLAIMS_EVIDENCE_TRUSTED_KEYS_SCHEMA,
    CLAIMS_MANIFEST_SCHEMA,
    ClaimsEvidenceError,
    build_claims_manifest,
    canonical_claims_json,
    digest_claims_artifacts,
    issue_claims_evidence,
    parse_claims_evidence_trusted_keys_json,
    tiny_claims_agent_output,
    verify_claims_evidence,
    write_claims_pack,
)
from cathedral.cli import main as cli_main

ISSUED_AT = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
KEY_ID = "claims-evidence-test-1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

SOURCE_PDF = b"%PDF-1.4 fixture paper bytes"
SOURCE_PAYLOAD = b'{"schema":"agent_v1_source_payload_v1","spans":[{"span_id":"s1","text":"hi"}]}'
IMAGE_REF = b"sha256:fixture-image"
COMMIT_REF = b"41573a43589f96ce27746e24426c3f025134ecae"
POLICY = b'{"stage":"shared_reference_prep","egress":"none"}'


def _public_b64(key: Ed25519PrivateKey = PRIVATE_KEY) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _trusted_keys_bytes(private_key: Ed25519PrivateKey = PRIVATE_KEY) -> bytes:
    return json.dumps(
        {
            "schema": CLAIMS_EVIDENCE_TRUSTED_KEYS_SCHEMA,
            "keys": {
                KEY_ID: {
                    "algorithm": "ed25519",
                    "public_key_base64": _public_b64(private_key),
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00.000000Z",
                    "valid_until": "2027-01-01T00:00:00.000000Z",
                }
            },
        },
        indent=2,
        sort_keys=True,
    ).encode("ascii")


def _digests(agent_output: bytes) -> dict[str, str]:
    return digest_claims_artifacts(
        source_pdf=SOURCE_PDF,
        source_payload=SOURCE_PAYLOAD,
        agent_output=agent_output,
        image_digest_ref=IMAGE_REF,
        workload_commit_ref=COMMIT_REF,
        execution_policy=POLICY,
    )


def _manifest(digests: dict[str, str], **over):
    values = dict(
        netuid=111,
        network="finney",
        batch_id="batch-2026-10-01",
        run_id="run-1",
        task_id="task-1",
        artifact_id="artifact-1",
        uid=42,
        hotkey="5FixtureMinerHotkey0000000000000001",
        paper_id="rietveld-2013",
        source_pdf_sha256=digests["source_pdf_sha256"],
        source_payload_hash=digests["source_payload_hash"],
        image_digest_sha256=digests["image_digest_sha256"],
        workload_commit_sha256=digests["workload_commit_sha256"],
        execution_policy_sha256=digests["execution_policy_sha256"],
        cathedral={
            "assignment_id": "assign-1",
            "operation_id": "op-1",
            "attempt_id": "attempt-1",
            "stage_id": "shared_reference_prep",
        },
    )
    values.update(over)
    return build_claims_manifest(**values)


def _issue(agent_output: bytes | None = None, **over):
    output = agent_output or tiny_claims_agent_output(
        paper_id="rietveld-2013",
        claim_statement="fixture claim",
    )
    digests = _digests(output)
    manifest = _manifest(digests)
    kwargs = dict(
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        issued_at=ISSUED_AT,
        manifest=manifest,
        artifact_hash=digests["artifact_hash"],
        terminal_status="succeeded",
        assurance_level="service_signed",
        reuse_authorized_until=ISSUED_AT + timedelta(days=14),
    )
    kwargs.update(over)
    return issue_claims_evidence(**kwargs), manifest, digests, output


def test_tiny_agent_output_is_ara_shaped():
    raw = tiny_claims_agent_output(paper_id="p1", claim_statement="c1")
    doc = json.loads(raw.decode("ascii"))
    assert doc["paper"]["paper_id"] == "p1"
    assert doc["logic"]["claims"][0]["statement"] == "c1"
    assert "evidence" in doc and "trace" in doc


def test_issue_and_verify_accepts_matching_bundle():
    evidence, manifest, digests, output = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=manifest,
        observed_agent_output=output,
        observed_source_pdf=SOURCE_PDF,
        observed_source_payload=SOURCE_PAYLOAD,
        now=ISSUED_AT + timedelta(hours=1),
    )
    assert verified.accepted is True
    assert verified.reject_reasons == ()
    assert verified.document["schema"] == CLAIMS_EVIDENCE_SCHEMA
    assert verified.document["policy_digest"] == CLAIMS_EVIDENCE_POLICY_DIGEST
    assert verified.document["assurance_level"] == "service_signed"
    assert verified.document["artifact_hash"] == digests["artifact_hash"]
    assert verified.document["run_id"] == "run-1"
    assert verified.document["uid"] == 42
    assert verified.document["hotkey"].startswith("5Fixture")
    assert json.loads(canonical_claims_json(manifest).decode())["schema"] == CLAIMS_MANIFEST_SCHEMA


def test_wrong_miner_is_rejected():
    evidence, _, _, output = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    wrong = _manifest(_digests(output), hotkey="5OtherMinerHotkey0000000000000000002")
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=wrong,
        observed_agent_output=output,
        now=ISSUED_AT + timedelta(hours=1),
    )
    assert verified.accepted is False
    assert "hotkey_mismatch" in verified.reject_reasons
    assert "manifest_digest_mismatch" in verified.reject_reasons


def test_tampered_agent_output_is_rejected():
    evidence, manifest, _, _ = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    tampered = tiny_claims_agent_output(paper_id="rietveld-2013", claim_statement="TAMPERED")
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=manifest,
        observed_agent_output=tampered,
        now=ISSUED_AT + timedelta(hours=1),
    )
    assert verified.accepted is False
    assert "artifact_digest_mismatch" in verified.reject_reasons


def test_expired_reuse_window_is_rejected():
    evidence, manifest, _, output = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=manifest,
        observed_agent_output=output,
        now=ISSUED_AT + timedelta(days=30),
    )
    assert verified.accepted is False
    assert "reuse_window_expired" in verified.reject_reasons


def test_bad_signature_is_rejected():
    evidence, _, _, _ = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes(OTHER_KEY))
    with pytest.raises(ClaimsEvidenceError) as err:
        verify_claims_evidence(evidence, trusted, now=ISSUED_AT + timedelta(hours=1))
    assert err.value.category == "signature"


def test_confidential_cpu_cannot_be_issued_yet():
    output = tiny_claims_agent_output(paper_id="p", claim_statement="c")
    digests = _digests(output)
    with pytest.raises(ClaimsEvidenceError) as err:
        issue_claims_evidence(
            private_key=PRIVATE_KEY,
            signing_key_id=KEY_ID,
            issued_at=ISSUED_AT,
            manifest=_manifest(digests),
            artifact_hash=digests["artifact_hash"],
            assurance_level="confidential_cpu",
        )
    assert err.value.category == "policy"


def test_failed_terminal_status_not_accepted():
    output = tiny_claims_agent_output(paper_id="p", claim_statement="c")
    digests = _digests(output)
    evidence = issue_claims_evidence(
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        issued_at=ISSUED_AT,
        manifest=_manifest(digests),
        artifact_hash=digests["artifact_hash"],
        terminal_status="failed",
    )
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=_manifest(digests),
        observed_agent_output=output,
        now=ISSUED_AT + timedelta(hours=1),
    )
    assert verified.accepted is False
    assert "terminal_status_not_succeeded" in verified.reject_reasons


def test_write_claims_pack_layout(tmp_path: Path):
    evidence, manifest, _, output = _issue()
    pack = write_claims_pack(
        tmp_path / "pack",
        manifest=manifest,
        evidence_bytes=evidence,
        source_pdf=SOURCE_PDF,
        source_payload=SOURCE_PAYLOAD,
        agent_output=output,
    )
    assert (pack / "manifest.json").is_file()
    assert (pack / "evidence" / "cathedral-claims-evidence.json").is_file()
    assert (pack / "outputs" / "agent_output.json").read_bytes() == output
    assert (pack / "outputs" / "paper.pdf").read_bytes() == SOURCE_PDF


def test_cli_issue_and_verify(tmp_path: Path, capsys):
    output = tiny_claims_agent_output(paper_id="cli-paper", claim_statement="cli claim")
    digests = _digests(output)
    manifest = _manifest(digests, paper_id="cli-paper")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_claims_json(manifest))
    output_path = tmp_path / "agent_output.json"
    output_path.write_bytes(output)
    (tmp_path / "paper.pdf").write_bytes(SOURCE_PDF)
    (tmp_path / "source_payload.json").write_bytes(SOURCE_PAYLOAD)
    key_path = tmp_path / "key.raw"
    key_path.write_bytes(
        PRIVATE_KEY.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    trusted_path = tmp_path / "trusted.json"
    trusted_path.write_bytes(_trusted_keys_bytes())
    evidence_path = tmp_path / "evidence.json"

    rc = cli_main(
        [
            "claims-evidence",
            "issue",
            "--manifest",
            str(manifest_path),
            "--agent-output",
            str(output_path),
            "--signing-key",
            str(key_path),
            "--signing-key-id",
            KEY_ID,
            "--issued-at",
            "2026-10-26T12:00:00.000000Z",
            "--out",
            str(evidence_path),
        ]
    )
    assert rc == 0
    assert evidence_path.is_file()
    capsys.readouterr()

    rc = cli_main(
        [
            "claims-evidence",
            "verify",
            "--evidence",
            str(evidence_path),
            "--trusted-keys",
            str(trusted_path),
            "--manifest",
            str(manifest_path),
            "--agent-output",
            str(output_path),
            "--source-pdf",
            str(tmp_path / "paper.pdf"),
            "--source-payload",
            str(tmp_path / "source_payload.json"),
            "--now",
            "2026-10-26T13:00:00.000000Z",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert '"accepted": true' in out or '"accepted":true' in out


def _claims_stable_hash(value) -> str:
    # Claims 41573a4 neurons/validator.py _stable_hash and neurons/miner.py _json_hash.
    import hashlib

    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def test_digests_match_claims_artifact_hash_for_pretty_non_ascii_json():
    # Claims writes agent_output.json with indent=2, ensure_ascii=False and hashes the
    # parsed object; the evidence digest must equal Claims artifact_hash, not file bytes.
    agent_output = {"paper": {"paper_id": "p1", "title": "β-catenin – GWAS"}, "logic": {"claims": []}}
    payload = {"schema_version": "agent_v1_source_payload_v1", "spans": [{"span_id": "s1", "text": "été"}]}
    raw_output = json.dumps(agent_output, indent=2, ensure_ascii=False).encode("utf-8")
    raw_payload = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")
    digests = digest_claims_artifacts(
        source_pdf=SOURCE_PDF,
        source_payload=raw_payload,
        agent_output=raw_output,
        image_digest_ref=IMAGE_REF,
        workload_commit_ref=COMMIT_REF,
        execution_policy=POLICY,
    )
    assert digests["artifact_hash"] == _claims_stable_hash(agent_output)
    assert digests["source_payload_hash"] == _claims_stable_hash(payload)

    evidence, manifest, _, _ = _issue(agent_output=raw_output)
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    # Claims re-serializes the backend row; any equivalent encoding must verify.
    reencoded = json.dumps(agent_output, sort_keys=True, ensure_ascii=True).encode("ascii")
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=manifest,
        observed_agent_output=reencoded,
        now=ISSUED_AT + timedelta(hours=1),
    )
    assert verified.accepted is True
    assert verified.document["artifact_hash"] == _claims_stable_hash(agent_output)


def test_manifest_agent_output_digest_is_enforced():
    output = tiny_claims_agent_output(paper_id="p", claim_statement="c")
    digests = _digests(output)
    other = tiny_claims_agent_output(paper_id="p", claim_statement="other")
    manifest = _manifest(digests, artifact_hash=_digests(other)["artifact_hash"])
    with pytest.raises(ClaimsEvidenceError) as err:
        issue_claims_evidence(
            private_key=PRIVATE_KEY,
            signing_key_id=KEY_ID,
            issued_at=ISSUED_AT,
            manifest=manifest,
            artifact_hash=digests["artifact_hash"],
        )
    assert err.value.category == "binding"

    evidence, _, _, _ = _issue(agent_output=output)
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    verified = verify_claims_evidence(
        evidence, trusted, expected_manifest=manifest, now=ISSUED_AT + timedelta(hours=1)
    )
    assert verified.accepted is False
    assert "artifact_hash_mismatch" in verified.reject_reasons


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m.update(operation_id="op-other"),
        lambda m: m.update(schema="bogus"),
        lambda m: m.pop("paper_id"),
        lambda m: m.update(netuid="111"),
        lambda m: m.update(netuid=True),
    ],
)
def test_manifest_is_strict(mutate):
    output = tiny_claims_agent_output(paper_id="p", claim_statement="c")
    digests = _digests(output)
    manifest = dict(_manifest(digests))
    mutate(manifest)
    with pytest.raises(ClaimsEvidenceError) as err:
        issue_claims_evidence(
            private_key=PRIVATE_KEY,
            signing_key_id=KEY_ID,
            issued_at=ISSUED_AT,
            manifest=manifest,
            artifact_hash=digests["artifact_hash"],
        )
    assert err.value.category == "schema"


def test_impossible_calendar_time_is_a_schema_error():
    document = json.loads(_trusted_keys_bytes())
    document["keys"][KEY_ID]["valid_from"] = "2026-02-30T00:00:00.000000Z"
    with pytest.raises(ClaimsEvidenceError) as err:
        parse_claims_evidence_trusted_keys_json(json.dumps(document))
    assert err.value.category == "schema"


def test_non_canonical_signature_base64_is_rejected():
    evidence, _, _, _ = _issue()
    document = json.loads(evidence)
    value = document["signature"]["value_base64"]
    raw = base64.b64decode(value)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alias = next(
        candidate
        for candidate in (value[:-3] + char + "==" for char in alphabet)
        if candidate != value and base64.b64decode(candidate) == raw
    )
    document["signature"]["value_base64"] = alias
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    with pytest.raises(ClaimsEvidenceError) as err:
        verify_claims_evidence(
            canonical_claims_json(document), trusted, now=ISSUED_AT + timedelta(hours=1)
        )
    assert err.value.category == "signature"


def test_future_issued_at_beyond_skew_is_rejected():
    evidence, _, _, _ = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    with pytest.raises(ClaimsEvidenceError) as err:
        verify_claims_evidence(
            evidence,
            trusted,
            max_age_seconds=60,
            now=ISSUED_AT - timedelta(days=30),
        )
    assert err.value.category == "freshness"


def test_cli_verify_rejects_oversized_observed_agent_output(tmp_path: Path, capsys):
    evidence, _, _, _ = _issue()
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_bytes(evidence)
    trusted_path = tmp_path / "trusted.json"
    trusted_path.write_bytes(_trusted_keys_bytes())
    huge = tmp_path / "huge_agent_output.json"
    huge.write_bytes(b"{" + (b"x" * (8 * 1024 * 1024 + 1)) + b"}")
    rc = cli_main(
        [
            "claims-evidence",
            "verify",
            "--evidence",
            str(evidence_path),
            "--trusted-keys",
            str(trusted_path),
            "--agent-output",
            str(huge),
            "--now",
            "2026-10-26T13:00:00.000000Z",
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert '"accepted": false' in out or '"accepted":false' in out
    assert "exceeds the maximum encoded size" in out



def test_claims_native_ids_are_bound():
    evidence, manifest, digests, output = _issue()
    trusted = parse_claims_evidence_trusted_keys_json(_trusted_keys_bytes())
    verified = verify_claims_evidence(
        evidence,
        trusted,
        expected_manifest=manifest,
        observed_agent_output=output,
        now=ISSUED_AT + timedelta(hours=1),
    )
    assert verified.accepted is True
    assert verified.document["run_id"] == "run-1"
    assert verified.document["task_id"] == "task-1"
    assert verified.document["artifact_id"] == "artifact-1"
    assert verified.document["uid"] == 42
    assert verified.document["network"] == "finney"
    assert verified.document["artifact_hash"] == digests["artifact_hash"]
    assert verified.document["source_payload_hash"] == digests["source_payload_hash"]
    assert verified.document["cathedral"]["stage_id"] == "shared_reference_prep"
