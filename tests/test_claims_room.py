"""claims-evidence run: one Claims stage in a broker room, then evidence (fake broker)."""

from __future__ import annotations

import base64
import json
import socket
import urllib.parse
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import claims_room
from cathedral.claims_evidence import (
    CLAIMS_EVIDENCE_SCHEMA,
    CLAIMS_EVIDENCE_TRUSTED_KEYS_SCHEMA,
    claims_json_sha256,
    digest_claims_artifacts,
    parse_claims_evidence_trusted_keys_json,
    tiny_claims_agent_output,
    verify_claims_evidence,
)
from cathedral.claims_room import (
    ClaimsStageSpec,
    run_claims_stage_and_issue,
)
from cathedral.cli import main as cli_main

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
KEY_ID = "claims-room-test-1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
GUEST_KEY = "guest-secret-not-for-logs"

SOURCE_PDF = b"%PDF-1.4 fixture paper bytes"
SOURCE_PAYLOAD = b'{"schema":"agent_v1_source_payload_v1","spans":[{"span_id":"s1","text":"hi"}]}'
AGENT_OUTPUT = tiny_claims_agent_output(paper_id="arxiv-2401.00001", claim_statement="x > y")
# Pretty-printed on purpose: Claims hashes the parsed object, not file bytes.
AGENT_OUTPUT_PRETTY = json.dumps(json.loads(AGENT_OUTPUT), indent=2).encode("utf-8")
OUTPUT_PATH = "/work/claims-out/agent_output.json"

JOB = {
    "netuid": 111,
    "network": "finney",
    "batch_id": "",
    "run_id": "run-20261026-01",
    "task_id": "task-7",
    "artifact_id": "artifact-7",
    "uid": 12,
    "miner_hotkey": "5Fminerhotkey",
    "paper_id": "arxiv-2401.00001",
}


def _trusted(private_key: Ed25519PrivateKey = PRIVATE_KEY):
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return json.dumps(
        {
            "schema": CLAIMS_EVIDENCE_TRUSTED_KEYS_SCHEMA,
            "keys": {
                KEY_ID: {
                    "algorithm": "ed25519",
                    "public_key_base64": base64.b64encode(raw).decode("ascii"),
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00.000000Z",
                    "valid_until": "2027-01-01T00:00:00.000000Z",
                }
            },
        }
    ).encode("ascii")


ExecHandler = Callable[[dict[str, bytes], Mapping[str, object]], dict[str, object]]


def _script(body: Mapping[str, object]) -> str:
    cmd = body["cmd"]
    assert isinstance(cmd, list) and cmd[:2] == ["/bin/sh", "-c"]
    return str(cmd[2])


def _writes_output(output: bytes = AGENT_OUTPUT_PRETTY) -> ExecHandler:
    def handler(files: dict[str, bytes], body: Mapping[str, object]) -> dict[str, object]:
        script = _script(body)
        assert f"export CLAIMS_AGENT_OUTPUT={OUTPUT_PATH};" in script
        assert "export CLAIMS_SOURCE_PDF=/work/claims-in/paper.pdf;" in script
        files[OUTPUT_PATH] = output
        return {"exit_code": 0, "stdout": "ok", "stderr": "", "timed_out": False}

    return handler


class FakeBroker:
    """The native broker routes the runner uses, in memory."""

    def __init__(
        self,
        stage: ExecHandler,
        *,
        hotel: str = "c46-sealed",
        sealed: bool = True,
        initial_state: str = "creating",
        fail_upload: bool = False,
    ) -> None:
        self.stage = stage
        self.hotel = hotel
        self.sealed = sealed
        self.initial_state = initial_state
        self.fail_upload = fail_upload
        self.calls: list[tuple[str, str]] = []
        self.rooms: dict[str, dict[str, object]] = {}
        self.files: dict[str, bytes] = {}
        self.created: list[dict[str, object]] = []
        self.deleted: list[str] = []
        self.exec_bodies: list[dict[str, object]] = []
        self.auth_headers: set[str] = set()

    def request(self, method, path, headers, body, timeout):
        self.calls.append((method, path))
        self.auth_headers.add(headers.get("Authorization", ""))
        parsed = urllib.parse.urlparse(path)
        query = urllib.parse.parse_qs(parsed.query)
        parts = parsed.path.split("/")
        if method == "POST" and parsed.path == "/v1/sandboxes":
            doc = json.loads(body)
            self.created.append(doc)
            room_id = f"{self.hotel}.r{len(self.created)}"
            room = {
                "id": room_id,
                "state": self.initial_state,
                "isolation": {"hotel_sealed": self.sealed, "room_runtime": "runsc"},
            }
            self.rooms[room_id] = room
            return 202, {"X-Broker-Hotel": self.hotel}, json.dumps(room).encode()
        room_id = parts[3]
        room = self.rooms.get(room_id)
        if room is None:
            return 404, {}, b'{"error":{"code":"sandbox_not_found"}}'
        tail = parts[4] if len(parts) > 4 else ""
        if method == "GET" and not tail:
            room["state"] = "running"
            return 200, {}, json.dumps(room).encode()
        if method == "DELETE" and not tail:
            del self.rooms[room_id]
            self.deleted.append(room_id)
            return 204, {}, b""
        if tail == "exec":
            doc = json.loads(body)
            self.exec_bodies.append(doc)
            if _script(doc).startswith("mkdir -p"):
                return 200, {}, json.dumps({"exit_code": 0, "timed_out": False}).encode()
            return 200, {}, json.dumps(self.stage(self.files, doc)).encode()
        if tail == "files" and method == "PUT":
            if self.fail_upload:
                return 507, {}, b'{"error":{"code":"disk_full"}}'
            self.files[query["path"][0]] = body
            return 200, {}, b"{}"
        if tail == "files" and method == "GET":
            data = self.files.get(query["path"][0])
            if data is None:
                return 404, {}, b'{"error":{"code":"not_found"}}'
            return 200, {}, data
        raise AssertionError(f"unexpected call {method} {path}")


def _stage(**overrides) -> ClaimsStageSpec:
    base = {
        "image": "alpine:3.20",
        "command": 'cat /work/claims-in/fixture.json > "$CLAIMS_AGENT_OUTPUT"',
        "workload_commit_ref": "41573a43589f96ce27746e24426c3f025134ecae",
        "timeout_seconds": 120,
        "forbidden_hotels": ("nc-sealed",),
    }
    base.update(overrides)
    return ClaimsStageSpec(**base)


def _run(broker: FakeBroker, tmp_path: Path, *, trusted=None, stage=None, job=None):
    return run_claims_stage_and_issue(
        transport=broker,
        guest_key=GUEST_KEY,
        job=job or JOB,
        source_pdf=SOURCE_PDF,
        source_payload=SOURCE_PAYLOAD,
        stage=stage or _stage(),
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        trusted_keys=parse_claims_evidence_trusted_keys_json(trusted or _trusted()),
        out_dir=tmp_path / "out",
        clock=lambda: NOW,
        sleep=lambda _s: None,
    )


def _assert_deleted(broker: FakeBroker, result) -> None:
    assert broker.rooms == {}
    assert broker.deleted == [result.room_id]
    assert result.room_deleted is True
    assert broker.calls[-1] == ("GET", f"/v1/sandboxes/{result.room_id}")


def test_success_issues_verified_pack_and_deletes_room(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output())
    result = _run(broker, tmp_path)

    assert result.ok and result.terminal_status == "succeeded"
    assert result.hotel == "c46-sealed" and result.hotel_sealed is True
    _assert_deleted(broker, result)
    assert broker.created[0]["sealed"] is True
    assert broker.created[0]["network"] == {"mode": "deny_all"}
    assert broker.auth_headers == {f"Bearer {GUEST_KEY}"}
    assert broker.files["/work/claims-in/paper.pdf"] == SOURCE_PDF
    assert broker.files["/work/claims-in/source_payload.json"] == SOURCE_PAYLOAD

    pack = tmp_path / "out" / "pack"
    assert result.pack_dir == pack
    assert not (tmp_path / "out" / ".pack-pending").exists()
    assert not (tmp_path / "out" / "failure.json").exists()
    evidence = (pack / "evidence" / "cathedral-claims-evidence.json").read_bytes()
    doc = json.loads(evidence)
    assert doc["schema"] == CLAIMS_EVIDENCE_SCHEMA
    assert doc["assurance_level"] == "service_signed"
    assert doc["terminal_status"] == "succeeded"
    assert doc["hotkey"] == "5Fminerhotkey"
    assert (pack / "outputs" / "agent_output.json").read_bytes() == AGENT_OUTPUT_PRETTY
    run = json.loads((tmp_path / "out" / "run.json").read_text())
    assert run["ok"] is True and run["room_deleted"] is True
    assert run["evidence_id"] == doc["evidence_id"]


def test_verify_after_issue_accepts_independently(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output())
    result = _run(broker, tmp_path)
    pack = tmp_path / "out" / "pack"
    verified = verify_claims_evidence(
        (pack / "evidence" / "cathedral-claims-evidence.json").read_bytes(),
        parse_claims_evidence_trusted_keys_json(_trusted()),
        expected_manifest=json.loads((pack / "manifest.json").read_bytes()),
        observed_agent_output=AGENT_OUTPUT,
        observed_source_pdf=SOURCE_PDF,
        observed_source_payload=SOURCE_PAYLOAD,
        now=NOW,
    )
    assert verified.accepted and verified.evidence_id == result.evidence_id


def test_digest_parity_with_claims_evidence(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output())
    stage = _stage()
    result = _run(broker, tmp_path, stage=stage)
    expected = digest_claims_artifacts(
        source_pdf=SOURCE_PDF,
        source_payload=SOURCE_PAYLOAD,
        agent_output=AGENT_OUTPUT,
        image_digest_ref=b"alpine:3.20",
        workload_commit_ref=stage.workload_commit_ref.encode(),
        execution_policy=stage.policy_bytes(),
    )
    assert result.digests == expected
    doc = json.loads(
        (tmp_path / "out" / "pack" / "evidence" / "cathedral-claims-evidence.json").read_bytes()
    )
    for key, value in expected.items():
        assert doc[key] == value
    # Pretty-printed room output hashes like Claims' canonical artifact_hash.
    assert doc["artifact_hash"] == claims_json_sha256(json.loads(AGENT_OUTPUT_PRETTY))


def test_command_failure_issues_nothing_and_deletes_room(tmp_path: Path) -> None:
    broker = FakeBroker(
        lambda files, body: {"exit_code": 3, "stdout": "", "stderr": "boom", "timed_out": False}
    )
    result = _run(broker, tmp_path)

    assert result.terminal_status == "failed" and not result.ok
    assert result.exit_code == 3 and result.evidence_issued is False
    _assert_deleted(broker, result)
    assert not (tmp_path / "out" / "pack").exists()
    failure = json.loads((tmp_path / "out" / "failure.json").read_text())
    assert failure["terminal_status"] == "failed"
    assert failure["evidence_issued"] is False
    assert failure["stderr_tail"] == "boom"


def test_hotel_timeout_is_timed_out_and_deletes_room(tmp_path: Path) -> None:
    broker = FakeBroker(
        lambda files, body: {"exit_code": 124, "stdout": "", "stderr": "", "timed_out": True}
    )
    result = _run(broker, tmp_path)
    assert result.terminal_status == "timed_out" and result.timed_out
    _assert_deleted(broker, result)
    assert not (tmp_path / "out" / "pack").exists()
    assert json.loads((tmp_path / "out" / "failure.json").read_text())["terminal_status"] == (
        "timed_out"
    )
    run_exec = [b for b in broker.exec_bodies if not _script(b).startswith("mkdir")]
    assert run_exec[0]["timeout_seconds"] == 120


def test_client_socket_timeout_is_timed_out_and_deletes_room(tmp_path: Path) -> None:
    def hang(files, body):
        raise socket.timeout("read timed out")

    broker = FakeBroker(hang)
    result = _run(broker, tmp_path)
    assert result.terminal_status == "timed_out"
    _assert_deleted(broker, result)
    assert not (tmp_path / "out" / "pack").exists()


def test_upload_failure_deletes_room(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output(), fail_upload=True)
    result = _run(broker, tmp_path)
    assert result.terminal_status == "failed" and result.error_category == "broker"
    _assert_deleted(broker, result)
    assert not any("CLAIMS_AGENT_OUTPUT" in _script(b) for b in broker.exec_bodies)


def test_missing_or_invalid_output_fails_and_deletes_room(tmp_path: Path) -> None:
    broker = FakeBroker(lambda files, body: {"exit_code": 0, "timed_out": False})
    result = _run(broker, tmp_path / "a")
    assert result.terminal_status == "failed"
    _assert_deleted(broker, result)

    broker = FakeBroker(_writes_output(b"[1, 2]"))
    result = _run(broker, tmp_path / "b")
    assert result.terminal_status == "failed" and "agent_output" in (result.error or "")
    _assert_deleted(broker, result)
    assert not (tmp_path / "b" / "out" / "pack").exists()


def test_uploads_happen_before_any_room_exec(tmp_path: Path) -> None:
    # A dir the room creates is not writable by the hotel files API (live path_escape).
    broker = FakeBroker(_writes_output())
    _run(broker, tmp_path)
    kinds = [
        "put" if method == "PUT" else "exec"
        for method, path in broker.calls
        if method == "PUT" or path.endswith("/exec")
    ]
    assert kinds[:3] == ["put", "put", "exec"]
    assert _script(broker.exec_bodies[0]) == "mkdir -p /work/claims-out"


def test_room_paths_outside_work_are_refused(tmp_path: Path) -> None:
    with pytest.raises(claims_room.ClaimsRunError):
        _run(FakeBroker(_writes_output()), tmp_path, stage=_stage(output_path="/tmp/out.json"))


def test_forbidden_hotel_fails_closed_before_any_upload(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output(), hotel="nc-sealed")
    result = _run(broker, tmp_path)
    assert result.terminal_status == "failed" and result.error_category == "placement"
    _assert_deleted(broker, result)
    assert broker.files == {} and broker.exec_bodies == []


def test_sealed_request_on_unsealed_hotel_fails_closed(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output(), hotel="nc", sealed=False)
    result = _run(broker, tmp_path)
    assert result.error_category == "placement"
    _assert_deleted(broker, result)


def test_self_verify_rejection_publishes_no_pack(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output())
    result = _run(broker, tmp_path, trusted=_trusted(OTHER_KEY))
    assert result.terminal_status == "succeeded" and not result.ok
    assert result.verify_accepted is False and result.evidence_issued is False
    _assert_deleted(broker, result)
    assert not (tmp_path / "out" / "pack").exists()
    assert not (tmp_path / "out" / ".pack-pending").exists()
    failure = json.loads((tmp_path / "out" / "failure.json").read_text())
    assert failure["error_category"] == "signature"


def test_bad_job_creates_no_room(tmp_path: Path) -> None:
    broker = FakeBroker(_writes_output())
    result = _run(broker, tmp_path, job={**JOB, "run_id": "bad id with spaces"})
    assert result.terminal_status == "failed" and result.room_id is None
    assert broker.calls == []
    expected_mismatch = {**JOB, "source_pdf_sha256": "0" * 64}
    result = _run(FakeBroker(_writes_output()), tmp_path / "b", job=expected_mismatch)
    assert result.error_category == "binding" and result.room_id is None


def test_cli_run_success_never_prints_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    broker = FakeBroker(_writes_output())
    import cathedral.cli as cli

    monkeypatch.setattr(cli, "HttpBrokerTransport", lambda _url: broker)
    files = {
        "job.json": json.dumps(JOB).encode(),
        "paper.pdf": SOURCE_PDF,
        "payload.json": SOURCE_PAYLOAD,
        "trusted.json": _trusted(),
        "signing.key": bytes(range(32)),
        "guest.key": (GUEST_KEY + "\n").encode(),
        "fixture.json": AGENT_OUTPUT,
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    rc = cli_main(
        [
            "claims-evidence",
            "run",
            "--broker-url",
            "https://broker.invalid",
            "--guest-key-file",
            str(tmp_path / "guest.key"),
            "--job",
            str(tmp_path / "job.json"),
            "--source-pdf",
            str(tmp_path / "paper.pdf"),
            "--source-payload",
            str(tmp_path / "payload.json"),
            "--image",
            "alpine:3.20",
            "--command",
            'cat /work/claims-in/fixture.json > "$CLAIMS_AGENT_OUTPUT"',
            "--workload-commit",
            "41573a4",
            "--upload",
            f"{tmp_path / 'fixture.json'}=/work/claims-in/fixture.json",
            "--forbid-hotel",
            "nc-sealed",
            "--signing-key",
            str(tmp_path / "signing.key"),
            "--signing-key-id",
            KEY_ID,
            "--trusted-keys",
            str(tmp_path / "trusted.json"),
            "--out-dir",
            str(tmp_path / "out"),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0, out
    summary = json.loads(out)
    assert summary["verify_accepted"] is True and summary["room_deleted"] is True
    assert broker.files["/work/claims-in/fixture.json"] == AGENT_OUTPUT
    signing_b64 = base64.b64encode(bytes(range(32))).decode()
    for root, text in [("stdout", out)] + [
        (str(p), p.read_text(errors="replace"))
        for p in (tmp_path / "out").rglob("*")
        if p.is_file() and p.suffix == ".json"
    ]:
        assert GUEST_KEY not in text, root
        assert signing_b64 not in text and bytes(range(32)).hex() not in text, root
