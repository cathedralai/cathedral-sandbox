"""Run one Claims agent stage in a Cathedral room, then issue Claims evidence.

``claims_evidence`` signs a binding over Claims artifacts that already exist.
This module produces those artifacts in a room: it creates ONE room through the
thin broker's native routes, uploads the source PDF and source payload, runs
the stage command with a timeout, downloads ``agent_output`` and always deletes
the room. Only a stage that ends ``succeeded`` gets evidence:

- digests come from :func:`claims_evidence.digest_claims_artifacts` (Claims
  canonical JSON hashing), so they equal Claims ``artifact_hash`` and
  ``source_payload_hash``;
- the envelope is ``cathedral_claims_evidence_v1`` at ``service_signed``;
- the pack is written to a pending directory, read back and verified with
  :func:`claims_evidence.verify_claims_evidence` against the trusted keys, and
  only an accepted pack is moved to ``<out_dir>/pack``.

A failed, timed-out or rejected run issues nothing and writes
``<out_dir>/failure.json`` instead. ``<out_dir>/run.json`` records every run.
Neither file, nor any error message here, contains the guest key or the
signing key.
"""

from __future__ import annotations

import json
import posixpath
import shlex
import shutil
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.claims_evidence import (
    CLAIMS_MANIFEST_SCHEMA,
    MAX_CLAIMS_OBSERVED_JSON_BYTES,
    ClaimsEvidenceError,
    ClaimsEvidenceVerificationKey,
    build_claims_manifest,
    canonical_claims_json,
    claims_json_bytes_sha256,
    digest_claims_artifacts,
    issue_claims_evidence,
    sha256_hex,
    verify_claims_evidence,
    write_claims_pack,
)

CLAIMS_ROOM_POLICY_SCHEMA = "cathedral_claims_room_policy_v1"
CLAIMS_RUN_SCHEMA = "cathedral_claims_run_v1"
CLAIMS_RUN_FAILURE_SCHEMA = "cathedral_claims_run_failure_v1"

# The files API reaches /work only. The hotel uploads first, so it owns the
# input dir; the room makes the output dir itself. A dir the room made is not
# writable by the hotel, and the reverse, so the two never nest.
DEFAULT_INPUT_DIR = "/work/claims-in"
DEFAULT_OUTPUT_PATH = "/work/claims-out/agent_output.json"
NETWORK_MODES = frozenset({"deny_all", "internet"})

# Job keys: Claims ids (as main requires) plus optional digests that must match.
_JOB_ID_FIELDS = ("network", "batch_id", "run_id", "task_id", "artifact_id", "hotkey", "paper_id")
_JOB_DIGEST_FIELDS = (
    "source_pdf_sha256",
    "source_payload_hash",
    "image_digest_sha256",
    "workload_commit_sha256",
    "execution_policy_sha256",
    "artifact_hash",
)
_JOB_ALLOWED_KEYS = frozenset(
    {"schema", "netuid", "uid", "miner_hotkey", "cathedral", *_JOB_ID_FIELDS, *_JOB_DIGEST_FIELDS}
)
_HTTP_SLACK_SECONDS = 60
_OUTPUT_TAIL_CHARS = 2000


class BrokerTransport(Protocol):
    """One HTTP request to the broker; returns (status, headers, body)."""

    def request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> tuple[int, Mapping[str, str], bytes]: ...


@dataclass(frozen=True)
class HttpBrokerTransport:
    base_url: str

    def __post_init__(self) -> None:
        # The guest key rides in a header on every call, so plain http would leak it.
        # Same rule as the evidence fetches in cli.py.
        if urllib.parse.urlparse(self.base_url).scheme != "https":
            raise ClaimsRunError("input", "broker url must use https")

    def request(
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> tuple[int, Mapping[str, str], bytes]:
        req = urllib.request.Request(
            self.base_url.rstrip("/") + path, data=body or None, method=method
        )
        for key, value in headers.items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read()


class ClaimsRunError(RuntimeError):
    def __init__(self, category: str, message: str) -> None:
        super().__init__(message)
        self.category = category


class _StageTimeout(Exception):
    pass


@dataclass(frozen=True)
class ClaimsStageSpec:
    """What runs in the room. Its policy document is the execution policy digest."""

    image: str
    command: str
    workload_commit_ref: str
    output_path: str = DEFAULT_OUTPUT_PATH
    input_dir: str = DEFAULT_INPUT_DIR
    timeout_seconds: int = 1800
    sealed: bool = True
    network_mode: str = "deny_all"
    # (remote absolute path, bytes): extra inputs the command reads.
    extra_uploads: tuple[tuple[str, bytes], ...] = ()
    forbidden_hotels: tuple[str, ...] = ()
    ready_timeout_seconds: int = 300

    def source_pdf_path(self) -> str:
        return self.input_dir.rstrip("/") + "/paper.pdf"

    def source_payload_path(self) -> str:
        return self.input_dir.rstrip("/") + "/source_payload.json"

    def policy_document(self) -> dict[str, object]:
        return {
            "schema": CLAIMS_ROOM_POLICY_SCHEMA,
            "image": self.image,
            "command": self.command,
            "sealed": self.sealed,
            "network_mode": self.network_mode,
            "timeout_seconds": self.timeout_seconds,
            "source_pdf_path": self.source_pdf_path(),
            "source_payload_path": self.source_payload_path(),
            "output_path": self.output_path,
            "extra_inputs": sorted(
                [{"path": path, "sha256": sha256_hex(data)} for path, data in self.extra_uploads],
                key=lambda row: row["path"],
            ),
        }

    def policy_bytes(self) -> bytes:
        return canonical_claims_json(self.policy_document())


@dataclass
class ClaimsRunResult:
    terminal_status: str  # succeeded | failed | timed_out
    out_dir: Path
    room_id: str | None = None
    hotel: str | None = None
    hotel_sealed: bool | None = None
    room_deleted: bool = False
    exit_code: int | None = None
    timed_out: bool = False
    evidence_issued: bool = False
    verify_accepted: bool | None = None
    reject_reasons: tuple[str, ...] = ()
    evidence_id: str | None = None
    pack_dir: Path | None = None
    error_category: str | None = None
    error: str | None = None
    digests: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.terminal_status == "succeeded" and bool(self.verify_accepted)

    def summary(self) -> dict[str, object]:
        return {
            "schema": CLAIMS_RUN_SCHEMA,
            "ok": self.ok,
            "terminal_status": self.terminal_status,
            "room_id": self.room_id,
            "hotel": self.hotel,
            "hotel_sealed": self.hotel_sealed,
            "room_deleted": self.room_deleted,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "evidence_issued": self.evidence_issued,
            "verify_accepted": self.verify_accepted,
            "reject_reasons": list(self.reject_reasons),
            "evidence_id": self.evidence_id,
            "pack_dir": str(self.pack_dir) if self.pack_dir else None,
            "error_category": self.error_category,
            "error": self.error,
            "digests": dict(self.digests),
            "duration_ms": self.duration_ms,
        }


class _BrokerRooms:
    """The native broker room routes this runner needs, nothing more."""

    def __init__(self, transport: BrokerTransport, guest_key: str) -> None:
        self._transport = transport
        self._auth = {"Authorization": f"Bearer {guest_key}"}

    def _call(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        json_body: object = None,
        timeout: float = 60,
    ) -> tuple[int, Mapping[str, str], bytes]:
        headers = dict(self._auth)
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        return self._transport.request(method, path, headers, body, timeout)

    @staticmethod
    def _fail(what: str, status: int, raw: bytes) -> ClaimsRunError:
        code = "error"
        try:
            doc = json.loads(raw.decode("utf-8"))
            err = doc.get("error") if isinstance(doc, dict) else None
            if isinstance(err, dict):
                code = str(err.get("code") or code)
            elif isinstance(err, str):
                code = err
        except (UnicodeDecodeError, ValueError):
            pass
        return ClaimsRunError("broker", f"{what} answered HTTP {status} ({code})")

    @staticmethod
    def _json(raw: bytes, what: str) -> dict[str, Any]:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ClaimsRunError("broker", f"{what} answer is not JSON") from exc
        if not isinstance(doc, dict):
            raise ClaimsRunError("broker", f"{what} answer is not a JSON object")
        return doc

    def create(self, body: Mapping[str, object]) -> tuple[dict[str, Any], Mapping[str, str]]:
        status, headers, raw = self._call(
            "POST", "/v1/sandboxes", json_body=dict(body), timeout=300
        )
        if status not in (200, 201, 202):
            raise self._fail("create", status, raw)
        return self._json(raw, "create"), headers

    def get(self, room_id: str) -> tuple[int, dict[str, Any] | None]:
        status, _, raw = self._call("GET", f"/v1/sandboxes/{_q(room_id)}")
        if status == 200:
            return status, self._json(raw, "get")
        return status, None

    def exec(
        self,
        room_id: str,
        script: str,
        *,
        timeout_seconds: int,
        env: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        # Sealed hotels take only an argv array; env goes inline so it works on every hotel.
        exports = "".join(
            f"export {name}={shlex.quote(value)}; " for name, value in (env or {}).items()
        )
        body: dict[str, object] = {
            "cmd": ["/bin/sh", "-c", exports + script],
            "timeout_seconds": timeout_seconds,
        }
        try:
            status, _, raw = self._call(
                "POST",
                f"/v1/sandboxes/{_q(room_id)}/exec",
                json_body=body,
                timeout=timeout_seconds + _HTTP_SLACK_SECONDS,
            )
        except (TimeoutError, socket.timeout) as exc:
            raise _StageTimeout() from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise _StageTimeout() from exc
            raise
        if status != 200:
            raise self._fail("exec", status, raw)
        return self._json(raw, "exec")

    def put_file(self, room_id: str, path: str, data: bytes) -> None:
        query = urllib.parse.urlencode({"path": path})
        status, _, raw = self._call(
            "PUT", f"/v1/sandboxes/{_q(room_id)}/files?{query}", body=data, timeout=300
        )
        if status not in (200, 201, 204):
            raise self._fail(f"upload {path}", status, raw)

    def get_file(self, room_id: str, path: str, *, max_bytes: int) -> bytes:
        query = urllib.parse.urlencode({"path": path, "max_bytes": max_bytes + 1})
        status, _, raw = self._call(
            "GET", f"/v1/sandboxes/{_q(room_id)}/files?{query}", timeout=300
        )
        if status != 200:
            raise self._fail(f"download {path}", status, raw)
        return raw

    def delete(self, room_id: str) -> int:
        status, _, _ = self._call("DELETE", f"/v1/sandboxes/{_q(room_id)}")
        return status


def _q(room_id: str) -> str:
    return urllib.parse.quote(room_id, safe=".")


def _now() -> datetime:
    return datetime.now(UTC)


def parse_claims_job(job: Mapping[str, object]) -> dict[str, object]:
    """Validate a Claims job document: Claims ids plus optional expected digests.

    ``miner_hotkey`` is accepted as Claims' own name for the manifest ``hotkey``.
    """

    if not isinstance(job, Mapping):
        raise ClaimsEvidenceError("schema", "claims job must be a JSON object")
    extra = set(job) - _JOB_ALLOWED_KEYS
    if extra:
        raise ClaimsEvidenceError("schema", f"claims job has unexpected fields: {sorted(extra)}")
    if "schema" in job and job["schema"] != CLAIMS_MANIFEST_SCHEMA:
        raise ClaimsEvidenceError("schema", "claims job schema is unsupported")
    parsed = dict(job)
    if "miner_hotkey" in parsed:
        alias = parsed.pop("miner_hotkey")
        if "hotkey" in parsed and parsed["hotkey"] != alias:
            raise ClaimsEvidenceError("schema", "hotkey and miner_hotkey differ")
        parsed["hotkey"] = alias
    missing = [key for key in ("netuid", "uid", *_JOB_ID_FIELDS) if key not in parsed]
    if missing:
        raise ClaimsEvidenceError("schema", f"claims job is missing fields: {missing}")
    for key in _JOB_ID_FIELDS:
        if not isinstance(parsed[key], str):
            raise ClaimsEvidenceError("schema", f"{key} is invalid")
    for key in ("netuid", "uid"):
        if isinstance(parsed[key], bool) or not isinstance(parsed[key], int):
            raise ClaimsEvidenceError("schema", f"{key} must be an integer in 0..65535")
    return parsed


def _build_manifest(
    job: Mapping[str, object], digests: Mapping[str, str], *, artifact_hash: str | None
) -> dict[str, object]:
    cathedral = job.get("cathedral")
    return build_claims_manifest(
        netuid=int(job["netuid"]),  # type: ignore[call-overload]
        uid=int(job["uid"]),  # type: ignore[call-overload]
        network=str(job["network"]),
        batch_id=str(job["batch_id"]),
        run_id=str(job["run_id"]),
        task_id=str(job["task_id"]),
        artifact_id=str(job["artifact_id"]),
        hotkey=str(job["hotkey"]),
        paper_id=str(job["paper_id"]),
        source_pdf_sha256=digests["source_pdf_sha256"],
        source_payload_hash=digests["source_payload_hash"],
        image_digest_sha256=digests["image_digest_sha256"],
        workload_commit_sha256=digests["workload_commit_sha256"],
        execution_policy_sha256=digests["execution_policy_sha256"],
        artifact_hash=artifact_hash,
        cathedral=cathedral if isinstance(cathedral, Mapping) else None,
    )


def _check_expected_digests(job: Mapping[str, object], digests: Mapping[str, str]) -> None:
    for key in _JOB_DIGEST_FIELDS:
        if key in job and key in digests and job[key] != digests[key]:
            raise ClaimsEvidenceError("binding", f"job {key} does not match the observed input")


def _write_json(path: Path, doc: Mapping[str, object]) -> None:
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _tail(text: object) -> str:
    return str(text or "")[-_OUTPUT_TAIL_CHARS:]


def run_claims_stage_and_issue(
    *,
    transport: BrokerTransport,
    guest_key: str,
    job: Mapping[str, object],
    source_pdf: bytes,
    source_payload: bytes,
    stage: ClaimsStageSpec,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    trusted_keys: Mapping[str, ClaimsEvidenceVerificationKey],
    out_dir: Path,
    clock: Callable[[], datetime] = _now,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> ClaimsRunResult:
    """Run one Claims stage in one broker room; issue evidence only on success.

    The room is deleted on every path once the broker returned its id. Inputs
    that cannot produce evidence (bad job ids, bad payload JSON, mismatched
    expected digests) fail before any room is created.
    """

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    final_pack = out_dir / "pack"
    pending_pack = out_dir / ".pack-pending"
    for stale in (out_dir / "run.json", out_dir / "failure.json"):
        if stale.exists():
            raise ClaimsRunError("output", f"{stale.name} already exists in the output dir")
    if final_pack.exists():
        raise ClaimsRunError("output", "pack already exists in the output dir")
    if stage.network_mode not in NETWORK_MODES:
        raise ClaimsRunError("policy", "network_mode must be deny_all or internet")
    if stage.timeout_seconds <= 0:
        raise ClaimsRunError("policy", "timeout_seconds must be positive")
    for label, path in (("input_dir", stage.input_dir), ("output_path", stage.output_path)):
        if not path.startswith("/work/") or ".." in path.split("/"):
            raise ClaimsRunError("policy", f"{label} must be a path under /work")
    # Uploads land after the source files, so one on a reserved path would silently
    # swap the PDF the signed evidence names. Refuse before any room exists.
    reserved = {
        posixpath.normpath(p)
        for p in (stage.source_pdf_path(), stage.source_payload_path(), stage.output_path)
    }
    for upload_path, _data in stage.extra_uploads:
        checked = check_upload_path(upload_path)
        if checked in reserved:
            raise ClaimsRunError("input", f"--upload may not overwrite reserved path {checked}")

    result = ClaimsRunResult(terminal_status="failed", out_dir=out_dir)
    started = monotonic()
    agent_output: bytes | None = None
    stdout_tail = stderr_tail = ""
    rooms = _BrokerRooms(transport, guest_key)

    # Everything that does not depend on the room is checked before a room exists.
    try:
        parsed_job = parse_claims_job(job)
        input_digests = digest_claims_artifacts(
            source_pdf=source_pdf,
            source_payload=source_payload,
            agent_output=b"{}",
            image_digest_ref=stage.image.encode("utf-8"),
            workload_commit_ref=stage.workload_commit_ref.encode("utf-8"),
            execution_policy=stage.policy_bytes(),
        )
        input_digests.pop("artifact_hash")
        _check_expected_digests(parsed_job, input_digests)
        _build_manifest(parsed_job, input_digests, artifact_hash=None)
    except ClaimsEvidenceError as exc:
        result.error_category, result.error = exc.category, str(exc)
        return _finish(result, started, monotonic, stdout_tail, stderr_tail)
    result.digests = dict(input_digests)

    create_body: dict[str, object] = {
        "image": stage.image,
        "sealed": stage.sealed,
        "network": {"mode": stage.network_mode},
        "labels": {"purpose": "claims-evidence-run"},
        # The room reaps itself even if this process dies before the finally.
        "ttl_seconds": stage.timeout_seconds + stage.ready_timeout_seconds + 600,
    }
    try:
        doc, headers = rooms.create(create_body)
    except (ClaimsRunError, OSError) as exc:
        result.error_category = getattr(exc, "category", "broker")
        result.error = f"create failed: {exc}"
        return _finish(result, started, monotonic, stdout_tail, stderr_tail)

    room_id = str(doc.get("id") or "")
    result.room_id = room_id or None
    try:
        if not room_id:
            raise ClaimsRunError("broker", "create answer has no room id")
        result.hotel = str(
            doc.get("hotel") or _header(headers, "X-Broker-Hotel") or room_id.split(".", 1)[0]
        )
        isolation = doc.get("isolation")
        if isinstance(isolation, Mapping):
            result.hotel_sealed = bool(isolation.get("hotel_sealed"))
        if result.hotel in stage.forbidden_hotels:
            raise ClaimsRunError("placement", f"room landed on forbidden hotel {result.hotel}")
        if stage.sealed and result.hotel_sealed is not True:
            raise ClaimsRunError("placement", "sealed room was not placed on a sealed hotel")

        _wait_running(rooms, room_id, doc, stage, sleep, monotonic)
        rooms.put_file(room_id, stage.source_pdf_path(), source_pdf)
        rooms.put_file(room_id, stage.source_payload_path(), source_payload)
        for path, data in stage.extra_uploads:
            rooms.put_file(room_id, path, data)
        out_parent = stage.output_path.rsplit("/", 1)[0]
        if out_parent != "/work":
            prep = rooms.exec(room_id, f"mkdir -p {shlex.quote(out_parent)}", timeout_seconds=60)
            if prep.get("exit_code") != 0:
                raise ClaimsRunError("room", "could not create the output directory")

        run = rooms.exec(
            room_id,
            stage.command,
            timeout_seconds=stage.timeout_seconds,
            env={
                "CLAIMS_SOURCE_PDF": stage.source_pdf_path(),
                "CLAIMS_SOURCE_PAYLOAD": stage.source_payload_path(),
                "CLAIMS_AGENT_OUTPUT": stage.output_path,
            },
        )
        stdout_tail, stderr_tail = _tail(run.get("stdout")), _tail(run.get("stderr"))
        exit_code = run.get("exit_code")
        result.exit_code = exit_code if isinstance(exit_code, int) else None
        if run.get("timed_out") is True:
            raise _StageTimeout()
        if result.exit_code != 0:
            raise ClaimsRunError("stage", f"stage command exited {result.exit_code}")
        agent_output = rooms.get_file(
            room_id, stage.output_path, max_bytes=MAX_CLAIMS_OBSERVED_JSON_BYTES
        )
        if len(agent_output) > MAX_CLAIMS_OBSERVED_JSON_BYTES:
            raise ClaimsRunError("stage", "agent_output exceeds the maximum size")
        claims_json_bytes_sha256(agent_output, label="agent_output")
        result.terminal_status = "succeeded"
    except _StageTimeout:
        result.terminal_status = "timed_out"
        result.timed_out = True
        result.error_category = "timeout"
        result.error = f"stage command did not finish in {stage.timeout_seconds} s"
    except ClaimsEvidenceError as exc:
        result.error_category, result.error = "stage", f"agent_output invalid: {exc}"
    except (ClaimsRunError, OSError) as exc:
        result.error_category = getattr(exc, "category", "broker")
        result.error = str(exc)
    finally:
        if room_id:
            result.room_deleted = _delete_room(rooms, room_id, sleep)

    if result.terminal_status != "succeeded" or agent_output is None:
        result.terminal_status = "timed_out" if result.terminal_status == "timed_out" else "failed"
        return _finish(result, started, monotonic, stdout_tail, stderr_tail)

    # Terminal success: issue, write pending pack, verify from disk, then publish.
    try:
        digests = digest_claims_artifacts(
            source_pdf=source_pdf,
            source_payload=source_payload,
            agent_output=agent_output,
            image_digest_ref=stage.image.encode("utf-8"),
            workload_commit_ref=stage.workload_commit_ref.encode("utf-8"),
            execution_policy=stage.policy_bytes(),
        )
        result.digests = dict(digests)
        _check_expected_digests(parsed_job, digests)
        manifest = _build_manifest(parsed_job, digests, artifact_hash=digests["artifact_hash"])
        evidence = issue_claims_evidence(
            private_key=private_key,
            signing_key_id=signing_key_id,
            issued_at=clock(),
            manifest=manifest,
            artifact_hash=digests["artifact_hash"],
            terminal_status="succeeded",
            assurance_level="service_signed",
        )
        result.evidence_issued = True
        if pending_pack.exists():
            shutil.rmtree(pending_pack)
        write_claims_pack(
            pending_pack,
            manifest=manifest,
            evidence_bytes=evidence,
            source_pdf=source_pdf,
            source_payload=source_payload,
            agent_output=agent_output,
        )
        _write_json(pending_pack / "execution_policy.json", stage.policy_document())
        verified = verify_claims_evidence(
            (pending_pack / "evidence" / "cathedral-claims-evidence.json").read_bytes(),
            trusted_keys,
            expected_manifest=json.loads((pending_pack / "manifest.json").read_bytes()),
            observed_agent_output=(pending_pack / "outputs" / "agent_output.json").read_bytes(),
            observed_source_pdf=(pending_pack / "outputs" / "paper.pdf").read_bytes(),
            observed_source_payload=(pending_pack / "outputs" / "source_payload.json").read_bytes(),
            now=clock(),
        )
        result.verify_accepted = verified.accepted
        result.reject_reasons = verified.reject_reasons
        result.evidence_id = verified.evidence_id
        if not verified.accepted:
            raise ClaimsEvidenceError(
                "verify", f"self-verify rejected: {', '.join(verified.reject_reasons)}"
            )
        pending_pack.rename(final_pack)
        result.pack_dir = final_pack
    except (ClaimsEvidenceError, OSError) as exc:
        result.verify_accepted = False if result.verify_accepted is None else result.verify_accepted
        # Nothing leaves this function signed unless it verified.
        result.evidence_issued = False
        result.error_category = getattr(exc, "category", "output")
        result.error = str(exc)
        if pending_pack.exists():
            shutil.rmtree(pending_pack)
    return _finish(result, started, monotonic, stdout_tail, stderr_tail)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _wait_running(
    rooms: _BrokerRooms,
    room_id: str,
    doc: Mapping[str, object],
    stage: ClaimsStageSpec,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
) -> None:
    state = doc.get("state")
    deadline = monotonic() + stage.ready_timeout_seconds
    while state != "running":
        if state in ("failed", "deleted", "terminated", "error"):
            raise ClaimsRunError("room", f"room entered state {state}")
        if monotonic() >= deadline:
            raise ClaimsRunError("room", f"room not running after {stage.ready_timeout_seconds} s")
        sleep(2)
        status, current = rooms.get(room_id)
        if status != 200 or current is None:
            raise ClaimsRunError("room", f"room lookup answered HTTP {status}")
        state = current.get("state")


def _delete_room(rooms: _BrokerRooms, room_id: str, sleep: Callable[[float], None]) -> bool:
    """Delete, then confirm the broker no longer knows the room."""

    for attempt in range(3):
        try:
            status = rooms.delete(room_id)
            if status in (200, 202, 204, 404):
                lookup, doc = rooms.get(room_id)
                if lookup == 404 or (doc is not None and doc.get("state") == "deleted"):
                    return True
        except OSError:
            pass
        sleep(2 * (attempt + 1))
    return False


def _finish(
    result: ClaimsRunResult,
    started: float,
    monotonic: Callable[[], float],
    stdout_tail: str,
    stderr_tail: str,
) -> ClaimsRunResult:
    result.duration_ms = int((monotonic() - started) * 1000)
    summary = result.summary()
    _write_json(result.out_dir / "run.json", summary)
    if not result.ok:
        _write_json(
            result.out_dir / "failure.json",
            {
                "schema": CLAIMS_RUN_FAILURE_SCHEMA,
                "terminal_status": result.terminal_status,
                "evidence_issued": result.evidence_issued,
                "room_id": result.room_id,
                "hotel": result.hotel,
                "room_deleted": result.room_deleted,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "error_category": result.error_category,
                "error": result.error,
                "stdout_tail": stdout_tail,
                "stderr_tail": stderr_tail,
            },
        )
    return result


def check_upload_path(remote: str) -> str:
    """Normalised upload destination, which must sit under /work."""

    if ".." in remote.split("/"):
        raise ClaimsRunError("input", f"--upload path may not contain '..': {remote!r}")
    normal = posixpath.normpath(remote)
    if not normal.startswith("/work/"):
        raise ClaimsRunError("input", f"--upload path must be under /work/: {remote!r}")
    return normal


def parse_uploads(specs: Sequence[str]) -> tuple[tuple[str, bytes], ...]:
    """``LOCAL=REMOTE`` pairs into (remote path, bytes)."""

    uploads: list[tuple[str, bytes]] = []
    for spec in specs:
        local, sep, remote = spec.partition("=")
        if not sep or not local or not remote.startswith("/"):
            raise ClaimsRunError("input", f"--upload must be LOCAL=/abs/remote/path: {spec!r}")
        check_upload_path(remote)
        uploads.append((remote, Path(local).read_bytes()))
    return tuple(uploads)
