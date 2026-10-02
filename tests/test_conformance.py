"""Conformance suite logic against an in-memory fake of the sandbox API.

The fake answers just enough of the contract for each check. Live behavior is
what the suite itself measures; these tests pin the verdict logic: thresholds,
skips, gating by tier, run order and cleanup.
"""

from __future__ import annotations

import json
import hashlib
import re
import shlex
import shutil
import subprocess
import urllib.parse

import pytest

from cathedral.conformance import checks as C
from cathedral.conformance.api import SYNC_EXEC_MAX_SECONDS, Api, Response
from cathedral.conformance.runner import ordered, run

# The live API (https://cathedral.computer/openapi.json) requires an
# Idempotency-Key on these calls and answers 422 without one.
KEYED = {("POST", "sandboxes"), ("DELETE", "sandbox"), ("POST", "lifetime"), ("POST", "execs")}


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class FakeCathedral:
    """Sandboxes run as soon as they are created; every call costs `latency` seconds."""

    def __init__(self, clock: FakeClock, *, latency: float = 0.05, quota_limit: int = 500,
                 second_delete_status: int = 202, create_fails: bool = False,
                 list_status: int = 200, malformed_list: bool = False,
                 foreign_sentinel: bool = False, ignore_list_filters: bool = False,
                 lose_create_response: bool = False, delete_delay_polls: int = 0,
                 reject_delete: bool = False, shared_filesystem: bool = False,
                 api_key_limit: int | None = None, quota_error: str = "sandbox_quota_exceeded",
                 snapshot_delete_delay_polls: int = 0, reject_snapshot_delete: bool = False,
                 lose_snapshot_response: bool = False, background_run_s: float = 40.0,
                 background_never_ends: bool = False):
        self.clock = clock
        self.latency = latency
        self.quota_limit = quota_limit
        self.api_key_limit = api_key_limit
        self.quota_error = quota_error
        self.second_delete_status = second_delete_status
        self.create_fails = create_fails
        self.background_run_s = background_run_s
        self.background_never_ends = background_never_ends
        self.delete_keys: list[str | None] = []
        self.sync_exec_timeouts: list[int] = []
        self.background: dict[str, dict] = {}
        self.stopped_execs: list[str] = []
        self.calls: list[tuple[str, str]] = []
        self.list_status = list_status
        self.malformed_list = malformed_list
        self.foreign_sentinel = foreign_sentinel
        self.ignore_list_filters = ignore_list_filters
        self.lose_create_response = lose_create_response
        self.delete_delay_polls = delete_delay_polls
        self.reject_delete = reject_delete
        self.shared_filesystem = shared_filesystem
        self.snapshot_delete_delay_polls = snapshot_delete_delay_polls
        self.reject_snapshot_delete = reject_snapshot_delete
        self.lose_snapshot_response = lose_snapshot_response
        self.sandboxes: dict[str, dict] = {}
        self.keys: dict[str, str] = {}
        self.deleted: list[str] = []
        self.snapshots: dict[str, dict] = {}
        self.files: dict[str, dict[str, str]] = {}
        self.delete_polls: dict[str, int] = {}
        self.snapshot_polls: dict[str, int] = {}
        self.parent_data = "pre-fork-state-bytes"
        self.parent_digest = hashlib.sha256(self.parent_data.encode()).hexdigest()
        if foreign_sentinel:
            self.sandboxes["foreign"] = {"id": "foreign", "state": "running", "labels": {"owner": "other"},
                                           "cleanup_state": "none"}

    def reply(self, status: int, body=None, headers=None) -> Response:
        data = b"" if body is None else json.dumps(body).encode()
        return Response(status, headers or {}, data, self.latency)

    @staticmethod
    def stdout_for(command) -> str:
        text = command if isinstance(command, str) else " ".join(command)
        if "6*7" in text:
            return "42\n"
        if "cat /work/probe" in text:
            return "ok\n"
        if "docker network ls" in text:
            return f"{C.Config.nested_networks}\n"
        return ""

    def __call__(self, method, url, headers, body, timeout) -> Response:
        self.clock.now += self.latency
        parsed = urllib.parse.urlparse(url)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        parts = path.strip("/").split("/")
        payload = json.loads(body) if body and headers.get("Content-Type") == "application/json" else None
        self.calls.append((method, path))
        if method == "DELETE" and len(parts) == 3 and parts[:2] == ["v1", "sandboxes"]:
            self.delete_keys.append(headers.get("Idempotency-Key"))
        if self.route(method, parts) in KEYED and not headers.get("Idempotency-Key"):
            return self.reply(422, {"detail": [{"loc": ["header", "Idempotency-Key"],
                                                "msg": "Field required"}]})
        if method == "POST" and path == "/v1/sandboxes":
            if self.create_fails:
                return self.reply(503, {"error_code": "no_capacity", "message": "full"})
            key = headers.get("Idempotency-Key")
            if key in self.keys:
                return self.reply(202, self.sandboxes[self.keys[key]])
            key_live = sum(1 for s in self.sandboxes.values()
                           if s["state"] != "deleted" and s.get("labels") == payload["labels"])
            if self.api_key_limit is not None and key_live >= self.api_key_limit:
                return self.reply(429, {"detail": {"error": "sandbox_key_quota_exceeded"}}, {"Retry-After": "5"})
            if self.live() >= self.quota_limit:
                return self.reply(429, {"detail": {"error": self.quota_error}}, {"Retry-After": "5"})
            sandbox_id = f"sb{len(self.sandboxes)}"
            source = self.snapshots.get(payload.get("snapshot_id"), {}).get("source_id")
            initial_files = dict(self.files.get(source, {})) if source else {}
            self.sandboxes[sandbox_id] = {"id": sandbox_id, "state": "running", "labels": payload["labels"],
                                          "cleanup_state": "none",
                                          "lifetime_deadline_at": "2026-10-01T12:00:00+00:00"}
            self.files[sandbox_id] = initial_files
            self.keys[key] = sandbox_id
            if self.lose_create_response:
                return self.reply(0, {"error_code": "response_lost"})
            return self.reply(202, self.sandboxes[sandbox_id])
        if method == "GET" and path == "/v1/sandboxes":
            if self.list_status != 200:
                return self.reply(self.list_status, {"error_code": "list_failed"})
            if self.malformed_list:
                return self.reply(200, {"sandboxes": "not-a-list", "has_more": False})
            rows = list(self.sandboxes.values())
            labels = query.get("label", [])
            if labels and not self.ignore_list_filters:
                required = dict(item.split("=", 1) for item in labels if "=" in item)
                rows = [s for s in rows if all(s.get("labels", {}).get(k) == v for k, v in required.items())]
            rows.sort(key=lambda row: row["id"], reverse=True)
            limit = int(query.get("limit", ["50"])[0])
            offset = int(query.get("offset", ["0"])[0])
            selected = rows[offset:offset + limit]
            return self.reply(200, {"sandboxes": selected, "has_more": offset + limit < len(rows)})
        if method == "GET" and path == "/v1/quota":
            used = self.live()

            def q(n):
                return {"sandboxes": n, "vcpu": n * 2, "memory_gib": n * 6}

            project_room = self.quota_limit - used
            response = {"limits": q(self.quota_limit), "usage": q(used),
                        "available": q(project_room)}
            if self.api_key_limit is not None:
                key_room = max(0, self.api_key_limit - used)
                response["api_key"] = {"limits": q(self.api_key_limit), "usage": q(used),
                                       "available": q(key_room)}
            return self.reply(200, response)
        if method == "GET" and path == "/v1/usage":
            return self.reply(200, {"groups": [{"label": query["group_by"][0], "value": v, "cost_usd": "0.01"}
                                               for v in {s["labels"].get("conformance_run") for s in self.sandboxes.values()}]})
        if method == "POST" and parts[:2] == ["v1", "sandboxes"] and len(parts) == 4 and parts[3] == "snapshots":
            snapshot_id = f"snap{len(self.snapshots)}"
            self.snapshots[snapshot_id] = {"id": snapshot_id, "state": "ready", "source_id": parts[2]}
            if self.lose_snapshot_response:
                return self.reply(0, {"error_code": "response_lost"})
            return self.reply(202, self.snapshots[snapshot_id])
        if method in {"GET", "DELETE"} and len(parts) == 3 and parts[:2] == ["v1", "snapshots"]:
            snapshot = self.snapshots.get(parts[2])
            if snapshot is None:
                return self.reply(404, {"detail": {"error": "snapshot_not_found"}})
            if method == "DELETE":
                if self.reject_snapshot_delete:
                    return self.reply(503, {"detail": {"error": "snapshot_delete_rejected"}})
                snapshot["state"] = "deleting"
                self.snapshot_polls[parts[2]] = 0
                return self.reply(202, snapshot)
            if snapshot["state"] == "deleting":
                self.snapshot_polls[parts[2]] += 1
                if self.snapshot_polls[parts[2]] > self.snapshot_delete_delay_polls:
                    snapshot["state"] = "deleted"
            return self.reply(200, snapshot)
        if parts[:2] == ["v1", "sandboxes"] and len(parts) >= 3:
            sandbox = self.sandboxes.get(parts[2])
            if method == "DELETE" and len(parts) == 3:
                if "Idempotency-Key" not in headers:
                    return self.reply(422, {"detail": {"error": "invalid_idempotency_key"}})
                if sandbox is None:
                    return self.reply(404, {"detail": {"error": "sandbox_not_found"}})
                if self.reject_delete:
                    return self.reply(503, {"detail": {"error": "delete_rejected"}})
                if sandbox["state"] in {"deleting", "deleted"}:
                    return self.reply(self.second_delete_status, {"id": parts[2], "state": "deleted"})
                sandbox["state"] = "deleting"
                sandbox["cleanup_state"] = "pending"
                self.delete_polls[parts[2]] = 0
                return self.reply(202, sandbox)
            if method == "GET" and len(parts) == 3:
                if sandbox and sandbox["state"] == "deleting":
                    self.delete_polls[parts[2]] += 1
                    if self.delete_polls[parts[2]] > self.delete_delay_polls:
                        sandbox["state"] = "deleted"
                        sandbox["cleanup_state"] = "confirmed"
                        self.deleted.append(parts[2])
                return self.reply(200, sandbox) if sandbox else self.reply(404, {"error_code": "sandbox_not_found"})
            if parts[3:] == ["lifetime"]:
                sandbox["lifetime_deadline_at"] = "2026-10-01T12:10:00+00:00"
                return self.reply(200, sandbox)
            if parts[3:] == ["exec"]:
                payload["sandbox_id"] = parts[2]
                return self.exec(payload)
            if parts[3:] == ["execs"] and method == "POST":
                return self.start_exec(payload)
            if parts[3:4] == ["execs"] and len(parts) == 5:
                return self.background_exec(method, parts[4], query)
            if parts[3:] == ["processes"] and method == "POST":
                return self.reply(202, {"process_id": f"p{len(self.calls)}"})
        return self.reply(404, {"error_code": "not_in_fake"})

    @staticmethod
    def route(method: str, parts: list[str]) -> tuple[str, str] | None:
        if parts[:2] != ["v1", "sandboxes"]:
            return None
        if len(parts) == 2:
            return method, "sandboxes"
        if len(parts) == 3:
            return method, "sandbox"
        return method, parts[3]

    @staticmethod
    def stdout_for(command) -> str:
        text = command if isinstance(command, str) else " ".join(command)
        if "6*7" in text:
            return "42\n"
        if "cat /work/probe" in text:
            return "ok\n"
        if "docker network ls" in text:
            return f"{C.Config.nested_networks}\n"
        return ""

    def exec(self, payload) -> Response:
        self.sync_exec_timeouts.append(payload["timeout_seconds"])
        if payload["timeout_seconds"] > SYNC_EXEC_MAX_SECONDS:
            # The API refuses it before anything starts (a request that sends
            # nothing for 60 s is closed, so the synchronous cap is 45 s).
            return self.reply(422, {"error_code": "exec_too_long_for_sync"})
        command = payload["command"]
        if command == ["sleep", "60"]:
            self.clock.now += payload["timeout_seconds"]
            return self.reply(200, {"exit_code": -1, "stdout": "", "stderr": "", "timed_out": True})
        text = command if isinstance(command, str) else " ".join(command)
        shell_command = command[-1] if isinstance(command, list) and command[:2] == ["sh", "-c"] else text
        sandbox_id = payload.get("sandbox_id")
        if shell_command.startswith("head -c 4194304 /dev/urandom"):
            if sandbox_id:
                self.files.setdefault(sandbox_id, {})["/tmp/state.bin"] = self.parent_data
            return self.reply(200, {"exit_code": 0, "stdout": f"{self.parent_digest} /tmp/state.bin\n", "stderr": ""})
        write = re.fullmatch(r"printf '%s\\n' '([^']+)' > (.+)", shell_command)
        if write and sandbox_id:
            store = self.files.setdefault(sandbox_id, {})
            if self.shared_filesystem:
                shared = self.files.setdefault("shared", {})
                store = shared
            store[shlex.split(write.group(2))[0]] = write.group(1) + "\n"
            return self.reply(200, {"exit_code": 0, "stdout": "", "stderr": ""})
        read = re.fullmatch(r"cat (.+?) && sha256sum (.+)", shell_command)
        if read:
            sentinel_path, state_path = (shlex.split(part)[0] for part in read.groups())
            store = self.files.get("shared", {}) if self.shared_filesystem else self.files.get(sandbox_id, {})
            if sentinel_path not in store or state_path not in store:
                return self.reply(200, {"exit_code": 1, "stdout": "", "stderr": "missing"})
            digest = hashlib.sha256(store[state_path].encode()).hexdigest()
            return self.reply(200, {"exit_code": 0, "stdout": f"{store[sentinel_path]}{digest}  {state_path}\n", "stderr": ""})
        missing = re.fullmatch(r"test ! -e (.+)", shell_command)
        if missing:
            store = self.files.get("shared", {}) if self.shared_filesystem else self.files.get(sandbox_id, {})
            path = shlex.split(missing.group(1))[0]
            return self.reply(200, {"exit_code": 0 if path not in store else 1, "stdout": "", "stderr": ""})
        stdout = "42\n" if "6*7" in shell_command else ""
        return self.reply(200, {"exit_code": 0, "stdout": stdout, "stderr": "", "timed_out": False})

    def start_exec(self, payload) -> Response:
        exec_id = f"ex{len(self.background)}"
        self.background[exec_id] = {"payload": payload, "ends_at": self.clock.now + self.background_run_s}
        return self.reply(202, {"exec_id": exec_id, "state": "running", "exit_code": None,
                                "stdout": None, "stderr": None, "timed_out": False})

    def background_exec(self, method, exec_id, query) -> Response:
        job = self.background[exec_id]
        if method == "DELETE":
            self.stopped_execs.append(exec_id)
            job["state"] = "killed"
            return self.reply(200, {"exec_id": exec_id, "state": "killed", "exit_code": None,
                                    "stdout": "", "stderr": "", "timed_out": False})
        wait = int(query.get("wait", ["0"])[0])
        assert wait <= 25  # the API's maximum
        if self.background_never_ends or self.clock.now + wait < job["ends_at"]:
            self.clock.now += wait
            return self.reply(200, {"exec_id": exec_id, "state": "running", "exit_code": None,
                                    "stdout": None, "stderr": None, "timed_out": False})
        self.clock.now = max(self.clock.now, job["ends_at"])
        return self.reply(200, {"exec_id": exec_id, "state": "exited", "exit_code": 0,
                                "stdout": self.stdout_for(job["payload"]["command"]), "stderr": "",
                                "timed_out": False})

    def live(self) -> int:
        return sum(1 for s in self.sandboxes.values() if s["state"] != "deleted")


def make(**fake_args):
    clock = FakeClock()
    fake = FakeCathedral(clock, **fake_args)
    api = Api("https://fake.test", "cat_sk_test", transport=fake, clock=clock, sleep=clock.sleep)
    return api, fake


def by_id(report):
    return {r["id"]: r for r in report["results"]}


def test_percentile_picks_nearest_rank():
    assert C.percentile([5, 1, 3], 50) == 3
    assert C.percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95) == 10
    assert C.percentile([7], 95) == 7


def test_shared_state_checks_run_last():
    ids = [c.id for c in ordered(C.CHECKS, None)]
    assert ids[0] == "create.first"
    assert ids[-2:] == ["snapshot.fork", "quota.full_429"]


def test_core_checks_pass_against_a_conforming_api():
    api, _ = make()
    only = {"create.first", "create.cached", "create.idempotent", "exec.latency", "exec.forms",
            "exec.timeout", "lifecycle.extend", "lifecycle.labels", "lifecycle.delete",
            "quota.visible", "quota.minimum", "usage.by_label"}
    report = run(api, C.Config(samples=2, exec_samples=5), only)
    failing = {i: r for i, r in by_id(report).items() if r["status"] != "pass"}
    assert failing == {}
    assert report["passed"] is True


def test_slow_exec_fails_latency_threshold():
    api, _ = make(latency=0.3)
    report = run(api, C.Config(exec_samples=5), {"create.first", "exec.latency"})
    result = by_id(report)["exec.latency"]
    assert result["status"] == "fail"
    assert result["measured"]["p50_ms"] >= 200


def test_second_delete_must_be_2xx():
    api, _ = make(second_delete_status=404)
    report = run(api, C.Config(), {"lifecycle.delete"})
    assert by_id(report)["lifecycle.delete"]["status"] == "fail"
    assert by_id(report)["lifecycle.delete"]["measured"]["second"] == 404


def test_small_quota_fails_affine_minimum():
    api, _ = make(quota_limit=5)
    report = run(api, C.Config(), {"quota.minimum"})
    assert by_id(report)["quota.minimum"]["status"] == "fail"
    assert "below minimum" in by_id(report)["quota.minimum"]["detail"]


def test_full_quota_answers_429_immediately():
    api, fake = make(quota_limit=4)
    report = run(api, C.Config(max_fill=10), {"quota.full_429"}, strict=True)
    result = by_id(report)["quota.full_429"]
    assert result["status"] == "pass", result
    assert result["measured"]["filled"] == 4
    assert fake.live() == 0  # cleanup removed every filler


def test_full_project_quota_requires_successful_fill_and_project_error_code():
    api, _ = make(quota_limit=4, quota_error="sandbox_key_quota_exceeded")
    report = run(api, C.Config(max_fill=10), {"quota.full_429"}, strict=True)
    result = by_id(report)["quota.full_429"]
    assert result["status"] == "fail"
    assert result["measured"]["error_code"] == "sandbox_key_quota_exceeded"


def test_generic_rate_limit_429_is_not_project_quota_proof():
    api, _ = make(quota_limit=2, quota_error="rate_limited")
    result = by_id(run(api, C.Config(max_fill=10), {"quota.full_429"}, strict=True))["quota.full_429"]
    assert result["status"] == "fail"
    assert result["measured"]["status"] == 429
    assert result["measured"]["error_code"] == "rate_limited"


def test_full_project_quota_skips_when_key_quota_is_lower():
    api, _ = make(quota_limit=8, api_key_limit=2)
    result = by_id(run(api, C.Config(max_fill=10), {"quota.full_429"}))["quota.full_429"]
    assert result["status"] == "skip"
    assert "API-key quota" in result["detail"]


def test_full_project_quota_fails_if_any_filler_create_fails():
    api, fake = make(quota_limit=1, create_fails=True)
    result = by_id(run(api, C.Config(max_fill=10), {"quota.full_429"}))["quota.full_429"]
    assert result["status"] == "fail"
    assert result["measured"]["filled"] == 0
    assert fake.live() == 0


def test_quota_fill_is_bounded_by_max_fill():
    api, fake = make(quota_limit=500)
    report = run(api, C.Config(max_fill=10), {"quota.full_429"})
    assert by_id(report)["quota.full_429"]["status"] == "skip"
    assert len(fake.sandboxes) == 0


def test_failed_create_skips_dependent_checks_and_fails_the_run():
    api, _ = make(create_fails=True)
    report = run(api, C.Config(), {"create.first", "exec.latency"})
    results = by_id(report)
    assert results["create.first"]["status"] == "fail"
    assert results["exec.latency"]["status"] == "skip"
    assert "no_capacity" in results["exec.latency"]["detail"]
    assert report["passed"] is False


def test_later_tier_gates_only_when_strict():
    api, _ = make(shared_filesystem=True)
    report = run(api, C.Config(), {"create.first", "snapshot.fork"})
    assert by_id(report)["snapshot.fork"]["status"] == "fail"
    assert report["passed"] is True
    api, _ = make(shared_filesystem=True)
    assert run(api, C.Config(), {"create.first", "snapshot.fork"}, strict=True)["passed"] is False


def test_cleanup_deletes_everything_the_run_created():
    api, fake = make()
    run(api, C.Config(samples=2), {"create.first", "create.cached", "create.idempotent", "lifecycle.delete"})
    assert fake.live() == 0


def test_cleanup_refuses_foreign_sentinel_but_reports_it():
    api, fake = make(foreign_sentinel=True, ignore_list_filters=True)
    ctx = C.Context(api, C.Config(run_id="owned-run"))
    assert ctx.create().ok
    cleanup = ctx.cleanup()
    assert cleanup["ok"] is False
    assert "foreign" not in fake.deleted
    assert fake.sandboxes["foreign"]["state"] == "running"
    assert fake.live() == 1


def test_cleanup_paginates_before_deleting_and_confirms_delayed_delete():
    api, fake = make(delete_delay_polls=2)
    ctx = C.Context(api, C.Config(run_id="many-run"))
    for _ in range(105):
        assert ctx.create().ok
    cleanup = ctx.cleanup()
    assert cleanup["ok"] is True
    assert cleanup["deleted"] == 105
    assert fake.live() == 0


def test_cleanup_waits_for_snapshot_deletion_confirmation():
    api, fake = make(snapshot_delete_delay_polls=2)
    ctx = C.Context(api, C.Config(run_id="snapshot-run"))
    fake.snapshots["snap-only"] = {"id": "snap-only", "state": "ready"}
    ctx.snapshots.append("snap-only")
    cleanup = ctx.cleanup()
    assert cleanup["ok"] is True
    assert fake.snapshots["snap-only"]["state"] == "deleted"
    assert fake.snapshot_polls["snap-only"] == 3


def test_cleanup_fails_when_snapshot_delete_is_rejected():
    api, fake = make(reject_snapshot_delete=True)
    ctx = C.Context(api, C.Config(run_id="snapshot-run"))
    fake.snapshots["snap-only"] = {"id": "snap-only", "state": "ready"}
    ctx.snapshots.append("snap-only")
    cleanup = ctx.cleanup()
    assert cleanup["ok"] is False
    assert cleanup["failed"] == ["snapshot:snap-only"]
    assert fake.snapshots["snap-only"]["state"] == "ready"


def test_lost_snapshot_response_blocks_success_even_without_strict():
    api, fake = make(lose_snapshot_response=True)
    report = run(api, C.Config(), {"create.first", "snapshot.fork"})
    assert by_id(report)["snapshot.fork"]["status"] == "fail"
    assert report["passed"] is False
    assert report["cleanup"]["ok"] is False
    assert any("snapshot create outcome is unknown" in error for error in report["cleanup"]["errors"])
    assert len(fake.snapshots) == 1
    assert fake.snapshots["snap0"]["state"] == "ready"


def test_cleanup_listing_failure_gates_run_after_later_tier_check():
    api, _ = make(list_status=503)
    report = run(api, C.Config(), {"quota.minimum"})
    assert by_id(report)["quota.minimum"]["status"] == "pass"
    assert report["passed"] is False
    assert report["cleanup"]["listing_complete"] is False
    assert any("list at offset 0 failed" in error for error in report["cleanup"]["errors"])


def test_lost_create_and_failed_list_are_unresolved_and_gate_run():
    api, fake = make(lose_create_response=True, list_status=503)
    report = run(api, C.Config(), {"create.first"})
    assert report["passed"] is False
    assert fake.live() == 1
    assert report["cleanup"]["ok"] is False
    assert report["cleanup"]["deleted"] == 0


def test_malformed_list_cannot_be_reported_as_clean():
    api, _ = make(malformed_list=True)
    report = run(api, C.Config(), {"quota.minimum"})
    assert report["passed"] is False
    assert report["cleanup"]["ok"] is False
    assert any("malformed page" in error for error in report["cleanup"]["errors"])


def test_snapshot_fork_checks_cross_fork_sentinels_and_confirmed_parent_deletion():
    api, fake = make()
    report = run(api, C.Config(fork_count=3), {"create.first", "snapshot.fork"}, strict=True)
    result = by_id(report)["snapshot.fork"]
    assert result["status"] == "pass", result
    assert result["measured"]["parent_delete_confirmed"] is True
    assert result["measured"]["alive_after_parent_delete"] == 3
    assert report["cleanup"]["ok"] is True
    assert report["cleanup"]["deleted"] == 5  # parent, snapshot and three forks
    assert fake.live() == 0  # run cleanup removes all forks after the check


def test_snapshot_fork_rejects_shared_storage():
    api, _ = make(shared_filesystem=True)
    report = run(api, C.Config(fork_count=3), {"create.first", "snapshot.fork"}, strict=True)
    result = by_id(report)["snapshot.fork"]
    assert result["status"] == "fail"
    assert result["measured"]["independent"] is False


def test_fork_sentinel_commands_work_in_shell_and_fake(tmp_path):
    marker = "fork-0-marker"
    state_path = tmp_path / "state.bin"
    state_path.write_text("pre-fork-state-bytes")
    write, read, _ = C._fork_sentinel_commands(0, marker, directory=str(tmp_path))
    shasum = shutil.which("shasum")
    assert shasum is not None
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sha256sum = bin_dir / "sha256sum"
    sha256sum.write_text(f'#!/bin/sh\nexec "{shasum}" -a 256 "$@"\n')
    sha256sum.chmod(0o755)
    shell_env = {"PATH": f"{bin_dir}:/opt/homebrew/bin:/usr/bin:/bin"}

    local_write = subprocess.run(["sh", "-c", write], capture_output=True, text=True,
                                 check=False, env=shell_env)
    assert local_write.returncode == 0
    local_read = subprocess.run(["sh", "-c", read], capture_output=True, text=True,
                                check=False, env=shell_env)
    assert local_read.returncode == 0
    assert local_read.stdout.splitlines()[0] == marker
    assert local_read.stdout.splitlines()[1].split()[0] == hashlib.sha256(b"pre-fork-state-bytes").hexdigest()

    api, fake = make()
    fake.sandboxes["sb-test"] = {"id": "sb-test", "state": "running", "labels": {"conformance_run": "test"}}
    fake.files["sb-test"] = {str(state_path): "pre-fork-state-bytes"}
    fake_write = api.exec("sb-test", ["sh", "-c", write])
    fake_read = api.exec("sb-test", ["sh", "-c", read])
    assert fake_write.ok and fake_write.json()["exit_code"] == 0
    assert fake_read.ok and fake_read.json()["exit_code"] == 0
    assert fake_read.json()["stdout"] == local_read.stdout


def test_snapshot_fork_requires_parent_delete_confirmation_before_survivors():
    api, _ = make(reject_delete=True)
    report = run(api, C.Config(fork_count=2), {"create.first", "snapshot.fork"}, strict=True)
    result = by_id(report)["snapshot.fork"]
    assert result["status"] == "fail"
    assert result["measured"]["parent_delete_confirmed"] is False
    assert result["measured"]["alive_after_parent_delete"] is None


def test_computesdk_score_matches_their_formula():
    # 1 s everywhere, all succeed: 100 x (1 - 0.1) = 90.
    assert C.computesdk_score([1000.0] * 10, 10) == 90.0
    # Half fail: the success rate halves the score.
    assert C.computesdk_score([1000.0] * 5, 10) == 45.0
    # Slower than the 10 s ceiling floors at zero.
    assert C.computesdk_score([20_000.0], 1) == 0.0
    assert C.computesdk_score([], 10) == 0.0


def test_burst_tti_measures_to_first_command():
    api, _ = make()
    report = run(api, C.Config(burst=5), {"create.burst_tti"})
    result = by_id(report)["create.burst_tti"]
    assert result["measured"]["succeeded"] == 5
    assert result["status"] == "pass", result


def test_delete_sends_a_fresh_idempotency_key():
    api, fake = make()
    report = run(api, C.Config(samples=2), {"create.first", "create.cached", "lifecycle.delete"})
    assert by_id(report)["lifecycle.delete"]["status"] == "pass"
    assert report["cleanup"]["failed"] == []
    assert fake.delete_keys and all(fake.delete_keys)
    assert len(set(fake.delete_keys)) == len(fake.delete_keys)  # one key per DELETE
    assert fake.live() == 0


def test_the_fake_refuses_a_delete_without_a_key_as_the_api_does():
    _, fake = make()
    created = fake("POST", "https://fake.test/v1/sandboxes", {"Idempotency-Key": "conf-k-1",
                   "Content-Type": "application/json"}, json.dumps({"labels": {}}).encode(), 5)
    sandbox_id = created.json()["id"]
    assert fake("DELETE", f"https://fake.test/v1/sandboxes/{sandbox_id}", {}, None, 5).status == 422
    assert fake.live() == 1


def test_no_synchronous_exec_exceeds_the_api_cap():
    api, fake = make()
    report = run(api, C.Config(samples=1, exec_samples=2, burst=2), None, strict=True)
    assert fake.sync_exec_timeouts
    assert max(fake.sync_exec_timeouts) <= SYNC_EXEC_MAX_SECONDS
    # No check asks for a synchronous exec past the cap (Api.exec refuses it).
    assert [r["id"] for r in report["results"] if "synchronous exec takes" in r["detail"]] == []
    # The nested Docker steps that may take minutes ran as background execs.
    assert sorted(job["payload"]["timeout_seconds"] for job in fake.background.values()) == [300, 300]
    assert by_id(report)["docker.nested"]["status"] == "pass", by_id(report)["docker.nested"]


def test_a_synchronous_exec_over_the_cap_is_refused_before_it_is_sent():
    api, fake = make()
    with pytest.raises(ValueError, match="up to 45"):
        api.exec("sb0", ["true"], timeout_seconds=SYNC_EXEC_MAX_SECONDS + 1)
    assert fake.calls == []
    api.exec("sb0", ["true"], timeout_seconds=SYNC_EXEC_MAX_SECONDS)
    assert fake.sync_exec_timeouts == [SYNC_EXEC_MAX_SECONDS]


def test_a_long_command_runs_in_the_background_and_is_polled_to_its_end():
    api, fake = make(background_run_s=70)
    reply = api.run("sb0", ["sh", "-c", "cat /work/probe"], timeout_seconds=300)
    assert reply.ok and reply.json()["state"] == "exited"
    assert reply.json()["exit_code"] == 0 and reply.json()["stdout"] == "ok\n"
    assert fake.sync_exec_timeouts == []
    polls = [path for method, path in fake.calls if method == "GET"]
    assert polls == ["/v1/sandboxes/sb0/execs/ex0"] * 3  # 25 + 25 + 20 s of a 70 s command


def test_a_background_exec_that_never_ends_is_stopped():
    api, fake = make(background_never_ends=True)
    reply = api.run("sb0", ["sleep", "infinity"], timeout_seconds=60)
    assert reply.status == 0 and b"did not end" in reply.data
    assert fake.stopped_execs == ["ex0"]


def test_burst_deletes_its_sandboxes_as_soon_as_they_are_measured():
    api, fake = make()
    ctx = C.Context(api, C.Config(burst=10))
    status, measured, _ = C.create_burst_tti(ctx)
    assert status == "pass" and measured["succeeded"] == 10
    # Before the end-of-run cleanup: none of the ten is left running.
    assert fake.live() == 0 and len(fake.deleted) == 10
