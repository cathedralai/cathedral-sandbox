"""Conformance suite logic against an in-memory fake of the sandbox API.

The fake answers just enough of the contract for each check. Live behavior is
what the suite itself measures; these tests pin the verdict logic: thresholds,
skips, gating by tier, run order and cleanup.
"""

from __future__ import annotations

import json
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
                 background_run_s: float = 40.0, background_never_ends: bool = False):
        self.clock = clock
        self.latency = latency
        self.quota_limit = quota_limit
        self.second_delete_status = second_delete_status
        self.create_fails = create_fails
        self.background_run_s = background_run_s
        self.background_never_ends = background_never_ends
        self.sandboxes: dict[str, dict] = {}
        self.keys: dict[str, str] = {}
        self.deleted: list[str] = []
        self.delete_keys: list[str | None] = []
        self.sync_exec_timeouts: list[int] = []
        self.background: dict[str, dict] = {}
        self.stopped_execs: list[str] = []
        self.calls: list[tuple[str, str]] = []

    def reply(self, status: int, body=None, headers=None) -> Response:
        data = b"" if body is None else json.dumps(body).encode()
        return Response(status, headers or {}, data, self.latency)

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
            if self.live() >= self.quota_limit:
                return self.reply(429, {"error_code": "quota_exceeded"}, {"Retry-After": "5"})
            sandbox_id = f"sb{len(self.sandboxes)}"
            self.sandboxes[sandbox_id] = {"id": sandbox_id, "state": "running", "labels": payload["labels"],
                                          "lifetime_deadline_at": "2026-10-01T12:00:00+00:00"}
            self.keys[key] = sandbox_id
            return self.reply(202, self.sandboxes[sandbox_id])
        if method == "GET" and path == "/v1/sandboxes":
            return self.reply(200, {"sandboxes": [s for s in self.sandboxes.values() if s["state"] != "deleted"]})
        if method == "GET" and path == "/v1/quota":
            used = self.live()

            def q(n):
                return {"sandboxes": n, "vcpu": n * 2, "memory_gib": n * 6}

            return self.reply(200, {"limits": q(self.quota_limit), "usage": q(used),
                                    "available": q(self.quota_limit - used)})
        if method == "GET" and path == "/v1/usage":
            return self.reply(200, {"groups": [{"label": query["group_by"][0], "value": v, "cost_usd": "0.01"}
                                               for v in {s["labels"].get("conformance_run") for s in self.sandboxes.values()}]})
        if parts[:2] == ["v1", "sandboxes"] and len(parts) >= 3:
            sandbox = self.sandboxes.get(parts[2])
            if method == "DELETE" and len(parts) == 3:
                if sandbox is None or sandbox["state"] == "deleted":
                    return self.reply(self.second_delete_status, {"id": parts[2], "state": "deleted"})
                sandbox["state"] = "deleted"
                self.deleted.append(parts[2])
                return self.reply(202, sandbox)
            if method == "GET" and len(parts) == 3:
                return self.reply(200, sandbox) if sandbox else self.reply(404, {"error_code": "sandbox_not_found"})
            if parts[3:] == ["lifetime"]:
                sandbox["lifetime_deadline_at"] = "2026-10-01T12:10:00+00:00"
                return self.reply(200, sandbox)
            if parts[3:] == ["exec"]:
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
            # A request that sends nothing for 60 s is closed; the cap is 45 s.
            return self.reply(422, {"error_code": "exec_timeout_too_long"})
        command = payload["command"]
        if command == ["sleep", "60"]:
            self.clock.now += payload["timeout_seconds"]
            return self.reply(200, {"exit_code": -1, "stdout": "", "stderr": "", "timed_out": True})
        return self.reply(200, {"exit_code": 0, "stdout": self.stdout_for(command), "stderr": "",
                                "timed_out": False})

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
    api, _ = make()
    report = run(api, C.Config(), {"create.first", "snapshot.fork"})
    assert by_id(report)["snapshot.fork"]["status"] == "fail"  # the fake has no snapshots
    assert report["passed"] is True
    api, _ = make()
    assert run(api, C.Config(), {"create.first", "snapshot.fork"}, strict=True)["passed"] is False


def test_cleanup_deletes_everything_the_run_created():
    api, fake = make()
    run(api, C.Config(samples=2), {"create.first", "create.cached", "create.idempotent", "lifecycle.delete"})
    assert fake.live() == 0


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
