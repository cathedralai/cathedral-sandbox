"""Conformance suite logic against an in-memory fake of the sandbox API.

The fake answers just enough of the contract for each check. Live behavior is
what the suite itself measures; these tests pin the verdict logic: thresholds,
skips, gating by tier, run order and cleanup.
"""

from __future__ import annotations

import json
import urllib.parse

from cathedral.conformance import checks as C
from cathedral.conformance.api import Api, Response
from cathedral.conformance.runner import ordered, run


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
                 second_delete_status: int = 202, create_fails: bool = False):
        self.clock = clock
        self.latency = latency
        self.quota_limit = quota_limit
        self.second_delete_status = second_delete_status
        self.create_fails = create_fails
        self.sandboxes: dict[str, dict] = {}
        self.keys: dict[str, str] = {}
        self.deleted: list[str] = []

    def reply(self, status: int, body=None, headers=None) -> Response:
        data = b"" if body is None else json.dumps(body).encode()
        return Response(status, headers or {}, data, self.latency)

    def __call__(self, method, url, headers, body, timeout) -> Response:
        self.clock.now += self.latency
        parsed = urllib.parse.urlparse(url)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        parts = path.strip("/").split("/")
        payload = json.loads(body) if body and headers.get("Content-Type") == "application/json" else None
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
        return self.reply(404, {"error_code": "not_in_fake"})

    def exec(self, payload) -> Response:
        command = payload["command"]
        if command == ["sleep", "60"]:
            self.clock.now += payload["timeout_seconds"]
            return self.reply(200, {"exit_code": -1, "stdout": "", "stderr": "", "timed_out": True})
        text = command if isinstance(command, str) else " ".join(command)
        stdout = "42\n" if "6*7" in text else ""
        return self.reply(200, {"exit_code": 0, "stdout": stdout, "stderr": "", "timed_out": False})

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
