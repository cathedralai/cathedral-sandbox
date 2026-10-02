"""Tests for the Cathedral compute sandbox API request contracts.

Covers the sandbox create/exec/lifecycle/fork/quota/idempotency surface
(``requirements.txt`` §§3.1-3.12) as encoded in :mod:`cathedral.sandbox_api`.
Uses Cathedral's own configuration variables (``CATHEDRAL_API_URL``,
``CATHEDRAL_KEY_QUOTAS``) so the same env that drives the operator tooling and
the audit facade drives these checks.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cathedral import sandbox_api
from cathedral.sandbox_api import (
    ApiKey,
    BuildSpec,
    CreateSandboxRequest,
    ExecRequest,
    ExecResult,
    ExposeRequest,
    FileGet,
    ForkPlan,
    ImageSource,
    Metrics,
    NetworkPatch,
    NetworkSpec,
    PrefetchRequest,
    Pricing,
    QuotaDecision,
    QuotaLimits,
    QuotaUsage,
    Resources,
    SandboxContractError,
    StatResult,
    StatusReport,
    evaluate_quota,
    gc_deadline,
    idempotency_digest,
    is_collectable,
    key_quota_for,
    operation_id,
    parse_byte_range,
    snapshot_gib_months,
    validate_idempotency_key,
)

# A canonical Harbor/SWE-bench style reference with the mutable :latest tag the
# sandbox create payload sends (and which workload.ImageReference would reject).
LATEST_IMAGE = "swebench/sweb.eval.x86_64.django__django-12345:latest"
PINNED_IMAGE = "registry.cathedral.computer/cathedral/worker@sha256:" + "a" * 64


def _create(**overrides) -> CreateSandboxRequest:
    values = {"image": ImageSource(image=LATEST_IMAGE)}
    values.update(overrides)
    return CreateSandboxRequest(**values)


# ---------------------------------------------------------------- §3.1 image sources
def test_image_source_accepts_mutable_tag() -> None:
    src = ImageSource(image=LATEST_IMAGE)
    assert src.tag == "latest"
    assert src.digest is None


def test_image_source_accepts_pinned_digest() -> None:
    src = ImageSource(image=PINNED_IMAGE)
    assert src.digest == "sha256:" + "a" * 64
    assert src.tag is None


def test_image_source_rejects_scheme_and_blank() -> None:
    for bad in ("https://cathedral.computer/x:latest", "", "UPPER/repo:latest"):
        with pytest.raises(SandboxContractError, match="invalid_image_reference"):
            ImageSource(image=bad)


def test_image_source_registry_auth_requires_both_fields() -> None:
    ImageSource(image=LATEST_IMAGE, registry_auth={"username": "u", "password": "p"})
    with pytest.raises(SandboxContractError, match="invalid_registry_auth"):
        ImageSource(image=LATEST_IMAGE, registry_auth={"username": "u"})


def test_image_source_never_leaks_credentials_to_document() -> None:
    doc = ImageSource(image=LATEST_IMAGE, registry_auth={"username": "u", "password": "p"}).to_document()
    assert doc["registry_auth"] is True  # presence flag only, no secret value
    assert "p" not in repr(dict(doc))


# ---------------------------------------------------------------- §3.1b build
def test_build_spec_content_hash_is_stable_cache_key() -> None:
    a = BuildSpec(dockerfile="FROM scratch\n", context_tar_url="https://x/ctx.tgz")
    b = BuildSpec(dockerfile="FROM scratch\n", context_tar_url="https://x/ctx.tgz")
    c = BuildSpec(dockerfile="FROM alpine\n", context_tar_url="https://x/ctx.tgz")
    assert a.content_hash == b.content_hash
    assert a.content_hash != c.content_hash


def test_build_spec_requires_context() -> None:
    with pytest.raises(SandboxContractError, match="invalid_build"):
        BuildSpec(dockerfile="FROM scratch\n")


# ---------------------------------------------------------------- §3.6 resources
def test_resources_enforce_numeric_bounds() -> None:
    Resources(vcpu=2, memory_gib=8, disk_gib=20)
    for kwargs in ({"vcpu": 0}, {"vcpu": 17}, {"memory_gib": 0}, {"disk_gib": 4}, {"vcpu": True}):
        with pytest.raises(SandboxContractError, match="invalid_resources"):
            Resources(**kwargs)


# ---------------------------------------------------------------- §3.7 network
def test_network_spec_modes_and_allowlist() -> None:
    NetworkSpec(mode="public")
    NetworkSpec(mode="none")
    NetworkSpec(mode="allowlist", allow=("api.cathedral.computer", "pypi.org"))
    with pytest.raises(SandboxContractError, match="invalid_network_mode"):
        NetworkSpec(mode="bridge")
    with pytest.raises(SandboxContractError, match="invalid_network_allowlist"):
        NetworkSpec(mode="allowlist", allow=())


# ---------------------------------------------------------------- §3.1/§3.4/§3.5 create
def test_create_requires_exactly_one_source() -> None:
    _create()  # image only
    CreateSandboxRequest(build=BuildSpec(dockerfile="FROM scratch\n", context_multipart=True))
    CreateSandboxRequest(snapshot_id="snap-1")
    with pytest.raises(SandboxContractError, match="invalid_source"):
        CreateSandboxRequest()  # no source
    with pytest.raises(SandboxContractError, match="invalid_source"):
        CreateSandboxRequest(image=ImageSource(image=LATEST_IMAGE), snapshot_id="snap-1")


def test_create_fork_count_bounds_and_flag() -> None:
    assert _create().count == 1
    fork = _create(image=None, snapshot_id="snap-1", count=16)
    assert fork.is_fork and fork.total_vcpu == fork.resources.vcpu * 16
    with pytest.raises(SandboxContractError, match="invalid_count"):
        _create(image=None, snapshot_id="snap-1", count=sandbox_api.FORK_MAX_COUNT + 1)


def test_create_ttl_bounds() -> None:
    _create(ttl_seconds=sandbox_api.TTL_MAX_SECONDS)
    with pytest.raises(SandboxContractError, match="invalid_ttl"):
        _create(ttl_seconds=sandbox_api.TTL_MAX_SECONDS + 1)


def test_create_idle_timeout_bounds_and_document() -> None:
    # §3.10/§3.11: an idle window is optional but, when set, bounded like the TTL.
    req = _create(idle_timeout_seconds=60)
    assert req.to_document()["idle_timeout_seconds"] == 60
    assert _create().to_document()["idle_timeout_seconds"] is None
    with pytest.raises(SandboxContractError, match="invalid_idle_timeout"):
        _create(idle_timeout_seconds=0)
    with pytest.raises(SandboxContractError, match="invalid_idle_timeout"):
        _create(idle_timeout_seconds=sandbox_api.TTL_MAX_SECONDS + 1)


def test_create_labels_and_env_validation() -> None:
    req = _create(labels={"job": "swebench"}, env={"SECRET": "hunter2"})
    assert req.labels["job"] == "swebench"
    # §3.17: the admitted document records env names, never values.
    doc = req.to_document()
    assert doc["env_keys"] == ["SECRET"]
    assert "hunter2" not in repr(dict(doc))
    with pytest.raises(SandboxContractError, match="invalid_env"):
        _create(env={"K": 1})  # type: ignore[dict-item]


# ---------------------------------------------------------------- §3.5 fork plan
def test_fork_plan_validates_count() -> None:
    ForkPlan(snapshot_id="snap-1", count=8)
    with pytest.raises(SandboxContractError, match="invalid_count"):
        ForkPlan(snapshot_id="snap-1", count=0)


# ---------------------------------------------------------------- §3.8 quota + 429
def test_evaluate_quota_admits_within_limits() -> None:
    limits = QuotaLimits(running_sandboxes=sandbox_api.MIN_RUNNING_SANDBOXES, vcpu=sandbox_api.MIN_VCPU, memory_gib=sandbox_api.MIN_MEMORY_GIB)
    decision = evaluate_quota(_create(), limits=limits, usage=QuotaUsage())
    assert isinstance(decision, QuotaDecision) and decision.admitted and decision.http_status == 202


def test_evaluate_quota_returns_429_with_retry_after_never_timeout() -> None:
    limits = QuotaLimits(running_sandboxes=500, vcpu=1000, memory_gib=3000)
    usage = QuotaUsage(running_sandboxes=500, vcpu=1000, memory_gib=3000)
    decision = evaluate_quota(_create(), limits=limits, usage=usage)
    assert decision.is_rate_limited and decision.http_status == 429
    assert decision.retry_after_seconds is not None  # a full quota is Retry-After, never a silent timeout


def test_evaluate_quota_respects_per_key_subquota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_KEY_QUOTAS", "ck_cathedral_demo:2")
    assert key_quota_for("ck_cathedral_demo") == 2
    limits = QuotaLimits(running_sandboxes=500, vcpu=1000, memory_gib=3000)
    usage = QuotaUsage(running_sandboxes=2, vcpu=2, memory_gib=8)
    decision = evaluate_quota(_create(), limits=limits, usage=usage, api_key="ck_cathedral_demo")
    assert decision.http_status == 429 and decision.reason == "key_subquota_exhausted"


# ---------------------------------------------------------------- §3.4 lifecycle / GC
def test_is_collectable_past_ttl_and_stalled_heartbeat() -> None:
    now = datetime(2026, 9, 30, tzinfo=timezone.utc)
    assert is_collectable(now, deadline_at=now - timedelta(seconds=1), last_heartbeat_at=None)
    assert not is_collectable(now, deadline_at=now + timedelta(hours=1), last_heartbeat_at=now)
    stalled = now - timedelta(seconds=sandbox_api.TTL_MAX_SECONDS + 1)
    assert is_collectable(now, deadline_at=now + timedelta(hours=1), last_heartbeat_at=stalled)


def test_gc_deadline_grace_window() -> None:
    expires = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    assert gc_deadline(expires) == expires + timedelta(seconds=sandbox_api.GC_GRACE_SECONDS)


# ---------------------------------------------------------------- §3.12 idempotency
def test_idempotency_key_grammar() -> None:
    validate_idempotency_key("cathedral-job_2026-09.30:a1")
    for bad in ("short", "x" * 129, "has spaces"):
        with pytest.raises(SandboxContractError, match="invalid_idempotency_key"):
            validate_idempotency_key(bad)


def test_idempotency_digest_is_content_stable() -> None:
    a = idempotency_digest("cathedral", "snap-1", 16)
    b = idempotency_digest("cathedral", "snap-1", 16)
    c = idempotency_digest("cathedral", "snap-1", 8)
    assert a == b and a != c


def test_operation_id_shape() -> None:
    op = operation_id()
    assert op.startswith("op_") and len(op) == 19


# ---------------------------------------------------------------- cathedral variables
def test_sandbox_api_base_derives_from_cathedral_api_url() -> None:
    assert sandbox_api.SANDBOX_API_BASE == f"{sandbox_api.CATHEDRAL_API_URL}/v1"


# ---------------------------------------------------------------- §3.2 exec


def test_exec_request_accepts_shell_and_argv() -> None:
    shell = ExecRequest(cmd="echo hi")
    assert shell.is_shell and shell.argv == ("bash", "-c", "echo hi")
    argv = ExecRequest(cmd=["python3", "-c", "print(1)"])
    assert not argv.is_shell and argv.argv == ("python3", "-c", "print(1)")


def test_exec_request_rejects_empty_and_bad_timeout() -> None:
    with pytest.raises(SandboxContractError, match="invalid_exec"):
        ExecRequest(cmd="")
    with pytest.raises(SandboxContractError, match="invalid_exec"):
        ExecRequest(cmd=[])
    with pytest.raises(SandboxContractError, match="invalid_timeout"):
        ExecRequest(cmd="true", timeout_seconds=sandbox_api.EXEC_MAX_TIMEOUT_SECONDS + 1)


def test_exec_result_document_is_stable() -> None:
    doc = ExecResult(exit_code=1, stdout="", stderr="boom", duration_ms=5, timed_out=False).to_document()
    assert doc["exit_code"] == 1 and doc["timed_out"] is False and doc["truncated"] is False


# ---------------------------------------------------------------- §3.3 files


def test_file_get_validates_max_bytes_and_range() -> None:
    FileGet(path="/work/x", max_bytes=100, range_start=0, range_end=9)
    with pytest.raises(SandboxContractError, match="invalid_max_bytes"):
        FileGet(path="/work/x", max_bytes=-1)
    with pytest.raises(SandboxContractError, match="invalid_range"):
        FileGet(path="/work/x", range_start=10, range_end=2)


def test_absolute_path_required() -> None:
    with pytest.raises(SandboxContractError, match="invalid_path"):
        FileGet(path="relative/x")
    with pytest.raises(SandboxContractError, match="invalid_path"):
        # '..' traversal is rejected even on an absolute path
        FileGet(path="/work/../etc/passwd")


def test_stat_result_document() -> None:
    doc = StatResult(is_dir=False, is_file=True, size=42, mode=0o644).to_document()
    assert doc == {"is_dir": False, "is_file": True, "size": 42, "mode": 0o644}


def test_parse_byte_range_forms() -> None:
    assert parse_byte_range(None, 100) is None
    assert parse_byte_range("bytes=0-9", 100) == (0, 9)
    assert parse_byte_range("bytes=90-", 100) == (90, 99)  # open-ended clamps to EOF
    with pytest.raises(SandboxContractError, match="range_not_satisfiable"):
        parse_byte_range("bytes=200-300", 100)


# ---------------------------------------------------------------- §3.7 / §3.9


def test_network_patch_requires_allowlist_entries() -> None:
    NetworkPatch(mode="allowlist", allow=("pypi.org",))
    with pytest.raises(SandboxContractError, match="invalid_network_allowlist"):
        NetworkPatch(mode="allowlist", allow=())


def test_expose_request_port_bounds() -> None:
    ExposeRequest(port=8080)
    with pytest.raises(SandboxContractError, match="invalid_port"):
        ExposeRequest(port=0)
    with pytest.raises(SandboxContractError, match="invalid_port"):
        ExposeRequest(port=70000)


def test_prefetch_request_validates_refs() -> None:
    PrefetchRequest(images=(LATEST_IMAGE,))
    with pytest.raises(SandboxContractError, match="invalid_image_reference"):
        PrefetchRequest(images=("https://bad/ref:latest",))


# ---------------------------------------------------------------- §3.13 / §3.14


def test_metrics_and_status_documents() -> None:
    m = Metrics(cpu_seconds=1.5, disk_bytes=100).to_document()
    assert m["cpu_seconds"] == 1.5 and m["deleted_at"] is None
    s = StatusReport(status="operational", create_latency_p50_ms=12, error_rate=0.0).to_document()
    assert s["create_latency_p50_ms"] == 12


def test_api_key_validation() -> None:
    ApiKey(key="ck_demo", project="p1", max_running=2)
    with pytest.raises(SandboxContractError, match="invalid_key"):
        ApiKey(key="", project="p1")
    with pytest.raises(SandboxContractError, match="invalid_key_quota"):
        ApiKey(key="ck", project="p1", max_running=-1)


# ---------------------------------------------------------------- §3.13 exec history


def test_exec_record_document() -> None:
    rec = sandbox_api.ExecRecord(
        command="make test", exit_code=1, duration_ms=4200, at=datetime(2026, 9, 30, tzinfo=timezone.utc)
    ).to_document()
    assert rec["command"] == "make test" and rec["exit_code"] == 1 and rec["duration_ms"] == 4200
    assert rec["at"].startswith("2026-09-30")


# ---------------------------------------------------------------- §3.16 pricing


def test_pricing_composition_and_reference_beats_target() -> None:
    pricing = Pricing()
    # cost is linear in vCPU-hours and GiB-hours, metered independently.
    assert pricing.cost_usd(vcpu_hours=2.0, gib_hours=0.0) == round(2.0 * pricing.vcpu_hour_usd, 6)
    assert pricing.cost_usd(vcpu_hours=0.0, gib_hours=8.0) == round(8.0 * pricing.gib_hour_usd, 6)
    # the Cathedral 1 vCPU / 4 GiB hour is at or below the Modal target (60% of Daytona).
    ref = pricing.reference_comparisons()
    assert ref["at_or_below_modal"] is True
    assert ref["cathedral_usd_per_hour"] <= sandbox_api.DAYTONA_REFERENCE_USD_PER_HOUR * (
        1 - sandbox_api.MODAL_TARGET_DISCOUNT
    ) + 1e-9


def test_pricing_rejects_negative_rate() -> None:
    with pytest.raises(SandboxContractError, match="invalid_pricing"):
        Pricing(vcpu_hour_usd=-0.01)


def test_snapshot_gib_months_scaling() -> None:
    # one GiB held for a full 30-day month is exactly one GiB-month.
    one_month_seconds = sandbox_api.HOURS_PER_MONTH * 3600
    assert round(snapshot_gib_months(1024 ** 3, one_month_seconds), 6) == 1.0
    # half a GiB for half a month -> 0.25 GiB-months.
    assert round(snapshot_gib_months(1024 ** 3 // 2, one_month_seconds / 2), 6) == 0.25


# ---------------------------------------------------------------- §3.5 snapshot retention + floor
def test_snapshot_record_default_ttl_and_validation() -> None:
    rec = sandbox_api.SnapshotRecord(snapshot_id="snap_1", size_bytes=10)
    assert rec.ttl_seconds == sandbox_api.SNAPSHOT_TTL_DEFAULT_SECONDS
    with pytest.raises(SandboxContractError, match="invalid_snapshot"):
        sandbox_api.SnapshotRecord(snapshot_id="snap_1", size_bytes=10, ttl_seconds=0)


def test_min_snapshots_floor_beats_daytona() -> None:
    # §3.5: we guarantee at least 1,000 snapshots per project (Daytona caps at 30).
    assert sandbox_api.MIN_SNAPSHOTS >= 1000
    assert 1 <= sandbox_api.SNAPSHOT_TTL_DEFAULT_SECONDS <= sandbox_api.SNAPSHOT_TTL_MAX_SECONDS
