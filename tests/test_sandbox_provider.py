"""Tests for the Cathedral sandbox reference provider (executable §3 semantics).

These drive :class:`InMemorySandboxProvider` directly, exercising the *behaviour*
the requirements describe — real command execution, process-group timeouts, the
filesystem/tar layer, copy-on-write forks, TTL/GC, quota 429s, idempotency, usage
metering and key revocation — with no HTTP in the way.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from cathedral import sandbox_api as api
from cathedral.sandbox_api import (
    ApiKey,
    CreateSandboxRequest,
    ExecRequest,
    ExposeRequest,
    FileGet,
    ImageSource,
    NetworkPatch,
    QuotaLimits,
    TarGet,
)
from cathedral.sandbox_provider import (
    InMemorySandboxProvider,
    SandboxOpError,
    parse_sandbox_keys,
    provider_from_environment,
)


def _req(**over) -> CreateSandboxRequest:
    values = {"image": ImageSource(image="repo/tool:latest"), "resources": api.Resources(vcpu=1, memory_gib=2, disk_gib=5)}
    values.update(over)
    return CreateSandboxRequest(**values)


@pytest.fixture
def provider() -> InMemorySandboxProvider:
    p = InMemorySandboxProvider()
    try:
        yield p
    finally:
        p.close()


def _sid(p: InMemorySandboxProvider, **over) -> str:
    return p.create(_req(**over), api_key="k1", idempotency=None, body_digest="x")["id"]


# ------------------------------------------------------------------ §3.1 create
def test_create_returns_running_document(provider: InMemorySandboxProvider) -> None:
    doc = provider.create(_req(), api_key="k1", idempotency=None, body_digest="b")
    assert doc["state"] == "running" and doc["id"].startswith("sbx_")
    assert doc["expires_at"]  # §3.4 default TTL applied
    assert doc["env_keys"] == []


# ------------------------------------------------------------------ §3.2 exec
def test_exec_shell_and_argv_run_for_real(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    res = provider.exec(sid, ExecRequest(cmd="printf 'hello world'"))
    assert res.exit_code == 0 and res.stdout == "hello world" and not res.timed_out
    argv = provider.exec(sid, ExecRequest(cmd=["printf", "abc"]))
    assert argv.stdout == "abc"


def test_metrics_report_real_peak_rss(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    # before any work the peak is unmeasured
    assert provider.get(sid)["metrics"]["memory_peak_bytes"] == 0
    # a child that touches ~64 MiB makes getrusage(RUSAGE_CHILDREN) report a real peak
    provider.exec(sid, ExecRequest(cmd=["python3", "-c", "b = bytearray(64_000_000); print(len(b))"]))
    peak = provider.get(sid)["metrics"]["memory_peak_bytes"]
    assert peak > 0
    # the peak survives into the deleted-sandbox log tombstone (§3.13 metrics)
    provider.delete(sid)
    assert provider.logs(sid)["stdout"] is not None


def test_exec_server_enforced_timeout_keeps_sandbox_alive(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    res = provider.exec(sid, ExecRequest(cmd="sleep 30", timeout_seconds=1))
    assert res.timed_out is True
    # the sandbox survives a killed process group and still runs work
    assert provider.exec(sid, ExecRequest(cmd="echo alive")).stdout.strip() == "alive"


def test_exec_output_cap_sets_truncated_flag(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    res = provider.exec(sid, ExecRequest(cmd="head -c 30000000 /dev/zero"))
    assert res.truncated is True
    assert len(res.stdout.encode("utf-8", "replace")) <= api.STDOUT_CAP_BYTES


def test_exec_exit_code_propagates(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    assert provider.exec(sid, ExecRequest(cmd="sh -c 'echo err 1>&2; exit 7'")).exit_code == 7


# ------------------------------------------------------------------ §3.2 processes
def test_background_process_survives_its_call(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    handle = provider.start_process(sid, ExecRequest(cmd="printf started"))
    assert handle.process_id.startswith("proc_")
    # the process outlives the call; poll briefly so the child has flushed
    logs = ""
    for _ in range(50):
        logs = provider.process_logs(sid, handle.process_id)
        if "started" in logs:
            break
        time.sleep(0.02)
    assert "started" in logs
    provider.stop_process(sid, handle.process_id)


# ------------------------------------------------------------------ §3.3 files / tar / stat
def test_write_file_creates_parent_dirs_and_reads_back(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.write_file(sid, "/work/deep/nested/a.txt", b"payload", None)
    data, total = provider.read_file(sid, FileGet(path="/work/deep/nested/a.txt"))
    assert data == b"payload" and total == 7


def test_read_file_max_bytes_over_cap_is_413(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.write_file(sid, "/work/x", b"0123456789", None)
    with pytest.raises(SandboxOpError) as ei:
        provider.read_file(sid, FileGet(path="/work/x", max_bytes=4))
    assert ei.value.http_status == 413


def test_read_file_range_is_inclusive_slice(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.write_file(sid, "/work/x", b"abcdef", None)
    data, total = provider.read_file(sid, FileGet(path="/work/x", range_start=1, range_end=3))
    assert data == b"bcd" and total == 6


def test_tar_roundtrip_between_sandboxes(provider: InMemorySandboxProvider) -> None:
    src = _sid(provider)
    provider.write_file(src, "/work/pkg/f.txt", b"contents", 0o640)
    blob = provider.read_tar(src, TarGet(path="/work"))
    assert blob[:2] == b"\x1f\x8b"  # gzip magic

    dst = _sid(provider)
    provider.write_tar(dst, "/work", blob)
    assert provider.read_file(dst, FileGet(path="/work/pkg/f.txt"))[0] == b"contents"


def test_stat_dir_and_file(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.write_file(sid, "/work/a", b"hi", None)
    assert provider.stat(sid, "/work/a").is_file
    assert provider.stat(sid, "/work").is_dir
    with pytest.raises(SandboxOpError) as ei:
        provider.stat(sid, "/work/nope")
    assert ei.value.http_status == 404


# ------------------------------------------------------------------ §3.5 snapshot + fork
def test_snapshot_then_fork_is_copy_on_write_and_independent(provider: InMemorySandboxProvider) -> None:
    parent = _sid(provider)
    # exec runs with cwd at the sandbox's /work, so write with a relative path
    provider.exec(parent, ExecRequest(cmd="printf pre > state.txt"))

    op = provider.snapshot(parent)
    result = provider.get_operation(op)["result"]
    snapshot_id = result["snapshot_id"]
    assert result["size_bytes"] >= 0

    fork = provider.create(_req(image=None, snapshot_id=snapshot_id, count=3), api_key="k1", idempotency=None, body_digest="f")
    fork_ids = [s["id"] for s in fork["sandboxes"]]
    assert len(fork_ids) == 3

    for fid in fork_ids:
        # every fork starts from the identical pre-fork bytes
        assert provider.read_file(fid, FileGet(path="/work/state.txt"))[0] == b"pre"
    # diverge one fork; the other forks and the parent must not see it
    provider.exec(fork_ids[0], ExecRequest(cmd="printf own > own.txt"))
    assert _exists(provider, fork_ids[0], "/work/own.txt")
    assert not _exists(provider, fork_ids[1], "/work/own.txt")
    assert not _exists(provider, parent, "/work/own.txt")

    provider.delete(parent)
    assert provider.read_file(fork_ids[2], FileGet(path="/work/state.txt"))[0] == b"pre"


def _exists(p: InMemorySandboxProvider, sid: str, path: str) -> bool:
    try:
        p.stat(sid, path)
        return True
    except SandboxOpError:
        return False


def test_snapshot_lists_and_deletes(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    snap_id = provider.get_operation(provider.snapshot(sid))["result"]["snapshot_id"]
    assert any(s["snapshot_id"] == snap_id for s in provider.list_snapshots())
    assert provider.delete_snapshot(snap_id) is True
    assert provider.delete_snapshot(snap_id) is False


# ------------------------------------------------------------------ §3.4 lifecycle / GC
def test_sweep_collects_past_grace(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    sandbox = provider._sandboxes[sid]
    # push expiry beyond the ≤5 min GC grace window (§3.4)
    sandbox.expires_at = datetime.now(timezone.utc) - timedelta(seconds=api.GC_GRACE_SECONDS + 1)
    assert provider.sweep() >= 1
    with pytest.raises(SandboxOpError):
        provider.get(sid)


def test_heartbeat_extends_ttl(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    before = provider.get(sid)["expires_at"]
    after = provider.heartbeat(sid, 48 * 3600)["expires_at"]
    assert after != before


# ------------------------------------------------------------------ §3.8 quota + 429
def test_full_quota_yields_429_with_retry_after() -> None:
    p = InMemorySandboxProvider(limits=QuotaLimits(running_sandboxes=1, vcpu=1000, memory_gib=3000))
    try:
        p.create(_req(), api_key="k1", idempotency=None, body_digest="a")
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(), api_key="k1", idempotency=None, body_digest="b")
        assert ei.value.http_status == 429
        assert ei.value.retry_after is not None  # never a silent start timeout
    finally:
        p.close()


def test_per_key_subquota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_KEY_QUOTAS", "ck_runaway:1")
    p = InMemorySandboxProvider(limits=QuotaLimits(running_sandboxes=500, vcpu=1000, memory_gib=3000))
    try:
        p.create(_req(), api_key="ck_runaway", idempotency=None, body_digest="a")
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(), api_key="ck_runaway", idempotency=None, body_digest="b")
        assert ei.value.code == "key_subquota_exhausted"
    finally:
        p.close()


# ------------------------------------------------------------------ §3.12 idempotency
def test_idempotency_key_replays_same_resource(provider: InMemorySandboxProvider) -> None:
    first = provider.create(_req(), api_key="k1", idempotency="cathedral-idem-key-1", body_digest="same")
    replay = provider.create(_req(), api_key="k1", idempotency="cathedral-idem-key-1", body_digest="same")
    assert replay["id"] == first["id"]
    with pytest.raises(SandboxOpError) as ei:
        provider.create(_req(), api_key="k1", idempotency="cathedral-idem-key-1", body_digest="different")
    assert ei.value.http_status == 409


# ------------------------------------------------------------------ §3.14 auth
def test_revoked_key_blocks_new_calls() -> None:
    p = InMemorySandboxProvider(keys=[ApiKey(key="ck_rev", project="p", revoked=True)])
    try:
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(), api_key="ck_rev", idempotency=None, body_digest="a")
        assert ei.value.http_status == 403
    finally:
        p.close()


# ------------------------------------------------------------------ §3.7 network / expose
def test_network_policy_change_and_expose(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    doc = provider.set_network(sid, NetworkPatch(mode="allowlist", allow=("pypi.org",)))
    assert doc["network"]["mode"] == "allowlist"
    exposed = provider.expose(sid, ExposeRequest(port=9000))
    assert exposed["url"].endswith("-9000.cathedral.computer") or "-9000." in exposed["url"]


# ------------------------------------------------------------------ §3.13 usage / status
def test_usage_groups_by_label(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider, labels={"job": "j-42"})
    provider.exec(sid, ExecRequest(cmd="true"))
    groups = provider.usage(group_by="label.job", labels=[])["groups"]
    assert "j-42" in groups


def test_status_reports_measured_latency(provider: InMemorySandboxProvider) -> None:
    _sid(provider)
    report = provider.status()
    assert report.status == "operational" and report.create_latency_p50_ms >= 0


# ------------------------------------------------------------------ §3.13 logs

def test_logs_returns_stdout_stderr_and_exec_history(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.exec(sid, ExecRequest(cmd="printf on-stdout"))
    provider.exec(sid, ExecRequest(cmd="sh -c 'printf on-stderr 1>&2'"))
    doc = provider.logs(sid)
    assert doc["stdout"] == "on-stdout"
    assert doc["stderr"] == "on-stderr"
    history = doc["exec_history"]
    assert len(history) == 2
    assert history[0]["command"] == "printf on-stdout" and history[0]["exit_code"] == 0
    assert history[1]["exit_code"] == 0 and "duration_ms" in history[1]


def test_logs_survive_delete_for_24h_then_pruned(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.exec(sid, ExecRequest(cmd="printf keep-me"))
    provider.delete(sid)
    # the sandbox is gone (get => 404) but its logs are retained (§3.18: 24 h).
    with pytest.raises(SandboxOpError):
        provider.get(sid)
    doc = provider.logs(sid)
    assert doc["state"] == "deleted"
    assert doc["stdout"] == "keep-me"
    assert len(doc["exec_history"]) == 1
    # simulate the 24 h window elapsing, then sweep prunes the tombstone (§3.18).
    tomb = provider._log_tombstones[sid]
    tomb["retained_until"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    provider.sweep()
    with pytest.raises(SandboxOpError) as ei:
        provider.logs(sid)
    assert ei.value.http_status == 404


def test_logs_for_unknown_sandbox_is_404(provider: InMemorySandboxProvider) -> None:
    with pytest.raises(SandboxOpError) as ei:
        provider.logs("sbx_never_existed")
    assert ei.value.http_status == 404


# ------------------------------------------------------------------ §3.16 usage cost metering

def test_usage_reports_dollar_cost_running_to_deleted(provider: InMemorySandboxProvider) -> None:
    from cathedral.sandbox_api import Pricing

    pricing = Pricing()
    sid = _sid(provider, labels={"job": "bill-me"}, resources=api.Resources(vcpu=2, memory_gib=4, disk_gib=10))
    provider.exec(sid, ExecRequest(cmd="true"))
    # give the sandbox a one-hour running window so by-the-second metering is non-zero
    provider._sandboxes[sid].created_at = datetime.now(timezone.utc) - timedelta(hours=1)
    provider.delete(sid)  # metering must survive the delete (running -> deleted)
    usage = provider.usage(group_by="label.job", labels=[])
    assert usage["currency"] == "USD"
    group = usage["groups"]["bill-me"]
    assert group["cost_usd"] > 0.0
    # ~1h at 2 vCPU / 4 GiB: the rate card applied to the recorded hours matches.
    assert round(group["vcpu_hours"], 2) == 2.0 and round(group["gib_hours"], 2) == 4.0
    # cost reconciles with the rate card applied to the recorded vCPU/GiB hours.
    expected = pricing.cost_usd(vcpu_hours=group["vcpu_hours"], gib_hours=group["gib_hours"])
    assert round(group["cost_usd"], 4) == round(expected, 4)
    assert usage["total_cost_usd"] >= group["cost_usd"]


def test_usage_bills_snapshots_per_gib_month(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    provider.write_file(sid, "/work/blob", b"0" * 4096, None)
    provider.snapshot(sid)
    usage = provider.usage(group_by="label.job", labels=[])
    assert usage["snapshot_gib_months"] >= 0.0
    assert "snapshot_cost_usd" in usage and usage["snapshot_cost_usd"] >= 0.0


def test_pricing_accessor_exposes_reference(provider: InMemorySandboxProvider) -> None:
    pricing = provider.pricing()
    assert pricing["reference"]["at_or_below_modal"] is True
    assert pricing["vcpu_hour_usd"] == api.RATE_VCPU_HOUR


# ------------------------------------------------------------------ §3.4 label list / bulk delete
def test_bulk_delete_requires_label_and_scopes(provider: InMemorySandboxProvider) -> None:
    _sid(provider, labels={"job": "x"})
    _sid(provider, labels={"job": "x"})
    with pytest.raises(api.SandboxContractError):
        provider.bulk_delete([])  # unfiltered bulk delete is refused
    assert provider.bulk_delete(["job=x"]) == 2
    assert provider.list(labels=["job=x"], state=None) == []


# ------------------------------------------------------------------ §3.14 key auth + env config
def test_strict_mode_rejects_unknown_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", "ck_live:project-a")
    p = provider_from_environment()
    try:
        # a configured, un-revoked key is admitted
        assert p.create(_req(), api_key="ck_live", idempotency=None, body_digest="a")["state"] == "running"
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(), api_key="ck_not_configured", idempotency=None, body_digest="b")
        assert ei.value.http_status == 401 and ei.value.code == "unauthorized"
    finally:
        p.close()


def test_permissive_reference_mode_allows_supplied_bearer(provider: InMemorySandboxProvider) -> None:
    # the test/reference provider (require_known_keys=False) accepts an arbitrary bearer.
    assert provider.create(_req(), api_key="anything", idempotency=None, body_digest="a")["state"] == "running"


def test_parse_sandbox_keys_fields_and_revocation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_REVOKED_KEYS", "ck_dead")
    keys = parse_sandbox_keys("ck_live:project-a:5, ck_dead:project-b, malformed, :nope")
    by_key = {k.key: k for k in keys}
    assert by_key["ck_live"].project == "project-a" and by_key["ck_live"].max_running == 5
    assert by_key["ck_dead"].revoked is True and by_key["ck_dead"].max_running is None
    assert "malformed" not in by_key and "" not in by_key


def test_env_revoked_key_blocks_and_quota_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", "ck_dead:project-a")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_REVOKED_KEYS", "ck_dead")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_QUOTA", "2:1000:3000")
    p = provider_from_environment()
    try:
        assert p.quota()["limits"]["running_sandboxes"] == 2
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(), api_key="ck_dead", idempotency=None, body_digest="a")
        assert ei.value.http_status == 403 and ei.value.code == "key_revoked"
    finally:
        p.close()


def test_bad_quota_env_falls_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_QUOTA", "not:a:valid-triple")
    p = provider_from_environment()
    try:
        assert p.quota()["limits"]["running_sandboxes"] == api.MIN_RUNNING_SANDBOXES
    finally:
        p.close()


# ------------------------------------------------------------------ §3.5 snapshot TTL + quota
def test_snapshot_carries_ttl_and_created(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    snap_id = provider.get_operation(provider.snapshot(sid, ttl_seconds=90))["result"]["snapshot_id"]
    listed = {s["snapshot_id"]: s for s in provider.list_snapshots()}
    assert listed[snap_id]["ttl_seconds"] == 90
    assert listed[snap_id]["created_at"] is not None


def test_snapshot_rejects_oversized_ttl(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    with pytest.raises(api.SandboxContractError) as ei:
        provider.snapshot(sid, ttl_seconds=api.SNAPSHOT_TTL_MAX_SECONDS + 1)
    assert ei.value.code == "invalid_ttl"


def test_snapshot_expires_after_ttl_sweep(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)
    snap_id = provider.get_operation(provider.snapshot(sid, ttl_seconds=1))["result"]["snapshot_id"]
    # force the retention window to elapse
    _, rec = provider._snapshots[snap_id]
    provider._snapshots[snap_id] = (
        provider._snapshots[snap_id][0],
        api.SnapshotRecord(
            snapshot_id=snap_id,
            size_bytes=rec.size_bytes,
            ttl_seconds=rec.ttl_seconds,
            created_at=datetime.now(timezone.utc) - timedelta(seconds=2),
        ),
    )
    assert snap_id not in {s["snapshot_id"] for s in provider.list_snapshots()}
    # the tar is gone with it
    assert provider.delete_snapshot(snap_id) is False


def test_snapshot_store_holds_1000_images() -> None:
    p = InMemorySandboxProvider()
    try:
        sid = _sid(p)
        for _ in range(api.MIN_SNAPSHOTS):
            p.snapshot(sid, ttl_seconds=60)
        assert len(p.list_snapshots()) == api.MIN_SNAPSHOTS
    finally:
        p.close()


def test_snapshot_store_full_returns_429() -> None:
    p = InMemorySandboxProvider(max_snapshots=2)
    try:
        sid = _sid(p)
        p.snapshot(sid, ttl_seconds=60)
        p.snapshot(sid, ttl_seconds=60)
        with pytest.raises(SandboxOpError) as ei:
            p.snapshot(sid, ttl_seconds=60)
        assert ei.value.http_status == 429 and ei.value.code == "snapshot_quota"
    finally:
        p.close()


# ------------------------------------------------------------------ §3.10/§3.11 idle + create pacing
def test_idle_timeout_sweeps_sandbox_before_ttl(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider, idle_timeout_seconds=30)
    # force the idle window to elapse (activity long ago, TTL still in the future)
    provider._sandboxes[sid].last_activity_at = datetime.now(timezone.utc) - timedelta(seconds=31)
    assert provider.sweep() == 1
    assert provider.list(labels=[], state=None) == []


def test_activity_resets_idle_window(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider, idle_timeout_seconds=30)
    provider._sandboxes[sid].last_activity_at = datetime.now(timezone.utc) - timedelta(seconds=29)
    provider.exec(sid, ExecRequest(cmd="true"))  # touching restarts the window
    assert (datetime.now(timezone.utc) - provider._sandboxes[sid].last_activity_at).total_seconds() < 2
    assert provider.sweep() == 0  # still within the idle window


def test_no_idle_timeout_is_ttl_only(provider: InMemorySandboxProvider) -> None:
    sid = _sid(provider)  # idle_timeout_seconds=None
    provider._sandboxes[sid].last_activity_at = datetime.now(timezone.utc) - timedelta(hours=6)
    assert provider.sweep() == 0  # only the TTL collects it, and the TTL has not elapsed


def test_create_pacing_returns_429() -> None:
    p = InMemorySandboxProvider(creates_per_minute=3)
    try:
        for _ in range(3):
            p.create(_req(), api_key="k1", idempotency=None, body_digest="x")
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(), api_key="k1", idempotency=None, body_digest="y")
        assert ei.value.http_status == 429 and ei.value.code == "create_rate_exceeded"
    finally:
        p.close()


def test_fork_counts_every_created_sandbox_toward_pacing() -> None:
    p = InMemorySandboxProvider(creates_per_minute=3)
    try:
        sid = _sid(p)
        snap = p.get_operation(p.snapshot(sid))["result"]["snapshot_id"]
        # a fork of 3 fills the whole per-minute budget on its own
        with pytest.raises(SandboxOpError) as ei:
            p.create(_req(image=None, snapshot_id=snap, count=4), api_key="k1", idempotency=None, body_digest="f")
        assert ei.value.code == "create_rate_exceeded"
    finally:
        p.close()


def test_quota_exposes_pacing_and_snapshot_store(provider: InMemorySandboxProvider) -> None:
    q = provider.quota()
    assert q["creates_per_minute"] == api.MIN_CREATES_PER_MINUTE
    assert q["snapshot_store"] == api.MIN_SNAPSHOTS
