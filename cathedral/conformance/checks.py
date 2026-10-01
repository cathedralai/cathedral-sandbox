"""The checks. Each one maps to a numbered section of the Affine sandbox
requirements (2026-09-22) and states its threshold in the report.

Tier ``mvp`` is what Affine needs to move its first SWE-bench job; a failing
mvp check fails the run. Tier ``later`` (fork, quota pressure) is reported
but only fails the run with ``--strict``.

Every number is a measurement from this run with its sample count. A check
that cannot run says why and is reported as ``skip``, never as a pass.
"""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from cathedral.conformance.api import Api, Response

MIB = 1024 * 1024

# Debian with docker-ce, buildx and compose; dockerd is started through the
# processes API. Same image and digest the Harbor provider uses.
DEFAULT_DIND_IMAGE = (
    "ghcr.io/cathedralai/cathedral-dind@"
    "sha256:a6b1d98d8dc3b9c71d3c1f8875d8cba8c6f600765c87f16c336b4235c473052a"
)

# Affine §3.8 minimum sustained quota.
AFFINE_MIN_QUOTA = {"sandboxes": 500, "vcpu": 1000, "memory_gib": 3000}


@dataclass
class Config:
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    image: str = "python:3.12-slim"
    dind_image: str = DEFAULT_DIND_IMAGE
    template: str | None = None
    lifetime_seconds: int = 1800
    max_spend_usd: str = "2.00"
    create_timeout_s: float = 600.0
    samples: int = 3
    exec_samples: int = 20
    fork_count: int = 8
    burst: int = 10
    max_fill: int = 10
    nested_networks: int = 50


@dataclass
class Result:
    id: str
    title: str
    spec: str
    tier: str
    status: str  # pass | fail | skip
    threshold: str
    measured: dict[str, Any] = field(default_factory=dict)
    detail: str = ""


@dataclass
class Check:
    id: str
    title: str
    spec: str
    tier: str
    threshold: str
    run: Callable[["Context"], tuple[str, dict, str]]
    needs_primary: bool = True


class Context:
    def __init__(self, api: Api, config: Config):
        self.api = api
        self.config = config
        self.labels = {"conformance_run": config.run_id}
        self.primary: str | None = None
        self.primary_failure = ""
        self.sandboxes: list[str] = []
        self.snapshots: list[str] = []

    def create_body(self, **overrides: Any) -> dict:
        body: dict[str, Any] = {
            "image": self.config.image,
            "network": "deny_all",
            "lifetime_seconds": self.config.lifetime_seconds,
            "max_spend_usd": self.config.max_spend_usd,
            "labels": dict(self.labels),
        }
        if self.config.template:
            body["template"] = self.config.template
        body.update(overrides)
        return body

    def create(self, body: dict | None = None, key: str | None = None) -> Response:
        reply = self.api.call("POST", "/v1/sandboxes", json=body or self.create_body(),
                              key=key or f"conf-{uuid.uuid4().hex}")
        view = reply.json()
        if reply.ok and isinstance(view, dict) and view.get("id") and view["id"] not in self.sandboxes:
            self.sandboxes.append(view["id"])
        return reply

    def create_running(self, body: dict | None = None) -> tuple[str | None, float, str]:
        """Create and wait. Returns (id or None, seconds from the create call, failure)."""
        started = self.api.clock()
        reply = self.create(body)
        if not reply.ok:
            return None, 0.0, reply.summary()
        sandbox_id = reply.json()["id"]
        view, _ = self.api.wait_running(sandbox_id, self.config.create_timeout_s)
        elapsed = self.api.clock() - started
        if view.get("state") != "running":
            return None, elapsed, f"sandbox {sandbox_id} is {view.get('state')}: {view.get('error')}"
        return sandbox_id, elapsed, ""

    def cleanup(self) -> dict:
        """Delete everything this run made, then sweep by label for lost creates."""
        listed = self.api.call("GET", "/v1/sandboxes",
                               params=[("label", f"conformance_run={self.config.run_id}")])
        for view in (listed.json() or {}).get("sandboxes", []) if listed.ok else []:
            if view.get("id") not in self.sandboxes:
                self.sandboxes.append(view["id"])
        failed = [s for s in self.sandboxes if not self.api.delete(s).ok]
        failed += [s for s in self.snapshots if not self.api.call("DELETE", f"/v1/snapshots/{s}").ok]
        return {"deleted": len(self.sandboxes) + len(self.snapshots) - len(failed), "failed": failed}


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[index]


def _sh(ctx: Context, command: str, timeout: int = 60, user: str | None = None) -> tuple[int, str, str]:
    reply = ctx.api.exec(ctx.primary, ["sh", "-c", command], timeout_seconds=timeout, user=user)
    if not reply.ok:
        return -1, "", reply.summary()
    body = reply.json()
    return int(body.get("exit_code", -1)), body.get("stdout", ""), body.get("stderr", "")


CHECKS: list[Check] = []


def check(id: str, title: str, spec: str, threshold: str, tier: str = "mvp", needs_primary: bool = True):
    def register(fn):
        CHECKS.append(Check(id, title, spec, tier, threshold, fn, needs_primary))
        return fn
    return register


# -- create -----------------------------------------------------------------

@check("create.first", "Create a sandbox from a public image", "§3.1, §3.15",
       "running; first pull p95 < 300 s", needs_primary=False)
def create_first(ctx: Context):
    sandbox_id, elapsed, failure = ctx.create_running()
    if not sandbox_id:
        ctx.primary_failure = failure
        return "fail", {"seconds": round(elapsed, 2)}, failure
    ctx.primary = sandbox_id
    return ("pass" if elapsed < 300 else "fail"), {"seconds": round(elapsed, 2), "sandbox": sandbox_id}, ""


@check("create.cached", "Create from an image already pulled", "§3.9, §3.15",
       "p50 < 10 s, p95 < 60 s")
def create_cached(ctx: Context):
    times, failures = [], []
    for _ in range(ctx.config.samples):
        sandbox_id, elapsed, failure = ctx.create_running()
        if sandbox_id:
            times.append(elapsed)
            ctx.api.delete(sandbox_id)
        else:
            failures.append(failure)
    if not times:
        return "fail", {"n": 0}, "; ".join(failures)
    measured = {"n": len(times), "p50_s": round(percentile(times, 50), 2),
                "p95_s": round(percentile(times, 95), 2), "failures": len(failures)}
    ok = not failures and measured["p50_s"] < 10 and measured["p95_s"] < 60
    return ("pass" if ok else "fail"), measured, "; ".join(failures)


def computesdk_score(times_ms: list[float], attempts: int) -> float:
    """ComputeSDK's composite: 100 x (1 - ms / 10,000) on median 60 %, p95 25 %,
    p99 15 %, each floored at 0, times the success rate."""
    if not times_ms:
        return 0.0
    part = lambda pct: max(0.0, 1 - percentile(times_ms, pct) / 10_000)  # noqa: E731
    return round(100 * (0.6 * part(50) + 0.25 * part(95) + 0.15 * part(99)) * len(times_ms) / attempts, 1)


@check("create.burst_tti", "Burst time to interactive (ComputeSDK method)", "ComputeSDK Burst TTI",
       "N concurrent creates; create() to first successful `true`; all succeed; median < 1 s",
       tier="later", needs_primary=False)
def create_burst_tti(ctx: Context):
    def one(_):
        started = ctx.api.clock()
        reply = ctx.create()
        if not reply.ok:
            return None, reply.summary()
        sandbox_id = reply.json()["id"]
        # TTI ends at the first command that succeeds, not at state=running.
        while ctx.api.clock() - started < ctx.config.create_timeout_s:
            ran = ctx.api.exec(sandbox_id, ["true"], timeout_seconds=10)
            if ran.ok and (ran.json() or {}).get("exit_code") == 0:
                return (ctx.api.clock() - started) * 1000, ""
            ctx.api.sleep(0.1)
        return None, f"{sandbox_id} never ran a command"

    n = ctx.config.burst
    with ThreadPoolExecutor(max_workers=n) as pool:
        outcomes = list(pool.map(one, range(n)))
    times = [t for t, _ in outcomes if t is not None]
    errors = [e for t, e in outcomes if t is None]
    measured: dict[str, Any] = {"n": n, "succeeded": len(times), "score": computesdk_score(times, n)}
    if times:
        measured.update({f"p{p}_ms": round(percentile(times, p)) for p in (50, 95, 99)})
    ok = not errors and measured.get("p50_ms", 10**9) < 1000
    return ("pass" if ok else "fail"), measured, "; ".join(sorted(set(errors)))[:500]


@check("create.idempotent", "Same Idempotency-Key makes one sandbox", "§3.12",
       "second create returns the first id", needs_primary=False)
def create_idempotent(ctx: Context):
    key, body = f"conf-idem-{uuid.uuid4().hex}", ctx.create_body()
    first, second = ctx.create(body, key), ctx.create(body, key)
    if not first.ok or not second.ok:
        return "fail", {}, f"first {first.summary()}, second {second.summary()}"
    a, b = first.json()["id"], second.json()["id"]
    return ("pass" if a == b else "fail"), {"first": a, "second": b}, ""


# -- exec -------------------------------------------------------------------

@check("exec.latency", "Exec round trip of `true`", "§3.2, §3.15", "p50 < 200 ms, p95 < 1 s")
def exec_latency(ctx: Context):
    times, bad = [], 0
    for _ in range(ctx.config.exec_samples):
        started = ctx.api.clock()
        reply = ctx.api.exec(ctx.primary, ["true"], timeout_seconds=10)
        elapsed = ctx.api.clock() - started
        if reply.ok and reply.json().get("exit_code") == 0:
            times.append(elapsed)
        else:
            bad += 1
    if not times:
        return "fail", {"n": 0, "errors": bad}, "no exec succeeded"
    measured = {"n": len(times), "errors": bad, "p50_ms": round(percentile(times, 50) * 1000),
                "p95_ms": round(percentile(times, 95) * 1000)}
    ok = bad == 0 and measured["p50_ms"] < 200 and measured["p95_ms"] < 1000
    return ("pass" if ok else "fail"), measured, ""


@check("exec.forms", "Exec takes argv and a shell string", "§3.2", "both print 42")
def exec_forms(ctx: Context):
    argv = ctx.api.exec(ctx.primary, ["sh", "-c", "echo $((6*7))"])
    shell = ctx.api.exec(ctx.primary, "echo $((6*7))")
    out = {"argv": (argv.json() or {}).get("stdout", argv.summary()).strip() if argv.ok else argv.summary(),
           "string": (shell.json() or {}).get("stdout", "").strip() if shell.ok else shell.summary()}
    return ("pass" if out == {"argv": "42", "string": "42"} else "fail"), out, ""


@check("exec.timeout", "Server-side exec timeout keeps the sandbox", "§3.2",
       "timed_out=true within timeout + 10 s; next exec succeeds")
def exec_timeout(ctx: Context):
    started = ctx.api.clock()
    reply = ctx.api.exec(ctx.primary, ["sleep", "60"], timeout_seconds=2)
    elapsed = ctx.api.clock() - started
    after = ctx.api.exec(ctx.primary, ["true"], timeout_seconds=10)
    measured = {"seconds": round(elapsed, 2), "timed_out": (reply.json() or {}).get("timed_out") if reply.ok else None,
                "sandbox_alive": after.ok and (after.json() or {}).get("exit_code") == 0}
    ok = measured["timed_out"] is True and elapsed < 12 and measured["sandbox_alive"]
    return ("pass" if ok else "fail"), measured, "" if reply.ok else reply.summary()


@check("exec.output", "Exec returns at least 10 MiB of output", "§3.2", "stdout >= 10 MiB")
def exec_output(ctx: Context):
    reply = ctx.api.exec(ctx.primary, ["sh", "-c", "head -c 11534336 /dev/zero | tr '\\0' a"],
                         timeout_seconds=60)
    if not reply.ok:
        return "fail", {}, reply.summary()
    body = reply.json()
    size = len(body.get("stdout", "").encode())
    measured = {"stdout_bytes": size, "truncated": body.get("stdout_truncated")}
    return ("pass" if size >= 10 * MIB else "fail"), measured, ""


@check("process.background", "A background process outlives the exec that started it", "§3.2",
       "running after start returns; stops on DELETE")
def process_background(ctx: Context):
    path = f"/v1/sandboxes/{ctx.primary}/processes"
    started = ctx.api.call("POST", path, json={"cmd": ["sleep", "3601"]}, key=f"conf-p-{uuid.uuid4().hex}")
    if not started.ok:
        return "fail", {}, started.summary()
    process_id = (started.json() or {}).get("process_id") or (started.json() or {}).get("id")
    # Bracket trick: the scanning shell's own command line must not match itself.
    probe = "for p in /proc/[0-9]*; do tr '\\0' ' ' < $p/cmdline 2>/dev/null; echo; done | grep -c 'sleep 360[1]'"
    ctx.api.sleep(2)
    _, alive, _ = _sh(ctx, probe)
    stopped = ctx.api.call("DELETE", f"{path}/{process_id}") if process_id else None
    ctx.api.sleep(2)
    _, after, _ = _sh(ctx, probe)
    measured = {"process_id": process_id, "alive_after_start": alive.strip(),
                "delete_status": stopped.status if stopped else None, "alive_after_delete": after.strip()}
    ok = alive.strip() not in ("", "0") and stopped is not None and stopped.ok and after.strip() == "0"
    return ("pass" if ok else "fail"), measured, ""


# -- files --------------------------------------------------------------------

@check("files.roundtrip", "Put and get a file, parents created, mode kept", "§3.3",
       "same sha256, mode 640, stat matches")
def files_roundtrip(ctx: Context):
    data, target = os.urandom(MIB), "/tmp/conformance/a/b/blob.bin"
    put = ctx.api.call("PUT", f"/v1/sandboxes/{ctx.primary}/files", params={"path": target, "mode": 0o640},
                       body=data, content_type="application/octet-stream", timeout=300)
    if not put.ok:
        return "fail", {}, put.summary()
    got = ctx.api.call("GET", f"/v1/sandboxes/{ctx.primary}/files", params={"path": target}, timeout=300)
    stat = ctx.api.call("GET", f"/v1/sandboxes/{ctx.primary}/stat", params={"path": target})
    _, mode, _ = _sh(ctx, f"stat -c %a {target}")
    measured = {"same_bytes": got.ok and hashlib.sha256(got.data).digest() == hashlib.sha256(data).digest(),
                "mode": mode.strip(), "stat": stat.json() if stat.ok else stat.summary()}
    st = measured["stat"] if isinstance(measured["stat"], dict) else {}
    ok = measured["same_bytes"] and measured["mode"] == "640" and st.get("is_file") and st.get("size") == MIB
    return ("pass" if ok else "fail"), measured, ""


def _sample_tar() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        script = b"#!/bin/sh\necho conformance\n"
        info = tarfile.TarInfo("run.sh")
        info.size, info.mode = len(script), 0o755
        tar.addfile(info, io.BytesIO(script))
        link = tarfile.TarInfo("link")
        link.type, link.linkname = tarfile.SYMTYPE, "run.sh"
        tar.addfile(link)
    return buffer.getvalue()


@check("files.tar", "Tar in and out keeps modes and symlinks", "§3.3",
       "run.sh mode 755, link -> run.sh, both members come back")
def files_tar(ctx: Context):
    target = "/tmp/conformance-tar"
    put = ctx.api.call("PUT", f"/v1/sandboxes/{ctx.primary}/tar", params={"path": target},
                       body=_sample_tar(), content_type="application/gzip", timeout=300)
    if not put.ok:
        return "fail", {}, put.summary()
    _, mode, _ = _sh(ctx, f"stat -c %a {target}/run.sh")
    _, link, _ = _sh(ctx, f"readlink {target}/link")
    got = ctx.api.call("GET", f"/v1/sandboxes/{ctx.primary}/tar", params={"path": target}, timeout=300)
    members: list[str] = []
    if got.ok:
        with tarfile.open(fileobj=io.BytesIO(got.data), mode="r:*") as tar:
            members = sorted(m.name.lstrip("./") for m in tar.getmembers() if m.name.strip("./"))
    measured = {"mode": mode.strip(), "link": link.strip(), "members": members}
    ok = measured["mode"] == "755" and measured["link"] == "run.sh" and {"run.sh", "link"} <= set(members)
    return ("pass" if ok else "fail"), measured, "" if got.ok else got.summary()


# -- lifecycle ----------------------------------------------------------------

@check("lifecycle.extend", "Heartbeat extends the lifetime deadline", "§3.4",
       "deadline moves forward by the extension")
def lifecycle_extend(ctx: Context):
    from datetime import datetime

    before = (ctx.api.get_sandbox(ctx.primary).json() or {}).get("lifetime_deadline_at")
    reply = ctx.api.call("POST", f"/v1/sandboxes/{ctx.primary}/lifetime", json={"extend_by_seconds": 600})
    after = (reply.json() or {}).get("lifetime_deadline_at") if reply.ok else None
    if not (before and after):
        return "fail", {"before": before, "after": after}, reply.summary()
    moved = (datetime.fromisoformat(after.replace("Z", "+00:00"))
             - datetime.fromisoformat(before.replace("Z", "+00:00"))).total_seconds()
    return ("pass" if 590 <= moved <= 610 else "fail"), {"moved_s": moved}, ""


@check("lifecycle.labels", "List sandboxes by label", "§3.4", "the run's sandbox is listed")
def lifecycle_labels(ctx: Context):
    reply = ctx.api.call("GET", "/v1/sandboxes", params=[("label", f"conformance_run={ctx.config.run_id}")])
    ids = [v.get("id") for v in (reply.json() or {}).get("sandboxes", [])] if reply.ok else []
    return ("pass" if ctx.primary in ids else "fail"), {"listed": len(ids)}, "" if reply.ok else reply.summary()


@check("lifecycle.delete", "Delete is idempotent", "§3.4", "both DELETEs answer 2xx", needs_primary=False)
def lifecycle_delete(ctx: Context):
    reply = ctx.create()
    if not reply.ok:
        return "fail", {}, reply.summary()
    sandbox_id = reply.json()["id"]
    first, second = ctx.api.delete(sandbox_id), ctx.api.delete(sandbox_id)
    measured = {"first": first.status, "second": second.status}
    return ("pass" if first.ok and second.ok else "fail"), measured, "" if second.ok else second.summary()


# -- quota and usage ----------------------------------------------------------

def _quota(ctx: Context) -> tuple[dict | None, str]:
    reply = ctx.api.call("GET", "/v1/quota")
    return (reply.json(), "") if reply.ok else (None, reply.summary())


@check("quota.visible", "Quota shows limits, usage and room", "§3.8",
       "sandboxes, vcpu and memory_gib in limits, usage, available")
def quota_visible(ctx: Context):
    quota, failure = _quota(ctx)
    if quota is None:
        return "fail", {}, failure
    keys = ("sandboxes", "vcpu", "memory_gib")
    complete = all(isinstance(quota.get(part), dict) and all(k in quota[part] for k in keys)
                   for part in ("limits", "usage", "available"))
    counted = complete and quota["usage"]["sandboxes"] >= 1
    return ("pass" if counted else "fail"), {k: quota.get(k) for k in ("limits", "usage", "available")}, ""


@check("quota.minimum", "Quota meets Affine's sustained minimum", "§3.8",
       "500 sandboxes, 1000 vCPU, 3000 GiB", needs_primary=False)
def quota_minimum(ctx: Context):
    quota, failure = _quota(ctx)
    if quota is None:
        return "fail", {}, failure
    limits = quota.get("limits") or {}
    short = {k: limits.get(k) for k, need in AFFINE_MIN_QUOTA.items() if (limits.get(k) or 0) < need}
    return ("pass" if not short else "fail"), {"limits": limits}, f"below minimum: {short}" if short else ""


@check("quota.full_429", "A create past quota answers 429 at once", "§3.8, §3.15",
       "429 with Retry-After within 1 s", tier="later", needs_primary=False)
def quota_full_429(ctx: Context):
    quota, failure = _quota(ctx)
    if quota is None:
        return "fail", {}, failure
    room = (quota.get("available") or {}).get("sandboxes")
    if room is None or room > ctx.config.max_fill:
        return "skip", {"available": room}, f"filling {room} sandboxes exceeds --max-fill {ctx.config.max_fill}"
    for _ in range(room):
        ctx.create()
    started = ctx.api.clock()
    reply = ctx.create()
    elapsed = ctx.api.clock() - started
    retry_after = {k.lower(): v for k, v in reply.headers.items()}.get("retry-after")
    measured = {"filled": room, "status": reply.status, "seconds": round(elapsed, 3), "retry_after": retry_after}
    ok = reply.status == 429 and elapsed < 1 and retry_after is not None
    return ("pass" if ok else "fail"), measured, ""


@check("usage.by_label", "Usage and cost grouped by label", "§3.13",
       "a group for this run's label with a cost")
def usage_by_label(ctx: Context):
    reply = ctx.api.call("GET", "/v1/usage", params={"group_by": "conformance_run"})
    if not reply.ok:
        return "fail", {}, reply.summary()
    groups = [g for g in (reply.json() or {}).get("groups", []) if g.get("value") == ctx.config.run_id]
    measured = {"group": groups[0] if groups else None}
    return ("pass" if groups and groups[0].get("cost_usd") is not None else "fail"), measured, ""


# -- nested docker ------------------------------------------------------------

@check("docker.nested", "Docker inside the sandbox: bind mounts and many networks", "§3.10, §3.17",
       "dockerd ready < 90 s, `docker run -v` works, N networks created", needs_primary=False)
def docker_nested(ctx: Context):
    sandbox_id, elapsed, failure = ctx.create_running(
        ctx.create_body(image=ctx.config.dind_image, network="internet"))
    if not sandbox_id:
        return "fail", {"create_s": round(elapsed, 2)}, failure
    start = ctx.api.call("POST", f"/v1/sandboxes/{sandbox_id}/processes", key=f"conf-d-{uuid.uuid4().hex}",
                         json={"cmd": ["sh", "-c", "exec dockerd > /var/log/dockerd.log 2>&1"], "user": "root"})

    def sh(command: str, timeout: int = 120) -> tuple[int, str]:
        reply = ctx.api.exec(sandbox_id, ["sh", "-c", command], timeout_seconds=timeout, user="root")
        body = reply.json() if reply.ok else {}
        return int(body.get("exit_code", -1)), (body.get("stdout", "") + body.get("stderr", ""))[-500:]

    ready_s = None
    began = ctx.api.clock()
    while ctx.api.clock() - began < 90:
        if sh("docker info >/dev/null 2>&1", 15)[0] == 0:
            ready_s = round(ctx.api.clock() - began, 1)
            break
        ctx.api.sleep(2)
    measured: dict[str, Any] = {"process_start": start.status, "dockerd_ready_s": ready_s}
    if ready_s is None:
        return "fail", measured, sh("tail -n 20 /var/log/dockerd.log")[1]
    code, out = sh("mkdir -p /work && echo ok > /work/probe && "
                   "docker run --rm -v /work:/work busybox cat /work/probe", 300)
    measured["bind_mount"] = code == 0 and out.strip().endswith("ok")
    n = ctx.config.nested_networks
    code, out = sh(f"i=0; while [ $i -lt {n} ]; do docker network create conf$i >/dev/null || exit 1; "
                   f"i=$((i+1)); done; docker network ls --filter name=conf -q | wc -l", 300)
    measured["networks"] = int(out.strip().splitlines()[-1]) if code == 0 and out.strip() else 0
    ok = measured["bind_mount"] and measured["networks"] >= n
    return ("pass" if ok else "fail"), measured, "" if ok else out


# -- snapshot and fork ----------------------------------------------------------

@check("snapshot.fork", "Snapshot a running sandbox and fork it N ways", "§3.5, §4 test 4",
       "snapshot ready <= 30 s; every fork running <= 15 s; same pre-fork bytes; forks independent; "
       "parent delete leaves forks", tier="later")
def snapshot_fork(ctx: Context):
    code, digest, err = _sh(ctx, "head -c 4194304 /dev/urandom > /tmp/state.bin && sha256sum /tmp/state.bin")
    if code != 0:
        return "fail", {}, err
    parent_digest = digest.split()[0]
    began = ctx.api.clock()
    reply = ctx.api.call("POST", f"/v1/sandboxes/{ctx.primary}/snapshots", json={},
                         key=f"conf-s-{uuid.uuid4().hex}")
    if not reply.ok:
        return "fail", {}, reply.summary()
    snapshot = reply.json()
    ctx.snapshots.append(snapshot["id"])
    while snapshot.get("state") not in ("ready", "failed") and ctx.api.clock() - began < 300:
        ctx.api.sleep(1)
        snapshot = ctx.api.call("GET", f"/v1/snapshots/{snapshot['id']}").json() or snapshot
    snapshot_s = round(ctx.api.clock() - began, 2)
    if snapshot.get("state") != "ready":
        return "fail", {"snapshot_s": snapshot_s}, f"snapshot {snapshot.get('state')}: {snapshot.get('error')}"

    body = ctx.create_body(snapshot_id=snapshot["id"])
    body.pop("image")
    with ThreadPoolExecutor(max_workers=ctx.config.fork_count) as pool:
        forks = list(pool.map(lambda _: ctx.create_running(dict(body)), range(ctx.config.fork_count)))
    running = [f[0] for f in forks if f[0]]
    fork_times = [f[1] for f in forks]
    measured: dict[str, Any] = {"snapshot_s": snapshot_s, "forks": len(forks), "running": len(running),
                                "fork_max_s": round(max(fork_times), 2) if fork_times else None}
    if len(running) != len(forks):
        return "fail", measured, "; ".join(f[2] for f in forks if not f[0])

    digests, marks = set(), set()
    for index, fork in enumerate(running):
        r = ctx.api.exec(fork, ["sh", "-c", f"sha256sum /tmp/state.bin && echo {index} > /tmp/fork && cat /tmp/fork"])
        lines = (r.json() or {}).get("stdout", "").split() if r.ok else []
        digests.add(lines[0] if lines else None)
        marks.add(lines[-1] if lines else None)
    ctx.api.delete(ctx.primary)
    survivors = sum(1 for f in running if (ctx.api.exec(f, ["true"]).json() or {}).get("exit_code") == 0)
    measured.update(same_state=digests == {parent_digest}, independent=len(marks) == len(running),
                    alive_after_parent_delete=survivors)
    ok = (snapshot_s <= 30 and measured["fork_max_s"] <= 15 and measured["same_state"]
          and measured["independent"] and survivors == len(running))
    return ("pass" if ok else "fail"), measured, ""
