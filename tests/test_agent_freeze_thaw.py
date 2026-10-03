"""Unit tests for Agent IDE freeze/thaw (G2) — Affline Harbor paths untouched."""

from __future__ import annotations

import json

import pytest

from cathedral.agent_profile import AGENT_CUSTOMER_LABEL, agent_create_body
from cathedral.sandbox_api import ApiKey, MIN_RUNNING_SANDBOXES, QuotaLimits
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_server import SandboxApplication

AUTH = {"Authorization": "Bearer agent-k1"}


@pytest.fixture
def app() -> SandboxApplication:
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key="agent-k1", project="agent", max_running=8)],
        limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
    )
    a = SandboxApplication(provider)
    try:
        yield a
    finally:
        provider.close()


def _create(app: SandboxApplication) -> str:
    r = app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(agent_create_body()).encode())
    assert r.status == 202, r.body
    return json.loads(r.body)["id"]


def test_affline_constants_untouched() -> None:
    assert MIN_RUNNING_SANDBOXES == 500


def test_agent_create_body_is_public_not_ditto_deny_all() -> None:
    body = agent_create_body(trial="t1")
    assert body["network"]["mode"] == "public"
    assert body["labels"]["customer"] == AGENT_CUSTOMER_LABEL


def test_freeze_thaw_roundtrip(app: SandboxApplication) -> None:
    sid = _create(app)
    frozen = app.dispatch("POST", f"/v1/sandboxes/{sid}/freeze", AUTH, b"")
    assert frozen.status == 200
    doc = json.loads(frozen.body)
    assert doc["state"] == "frozen"
    assert doc["labels"]["customer"] == "agent"

    ex = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/exec",
        AUTH,
        json.dumps({"cmd": "printf x"}).encode(),
    )
    assert ex.status == 409
    assert json.loads(ex.body)["error"]["code"] == "sandbox_frozen"

    thawed = app.dispatch("POST", f"/v1/sandboxes/{sid}/thaw", AUTH, b"")
    assert thawed.status == 200
    assert json.loads(thawed.body)["state"] == "running"
    ok = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/exec",
        AUTH,
        json.dumps({"cmd": "printf ok"}).encode(),
    )
    assert ok.status == 200
    assert json.loads(ok.body)["stdout"] == "ok"


def test_freeze_still_counts_resident_quota(app: SandboxApplication) -> None:
    """Freeze pauses compute but does not free create slots (anti-oversubscribe)."""
    sid = _create(app)
    q1 = json.loads(app.dispatch("GET", "/v1/quota", AUTH, b"").body)
    assert q1["usage"]["running_sandboxes"] == 1
    assert q1["usage"]["resident_sandboxes"] == 1
    app.dispatch("POST", f"/v1/sandboxes/{sid}/freeze", AUTH, b"")
    q2 = json.loads(app.dispatch("GET", "/v1/quota", AUTH, b"").body)
    assert q2["usage"]["running_sandboxes"] == 0
    assert q2["usage"]["frozen_sandboxes"] == 1
    assert q2["usage"]["resident_sandboxes"] == 1
    app.dispatch("POST", f"/v1/sandboxes/{sid}/thaw", AUTH, b"")
    q3 = json.loads(app.dispatch("GET", "/v1/quota", AUTH, b"").body)
    assert q3["usage"]["running_sandboxes"] == 1
    assert q3["usage"]["resident_sandboxes"] == 1


def test_idempotent_freeze_and_thaw(app: SandboxApplication) -> None:
    sid = _create(app)
    assert app.dispatch("POST", f"/v1/sandboxes/{sid}/freeze", AUTH, b"").status == 200
    assert app.dispatch("POST", f"/v1/sandboxes/{sid}/freeze", AUTH, b"").status == 200
    assert json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/thaw", AUTH, b"").body)["state"] == "running"
    assert json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/thaw", AUTH, b"").body)["state"] == "running"


def test_snapshot_fork_while_running_then_freeze(app: SandboxApplication) -> None:
    sid = _create(app)
    snap = app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", AUTH, b"{}")
    assert snap.status == 202
    snap_id = json.loads(snap.body)["result"]["snapshot_id"]
    fork = app.dispatch(
        "POST",
        "/v1/sandboxes",
        AUTH,
        json.dumps({"snapshot_id": snap_id, "count": 1, "labels": {"customer": "agent"}}).encode(),
    )
    assert fork.status == 202
    child = json.loads(fork.body)["id"]
    assert app.dispatch("POST", f"/v1/sandboxes/{child}/freeze", AUTH, b"").status == 200


def test_provider_freeze_rejects_non_running() -> None:
    p = InMemorySandboxProvider()
    try:
        from cathedral.sandbox_api import CreateSandboxRequest, ImageSource

        doc = p.create(
            CreateSandboxRequest(image=ImageSource(image="repo/x:latest")),
            api_key="k",
            idempotency=None,
            body_digest="d",
        )
        sid = doc["id"]
        assert p.freeze(sid)["state"] == "frozen"
        with p._lock:  # noqa: SLF001
            p._sandboxes[sid].state = "failed"  # noqa: SLF001
        with pytest.raises(SandboxOpError) as ei:
            p.freeze(sid)
        assert ei.value.code == "sandbox_not_running"
    finally:
        p.close()
