"""BOLA / tenant AuthZ — cross-key sandbox access must 404."""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import ApiKey, CreateSandboxRequest, ImageSource, QuotaLimits
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication


@pytest.fixture
def app() -> SandboxApplication:
    provider = InMemorySandboxProvider(
        keys=[
            ApiKey(key="alice", project="a", max_running=10),
            ApiKey(key="bob", project="b", max_running=10),
        ],
        limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
        require_known_keys=True,
    )
    a = SandboxApplication(provider, require_auth=True)
    try:
        yield a
    finally:
        provider.close()


def _create(app: SandboxApplication, key: str) -> str:
    body = json.dumps(
        {"image": {"image": "repo/x:latest"}, "count": 1, "labels": {"owner": key}}
    ).encode()
    r = app.dispatch(
        "POST",
        "/v1/sandboxes",
        {"Authorization": f"Bearer {key}"},
        body,
    )
    assert r.status == 202, r.body
    return json.loads(r.body)["id"]


def test_cross_tenant_get_is_404(app: SandboxApplication) -> None:
    sid = _create(app, "alice")
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}", {"Authorization": "Bearer bob"}, b"")
    assert r.status == 404


def test_cross_tenant_exec_is_404(app: SandboxApplication) -> None:
    sid = _create(app, "alice")
    r = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/exec",
        {"Authorization": "Bearer bob"},
        json.dumps({"cmd": "printf pwn"}).encode(),
    )
    assert r.status == 404


def test_list_is_scoped_to_caller(app: SandboxApplication) -> None:
    a = _create(app, "alice")
    b = _create(app, "bob")
    listed = json.loads(
        app.dispatch("GET", "/v1/sandboxes", {"Authorization": "Bearer alice"}, b"").body
    )["sandboxes"]
    ids = {s["id"] for s in listed}
    assert a in ids
    assert b not in ids


def test_guest_env_strips_host_secrets() -> None:
    import os

    p = InMemorySandboxProvider()
    try:
        os.environ["CATHEDRAL_API_KEY"] = "host-secret-should-not-leak"
        doc = p.create(
            CreateSandboxRequest(image=ImageSource(image="repo/x:latest")),
            api_key="k",
            idempotency=None,
            body_digest="d",
        )
        sid = doc["id"]
        from cathedral.sandbox_api import ExecRequest

        result = p.exec(sid, ExecRequest(cmd="printenv CATHEDRAL_API_KEY", timeout_seconds=10))
        assert "host-secret-should-not-leak" not in (result.stdout or "")
        assert "host-secret-should-not-leak" not in (result.stderr or "")
    finally:
        os.environ.pop("CATHEDRAL_API_KEY", None)
        p.close()
