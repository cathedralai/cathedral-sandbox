"""Unit tests for the additive Ditto profile (no Affline constant changes)."""

from __future__ import annotations

import json

import pytest

from cathedral.ditto_profile import (
    DITTO_CUSTOMER_LABEL,
    DITTO_MAX_SLOTS,
    DITTO_MIN_SLOTS,
    DITTO_NETWORK_MODE,
    ditto_create_body,
    ditto_key_env,
)
from cathedral.sandbox_api import ApiKey, QuotaLimits, MIN_RUNNING_SANDBOXES
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication


def test_affline_min_running_untouched_by_ditto_profile() -> None:
    """Crash-safety: Ditto pack must not redefine Affline §3.8 floor."""
    assert MIN_RUNNING_SANDBOXES == 500
    assert DITTO_MAX_SLOTS == 8
    assert DITTO_MIN_SLOTS == 2
    assert DITTO_MAX_SLOTS < MIN_RUNNING_SANDBOXES


def test_ditto_key_env_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        ditto_key_env(max_running=1)
    with pytest.raises(ValueError):
        ditto_key_env(max_running=9)


def test_ditto_create_body_is_deny_all_and_labelled() -> None:
    body = ditto_create_body(trial="abc")
    assert body["network"] == {"mode": DITTO_NETWORK_MODE, "allow": []}
    assert body["labels"]["customer"] == DITTO_CUSTOMER_LABEL
    assert body["labels"]["trial"] == "abc"
    assert body["ttl_seconds"] == 600


def test_ditto_shaped_key_admits_cap_then_429() -> None:
    """In-process: Ditto key max_running=3 admits exactly 3, then 429."""
    key = "ditto-unit"
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key=key, project="ditto", max_running=3)],
        limits=QuotaLimits(running_sandboxes=100, vcpu=1000, memory_gib=3000),
    )
    app = SandboxApplication(provider)
    auth = {"Authorization": f"Bearer {key}"}
    try:
        ids = []
        for _ in range(3):
            r = app.dispatch(
                "POST",
                "/v1/sandboxes",
                auth,
                json.dumps(ditto_create_body()).encode(),
            )
            assert r.status == 202, r.body
            ids.append(json.loads(r.body)["id"])
            doc = json.loads(app.dispatch("GET", f"/v1/sandboxes/{ids[-1]}", auth, b"").body)
            assert doc["network"]["mode"] == "none"
            assert doc["labels"]["customer"] == "ditto"
        blocked = app.dispatch(
            "POST",
            "/v1/sandboxes",
            auth,
            json.dumps(ditto_create_body()).encode(),
        )
        assert blocked.status == 429
        assert "Retry-After" in blocked.headers
        for sid in ids:
            assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", auth, b"").status in (200, 204)
            assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", auth, b"").status in (200, 204)
    finally:
        provider.close()


def test_ditto_lifecycle_create_exec_delete() -> None:
    key = "ditto-life"
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key=key, project="ditto", max_running=8)],
    )
    app = SandboxApplication(provider)
    auth = {"Authorization": f"Bearer {key}"}
    try:
        r = app.dispatch("POST", "/v1/sandboxes", auth, json.dumps(ditto_create_body()).encode())
        assert r.status == 202
        sid = json.loads(r.body)["id"]
        state = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}", auth, b"").body)
        assert state["state"] == "running"
        assert state["network"]["mode"] == "none"
        ex = app.dispatch(
            "POST",
            f"/v1/sandboxes/{sid}/exec",
            auth,
            json.dumps({"cmd": "printf ok"}).encode(),
        )
        assert ex.status == 200
        assert json.loads(ex.body)["stdout"] == "ok"
        assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", auth, b"").status in (200, 204)
    finally:
        provider.close()
