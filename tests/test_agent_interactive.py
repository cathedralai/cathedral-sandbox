"""Phase 2 Agent IDE: tickets, terminals, publish, desktop gate."""

from __future__ import annotations

import json
import os

import pytest

from cathedral.agent_profile import agent_create_body
from cathedral.sandbox_api import ApiKey, MIN_RUNNING_SANDBOXES, QuotaLimits
from cathedral.sandbox_server import SandboxApplication

AUTH = {"Authorization": "Bearer agent-k1"}


@pytest.fixture
def app() -> SandboxApplication:
    from cathedral.sandbox_provider import InMemorySandboxProvider

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


def test_affline_untouched() -> None:
    assert MIN_RUNNING_SANDBOXES == 500


def test_access_ticket_mint_and_single_use(app: SandboxApplication) -> None:
    sid = _create(app)
    t = app.dispatch("POST", f"/v1/sandboxes/{sid}/access-tickets", AUTH, json.dumps({"ttl_sec": 60}).encode())
    assert t.status == 200
    ticket = json.loads(t.body)["ticket"]
    assert ticket.startswith("sat_")
    term = app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, json.dumps({"cols": 100, "rows": 40}).encode())
    assert term.status == 201
    tid = json.loads(term.body)["id"]
    conn = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/terminals/{tid}/connect",
        AUTH,
        json.dumps({"ticket": ticket}).encode(),
    )
    assert conn.status == 200
    assert json.loads(conn.body)["connected"] is True
    # replay rejected
    again = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/terminals/{tid}/connect",
        AUTH,
        json.dumps({"ticket": ticket}).encode(),
    )
    assert again.status == 401


def test_terminal_write_read_after_connect(app: SandboxApplication) -> None:
    sid = _create(app)
    ticket = json.loads(
        app.dispatch("POST", f"/v1/sandboxes/{sid}/access-tickets", AUTH, b"{}").body
    )["ticket"]
    tid = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, b"{}").body)["id"]
    app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/terminals/{tid}/connect",
        AUTH,
        json.dumps({"ticket": ticket}).encode(),
    )
    # drain connect banner
    app.dispatch("GET", f"/v1/sandboxes/{sid}/terminals/{tid}/output", AUTH, b"")
    w = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/terminals/{tid}/input",
        AUTH,
        json.dumps({"data": "printf hello-agent\n"}).encode(),
    )
    assert w.status == 200
    out = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/terminals/{tid}/output", AUTH, b"").body)
    assert "hello-agent" in out["data"]
    listed = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/terminals", AUTH, b"").body)
    assert any(t["id"] == tid for t in listed)
    assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}/terminals/{tid}", AUTH, b"").status == 204


def test_terminal_write_requires_connect(app: SandboxApplication) -> None:
    sid = _create(app)
    tid = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, b"{}").body)["id"]
    r = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/terminals/{tid}/input",
        AUTH,
        json.dumps({"data": "echo x\n"}).encode(),
    )
    assert r.status == 409
    assert json.loads(r.body)["error"]["code"] == "terminal_not_connected"


def test_publish_template_and_create_from_it(app: SandboxApplication) -> None:
    sid = _create(app)
    pub = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/publish",
        AUTH,
        json.dumps({"name": "python-tools", "display_name": "Python tools"}).encode(),
    )
    assert pub.status == 202, pub.body
    tmpl = json.loads(pub.body)
    assert tmpl["kind"] == "USER" and tmpl["status"] == "READY"
    uid = tmpl["uid"]
    assert uid.startswith("sbt-")
    items = json.loads(app.dispatch("GET", "/v1/sandbox-templates?status=READY", AUTH, b"").body)["items"]
    assert any(i["uid"] == uid for i in items)
    got = json.loads(app.dispatch("GET", f"/v1/sandbox-templates/{uid}", AUTH, b"").body)
    assert got["name"] == "python-tools"
    child = app.dispatch(
        "POST",
        "/v1/sandboxes",
        AUTH,
        json.dumps(agent_create_body(image=uid)).encode(),
    )
    assert child.status == 202, child.body
    assert json.loads(child.body)["image_id"] == tmpl["image_ref"]


def test_desktop_gated_by_env(app: SandboxApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    sid = _create(app)
    monkeypatch.delenv("CATHEDRAL_AGENT_DESKTOP", raising=False)
    off = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/desktop", AUTH, b"").body)
    assert off == {"available": False}
    monkeypatch.setenv("CATHEDRAL_AGENT_DESKTOP", "1")
    on = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/desktop", AUTH, b"").body)
    assert on["available"] is True
    assert on["listening"] is True
    assert "/desktop/ws" in on["ws_url"]


def test_invalid_ticket_ttl(app: SandboxApplication) -> None:
    sid = _create(app)
    bad = app.dispatch(
        "POST",
        f"/v1/sandboxes/{sid}/access-tickets",
        AUTH,
        json.dumps({"ttl_sec": 9999}).encode(),
    )
    assert bad.status == 400
