"""Tests for the Cathedral sandbox HTTP surface (§§3.1-3.13 routing + codes).

These drive :meth:`SandboxApplication.dispatch` in-process, so the whole REST contract
is exercised — status codes, ``Range``/``max_bytes`` semantics, ``Retry-After``,
idempotent deletes, idempotency keys, label filtering and async operations — without
opening a socket.  A couple of integration checks bind the same app to a real listener.
"""

from __future__ import annotations

import json
import threading

import pytest
from urllib.request import urlopen

from cathedral.sandbox_api import ApiKey, QuotaLimits
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication, run, serve

AUTH = {"Authorization": "Bearer k1"}


@pytest.fixture
def app() -> SandboxApplication:
    provider = InMemorySandboxProvider()
    a = SandboxApplication(provider)
    try:
        yield a
    finally:
        provider.close()


def _create(a: SandboxApplication, **body) -> str:
    payload = {"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}}
    payload.update(body)
    r = a.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(payload).encode())
    assert r.status == 202, r.body
    return json.loads(r.body)["id"]


# ------------------------------------------------------------------ auth + routing
def test_missing_auth_is_401(app: SandboxApplication) -> None:
    r = app.dispatch("GET", "/v1/quota", {}, b"")
    assert r.status == 401
    assert json.loads(r.body)["error"]["code"] == "unauthorized"


def test_unknown_route_is_404(app: SandboxApplication) -> None:
    r = app.dispatch("GET", "/v1/nothing", AUTH, b"")
    assert r.status == 404 and json.loads(r.body)["error"]["code"] == "route_not_found"


def test_revoked_key_is_403() -> None:
    provider = InMemorySandboxProvider(keys=[ApiKey(key="ck_rev", project="p", revoked=True)])
    a = SandboxApplication(provider)
    try:
        r = a.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer ck_rev"},
                       json.dumps({"image": "repo/x:latest"}).encode())
        assert r.status == 403 and json.loads(r.body)["error"]["code"] == "key_revoked"
    finally:
        provider.close()


# ------------------------------------------------------------------ §3.1 / §3.2 / §3.3 happy path
def test_create_exec_and_read_back(app: SandboxApplication) -> None:
    sid = _create(app)
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/exec", AUTH, json.dumps({"cmd": "printf hi"}).encode())
    assert r.status == 200
    doc = json.loads(r.body)
    assert doc["exit_code"] == 0 and doc["stdout"] == "hi" and doc["timed_out"] is False

    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/a", AUTH, b"payload")
    got = app.dispatch("GET", f"/v1/sandboxes/{sid}/files?path=/work/a", AUTH, b"")
    assert got.status == 200 and got.body == b"payload"


def test_stat_endpoint(app: SandboxApplication) -> None:
    sid = _create(app)
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/a", AUTH, b"123")
    st = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/stat?path=/work/a", AUTH, b"").body)
    assert st == {"is_dir": False, "is_file": True, "size": 3, "mode": st["mode"]}


# ------------------------------------------------------------------ §3.3 Range / max_bytes codes
def test_get_file_range_returns_206(app: SandboxApplication) -> None:
    sid = _create(app)
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/a", AUTH, b"abcdefghij")
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}/files?path=/work/a", {**AUTH, "Range": "bytes=2-4"}, b"")
    assert r.status == 206
    assert r.body == b"cde"
    assert r.headers["Content-Range"] == "bytes 2-4/10"


def test_get_file_unsatisfiable_range_returns_416(app: SandboxApplication) -> None:
    sid = _create(app)
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/a", AUTH, b"abc")
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}/files?path=/work/a", {**AUTH, "Range": "bytes=50-60"}, b"")
    assert r.status == 416 and json.loads(r.body)["error"]["code"] == "range_not_satisfiable"


def test_get_file_over_max_bytes_returns_413(app: SandboxApplication) -> None:
    sid = _create(app)
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/a", AUTH, b"abcdefghij")
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}/files?path=/work/a&max_bytes=3", AUTH, b"")
    assert r.status == 413 and json.loads(r.body)["error"]["code"] == "file_too_large"


# ------------------------------------------------------------------ §3.2 exec timeout / attach
def test_exec_timeout_flag(app: SandboxApplication) -> None:
    sid = _create(app)
    doc = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/exec", AUTH,
                                  json.dumps({"cmd": "sleep 30", "timeout_seconds": 1}).encode()).body)
    assert doc["timed_out"] is True


def test_ws_attach_returns_501(app: SandboxApplication) -> None:
    sid = _create(app)
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/processes/proc_x/attach", AUTH, b"")
    assert r.status == 501


def test_background_process_routes(app: SandboxApplication) -> None:
    sid = _create(app)
    started = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/processes", AUTH,
                                      json.dumps({"cmd": "printf x"}).encode()).body)
    pid = started["process_id"]
    assert app.dispatch("GET", f"/v1/sandboxes/{sid}/processes/{pid}/logs", AUTH, b"").status == 200
    assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}/processes/{pid}", AUTH, b"").status == 204


# ------------------------------------------------------------------ §3.4 lifecycle codes
def test_delete_is_idempotent_204(app: SandboxApplication) -> None:
    sid = _create(app)
    assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", AUTH, b"").status == 204
    assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", AUTH, b"").status == 204  # already gone


def test_heartbeat_and_patch_lifetime(app: SandboxApplication) -> None:
    sid = _create(app)
    hb = app.dispatch("POST", f"/v1/sandboxes/{sid}/heartbeat", AUTH, json.dumps({"ttl_seconds": 7200}).encode())
    assert hb.status == 200
    patch = app.dispatch("PATCH", f"/v1/sandboxes/{sid}", AUTH, json.dumps({"ttl_seconds": 300}).encode())
    assert patch.status == 200
    # Customer / Cathedral alias: PATCH /lifetime must also extend TTL.
    lifetime = app.dispatch(
        "PATCH", f"/v1/sandboxes/{sid}/lifetime", AUTH, json.dumps({"ttl_seconds": 600}).encode()
    )
    assert lifetime.status == 200


def test_list_and_bulk_delete_by_label(app: SandboxApplication) -> None:
    _create(app, labels={"job": "x"})
    _create(app, labels={"job": "x"})
    listed = json.loads(app.dispatch("GET", "/v1/sandboxes?label=job=x", AUTH, b"").body)
    assert len(listed["sandboxes"]) == 2
    assert app.dispatch("DELETE", "/v1/sandboxes?label=job=x", AUTH, b"").status == 204
    assert json.loads(app.dispatch("GET", "/v1/sandboxes?label=job=x", AUTH, b"").body)["sandboxes"] == []


def test_bulk_delete_without_label_rejected(app: SandboxApplication) -> None:
    r = app.dispatch("DELETE", "/v1/sandboxes", AUTH, b"")
    assert r.status == 400 and json.loads(r.body)["error"]["code"] == "invalid_label"


# ------------------------------------------------------------------ §3.5 snapshot / fork
def test_snapshot_operation_and_lookup(app: SandboxApplication) -> None:
    sid = _create(app)
    resp = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", AUTH, b"{}").body)
    assert "operation_id" in resp and resp["result"]["snapshot_id"].startswith("snap_")
    op = app.dispatch("GET", f"/v1/operations/{resp['operation_id']}", AUTH, b"")
    assert op.status == 200 and json.loads(op.body)["status"] == "done"
    snaps = json.loads(app.dispatch("GET", "/v1/snapshots", AUTH, b"").body)["snapshots"]
    assert any(s["snapshot_id"] == resp["result"]["snapshot_id"] for s in snaps)


def test_unknown_operation_is_404(app: SandboxApplication) -> None:
    assert app.dispatch("GET", "/v1/operations/op_missing", AUTH, b"").status == 404


def test_snapshot_ttl_roundtrips_and_bad_ttl_is_400(app: SandboxApplication) -> None:
    sid = _create(app)
    resp = json.loads(
        app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", AUTH, json.dumps({"ttl_seconds": 120}).encode()).body
    )
    snap_id = resp["result"]["snapshot_id"]
    snaps = json.loads(app.dispatch("GET", "/v1/snapshots", AUTH, b"").body)["snapshots"]
    mine = next(s for s in snaps if s["snapshot_id"] == snap_id)
    assert mine["ttl_seconds"] == 120 and mine["created_at"]
    bad = app.dispatch(
        "POST", f"/v1/sandboxes/{sid}/snapshot", AUTH, json.dumps({"ttl_seconds": 0}).encode()
    )
    assert bad.status == 400 and json.loads(bad.body)["error"]["code"] == "invalid_ttl"


def test_fork_returns_multiple_sandboxes(app: SandboxApplication) -> None:
    sid = _create(app)
    snap = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", AUTH, b"{}").body)["result"]["snapshot_id"]
    fork = app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps({"snapshot_id": snap, "count": 2}).encode())
    assert fork.status == 202
    body = json.loads(fork.body)
    assert body["count"] == 2 and len(body["sandboxes"]) == 2


# ------------------------------------------------------------------ §3.7 network / expose
def test_network_and_expose(app: SandboxApplication) -> None:
    sid = _create(app)
    net = app.dispatch("POST", f"/v1/sandboxes/{sid}/network", AUTH, json.dumps({"mode": "none", "allow": []}).encode())
    assert net.status == 200 and json.loads(net.body)["network"]["mode"] == "none"
    ex = app.dispatch("POST", f"/v1/sandboxes/{sid}/expose", AUTH, json.dumps({"port": 8080}).encode())
    assert ex.status == 200 and "8080" in json.loads(ex.body)["url"]


# ------------------------------------------------------------------ §3.9 images
def test_prefetch_and_image_lookup(app: SandboxApplication) -> None:
    pf = app.dispatch("POST", "/v1/images/prefetch", AUTH, json.dumps({"images": ["repo/x:latest"]}).encode())
    assert pf.status == 202 and "operation_id" in json.loads(pf.body)
    look = app.dispatch("GET", "/v1/images/repo/x:latest", AUTH, b"")
    assert look.status == 200 and json.loads(look.body)["cached"] is True


def test_bad_image_reference_is_400(app: SandboxApplication) -> None:
    r = app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps({"image": "https://bad/x:latest"}).encode())
    assert r.status == 400 and json.loads(r.body)["error"]["code"] == "invalid_image_reference"


# ------------------------------------------------------------------ §3.8 quota / usage / status
def test_quota_over_limit_returns_429_with_retry_after() -> None:
    provider = InMemorySandboxProvider(limits=QuotaLimits(running_sandboxes=1, vcpu=1000, memory_gib=3000))
    a = SandboxApplication(provider)
    try:
        assert _create(a)  # first ok
        r = a.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps({"image": "repo/y:latest"}).encode())
        assert r.status == 429
        assert "Retry-After" in r.headers
    finally:
        provider.close()


def test_aggregate_endpoints(app: SandboxApplication) -> None:
    assert app.dispatch("GET", "/v1/quota", AUTH, b"").status == 200
    quota = json.loads(app.dispatch("GET", "/v1/quota", AUTH, b"").body)
    assert quota["creates_per_minute"] >= 100 and quota["snapshot_store"] >= 1000
    usage = app.dispatch("GET", "/v1/usage?group_by=label.job", AUTH, b"")
    assert usage.status == 200 and "groups" in json.loads(usage.body)
    status = app.dispatch("GET", "/v1/status", AUTH, b"")
    assert status.status == 200 and json.loads(status.body)["status"] == "operational"


# ------------------------------------------------------------------ §3.10/§3.11 idle + pacing
def test_create_accepts_idle_timeout(app: SandboxApplication) -> None:
    r = app.dispatch(
        "POST",
        "/v1/sandboxes",
        AUTH,
        json.dumps({"image": "repo/idle:latest", "idle_timeout_seconds": 120}).encode(),
    )
    assert r.status == 202
    assert json.loads(r.body)["idle_timeout_seconds"] == 120


def test_create_bad_idle_timeout_is_400(app: SandboxApplication) -> None:
    r = app.dispatch(
        "POST",
        "/v1/sandboxes",
        AUTH,
        json.dumps({"image": "repo/idle:latest", "idle_timeout_seconds": 0}).encode(),
    )
    assert r.status == 400 and json.loads(r.body)["error"]["code"] == "invalid_idle_timeout"


def test_create_pacing_returns_429_over_http() -> None:
    provider = InMemorySandboxProvider(creates_per_minute=2)
    a = SandboxApplication(provider)
    try:
        _create(a)
        _create(a)
        r = a.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps({"image": "repo/y:latest"}).encode())
        assert r.status == 429 and json.loads(r.body)["error"]["code"] == "create_rate_exceeded"
    finally:
        provider.close()


# ------------------------------------------------------------------ §3.12 idempotency
def test_idempotency_key_replays_same_sandbox(app: SandboxApplication) -> None:
    body = json.dumps({"image": "repo/z:latest"}).encode()
    headers = {**AUTH, "Idempotency-Key": "cathedral-idem-key-abc"}
    first = json.loads(app.dispatch("POST", "/v1/sandboxes", headers, body).body)
    replay = json.loads(app.dispatch("POST", "/v1/sandboxes", headers, body).body)
    assert replay["id"] == first["id"]


# ------------------------------------------------------------------ §3.13 logs route
def test_logs_route_returns_stream_and_history(app: SandboxApplication) -> None:
    sid = _create(app)
    app.dispatch("POST", f"/v1/sandboxes/{sid}/exec", AUTH, json.dumps({"cmd": "printf out"}).encode())
    app.dispatch("POST", f"/v1/sandboxes/{sid}/exec", AUTH, json.dumps({"cmd": "sh -c 'printf err 1>&2'"}).encode())
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}/logs", AUTH, b"")
    assert r.status == 200
    doc = json.loads(r.body)
    assert doc["stdout"] == "out" and doc["stderr"] == "err"
    assert len(doc["exec_history"]) == 2


def test_logs_route_survives_delete_24h(app: SandboxApplication) -> None:
    sid = _create(app)
    app.dispatch("POST", f"/v1/sandboxes/{sid}/exec", AUTH, json.dumps({"cmd": "printf retained"}).encode())
    assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", AUTH, b"").status == 204
    # GET on the sandbox itself is now 404, but logs are still served (§3.18 24 h).
    assert app.dispatch("GET", f"/v1/sandboxes/{sid}", AUTH, b"").status == 404
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}/logs", AUTH, b"")
    assert r.status == 200 and json.loads(r.body)["stdout"] == "retained"


# ------------------------------------------------------------------ §3.16 usage cost
def test_usage_endpoint_reports_cost(app: SandboxApplication) -> None:
    sid = _create(app, labels={"job": "billed"})
    r = app.dispatch("GET", "/v1/usage?group_by=label.job", AUTH, b"")
    assert r.status == 200
    body = json.loads(r.body)
    assert body["currency"] == "USD"
    assert "cost_usd" in body["groups"]["billed"]
    assert "total_cost_usd" in body


# ------------------------------------------------------------------ integration: real listener
def test_serves_over_real_http(app: SandboxApplication) -> None:
    httpd = serve(app, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        req_headers = {"Authorization": "Bearer k1", "Content-Type": "application/json"}
        import urllib.request

        data = json.dumps({"image": "repo/live:latest"}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/sandboxes", data=data, headers=req_headers, method="POST")
        with urlopen(req, timeout=5) as resp:
            assert resp.status == 202
            sid = json.loads(resp.read())["id"]
        get_req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/sandboxes/{sid}", headers=req_headers)
        with urlopen(get_req, timeout=5) as resp:  # authenticated read-back
            assert resp.status == 200
        assert sid
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_run_helper_and_strict_env_auth_over_real_http(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.request
    import urllib.error

    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", "ck_ok:project-a")
    from cathedral.sandbox_provider import provider_from_environment

    p = provider_from_environment()
    app = SandboxApplication(p, require_auth=True)
    httpd, (host, port) = run(app, host="127.0.0.1", port=0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        assert port != 0 and host == "127.0.0.1"
        good = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/quota", headers={"Authorization": "Bearer ck_ok"}
        )
        with urlopen(good, timeout=5) as resp:
            assert resp.status == 200
        bad = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/quota", headers={"Authorization": "Bearer nope"}
        )
        with pytest.raises(urllib.error.HTTPError) as ei:
            urlopen(bad, timeout=5)
        assert ei.value.code == 401
    finally:
        httpd.shutdown()
        httpd.server_close()
        p.close()


# ------------------------------------------------------------------ §3.10/§3.11 OpenAPI contract
def test_openapi_is_public_without_auth(app: SandboxApplication) -> None:
    r = app.dispatch("GET", "/openapi.json", {}, b"")  # no Authorization header
    assert r.status == 200
    doc = json.loads(r.body)
    assert doc["openapi"] == "3.0.3"
    assert doc["info"]["title"] == "Cathedral Compute Sandbox API"


def test_openapi_covers_core_verbs(app: SandboxApplication) -> None:
    from cathedral.sandbox_server import openapi_document

    doc = openapi_document()
    paths = doc["paths"]
    assert "post" in paths["/v1/sandboxes"]
    assert "post" in paths["/v1/sandboxes/{id}/exec"]
    assert "get" in paths["/v1/usage"]
    assert "delete" in paths["/v1/snapshots/{id}"]
    # every documented path verb carries a security scheme and error responses
    op = paths["/v1/sandboxes"]["post"]
    assert op["security"] == [{"bearerAuth": []}]
    assert "429" in op["responses"]
    assert "Idempotency-Key" in [p["name"] for p in op["parameters"]]


def test_openapi_security_scheme_present() -> None:
    from cathedral.sandbox_server import openapi_document

    doc = openapi_document(base_url="https://cathedral.test/api")
    assert doc["servers"][0]["url"] == "https://cathedral.test/api"
    assert doc["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
