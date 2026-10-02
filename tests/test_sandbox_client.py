"""Tests for the thin Cathedral sandbox Python SDK (§3 style note: "SDK welcome").

The SDK is transport-agnostic, so every check here runs against an in-process
:class:`SandboxApplication` through :class:`DispatchTransport` — no sockets — while
exercising the same verbs a caller would use against the hosted API.  A couple of
end-to-end checks bind :func:`serve` and drive the SDK over real HTTP via
:class:`HttpTransport`, proving the documented REST shape round-trips.
"""

from __future__ import annotations

import json
import threading

import pytest

from cathedral.sandbox_client import (
    DispatchTransport,
    HttpTransport,
    SandboxAPIError,
    SandboxClient,
)
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication, serve


@pytest.fixture
def client() -> SandboxClient:
    provider = InMemorySandboxProvider()
    app = SandboxApplication(provider)
    try:
        yield SandboxClient(transport=DispatchTransport(app, api_key="k1"))
    finally:
        provider.close()


# ------------------------------------------------------------------ §3.1 create / read
def test_create_get_and_delete_roundtrip(client: SandboxClient) -> None:
    doc = client.create(image="repo/tool:latest", resources={"vcpu": 1, "memory_gib": 2, "disk_gib": 5})
    sid = doc["id"]
    assert sid.startswith("sbx_")
    assert client.get(sid)["state"] == "running"
    client.delete(sid)
    with pytest.raises(SandboxAPIError) as ei:
        client.get(sid)
    assert ei.value.status == 404 and ei.value.code == "sandbox_not_found"


def test_create_propagates_stable_error_code(client: SandboxClient) -> None:
    with pytest.raises(SandboxAPIError) as ei:
        client.create(image="https://bad/x:latest")
    assert ei.value.status == 400 and ei.value.code == "invalid_image_reference"


# ------------------------------------------------------------------ §3.2 exec / processes
def test_exec_shell_and_argv(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    assert client.exec(sid, "printf hello")["stdout"] == "hello"
    assert client.exec(sid, ["printf", "argv"])["stdout"] == "argv"


def test_exec_timeout_flag(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    assert client.exec(sid, "sleep 30", timeout_seconds=1)["timed_out"] is True


def test_background_process_lifecycle(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    pid = client.start_process(sid, "printf bg")["process_id"]
    assert client.stop_process(sid, pid) is None


# ------------------------------------------------------------------ §3.3 files / tar / stat
def test_file_write_read_and_stat(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    client.write_file(sid, "/work/a.txt", b"payload")
    assert client.read_file(sid, "/work/a.txt") == b"payload"
    assert client.stat(sid, "/work/a.txt")["size"] == 7


def test_read_file_range_uses_header(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    client.write_file(sid, "/work/a.txt", b"abcdefghij")
    assert client.read_file(sid, "/work/a.txt", range_header="bytes=2-4") == b"cde"


def test_read_file_max_bytes_raises_413(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    client.write_file(sid, "/work/a.txt", b"abcdefghij")
    with pytest.raises(SandboxAPIError) as ei:
        client.read_file(sid, "/work/a.txt", max_bytes=3)
    assert ei.value.status == 413


def test_tar_roundtrip(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    client.write_file(sid, "/work/pkg/f.txt", b"inside")
    blob = client.read_tar(sid, "/work")
    other = client.create(image="repo/tool:latest")["id"]
    client.write_tar(other, "/work", blob)
    assert client.read_file(other, "/work/pkg/f.txt") == b"inside"


# ------------------------------------------------------------------ §3.4 lifecycle
def test_heartbeat_extends_lifetime(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    before = client.get(sid)["expires_at"]
    after = client.heartbeat(sid, 48 * 3600)["expires_at"]
    assert after != before


def test_list_and_bulk_delete_by_label(client: SandboxClient) -> None:
    client.create(image="repo/tool:latest", labels={"job": "x"})
    client.create(image="repo/tool:latest", labels={"job": "x"})
    assert len(client.list(labels=["job=x"])) == 2
    client.bulk_delete(labels=["job=x"])
    assert client.list(labels=["job=x"]) == []


# ------------------------------------------------------------------ §3.5 snapshot / fork
def test_snapshot_then_fork(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    client.exec(sid, "printf pre > state.txt")
    snap = client.snapshot(sid)["result"]["snapshot_id"]
    forks = client.fork(snap, count=2)
    assert forks["count"] == 2
    for fork in forks["sandboxes"]:
        assert client.read_file(fork["id"], "/work/state.txt") == b"pre"


def test_snapshot_listing_and_delete(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    snap = client.snapshot(sid)["result"]["snapshot_id"]
    assert any(s["snapshot_id"] == snap for s in client.list_snapshots())
    assert client.delete_snapshot(snap) is True
    # a second delete is a 404 over the wire (the server signals the gone snapshot).
    with pytest.raises(SandboxAPIError) as ei:
        client.delete_snapshot(snap)
    assert ei.value.status == 404 and ei.value.code == "snapshot_not_found"


# ------------------------------------------------------------------ §3.7 network / expose
def test_network_and_expose(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest")["id"]
    assert client.set_network(sid, "allowlist", ["pypi.org"])["network"]["mode"] == "allowlist"
    assert "8080" in client.expose(sid, 8080)["url"]


# ------------------------------------------------------------------ §3.9 images
def test_prefetch_and_image_status(client: SandboxClient) -> None:
    op_id = client.prefetch(["repo/x:latest"])
    assert client.get_operation(op_id)["status"] == "done"
    assert client.image_status("repo/x:latest")["cached"] is True


# ------------------------------------------------------------------ §3.13 logs / usage / status / quota
def test_logs_and_usage_and_status(client: SandboxClient) -> None:
    sid = client.create(image="repo/tool:latest", labels={"job": "j1"})["id"]
    client.exec(sid, "printf logged")
    logs = client.logs(sid)
    assert logs["stdout"] == "logged" and len(logs["exec_history"]) == 1
    usage = client.usage(group_by="label.job")
    assert usage["currency"] == "USD" and "j1" in usage["groups"]
    assert client.status()["status"] == "operational"
    assert "limits" in client.quota()


# ------------------------------------------------------------------ §3.8 quota 429 code
def test_quota_429_surfaces_code() -> None:
    from cathedral.sandbox_api import QuotaLimits

    provider = InMemorySandboxProvider(limits=QuotaLimits(running_sandboxes=1, vcpu=1000, memory_gib=3000))
    client = SandboxClient(transport=DispatchTransport(SandboxApplication(provider), api_key="k1"))
    try:
        client.create(image="repo/a:latest")
        with pytest.raises(SandboxAPIError) as ei:
            client.create(image="repo/b:latest")
        assert ei.value.status == 429 and ei.value.code == "quota_exhausted"
    finally:
        provider.close()


# ------------------------------------------------------------------ §3.14 auth revoke
def test_revoked_key_surfaces_403() -> None:
    from cathedral.sandbox_api import ApiKey

    provider = InMemorySandboxProvider(keys=[ApiKey(key="ck_rev", project="p", revoked=True)])
    client = SandboxClient(transport=DispatchTransport(SandboxApplication(provider), api_key="ck_rev"))
    try:
        with pytest.raises(SandboxAPIError) as ei:
            client.create(image="repo/a:latest")
        assert ei.value.status == 403 and ei.value.code == "key_revoked"
    finally:
        provider.close()


# ------------------------------------------------------------------ integration over HTTP
def test_sdk_over_real_http_listener() -> None:
    provider = InMemorySandboxProvider()
    app = SandboxApplication(provider)
    httpd = serve(app, host="127.0.0.1", port=0)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    client = SandboxClient(base_url=f"http://127.0.0.1:{port}", api_key="k1")
    assert isinstance(client._transport, HttpTransport)
    try:
        sid = client.create(image="repo/live:latest")["id"]
        assert client.exec(sid, "printf live")["stdout"] == "live"
        client.write_file(sid, "/work/x", b"down")
        assert client.read_file(sid, "/work/x") == b"down"
        client.delete(sid)
    finally:
        httpd.shutdown()
        httpd.server_close()
        provider.close()


def test_client_requires_credentials_or_transport() -> None:
    with pytest.raises(ValueError):
        SandboxClient()
