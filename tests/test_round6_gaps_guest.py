"""Review round 6 (reader P): Docker guest fixes of PR #312 that no test guarded.

Each test here failed on the code before its fix (22e7824), or before the fix
made in this pass, on the behaviour it names. Fake docker CLI only.
"""
from __future__ import annotations

import http.server
import io
import tarfile
import threading

import pytest

from cathedral import sandbox_guest as sg
from cathedral.sandbox_api import CreateSandboxRequest, ExecRequest, ImageSource, NetworkSpec, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from tests.fake_docker_cli import install
from tests.test_sandbox_egress import Daemon

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)
AUTH = {"username": "u", "password": "p"}


@pytest.fixture
def fake(tmp_path, monkeypatch):
    f = install(tmp_path, monkeypatch)
    f.add_image("alpine:3.20")
    f.set(exec_model=True)
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RECONCILE_SECONDS", "0")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_AUTH_PULLED_FILE", str(tmp_path / "auth-pulled.json"))
    return f


@pytest.fixture
def provider(fake):
    p = DockerGuestProvider()
    try:
        yield p
    finally:
        p.close()


@pytest.fixture
def daemon(fake, monkeypatch):
    d = Daemon(monkeypatch)
    yield d
    d.close()


@pytest.fixture
def managed(daemon):
    # A provider started after the egress daemon, so it manages its rooms' policies.
    p = DockerGuestProvider()
    try:
        yield p
    finally:
        p.close()


def _room(provider, api_key="k", digest="x", image="alpine:3.20", **over) -> str:
    req = CreateSandboxRequest(image=ImageSource(image=image), resources=RES, **over)
    return provider.create(req, api_key=api_key, idempotency=None, body_digest=digest)["id"]


def _snap(provider, sid, **kw) -> str:
    return provider.get_operation(provider.snapshot(sid, **kw))["result"]["snapshot_id"]


# ---------------------------------------------------------------- O1: push untags the registry name

def test_a_pushed_snapshot_leaves_no_local_copy_under_the_registry_name(fake, provider) -> None:
    # The create path pulls only credentialed or always-pull images. A local
    # copy under the registry name would start for any key on this hotel with
    # no pull and no credentials: another key's private snapshot, for free.
    sid = _room(provider)
    snap = _snap(provider, sid)
    pushed = "registry.example.com/acme/pushed:1"
    provider.push_snapshot(snap, image=pushed, registry_auth=AUTH)
    assert ["image", "rm", pushed] in fake.calls_of("image", "rm")
    assert pushed not in fake.state["images"]
    assert f"cathedral-snap-{snap}:latest" in fake.state["images"]  # the snapshot itself stays
    # A key without credentials that names the pushed image goes through the
    # registry, which refuses it.
    fake.set(pull_fail=[pushed])
    provider.authorize("other")
    with pytest.raises(SandboxOpError) as err:
        _room(provider, api_key="other", digest="y", image=pushed)
    assert err.value.code == "image_pull_failed"


# ---------------------------------------------------------------- O3: snapshot visibility on the Docker provider

def test_another_key_cannot_push_fork_or_delete_a_snapshot_on_the_docker_provider(fake, provider) -> None:
    # The Docker provider resolves snapshot ids and names itself (fork image
    # lookup, push, delete). It must see what the inner provider lets the
    # caller see, or key B pushes key A's root file system to B's registry.
    sa = _room(provider, api_key="alice")
    snap = _snap(provider, sa, name="base")
    image = f"cathedral-snap-{snap}:latest"
    provider.authorize("bob")
    for ref in (snap, "base"):
        with pytest.raises(SandboxOpError) as err:
            provider.push_snapshot(ref, image="registry.example.com/bob/taken:1", registry_auth=AUTH)
        assert err.value.code == "snapshot_not_found"
        with pytest.raises(SandboxOpError) as err:
            provider.create(CreateSandboxRequest(snapshot_id=ref, resources=RES), api_key="bob", idempotency=None, body_digest="b")
        assert err.value.code == "snapshot_not_found"
    assert not fake.state.get("pushed")
    # Bob's delete is a 404 for him and must not take Alice's image with it.
    assert provider.delete_snapshot(snap) is False
    assert image in fake.state["images"]
    provider.authorize("alice")
    forked = provider.create(CreateSandboxRequest(snapshot_id="base", resources=RES), api_key="alice", idempotency=None, body_digest="c")
    assert forked["guest"]["image"] == image


# ---------------------------------------------------------------- O4: entrypoint that ends at once

def test_an_entrypoint_that_ends_at_once_is_a_400_when_the_policy_cannot_apply(fake, daemon, managed, monkeypatch) -> None:
    # The egress daemon finds no running container for a room whose
    # entrypoint ended at once. That is the request's fault: a 502 here made
    # the broker rest this hotel 10 s for every guest, one bad image at a time.
    fake.set(exit_at_once={"false": 1})

    def not_running(cid):
        raise RuntimeError(f"container {cid[:12]} is not running with one network")

    monkeypatch.setattr(daemon.table.docker, "facts", not_running)
    with pytest.raises(SandboxOpError) as err:
        _room(managed, entrypoint=("false",), network=NetworkSpec(mode="internet"))
    assert err.value.http_status == 400 and err.value.code == "entrypoint_exited"
    assert "exit code 1" in str(err.value)
    assert fake.containers == {}  # the exited container is gone
    assert managed.list(labels=[], state=None) == []


# ---------------------------------------------------------------- O7: memory caps

def test_a_build_context_url_past_the_cap_is_a_413(monkeypatch) -> None:
    # The fetch read the whole answer into memory: a customer URL of any size.
    cap = 1000
    monkeypatch.setattr(sg, "BUILD_CONTEXT_CAP", cap, raising=False)
    monkeypatch.setattr(sg, "_public_ip", lambda raw: True)  # the test server is local

    class Big(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(cap + 2))
            self.end_headers()
            self.wfile.write(b"x" * (cap + 2))

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Big)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with pytest.raises(SandboxOpError) as err:
            sg._fetch_context_tar(f"http://127.0.0.1:{httpd.server_address[1]}/context.tar")  # noqa: SLF001
        assert err.value.http_status == 413 and err.value.code == "build_context_too_large"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_build_context_that_expands_past_the_cap_is_refused(fake, provider, monkeypatch) -> None:
    # A small gzip tar can expand to many GiB on the hotel's data volume.
    monkeypatch.setattr(sg, "BUILD_CONTEXT_EXPANDED_CAP", 100, raising=False)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("big.bin")
        info.size = 200
        tf.addfile(info, io.BytesIO(b"\0" * 200))
    with pytest.raises(SandboxOpError) as err:
        provider.build_image("FROM alpine:3.20\nCOPY big.bin /big.bin\n", buf.getvalue())
    assert err.value.http_status == 400 and err.value.code == "invalid_build_context"
    assert not fake.calls_of("build")


def test_a_room_log_read_stops_at_the_cap(tmp_path, monkeypatch) -> None:
    # The room writes its own process log under /work, without limit.
    monkeypatch.setattr(sg, "EXEC_OUTPUT_CAP", 1000, raising=False)
    log = tmp_path / ".process-1.log"
    log.write_bytes(b"y" * 1001)
    assert len(sg._read_room_log(log)) == 1000  # noqa: SLF001


def test_the_exec_log_record_keeps_the_last_cap_bytes_only(fake, provider, monkeypatch) -> None:
    # Every exec appended its whole output to the API's in-memory log record.
    cap = 100
    monkeypatch.setattr(sg, "EXEC_OUTPUT_CAP", cap, raising=False)
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "marker", "stdout": "a" * 80, "exit": 0}])
    sid = _room(provider)
    for _ in range(2):
        assert provider.exec(sid, ExecRequest(cmd=["echo", "marker"], timeout_seconds=10)).stdout == "a" * 80
    record = provider._inner._sandboxes[sid]  # noqa: SLF001
    assert len(record.container_stdout) == cap
    assert bytes(record.container_stdout) == b"a" * cap


# ---------------------------------------------------------------- O13: idempotency after a failed start

def test_a_failed_guest_start_frees_the_idempotency_key_for_its_own_key_only(fake, provider) -> None:
    # The inner provider keys replays by (api key, Idempotency-Key). The
    # cleanup after a failed start must drop that same entry, or a retry
    # replays the document of a room that was removed. Another key's same
    # Idempotency-Key stays its own and never hands out this key's room.
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES)
    key = "retry-key-1"
    fake.set(run_fail_images=["alpine:3.20"])
    with pytest.raises(SandboxOpError) as err:
        provider.create(req, api_key="alice", idempotency=key, body_digest="same")
    assert err.value.code == "guest_start_failed"
    fake.set(run_fail_images=[])
    retry = provider.create(req, api_key="alice", idempotency=key, body_digest="same")
    assert retry["id"] in provider._guests and provider.get(retry["id"])["state"] == "running"  # noqa: SLF001
    assert provider.create(req, api_key="alice", idempotency=key, body_digest="same")["id"] == retry["id"]
    provider.authorize("bob")
    bob = provider.create(req, api_key="bob", idempotency=key, body_digest="same")
    assert bob["id"] != retry["id"] and bob["id"] in provider._guests  # noqa: SLF001
