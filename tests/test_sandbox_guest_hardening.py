"""Docker guest provider: review round 6 (reader F) findings, each a test that failed first."""
from __future__ import annotations

import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ExecRequest, ImageSource, NetworkPatch, NetworkSpec, Resources
from cathedral.sandbox_guest import DockerClient, DockerGuestProvider, _guest_start_fault
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_server import install_stop_signal
from tests.fake_docker_cli import install
from tests.test_sandbox_egress import Daemon

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    f = install(tmp_path, monkeypatch)
    f.add_image("alpine:3.20")
    f.set(exec_model=True)
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RECONCILE_SECONDS", "0")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_AUTH_PULLED_FILE", str(tmp_path / "auth-pulled.json"))
    return f


@pytest.fixture
def daemon(fake, monkeypatch):
    d = Daemon(monkeypatch)
    yield d
    d.close()


def _room(provider, digest="x", **over) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES, **over)
    return provider.create(req, api_key="k", idempotency=None, body_digest=digest)["id"]


def test_output_that_is_not_utf8_is_replaced_not_fatal() -> None:
    # A room may print any bytes (cat image.png). A decode error dropped the request.
    client = DockerClient()
    r = client.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff\\xfeok'); sys.stderr.buffer.write(b'\\xff')"], timeout=30)
    assert r.returncode == 0 and r.stdout.endswith("ok") and "�" in r.stdout and "�" in r.stderr


def test_run_keeps_at_most_cap_plus_one_bytes_of_output() -> None:
    client = DockerClient()
    r = client.run([sys.executable, "-c", "import sys; sys.stdout.write('x' * 3_000_000); sys.stderr.write('e' * 10)"],
                   timeout=60, output_cap=1_000_000)
    assert r.returncode == 0 and len(r.stdout) == 1_000_001 and r.stderr == "e" * 10


def test_exec_asks_for_bounded_output(fake, monkeypatch) -> None:
    seen = {}
    original = DockerClient.run

    def spy(self, argv, **kw):
        if argv[:2] == ["docker", "exec"]:
            seen["cap"] = kw.get("output_cap")
        return original(self, argv, **kw)

    monkeypatch.setattr(DockerClient, "run", spy)
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd=["echo", "hi"], timeout_seconds=10))
        assert seen["cap"] == 16 * 1024 * 1024
    finally:
        provider.close()


@pytest.mark.parametrize("stderr,code", [
    ('docker: Error response from daemon: ... exec: "/no/such": stat /no/such: no such file or directory', "invalid_entrypoint"),
    ("executable file not found in $PATH", "invalid_entrypoint"),
    ("unable to find user nosuchuser: no matching entries in passwd file", "invalid_user"),
    ("chdir to cwd (\"/etc/passwd\") set in config.json failed: not a directory", "invalid_workdir"),
    ("Error response from daemon: could not add veth: bridge full", None),
])
def test_start_faults_that_are_the_request_s(stderr, code) -> None:
    assert _guest_start_fault(stderr) == code


def test_a_bad_entrypoint_is_a_400_not_a_hotel_fault(fake, monkeypatch) -> None:
    # The broker rests a hotel on a 502 create: one guest's bad entrypoint took
    # every shared hotel out of placement in turn.
    def failed_run(self, argv, name):
        return subprocess.CompletedProcess(argv, 127, "", 'exec: "/no/such/binary": stat /no/such/binary: no such file or directory')

    monkeypatch.setattr(DockerClient, "_run_guest", failed_run)
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as err:
            _room(provider, entrypoint=("/no/such/binary",))
        assert err.value.http_status == 400 and err.value.code == "invalid_entrypoint"
    finally:
        provider.close()


def test_timeout_wrappers_kill_a_command_that_ignores_term(fake) -> None:
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "hello", "stdout": "hi", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd=["echo", "hello"], timeout_seconds=30))
        runs = [c for c in fake.calls_of("exec") if "hello" in c]
        assert runs and runs[-1][runs[-1].index("timeout"):][:4] == ["timeout", "-k", "5", "30"]
    finally:
        provider.close()


def test_network_change_on_a_frozen_room_is_refused_before_the_daemon_moves(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        sid = _room(provider, network=NetworkSpec(mode="deny_all"))
        provider.freeze(sid)
        with pytest.raises(SandboxOpError) as err:
            provider.set_network(sid, NetworkPatch(mode="internet"))
        assert err.value.http_status == 409
        assert provider._guests[sid].network_mode == "deny_all"  # noqa: SLF001
    finally:
        provider.close()


def _expire(provider, sid) -> None:
    with provider._inner._lock:  # noqa: SLF001
        provider._inner._sandboxes[sid].expires_at = datetime.now(timezone.utc) - timedelta(hours=1)  # noqa: SLF001


def test_a_ttl_that_ends_during_the_drain_still_gets_the_two_phase_delete(fake, daemon, monkeypatch) -> None:
    provider = DockerGuestProvider()
    try:
        a = provider.create(CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES, network=NetworkSpec(mode="internet")),
                            api_key="k", idempotency=None, body_digest="a")
        b = provider.create(CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES, network=NetworkSpec(mode="internet")),
                            api_key="k", idempotency=None, body_digest="b")
        sid_a, sid_b, cid_b = a["id"], b["id"], b["guest"]["container_id"]
        _expire(provider, sid_a)
        drain = provider._drain_locked  # noqa: SLF001

        def drain_then_b_expires():
            n = drain()
            if provider._inner.has_record(sid_b):  # noqa: SLF001
                _expire(provider, sid_b)
            return n

        monkeypatch.setattr(provider, "_drain_locked", drain_then_b_expires)
        provider.sweep()
        assert not provider._inner.has_record(sid_a)  # noqa: SLF001
        # B is never "record gone, container running": either untouched yet or fully retired.
        gone = cid_b not in fake.containers or fake.containers[cid_b].get("removed")
        assert provider._inner.has_record(sid_b) or gone  # noqa: SLF001
        monkeypatch.setattr(provider, "_drain_locked", drain)
        provider.sweep()
        assert not provider._inner.has_record(sid_b)  # noqa: SLF001
        assert cid_b not in fake.containers or fake.containers[cid_b].get("removed")
        assert cid_b not in daemon.table.by_cid
        assert sid_b not in provider._guests  # noqa: SLF001
    finally:
        provider.close()


def test_an_expired_snapshot_loses_its_image(fake) -> None:
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        snap = provider.get_operation(provider.snapshot(sid, ttl_seconds=1))["result"]["snapshot_id"]
        image = f"cathedral-snap-{snap}:latest"
        assert image in fake.state["images"]
        time.sleep(1.2)
        provider.sweep()
        assert provider.list_snapshots() == []
        assert image not in fake.state["images"]
        assert snap not in provider._snapshot_images  # noqa: SLF001
    finally:
        provider.close()


def test_a_restart_removes_snapshot_images_nobody_names(fake) -> None:
    first = DockerGuestProvider()
    try:
        sid = _room(first)
        snap = first.get_operation(first.snapshot(sid))["result"]["snapshot_id"]
        image = f"cathedral-snap-{snap}:latest"
    finally:
        first.close()
    assert image in fake.state["images"]
    second = DockerGuestProvider()
    try:
        second.sweep()  # reconcile runs at once (interval 0)
        assert image not in fake.state["images"]
    finally:
        second.close()


def test_sigterm_ends_the_server_like_ctrl_c() -> None:
    install_stop_signal()
    handler = signal.getsignal(signal.SIGTERM)
    assert callable(handler)
    with pytest.raises(KeyboardInterrupt):
        handler(signal.SIGTERM, None)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


def test_credentialed_pulls_are_remembered_across_a_restart(fake, tmp_path) -> None:
    # A private image pulled with one key's credentials must not start for a
    # key without credentials after the API restarts.
    first = DockerGuestProvider()
    try:
        first._auth_pulled.add("registry.example.com/acme/private:v1")  # noqa: SLF001
        from cathedral.sandbox_guest import _save_auth_pulled

        _save_auth_pulled(first._auth_pulled)  # noqa: SLF001
    finally:
        first.close()
    second = DockerGuestProvider()
    try:
        assert "registry.example.com/acme/private:v1" in second._auth_pulled  # noqa: SLF001
    finally:
        second.close()
