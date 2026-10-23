"""DockerGuestProvider exec against a fake docker CLI.

Issue #289: when a command exited with 127, exec read it as "no timeout
binary" and ran the command again, up to three times.
"""

from __future__ import annotations

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ExecRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    return docker


def _room(provider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    return provider.create(req, api_key="k", idempotency=None, body_digest="x")["id"]


def _guest_execs(fake: FakeDocker, marker: str) -> list[list[str]]:
    return [c for c in fake.calls_of("exec") if any(marker in part for part in c)]


@pytest.mark.parametrize("form", ["gnu", "busybox", "none"])
def test_command_that_exits_127_runs_once(fake: FakeDocker, tmp_path, form: str) -> None:
    log = tmp_path / "appended.txt"
    fake.set(timeout_form=form, exec_rules=[{"contains": "append-marker", "append": str(log), "exit": 127}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "echo append-marker >> f; exit 127"]))
        assert result.exit_code == 127
        assert result.timed_out is False
        assert log.read_text().splitlines() == ["ran"]
        assert len(_guest_execs(fake, "append-marker")) == 1
    finally:
        provider.close()


def test_timeout_form_is_probed_once_per_room(fake: FakeDocker) -> None:
    fake.set(timeout_form="busybox", exec_rules=[{"contains": "hello", "stdout": "hi", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        for _ in range(3):
            result = provider.exec(sid, ExecRequest(cmd=["echo", "hello"], timeout_seconds=30))
            assert result.exit_code == 0 and result.stdout == "hi"
        runs = _guest_execs(fake, "hello")
        assert len(runs) == 3
        assert all(c[c.index("timeout"):][:3] == ["timeout", "-t", "30"] for c in runs)
        probes = [c for c in fake.calls_of("exec") if c[-1] == "true"]
        assert len(probes) == 2  # GNU form refused, BusyBox form accepted; then cached
    finally:
        provider.close()


def test_exit_124_from_the_timeout_wrapper_is_a_timeout(fake: FakeDocker) -> None:
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "sleep", "exit": 124}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["sleep", "100"], timeout_seconds=1))
        assert result.timed_out is True
        assert len(_guest_execs(fake, "sleep")) == 1
    finally:
        provider.close()


def test_process_log_read_refuses_a_symlink(tmp_path) -> None:
    # The log file sits in /work, which the room can write: a room that swaps
    # it for a symlink must not make the hotel read a host file for it.
    from cathedral.sandbox_guest import _read_room_log

    secret = tmp_path / "api.key"
    secret.write_text("hotel-key")
    log = tmp_path / ".process-1.log"
    log.symlink_to(secret)
    assert _read_room_log(log) == ""
    log.unlink()
    log.write_text("hello-bg\n")
    assert _read_room_log(log) == "hello-bg\n"
    assert _read_room_log(tmp_path / "missing.log") == ""
