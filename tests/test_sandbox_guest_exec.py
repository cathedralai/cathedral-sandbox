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


def _ran_argv0(fake: FakeDocker, marker: str) -> str:
    (call,) = _guest_execs(fake, marker)
    rest = call[call.index("timeout"):] if "timeout" in call else call
    return next(p for p in rest if p in ("bash", "sh"))


def test_bash_argv_runs_bash_when_the_image_has_it(fake: FakeDocker) -> None:
    fake.set(exec_rules=[{"contains": "pipefail-marker", "stdout": "5.2", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd=["bash", "-c", "set -o pipefail; echo pipefail-marker"]))
        assert _ran_argv0(fake, "pipefail-marker") == "bash"
    finally:
        provider.close()


def test_string_cmd_runs_bash_when_the_image_has_it(fake: FakeDocker) -> None:
    fake.set(exec_rules=[{"contains": "string-marker", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd="echo string-marker"))
        assert _ran_argv0(fake, "string-marker") == "bash"
    finally:
        provider.close()


def test_bash_argv_falls_back_to_sh_when_the_image_has_no_bash(fake: FakeDocker) -> None:
    fake.set(no_bash=True, exec_rules=[{"contains": "nobash-marker", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        for _ in range(2):
            provider.exec(sid, ExecRequest(cmd=["bash", "-c", "echo nobash-marker"]))
        runs = _guest_execs(fake, "nobash-marker")
        assert len(runs) == 2
        assert all("sh" in c and "bash" not in c for c in runs)
        probes = [c for c in fake.calls_of("exec") if c[-3:] == ["bash", "-c", ":"]]
        assert len(probes) == 1  # probed once per room
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
        assert all(c[c.index("timeout"):][:5] == ["timeout", "-s", "KILL", "-t", "30"] for c in runs)
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


@pytest.mark.parametrize("path", ["/home/u/x", "/etc/passwd", "/workspace/x", "/"])
def test_file_paths_outside_work_are_refused(fake: FakeDocker, path: str) -> None:
    # Only /work is mounted into the room. A file elsewhere landed on the host
    # beside the mount: a 200 for a file the room never sees.
    from cathedral.sandbox_api import FileGet, TarGet
    from cathedral.sandbox_provider import SandboxOpError

    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        calls = [
            lambda: provider.write_file(sid, path, b"x", None),
            lambda: provider.read_file(sid, FileGet(path=path)),
            lambda: provider.write_tar(sid, path, b""),
            lambda: provider.read_tar(sid, TarGet(path=path)),
            lambda: provider.stat(sid, path),
        ]
        for call in calls:
            with pytest.raises(SandboxOpError) as err:
                call()
            assert err.value.http_status == 400 and err.value.code == "path_outside_work"
        provider.write_file(sid, "/work/ok.txt", b"hi", None)
        assert provider.read_file(sid, FileGet(path="/work/ok.txt"))[0] == b"hi"
        assert provider.stat(sid, "/work").is_dir
    finally:
        provider.close()


def test_memory_bomb_names_the_oom_kill_and_the_dead_room(fake: FakeDocker) -> None:
    """AB#235: the host cgroup kills the whole room; docker exec answers 128."""
    fake.set(exec_rules=[{"contains": "bomb-marker", "exit": 128, "kill_container": True}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "bomb-marker"]))
        assert result.exit_code == 137
        assert result.oom_killed is True
        assert result.room_alive is False
        assert result.timed_out is False
        assert "out of memory" in result.stderr
        doc = result.to_document()
        assert doc["oom_killed"] is True and doc["room_alive"] is False
    finally:
        provider.close()


def test_exit_128_from_a_live_room_is_left_alone(fake: FakeDocker) -> None:
    fake.set(exec_rules=[{"contains": "plain-128", "exit": 128}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "plain-128"]))
        assert result.exit_code == 128
        assert result.oom_killed is False and result.room_alive is True
        assert "oom_killed" not in result.to_document()
    finally:
        provider.close()


def test_room_that_died_without_oom_keeps_its_exit_code(fake: FakeDocker) -> None:
    fake.set(exec_rules=[{"contains": "died-marker", "exit": 128, "kill_container": True, "container_exit": 2, "oom_killed": False}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "died-marker"]))
        assert result.exit_code == 128 and result.oom_killed is False and result.room_alive is False
    finally:
        provider.close()
