"""Cancel a running exec inside the room (AB#406, hotel side).

The start wrapper writes a pid file, the cancel route validates it and signals
the process group, and `stopped` is claimed only when the exec call returns.
The shell scripts run for real on the test host. The provider tests use the
fake docker CLI, with a rule that holds the exec open until the kill call.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import threading
import time

import pytest

from cathedral import exec_cancel
from cathedral.sandbox_api import (
    ApiKey,
    CreateSandboxRequest,
    ExecRequest,
    ExecResult,
    ImageSource,
    QuotaLimits,
    Resources,
)
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

TOKEN = "ab" * 16
OTHER = "cd" * 16


# ---------------------------------------------------------------- the kill script, run for real

def _kill(pidfile, form="busybox", sig="TERM"):
    return subprocess.run(
        ["sh", "-c", exec_cancel.KILL_SCRIPT, "sh", str(pidfile), form, sig],
        capture_output=True, text=True, timeout=20,
    ).returncode


def _leader(*argv):
    """A process that leads its own group, as `docker exec` makes it under runsc."""
    return subprocess.Popen(list(argv), start_new_session=True)


def _dead(proc, seconds=3.0):
    try:
        proc.wait(seconds)
    except subprocess.TimeoutExpired:
        return False
    return True


@pytest.fixture
def bystander():
    """An unrelated group that no guard failure may touch."""
    proc = _leader("sleep", "60")
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait()


@pytest.mark.parametrize("content", ["1", "0", "1\n", "abc", "12 34", "-5", "", "9" * 40, "1\n2"])
def test_guard_refuses_a_forged_pid_file_and_signals_nothing(tmp_path, bystander, content):
    pidfile = tmp_path / "p"
    pidfile.write_text(content)
    assert _kill(pidfile) == exec_cancel.REFUSED
    assert bystander.poll() is None


def test_guard_refuses_a_pid_that_is_not_its_own_group_leader(tmp_path, bystander):
    # Same group as this test process, so pgid != pid.
    child = subprocess.Popen(["sleep", "60"])
    try:
        pidfile = tmp_path / "p"
        pidfile.write_text(str(child.pid))
        assert _kill(pidfile) == exec_cancel.REFUSED
        assert child.poll() is None
    finally:
        child.kill()
        child.wait()


def test_guard_refuses_a_dead_pid(tmp_path):
    done = subprocess.Popen(["true"])
    done.wait()
    pidfile = tmp_path / "p"
    pidfile.write_text(str(done.pid))
    assert _kill(pidfile) == exec_cancel.REFUSED


def test_a_missing_pid_file_is_not_a_refusal(tmp_path):
    assert _kill(tmp_path / "absent") == exec_cancel.NO_PID_FILE


def test_valid_leader_and_its_children_die_on_a_group_term(tmp_path):
    proc = _leader("sh", "-c", "sleep 60 & sleep 61; wait")
    time.sleep(0.3)
    pidfile = tmp_path / "p"
    pidfile.write_text(str(proc.pid) + "\n")
    assert _kill(pidfile, "busybox", "TERM") == 0
    assert _dead(proc)
    time.sleep(0.2)
    survivors = subprocess.run(["pgrep", "-g", str(proc.pid)], capture_output=True).stdout
    assert survivors.strip() == b""


def test_a_command_that_ignores_term_dies_on_the_kill_signal(tmp_path):
    proc = _leader("sh", "-c", "trap '' TERM; sleep 60")
    time.sleep(0.3)
    pidfile = tmp_path / "p"
    pidfile.write_text(str(proc.pid))
    assert _kill(pidfile, "busybox", "TERM") == 0
    assert not _dead(proc, 1.0)
    assert _kill(pidfile, "busybox", "KILL") == 0
    assert _dead(proc)


@pytest.mark.skipif(shutil.which("timeout") is None, reason="needs GNU timeout")
def test_gnu_rooms_require_the_leader_to_be_timeout_busybox_rooms_do_not(tmp_path):
    cmd = _leader("sh", "-c", "sleep 60")
    time.sleep(0.2)
    pidfile = tmp_path / "p"
    pidfile.write_text(str(cmd.pid))
    try:
        assert _kill(pidfile, "gnu") == exec_cancel.REFUSED
        assert cmd.poll() is None
        assert _kill(pidfile, "busybox") == 0
        assert _dead(cmd)
    finally:
        if cmd.poll() is None:
            cmd.kill()
    gnu = _leader("timeout", "-k", "5", "60", "sleep", "60")
    time.sleep(0.3)
    pidfile.write_text(str(gnu.pid))
    assert _kill(pidfile, "gnu") == 0
    assert _dead(gnu)


def test_the_kill_command_has_no_double_dash():
    assert "-- -" not in exec_cancel.KILL_SCRIPT
    assert "kill -" in exec_cancel.KILL_SCRIPT


# ---------------------------------------------------------------- the start wrapper, run for real

def _wrap(pidfile, *argv, stdin=None):
    return subprocess.run(
        ["sh", "-c", exec_cancel.WRAP_SCRIPT, "sh", str(pidfile), *argv],
        capture_output=True, text=True, input=stdin, timeout=20,
    )


def test_wrapper_consumes_the_pid_file_argument_and_runs_the_command_unchanged(tmp_path):
    pidfile = tmp_path / "p"
    r = _wrap(pidfile, "sh", "-c", 'echo "$1 $2"; cat; exit 7', "x", "A", "B", stdin="in")
    assert (r.stdout, r.returncode) == ("A B\nin", 7)
    assert pidfile.read_text().strip().isdigit()


def test_wrapper_still_starts_the_command_when_the_pid_file_is_unwritable(tmp_path):
    r = _wrap(tmp_path / "no-such-dir" / "p", "sh", "-c", "echo ran; exit 3")
    assert (r.stdout, r.returncode) == ("ran\n", 3)


def test_the_pid_file_names_the_process_that_becomes_the_command(tmp_path):
    pidfile = tmp_path / "p"
    r = _wrap(pidfile, "sh", "-c", "echo $$")
    assert pidfile.read_text().strip() == r.stdout.strip()


# ---------------------------------------------------------------- the provider, against the fake docker

@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    monkeypatch.setattr(exec_cancel, "TERM_WAIT_SECONDS", 0.4)
    monkeypatch.setattr(exec_cancel, "CANCEL_WINDOW_SECONDS", 1.0)
    exec_cancel.registry.clear()
    return docker


def _room(provider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    return provider.create(req, api_key="k", idempotency=None, body_digest="x")["id"]


def _guest_calls(fake: FakeDocker, marker: str) -> list[list[str]]:
    return [c for c in fake.calls_of("exec") if marker in " ".join(c)]


def _start(provider, sid, request) -> tuple[threading.Thread, list]:
    out: list = []
    t = threading.Thread(target=lambda: out.append(provider.exec(sid, request)))
    t.start()
    return t, out


def _wait_running(token, sid):
    deadline = time.time() + 5
    while time.time() < deadline:
        if exec_cancel.registry.is_running(sid, token):
            return
        time.sleep(0.02)
    raise AssertionError("exec never registered")


@pytest.mark.parametrize("form", ["gnu", "busybox"])
def test_exec_with_a_token_runs_behind_the_pid_file_wrapper(fake, form):
    fake.set(timeout_form=form, exec_rules=[{"contains": "hello-marker", "stdout": "hi", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["echo", "hello-marker"], timeout_seconds=30, spill_token=TOKEN))
        assert result.stdout == "hi" and not result.cancelled
        (call,) = _guest_calls(fake, "hello-marker")
        i = call.index("sh")
        assert call[i + 1] == "-c" and call[i + 2] == exec_cancel.WRAP_SCRIPT
        assert call[i + 3:i + 5] == ["sh", exec_cancel.pid_file(TOKEN)]
        expected = ["timeout", "-k", "5", "30"] if form == "gnu" else ["timeout", "-s", "KILL", "-t", "30"]
        assert call[i + 5:i + 5 + len(expected)] == expected
    finally:
        provider.close()


def test_exec_without_a_token_is_not_wrapped(fake):
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "plain-marker", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd=["echo", "plain-marker"], timeout_seconds=30))
        (call,) = _guest_calls(fake, "plain-marker")
        assert exec_cancel.WRAP_SCRIPT not in call
        assert call[call.index("timeout"):][:4] == ["timeout", "-k", "5", "30"]
    finally:
        provider.close()


def test_exec_in_a_room_with_no_sh_is_not_wrapped_and_cancel_is_unsupported(fake):
    fake.set(no_sh=True, exec_rules=[{"contains": "nosh-marker", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd=["echo", "nosh-marker"], timeout_seconds=30, spill_token=TOKEN))
        (call,) = _guest_calls(fake, "nosh-marker")
        assert exec_cancel.WRAP_SCRIPT not in call
    finally:
        provider.close()


def _held_exec(fake, tmp_path, form, rules_extra):
    release = tmp_path / "release"
    fake.set(
        timeout_form=form,
        exec_rules=[
            *rules_extra,
            {"contains": "hold-marker", "stdout": "partial", "wait_for": str(release), "exit": 143},
        ],
    )
    return release


@pytest.mark.parametrize("form", ["gnu", "busybox"])
def test_cancel_stops_the_exec_and_names_it_cancelled(fake, tmp_path, form):
    release = tmp_path / "release"
    fake.set(
        timeout_form=form,
        exec_rules=[
            {"contains": f"{form} TERM", "append": str(release), "exit": 0},
            {"contains": "hold-marker", "stdout": "partial", "wait_for": str(release), "exit": 143},
        ],
    )
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        t, out = _start(provider, sid, ExecRequest(cmd=["sh", "-c", "hold-marker"], timeout_seconds=300, spill_token=TOKEN))
        _wait_running(TOKEN, sid)
        assert provider.cancel_exec(sid, TOKEN) == "stopped"
        t.join(5)
        (result,) = out
        assert result.cancelled is True and result.timed_out is False
        assert result.exit_code == 143 and result.stdout == "partial"
        kills = _guest_calls(fake, f"{form} TERM")
        assert len(kills) == 1
        assert kills[0][kills[0].index("sh"):][4:] == [exec_cancel.pid_file(TOKEN), form, "TERM"]
        assert _guest_calls(fake, f"{form} KILL") == []
        # A repeat replays the stored result and signals nothing.
        assert provider.cancel_exec(sid, TOKEN) == "already_stopped"
        assert len(_guest_calls(fake, f"{form} TERM")) == 1
    finally:
        provider.close()


def test_the_hotel_sends_kill_itself_when_term_is_ignored(fake, tmp_path):
    release = tmp_path / "release"
    fake.set(
        timeout_form="busybox",
        exec_rules=[
            {"contains": "busybox TERM", "exit": 0},
            {"contains": "busybox KILL", "append": str(release), "exit": 0},
            {"contains": "hold-marker", "wait_for": str(release), "exit": 137},
        ],
    )
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        t, out = _start(provider, sid, ExecRequest(cmd=["sh", "-c", "hold-marker"], timeout_seconds=300, spill_token=TOKEN))
        _wait_running(TOKEN, sid)
        assert provider.cancel_exec(sid, TOKEN) == "stopped"
        t.join(5)
        assert out[0].cancelled is True and out[0].exit_code == 137
        assert len(_guest_calls(fake, "busybox TERM")) == 1
        assert len(_guest_calls(fake, "busybox KILL")) == 1
    finally:
        provider.close()


def test_a_refused_pid_file_is_never_stopped_and_the_exec_is_not_called_cancelled(fake, tmp_path):
    release = tmp_path / "release"
    fake.set(
        timeout_form="gnu",
        exec_rules=[
            {"contains": "gnu TERM", "exit": exec_cancel.REFUSED},
            {"contains": "gnu KILL", "exit": exec_cancel.REFUSED},
            {"contains": "hold-marker", "wait_for": str(release), "exit": 143},
        ],
    )
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        t, out = _start(provider, sid, ExecRequest(cmd=["sh", "-c", "hold-marker"], timeout_seconds=300, spill_token=TOKEN))
        _wait_running(TOKEN, sid)
        assert provider.cancel_exec(sid, TOKEN) == "signalled"
        assert t.is_alive()
        release.write_text("x")
        t.join(5)
        assert out[0].cancelled is False
    finally:
        provider.close()


def test_no_pid_file_means_unsupported(fake, tmp_path):
    release = tmp_path / "release"
    fake.set(
        timeout_form="gnu",
        exec_rules=[
            {"contains": "gnu TERM", "exit": exec_cancel.NO_PID_FILE},
            {"contains": "hold-marker", "wait_for": str(release), "exit": 0},
        ],
    )
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        t, out = _start(provider, sid, ExecRequest(cmd=["sh", "-c", "hold-marker"], timeout_seconds=300, spill_token=TOKEN))
        _wait_running(TOKEN, sid)
        assert provider.cancel_exec(sid, TOKEN) == "unsupported"
        release.write_text("x")
        t.join(5)
    finally:
        provider.close()


def test_a_real_timeout_exit_143_is_not_a_cancel(fake):
    fake.set(timeout_form="busybox", exec_rules=[{"contains": "slow-marker", "exit": 143}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        result = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "slow-marker"], timeout_seconds=30, spill_token=TOKEN))
        assert result.exit_code == 143 and result.cancelled is False and result.timed_out is True
        assert "cancelled" not in result.to_document()
    finally:
        provider.close()


def test_cancel_of_an_exec_that_ended_on_its_own_says_so(fake):
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "quick-marker", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        provider.exec(sid, ExecRequest(cmd=["sh", "-c", "quick-marker"], timeout_seconds=30, spill_token=TOKEN))
        assert provider.cancel_exec(sid, TOKEN) == "finished_before_cancel"
        assert _guest_calls(fake, "gnu TERM") == []
    finally:
        provider.close()


def test_cancel_before_the_exec_arrives_leaves_a_tombstone_and_nothing_runs(fake, tmp_path):
    marker = tmp_path / "ran"
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "late-marker", "append": str(marker), "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        assert provider.cancel_exec(sid, TOKEN) == "cancelled_before_start"
        result = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "late-marker"], timeout_seconds=30, spill_token=TOKEN))
        assert result.cancelled is True
        assert not marker.exists()
        assert _guest_calls(fake, "late-marker") == []
    finally:
        provider.close()


def test_an_exec_past_its_launch_deadline_is_refused_and_one_without_is_accepted(fake):
    fake.set(timeout_form="gnu", exec_rules=[{"contains": "dl-marker", "exit": 0}])
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        stale = int(time.time()) - 120
        with pytest.raises(SandboxOpError) as err:
            provider.exec(sid, ExecRequest(cmd=["sh", "-c", "dl-marker"], timeout_seconds=30, spill_token=TOKEN, launch_by=stale))
        assert (err.value.code, err.value.http_status) == ("exec_launch_expired", 409)
        assert _guest_calls(fake, "dl-marker") == []
        ok = provider.exec(sid, ExecRequest(cmd=["sh", "-c", "dl-marker"], timeout_seconds=30, spill_token=OTHER))
        assert ok.exit_code == 0
        fresh = int(time.time()) + 30
        provider.exec(sid, ExecRequest(cmd=["sh", "-c", "dl-marker"], timeout_seconds=30, spill_token="ef" * 16, launch_by=fresh))
    finally:
        provider.close()


def test_a_full_tombstone_table_refuses_with_503_and_keeps_unexpired_entries(fake, monkeypatch):
    monkeypatch.setattr(exec_cancel, "MAX_TOMBSTONES", 2)
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        assert provider.cancel_exec(sid, "01" * 16) == "cancelled_before_start"
        assert provider.cancel_exec(sid, "02" * 16) == "cancelled_before_start"
        with pytest.raises(SandboxOpError) as err:
            provider.cancel_exec(sid, "03" * 16)
        assert (err.value.code, err.value.http_status) == ("cancel_table_full", 503)
        # The first one is still held: its exec must not run.
        assert provider.cancel_exec(sid, "01" * 16) == "cancelled_before_start"
    finally:
        provider.close()


def test_result_memory_evicts_the_oldest_finished_entry_and_never_a_running_one():
    reg = exec_cancel.ExecRegistry(max_results=2)
    reg.begin("s", "a" * 32, None, "u")
    for n in range(3):
        token = f"{n}" * 32
        reg.begin("s", token, None, "u")
        reg.finish("s", token, cancelled=False)
    assert reg.is_running("s", "a" * 32)
    assert reg.result("s", "0" * 32) is None
    assert reg.result("s", "2" * 32) == "finished"


# ---------------------------------------------------------------- the route and the wire shape

@pytest.fixture
def app():
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key="k1", project="p", max_running=8)],
        limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
    )
    a = SandboxApplication(provider)
    try:
        yield a
    finally:
        provider.close()


def test_the_cancel_route_answers_without_a_room_id_and_validates_the_token(app, monkeypatch):
    sid = "sbx_x"
    monkeypatch.setattr(app.provider, "cancel_exec", lambda s, t: "stopped", raising=False)
    auth = {"Authorization": "Bearer k1"}
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/exec/cancel", auth, json.dumps({"spill_token": TOKEN}).encode())
    assert r.status == 200
    doc = json.loads(r.body)
    assert doc == {"result": "stopped", "token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest()}
    assert sid not in r.body.decode()
    bad = app.dispatch("POST", f"/v1/sandboxes/{sid}/exec/cancel", auth, b'{"spill_token":"nope"}')
    assert bad.status == 400


def test_a_provider_without_cancel_answers_unsupported(app):
    auth = {"Authorization": "Bearer k1"}
    r = app.dispatch("POST", "/v1/sandboxes/sbx_x/exec/cancel", auth, json.dumps({"spill_token": TOKEN}).encode())
    assert r.status == 200 and json.loads(r.body)["result"] == "unsupported"


def test_exec_launch_by_is_validated_and_cancelled_is_omitted_unless_true():
    assert ExecRequest(cmd=["true"], launch_by=1_900_000_000).launch_by == 1_900_000_000
    with pytest.raises(Exception):
        ExecRequest(cmd=["true"], launch_by="soon")
    base = ExecResult(exit_code=0, stdout="", stderr="", duration_ms=1, timed_out=False)
    assert "cancelled" not in base.to_document()
    assert ExecResult(exit_code=143, stdout="", stderr="", duration_ms=1, timed_out=False, cancelled=True).to_document()["cancelled"] is True


@pytest.mark.skipif(shutil.which("timeout") is None, reason="needs GNU timeout")
def test_wrapper_and_kill_script_work_together_on_a_gnu_timeout_chain(tmp_path):
    pidfile = tmp_path / "p"
    proc = _leader("sh", "-c", exec_cancel.WRAP_SCRIPT, "sh", str(pidfile), "timeout", "-k", "5", "60", "sh", "-c", "sleep 61 & sleep 62; wait")
    time.sleep(0.5)
    assert pidfile.read_text().strip() == str(proc.pid)
    assert _kill(pidfile, "gnu", "TERM") == 0
    assert _dead(proc)
