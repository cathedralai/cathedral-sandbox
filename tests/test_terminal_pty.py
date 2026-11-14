"""Real PTY terminals in the room (AB#405, step 1: the hotel side).

A PTY terminal runs one interactive shell on a pseudo terminal and pumps raw
bytes both ways, so full-screen programs, ctrl-C and resize work. The tests
spawn a local /bin/sh in place of ``docker exec -it <room> bash -l``; the
Docker guest's argv is checked on its own.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import threading
import time

import pytest

from cathedral import agent_interactive as agent_ux
from cathedral import agent_websocket as ws
from cathedral.agent_profile import agent_create_body
from cathedral.agent_pty import PtyProcess
from cathedral.sandbox_api import ApiKey, CreateSandboxRequest, ImageSource, QuotaLimits, Resources
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_server import SandboxApplication, run

AUTH = {"Authorization": "Bearer agent-k1"}
SHELL = ["/bin/sh", "-i"]


def _local_spawn(argv=SHELL):
    spawned: list[PtyProcess] = []

    def spawn(cols, rows, on_output, on_exit):
        proc = PtyProcess(argv, cols=cols, rows=rows, on_output=on_output, on_exit=on_exit, env={"PS1": "$ ", "PATH": "/usr/bin:/bin", "TERM": "xterm"})
        spawned.append(proc)
        return proc

    spawn.spawned = spawned  # type: ignore[attr-defined]
    return spawn


class _Collector:
    def __init__(self) -> None:
        self.data = bytearray()
        self.code: int | None = None
        self.cond = threading.Condition()

    def out(self, chunk: bytes) -> None:
        with self.cond:
            self.data.extend(chunk)
            self.cond.notify_all()

    def exit(self, code: int) -> None:
        with self.cond:
            self.code = code
            self.cond.notify_all()

    def wait_for(self, needle: bytes, timeout: float = 5.0) -> bytes:
        deadline = time.monotonic() + timeout
        with self.cond:
            while needle not in self.data:
                left = deadline - time.monotonic()
                assert left > 0, f"{needle!r} not in {bytes(self.data)!r}"
                self.cond.wait(left)
            return bytes(self.data)


# ------------------------------------------------------------------ PtyProcess


def test_pty_reports_its_size_and_follows_a_resize() -> None:
    got = _Collector()
    script = "stty size; echo first-done; read x; stty size; echo got:$x"
    proc = PtyProcess(["/bin/sh", "-c", script], cols=80, rows=24, on_output=got.out, on_exit=got.exit)
    got.wait_for(b"first-done")
    assert b"24 80" in got.data
    proc.resize(100, 40)
    proc.write(b"hello\n")
    got.wait_for(b"got:hello")
    assert b"40 100" in got.data
    assert proc.wait(5) == 0
    assert got.code == 0


def test_pty_passes_raw_keys_and_reports_the_exit_code() -> None:
    got = _Collector()
    proc = PtyProcess(["/bin/sh", "-c", "read x; exit 7"], cols=80, rows=24, on_output=got.out, on_exit=got.exit)
    # The tty echoes what is typed, as a real terminal does.
    proc.write(b"typed\r")
    got.wait_for(b"typed")
    assert proc.wait(5) == 7
    with pytest.raises(BrokenPipeError):
        proc.write(b"late\n")


def test_pty_close_hangs_up_the_shell() -> None:
    got = _Collector()
    proc = PtyProcess(["/bin/sh", "-c", "echo up; sleep 30"], cols=80, rows=24, on_output=got.out, on_exit=got.exit)
    got.wait_for(b"up")
    proc.close()
    assert proc.wait(6) is not None


# ------------------------------------------------------------------ provider


@pytest.fixture
def provider():
    p = InMemorySandboxProvider(
        keys=[ApiKey(key="agent-k1", project="agent", max_running=8)],
        limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
        base_url="http://127.0.0.1",
    )
    yield p
    p.close()


def _room(p: InMemorySandboxProvider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    return p.create(req, api_key="agent-k1", idempotency=None, body_digest="x")["id"]


def _read_until(p, sid, tid, needle: bytes, timeout: float = 5.0) -> bytes:
    got = b""
    deadline = time.monotonic() + timeout
    while needle not in got:
        left = deadline - time.monotonic()
        assert left > 0, got
        out = p.terminal_read_wait(sid, tid, left)
        got += base64.b64decode(out["data_b64"])
    return got


def test_the_reference_provider_has_no_pty_and_rejects_unknown_modes(provider) -> None:
    sid = _room(provider)
    with pytest.raises(SandboxOpError) as exc:
        provider.create_terminal(sid, mode="pty")
    assert (exc.value.code, exc.value.http_status) == ("terminal_mode_unsupported", 422)
    with pytest.raises(SandboxOpError) as exc:
        provider.create_terminal(sid, mode="vt100")
    assert exc.value.code == "invalid_terminal_mode"
    assert provider.create_terminal(sid)["mode"] == "line"


def test_a_pty_terminal_starts_once_on_connect_and_takes_raw_input(provider) -> None:
    sid = _room(provider)
    spawn = _local_spawn()
    tid = provider.create_terminal(sid, mode="pty", spawn=spawn)["id"]
    assert spawn.spawned == []
    doc = provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    assert doc["mode"] == "pty"
    assert len(spawn.spawned) == 1
    # No newline is added and no line exec runs: the shell sees the bytes.
    assert provider.terminal_write(sid, tid, "echo pty-") == {"written": 9, "pending": False}
    provider.terminal_write(sid, tid, b"marker\n")
    assert b"pty-marker" in _read_until(provider, sid, tid, b"pty-marker\r\n")
    # A second connect with a fresh ticket does not start a second shell.
    provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    assert len(spawn.spawned) == 1
    assert provider.terminal_resize(sid, tid, 120, 30) == {"terminal_id": tid, "cols": 120, "rows": 30}
    provider.terminal_write(sid, tid, "stty size\n")
    _read_until(provider, sid, tid, b"30 120")
    provider.terminal_write(sid, tid, "exit 3\n")
    deadline = time.monotonic() + 5
    out = provider.terminal_read_wait(sid, tid, 5)
    while not out["exited"] and time.monotonic() < deadline:
        out = provider.terminal_read_wait(sid, tid, 1)
    assert out["exited"] and out["exit_code"] == 3
    with pytest.raises(SandboxOpError) as exc:
        provider.terminal_write(sid, tid, "echo late\n")
    assert exc.value.code == "terminal_not_found"


def test_pty_input_is_bounded(provider) -> None:
    sid = _room(provider)
    tid = provider.create_terminal(sid, mode="pty", spawn=_local_spawn())["id"]
    provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    with pytest.raises(SandboxOpError) as exc:
        provider.terminal_write(sid, tid, b"x" * (agent_ux.TERMINAL_INPUT_MAX + 1))
    assert exc.value.http_status == 413
    provider.delete_terminal(sid, tid)


def test_pty_output_keeps_the_newest_bytes_and_counts_the_gap(provider, monkeypatch) -> None:
    monkeypatch.setattr(agent_ux, "TERMINAL_OUTPUT_CAP", 1000)
    sid = _room(provider)
    tid = provider.create_terminal(sid, mode="pty", spawn=_local_spawn(["/bin/sh", "-c", "head -c 5000 /dev/zero | tr '\\0' a; echo END; sleep 30"]))["id"]
    provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        doc = next(t for t in provider.list_terminals(sid) if t["id"] == tid)
        with provider._lock:  # noqa: SLF001
            tail = bytes(provider._terminals[sid][tid].output)  # noqa: SLF001
        if b"END" in tail:
            break
        time.sleep(0.05)
    out = provider.terminal_read(sid, tid)
    raw = base64.b64decode(out["data_b64"])
    assert len(raw) <= 1000 and raw.rstrip().endswith(b"END")
    assert out["output_dropped"] >= 4000
    assert doc["output_dropped"] == out["output_dropped"]
    provider.delete_terminal(sid, tid)


def test_deleting_the_terminal_or_the_sandbox_hangs_up_the_shell(provider) -> None:
    sid = _room(provider)
    spawn = _local_spawn()
    t1 = provider.create_terminal(sid, mode="pty", spawn=spawn)["id"]
    t2 = provider.create_terminal(sid, mode="pty", spawn=spawn)["id"]
    for tid in (t1, t2):
        provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    provider.delete_terminal(sid, t1)
    assert spawn.spawned[0].wait(6) is not None
    provider.delete(sid)
    assert spawn.spawned[1].wait(6) is not None


def test_a_failed_spawn_is_a_named_error(provider) -> None:
    sid = _room(provider)

    def broken(*_a):
        raise OSError("no docker")

    tid = provider.create_terminal(sid, mode="pty", spawn=broken)["id"]
    with pytest.raises(SandboxOpError) as exc:
        provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    assert (exc.value.code, exc.value.http_status) == ("terminal_spawn_failed", 502)


# ------------------------------------------------------------------ Docker guest argv


def test_the_docker_guest_runs_an_interactive_login_shell_in_the_room(tmp_path, monkeypatch) -> None:
    from cathedral.sandbox_guest import DockerGuestProvider
    from tests.fake_docker_cli import install

    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    monkeypatch.setenv("CATHEDRAL_SANDBOX_AUTH_PULLED_FILE", str(tmp_path / "auth-pulled.json"))
    provider = DockerGuestProvider()
    try:
        req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
        sid = provider.create(req, api_key="k", idempotency=None, body_digest="x")["id"]
        guest = provider._guests[sid]  # noqa: SLF001
        guest.env_overlay = {"API_TOKEN": "s3cret-value"}
        argv, overlay = provider._terminal_command(guest)  # noqa: SLF001
        shell = "bash" if guest.has_bash else "sh"
        assert argv[:3] == ["docker", "exec", "-it"]
        assert argv[-3:] == [guest.container_id, shell, "-l"]
        assert "TERM=xterm-256color" in argv and "/work" in argv
        # The overlay is not on the argv at all; spawn hands it over in an env file.
        assert not any("API_TOKEN" in a or "s3cret-value" in a for a in argv)
        assert overlay == {"API_TOKEN": "s3cret-value"}
        doc = provider.create_terminal(sid, mode="pty")
        assert doc["mode"] == "pty"
        assert provider.create_terminal(sid)["mode"] == "line"
    finally:
        provider.close()


def _docker_room(tmp_path, monkeypatch):
    from cathedral.sandbox_guest import DockerGuestProvider
    from tests.fake_docker_cli import install

    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    monkeypatch.setenv("CATHEDRAL_SANDBOX_AUTH_PULLED_FILE", str(tmp_path / "auth-pulled.json"))
    provider = DockerGuestProvider()
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    sid = provider.create(req, api_key="k", idempotency=None, body_digest="x")["id"]
    return provider, sid


def test_the_room_env_overlay_never_reaches_the_hotels_docker_client(tmp_path, monkeypatch) -> None:
    """A customer overlay with DOCKER_HOST must not steer the hotel's docker exec.

    The overlay reaches the container through a private 0600 env file, so its
    values are in neither the client's env nor its argv.
    """
    import os
    import stat as stat_mod

    import cathedral.sandbox_guest as guest_mod

    seen: dict = {}

    class _Recorder:
        def __init__(self, argv, *, cols, rows, on_output, on_exit, env=None):
            seen["argv"] = list(argv)
            seen["env"] = env
            seen["on_output"] = on_output
            seen["on_exit"] = on_exit
            if "--env-file" in argv:
                path = argv[argv.index("--env-file") + 1]
                seen["env_file"] = path
                seen["file_mode"] = stat_mod.S_IMODE(os.stat(path).st_mode)
                seen["dir_mode"] = stat_mod.S_IMODE(os.stat(os.path.dirname(path)).st_mode)
                with open(path, encoding="utf-8") as handle:
                    seen["file_lines"] = handle.read().splitlines()
            self.exit_code = None
            self.pid = 0

        def write(self, data):
            return len(data)

        def resize(self, cols, rows):
            pass

        def close(self):
            pass

    monkeypatch.setattr(guest_mod, "PtyProcess", _Recorder)
    hostile = "tcp://203.0.113.7:2375"
    provider, sid = _docker_room(tmp_path, monkeypatch)
    try:
        provider._guests[sid].env_overlay = {"DOCKER_HOST": hostile, "API_TOKEN": "s3cret-value"}  # noqa: SLF001
        tid = provider.create_terminal(sid, mode="pty")["id"]
        provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
        client_env = os.environ if seen["env"] is None else seen["env"]
        assert client_env.get("DOCKER_HOST") != hostile
        assert "s3cret-value" not in client_env.values()
        assert not any(hostile in a or "s3cret-value" in a for a in seen["argv"])
        # The values still reach the container, from a file only the hotel can read.
        assert seen["argv"][:3] == ["docker", "exec", "-it"]
        assert sorted(seen["file_lines"]) == ["API_TOKEN=s3cret-value", f"DOCKER_HOST={hostile}"]
        assert (seen["file_mode"], seen["dir_mode"]) == (0o600, 0o700)
        # Gone once the exec has started (first output), and stays gone at exit.
        seen["on_output"](b"$ ")
        assert not os.path.exists(seen["env_file"])
        assert not os.path.exists(os.path.dirname(seen["env_file"]))
        seen["on_exit"](0)
    finally:
        provider.close()


def test_a_pty_terminal_refuses_an_overlay_value_an_env_file_cannot_carry(tmp_path, monkeypatch) -> None:
    provider, sid = _docker_room(tmp_path, monkeypatch)
    try:
        provider._guests[sid].env_overlay = {"PEM": "line one\nline two"}  # noqa: SLF001
        with pytest.raises(SandboxOpError) as exc:
            provider.create_terminal(sid, mode="pty")
        assert (exc.value.code, exc.value.http_status) == ("terminal_env_unsupported", 422)
        assert "line one" not in str(exc.value)
        assert provider.create_terminal(sid)["mode"] == "line"
    finally:
        provider.close()


# ------------------------------------------------------------------ WebSocket


class _PtyProvider(InMemorySandboxProvider):
    """The reference provider with a local shell standing in for the room's."""

    def create_terminal(self, sandbox_id, *, cols=None, rows=None, mode=None, spawn=None):
        if mode == "pty":
            spawn = _local_spawn()
        return super().create_terminal(sandbox_id, cols=cols, rows=rows, mode=mode, spawn=spawn)


@pytest.fixture
def live_pty():
    provider = _PtyProvider(
        keys=[ApiKey(key="agent-k1", project="agent", max_running=8)],
        limits=QuotaLimits(running_sandboxes=50, vcpu=100, memory_gib=200),
        base_url="http://127.0.0.1",
    )
    app = SandboxApplication(provider)
    httpd, (host, port) = run(app, host="127.0.0.1", port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield app, host, int(port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        provider.close()


def _open_ws(app, host, port, *, mode="pty"):
    sid = json.loads(app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(agent_create_body()).encode()).body)["id"]
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, json.dumps({"mode": mode, "cols": 80, "rows": 24}).encode())
    assert r.status == 201, r.body
    tid = json.loads(r.body)["id"]
    ticket = json.loads(app.dispatch("POST", f"/v1/sandboxes/{sid}/access-tickets", AUTH, b"{}").body)["ticket"]
    sock = socket.create_connection((host, port), timeout=5)
    req, _ = ws.iter_client_handshake(f"/v1/sandboxes/{sid}/terminals/{tid}/ws", f"{host}:{port}", ticket=ticket)
    sock.sendall(req)
    head = b""
    while b"\r\n\r\n" not in head:
        head += sock.recv(1)
    assert b" 101 " in head.split(b"\r\n", 1)[0]
    return sid, tid, sock


def _recv_until(sock, pred, timeout=5.0):
    buf = bytearray()
    frames: list[tuple[int, bytes]] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf.extend(chunk)
        got, buf = ws.decode_frames(buf)
        frames += got
        if pred(frames):
            return frames
    raise AssertionError(f"not seen; frames {frames!r}")


def _output(frames) -> bytes:
    return b"".join(p for op, p in frames if op == ws.OP_BINARY)


def test_a_pty_websocket_streams_raw_bytes_resizes_and_closes_on_exit(live_pty) -> None:
    app, host, port = live_pty
    sid, tid, sock = _open_ws(app, host, port)
    try:
        sock.sendall(ws.encode_frame(b"echo ws-", opcode=ws.OP_BINARY, masked=True))
        sock.sendall(ws.encode_frame(json.dumps({"type": "input", "data": "pty-ok\n"}).encode(), opcode=ws.OP_TEXT, masked=True))
        frames = _recv_until(sock, lambda f: b"ws-pty-ok\r\n" in _output(f))
        assert all(op == ws.OP_BINARY for op, _ in frames)
        sock.sendall(ws.encode_frame(json.dumps({"type": "resize", "cols": 132, "rows": 43}).encode(), opcode=ws.OP_TEXT, masked=True))
        sock.sendall(ws.encode_frame(b"stty size\n", opcode=ws.OP_BINARY, masked=True))
        _recv_until(sock, lambda f: b"43 132" in _output(f))
        sock.sendall(ws.encode_frame(b"\x03exit 0\n", opcode=ws.OP_BINARY, masked=True))
        frames = _recv_until(sock, lambda f: any(op == ws.OP_CLOSE for op, _ in f))
        close = next(p for op, p in frames if op == ws.OP_CLOSE)
        assert struct.unpack("!H", close[:2])[0] == 1000 and close[2:] == b"terminal_exited"
    finally:
        sock.close()
    docs = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/terminals", AUTH, b"").body)
    assert next(d for d in docs if d["id"] == tid)["exited"] is True


def test_a_pty_websocket_refuses_a_bad_control_frame(live_pty) -> None:
    app, host, port = live_pty
    _sid, _tid, sock = _open_ws(app, host, port)
    try:
        sock.sendall(ws.encode_frame(b"not json", opcode=ws.OP_TEXT, masked=True))
        frames = _recv_until(sock, lambda f: any(op == ws.OP_CLOSE for op, _ in f))
        close = next(p for op, p in frames if op == ws.OP_CLOSE)
        assert struct.unpack("!H", close[:2])[0] == 1003 and close[2:] == b"invalid_control_frame"
    finally:
        sock.close()


def test_a_pty_websocket_closes_when_the_sandbox_is_deleted(live_pty) -> None:
    app, host, port = live_pty
    sid, _tid, sock = _open_ws(app, host, port)
    try:
        sock.sendall(ws.encode_frame(b"echo alive\n", opcode=ws.OP_BINARY, masked=True))
        _recv_until(sock, lambda f: b"alive\r\n" in _output(f))
        assert app.dispatch("DELETE", f"/v1/sandboxes/{sid}", AUTH, b"").status in (202, 204)
        frames = _recv_until(sock, lambda f: any(op == ws.OP_CLOSE for op, _ in f))
        assert any(op == ws.OP_CLOSE for op, _ in frames)
    finally:
        sock.close()


def test_rest_resize_and_line_mode_stay_as_they_were(live_pty) -> None:
    app, host, port = live_pty
    sid = json.loads(app.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(agent_create_body()).encode()).body)["id"]
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals", AUTH, b"{}")
    doc = json.loads(r.body)
    assert doc["mode"] == "line" and "output_dropped" not in doc
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals/{doc['id']}/resize", AUTH, json.dumps({"cols": 100, "rows": 50}).encode())
    assert r.status == 200 and json.loads(r.body)["cols"] == 100
    r = app.dispatch("POST", f"/v1/sandboxes/{sid}/terminals/{doc['id']}/resize", AUTH, json.dumps({"cols": 0, "rows": 50}).encode())
    assert r.status == 400
