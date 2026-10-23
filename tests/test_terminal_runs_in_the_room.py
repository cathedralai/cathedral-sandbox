"""Terminal input on a container runtime runs in the room (B154).

The Docker guest provider hands the terminal routes to the in-memory
provider for bookkeeping. Its terminal_write ran each line through its own
exec, which is the reference provider's local exec, so a line typed into a
room's terminal ran on the hotel, not in the room's container. Each line must
go through the runtime's exec instead.
"""

from __future__ import annotations

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    monkeypatch.setenv("CATHEDRAL_SANDBOX_AUTH_PULLED_FILE", str(tmp_path / "auth-pulled.json"))
    return docker


def _room(provider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    return provider.create(req, api_key="k", idempotency=None, body_digest="x")["id"]


def _connected_terminal(provider, sid: str) -> str:
    tid = provider.create_terminal(sid)["id"]
    ticket = provider.mint_access_ticket(sid)["ticket"]
    provider.connect_terminal(sid, tid, ticket=ticket)
    return tid


def test_a_terminal_line_runs_through_the_container_runtime(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        tid = _connected_terminal(provider, sid)
        provider.terminal_write(sid, tid, "echo terminal-marker\n")
        in_room = [c for c in fake.calls_of("exec") if any("terminal-marker" in part for part in c)]
        assert len(in_room) == 1, fake.calls_of("exec")
        assert "terminal-marker" in provider.terminal_read(sid, tid)["data"]
    finally:
        provider.close()


def test_a_partial_line_runs_nothing_until_the_newline(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        tid = _connected_terminal(provider, sid)
        assert provider.terminal_write(sid, tid, "echo half-")["pending"] is True
        assert not [c for c in fake.calls_of("exec") if any("half-" in part for part in c)]
        provider.terminal_write(sid, tid, "line\n")
        assert len([c for c in fake.calls_of("exec") if any("half-line" in part for part in c)]) == 1
    finally:
        provider.close()


def test_every_terminal_method_the_docker_guest_delegates_runs_no_local_exec() -> None:
    # The guard for the class of bug: a delegated method that calls the
    # in-memory provider's own exec, process start or local run would run
    # on the hotel. terminal_write is the only one that needs the runtime's
    # exec, and the Docker guest now passes it in.
    import inspect

    from cathedral import sandbox_provider as sp

    own = set(vars(DockerGuestProvider))
    for name in dir(sp.InMemorySandboxProvider):
        if name.startswith("_") or name in own:
            continue
        member = getattr(sp.InMemorySandboxProvider, name)
        if not callable(member):
            continue
        src = inspect.getsource(member)
        for call in ("self.exec(", "self._run(", "self.start_process(", "subprocess."):
            assert call not in src, f"{name} is delegated to the in-memory provider and calls {call}"
