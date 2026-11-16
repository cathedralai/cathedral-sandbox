"""AB#419: process log offset paging and the room's entrypoint log.

Done when: a guest log read takes an offset, returns the next offset, and also
returns the entrypoint json-file log; a second read returns only new bytes.
"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ExecRequest, ImageSource, Resources
from cathedral.sandbox_guest import (
    DockerGuestProvider,
    _read_room_log_page,
    entrypoint_log_page,
    parse_entrypoint_cursor,
)
from cathedral.sandbox_provider import (
    LOG_PAGE_CAP,
    InMemorySandboxProvider,
    SandboxOpError,
    utf8_page_end,
)
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

AUTH = {"Authorization": "Bearer k1"}
SEC = 1_000_000_000
T0 = 1_763_000_000 * SEC


# ------------------------------------------------------------------ fixtures
@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.set(exec_model=True)
    return docker


@pytest.fixture
def guest(fake, monkeypatch):
    monkeypatch.delenv("CATHEDRAL_SEALED_SECRETS_DIR", raising=False)
    provider = DockerGuestProvider()
    try:
        yield provider
    finally:
        provider.close()


def _room(provider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    return provider.create(req, api_key="k", idempotency=None, body_digest="x")["id"]


def _guest_log(provider: DockerGuestProvider, sid: str) -> tuple[str, object]:
    pid = provider.start_process(sid, ExecRequest(cmd=["sh", "-c", "echo hi"])).process_id
    path = provider._guests[sid].guest_processes[pid]  # noqa: SLF001
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"")
    return pid, path


def _cid(provider: DockerGuestProvider, sid: str) -> str:
    return provider._guests[sid].container_id  # noqa: SLF001


# ------------------------------------------------------------------ process log paging
def test_in_memory_second_read_returns_only_new_bytes(tmp_path) -> None:
    provider = InMemorySandboxProvider()
    app = SandboxApplication(provider)
    try:
        body = json.dumps({"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}})
        sid = json.loads(app.dispatch("POST", "/v1/sandboxes", AUTH, body.encode()).body)["id"]
        started = app.dispatch("POST", f"/v1/sandboxes/{sid}/processes", AUTH, json.dumps({"cmd": ["true"]}).encode())
        pid = json.loads(started.body)["process_id"]
        log = provider._sandboxes[sid].processes[pid][1]  # noqa: SLF001
        log.write_bytes(b"first\n")

        r = app.dispatch("GET", f"/v1/sandboxes/{sid}/processes/{pid}/logs?offset=0", AUTH, b"")
        first = json.loads(r.body)
        assert r.status == 200
        assert first["logs"] == "first\n" and first["offset"] == 0 and first["next_offset"] == 6
        assert first["more"] is False and first["size"] == 6

        with log.open("ab") as fh:
            fh.write(b"second\n")
        r = app.dispatch("GET", f"/v1/sandboxes/{sid}/processes/{pid}/logs?offset={first['next_offset']}", AUTH, b"")
        second = json.loads(r.body)
        assert second["logs"] == "second\n" and second["next_offset"] == 13

        # No query: the old answer (whole log under "logs") is unchanged.
        whole = json.loads(app.dispatch("GET", f"/v1/sandboxes/{sid}/processes/{pid}/logs", AUTH, b"").body)
        assert whole["logs"] == "first\nsecond\n" and whole["process_id"] == pid
    finally:
        provider.close()


@pytest.mark.parametrize("query", ["offset=-1", "offset=abc", "limit=0", f"limit={LOG_PAGE_CAP + 1}", "offset=1.5"])
def test_bad_offset_or_limit_is_400(query: str) -> None:
    provider = InMemorySandboxProvider()
    app = SandboxApplication(provider)
    try:
        body = json.dumps({"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}})
        sid = json.loads(app.dispatch("POST", "/v1/sandboxes", AUTH, body.encode()).body)["id"]
        started = app.dispatch("POST", f"/v1/sandboxes/{sid}/processes", AUTH, json.dumps({"cmd": ["true"]}).encode())
        pid = json.loads(started.body)["process_id"]
        r = app.dispatch("GET", f"/v1/sandboxes/{sid}/processes/{pid}/logs?{query}", AUTH, b"")
        assert r.status == 400, r.body
        assert json.loads(r.body)["error"]["code"] == "invalid_request"
    finally:
        provider.close()


def test_guest_process_log_page_second_read_returns_only_new_bytes(guest) -> None:
    sid = _room(guest)
    pid, path = _guest_log(guest, sid)
    path.write_bytes(b"one\n")
    first = guest.process_logs_page(sid, pid, offset=0)
    assert first == {"process_id": pid, "logs": "one\n", "offset": 0, "next_offset": 4, "size": 4, "more": False}
    with path.open("ab") as fh:
        fh.write(b"two\n")
    second = guest.process_logs_page(sid, pid, offset=first["next_offset"])
    assert second["logs"] == "two\n" and second["next_offset"] == 8
    # Past the end: nothing, and the offset stays where it was.
    later = guest.process_logs_page(sid, pid, offset=100)
    assert later["logs"] == "" and later["next_offset"] == 100 and later["more"] is False
    # The old whole read still answers.
    assert guest.process_logs(sid, pid) == "one\ntwo\n"


def test_guest_process_log_page_limit_and_utf8_boundary(guest) -> None:
    sid = _room(guest)
    pid, path = _guest_log(guest, sid)
    path.write_bytes("abécd".encode())  # e-acute is 2 bytes at offsets 2 and 3
    page = guest.process_logs_page(sid, pid, offset=0, limit=3)
    assert page["logs"] == "ab" and page["next_offset"] == 2 and page["more"] is True
    page = guest.process_logs_page(sid, pid, offset=page["next_offset"], limit=3)
    assert page["logs"] == "éc" and page["next_offset"] == 5
    page = guest.process_logs_page(sid, pid, offset=page["next_offset"], limit=3)
    assert page["logs"] == "d" and page["more"] is False


def test_utf8_page_end_always_makes_progress() -> None:
    assert utf8_page_end(b"\xe2\x82") == 2  # lead byte at 0: keep, a page never comes back empty
    assert utf8_page_end(b"a\xe2\x82") == 1
    assert utf8_page_end(b"a\xe2\x82\xac") == 4
    assert utf8_page_end(b"\x80\x80\x80\x80\x80") == 5  # invalid bytes: keep all


def test_guest_page_refuses_a_symlink(tmp_path) -> None:
    secret = tmp_path / "api.key"
    secret.write_text("hotel-key")
    log = tmp_path / ".process-1.log"
    log.symlink_to(secret)
    page = _read_room_log_page(log, 0, 1024)
    assert page["logs"] == "" and page["size"] == 0 and page["next_offset"] == 0


def test_guest_page_of_another_owner_is_refused(guest) -> None:
    sid = _room(guest)
    pid, _ = _guest_log(guest, sid)
    guest.delete(sid)
    with pytest.raises(SandboxOpError):
        guest.process_logs_page(sid, pid, offset=0)


# ------------------------------------------------------------------ entrypoint log
def test_entrypoint_second_read_returns_only_new_lines(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    fake.add_log(cid, "stdout", "booting\n", T0)
    fake.add_log(cid, "stderr", "warn: x\n", T0 + 5)

    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "booting\n" and first["stderr"] == "warn: x\n"
    assert first["more"] is False and first["cursor"] == ""

    fake.add_log(cid, "stdout", "ready\n", T0 + 9)
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "ready\n" and second["stderr"] == ""

    third = guest.logs(sid, entrypoint_cursor=second["next_cursor"])["entrypoint"]
    assert third["stdout"] == "" and third["stderr"] == "" and third["next_cursor"] == second["next_cursor"]
    # --since was passed: the read did not ask docker for the whole log again.
    assert any("--since" in call for call in fake.calls_of("logs"))


def test_entrypoint_lines_at_the_same_nanosecond_are_not_repeated_or_lost(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    fake.add_log(cid, "stdout", "a\n", T0)
    fake.add_log(cid, "stderr", "e1\n", T0)
    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["next_cursor"] == f"{T0}:1:1"
    fake.add_log(cid, "stdout", "b\n", T0)  # same ns as the cursor
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "b\n" and second["stderr"] == ""
    assert second["next_cursor"] == f"{T0}:2:1"


def test_entrypoint_log_is_not_read_without_a_cursor(fake, guest) -> None:
    sid = _room(guest)
    fake.add_log(_cid(guest, sid), "stdout", "x\n", T0)
    doc = guest.logs(sid)
    assert "entrypoint" not in doc
    assert fake.calls_of("logs") == []


def test_entrypoint_partial_last_line_waits_while_running(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    fake.add_log(cid, "stdout", "whole\n", T0)
    fake.add_log(cid, "stdout", "part", T0 + 1)
    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "whole\n"
    # docker prints the rest of the line with a new timestamp once it arrives.
    fake.add_log(cid, "stdout", "-rest\n", T0 + 2)
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "part-rest\n"


def test_entrypoint_long_line_split_by_docker_is_joined(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    # json-file keeps a line over 16 KiB as partial messages; docker logs prints
    # each with its own stamp and no newline between them.
    fake.add_log(cid, "stdout", "aaa", T0)
    fake.add_log(cid, "stdout", "bbb", T0 + 1)
    fake.add_log(cid, "stdout", "ccc\n", T0 + 2)
    fake.add_log(cid, "stdout", "next\n", T0 + 3)
    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "aaabbbccc\nnext\n"
    fake.add_log(cid, "stdout", "last\n", T0 + 4)
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "last\n"


def test_entrypoint_docker_failure_keeps_the_rest_of_the_answer(fake, guest) -> None:
    sid = _room(guest)
    fake.set(logs_fail=True)
    doc = guest.logs(sid, entrypoint_cursor="")
    assert "No such container" in doc["entrypoint"]["error"]
    assert doc["sandbox_id"] == sid and "exec_history" in doc


def test_entrypoint_withheld_on_a_sealed_secrets_hotel(fake, tmp_path, monkeypatch) -> None:
    (tmp_path / "secrets").mkdir()
    monkeypatch.setenv("CATHEDRAL_SEALED_SECRETS_DIR", str(tmp_path / "secrets"))
    provider = DockerGuestProvider()
    try:
        sid = _room(provider)
        fake.add_log(_cid(provider, sid), "stdout", "secret-ish\n", T0)
        page = provider.logs(sid, entrypoint_cursor="")["entrypoint"]
        assert "withheld" in page["error"] and "stdout" not in page
        assert fake.calls_of("logs") == []
    finally:
        provider.close()


def test_entrypoint_cursor_must_be_one_the_api_returned(guest) -> None:
    sid = _room(guest)
    with pytest.raises(SandboxOpError) as err:
        guest.logs(sid, entrypoint_cursor="yesterday")
    assert err.value.http_status == 400


def test_server_bad_entrypoint_cursor_is_400(guest) -> None:
    app = SandboxApplication(guest)
    sid = _room(guest)
    r = app.dispatch("GET", f"/v1/sandboxes/{sid}/logs?entrypoint_cursor=yesterday", AUTH, b"")
    assert r.status == 400, r.body
    assert json.loads(r.body)["error"]["code"] == "invalid_request"


def test_entrypoint_cut_stream_sets_more_and_the_next_read_continues() -> None:
    def line(ns: int, text: str) -> str:
        return f"2025-11-13T02:13:20.{ns % SEC:09d}Z {text}\n"

    base = 1_763_000_000 * SEC
    # stdout hit the cap mid line at ns 3; stderr has a line at ns 5 that must wait.
    out = line(base + 1, "o1") + line(base + 2, "o2") + "2025-11-13T02:13:20.000000003Z o3-cu"
    err = line(base + 1, "e1") + line(base + 5, "e5")
    page = entrypoint_log_page(out, err, (True, False), (0, 0, 0), running=True)
    assert page["more"] is True
    assert page["stdout"] == "o1\no2\n" and page["stderr"] == "e1\n"
    assert page["next_cursor"] == f"{base + 2}:1:0"
    # The next read (docker --since base+2) returns the lines from there.
    out2 = line(base + 2, "o2") + line(base + 3, "o3-cut-line")
    nxt = entrypoint_log_page(out2, line(base + 5, "e5"), (False, False), parse_entrypoint_cursor(page["next_cursor"]))
    assert nxt["stdout"] == "o3-cut-line\n" and nxt["stderr"] == "e5\n" and nxt["more"] is False


def test_server_passes_entrypoint_cursor_and_rejects_a_bad_one() -> None:
    provider = InMemorySandboxProvider()
    app = SandboxApplication(provider)
    try:
        body = json.dumps({"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}})
        sid = json.loads(app.dispatch("POST", "/v1/sandboxes", AUTH, body.encode()).body)["id"]
        # The in-memory runtime has no container: the cursor is accepted and ignored.
        r = app.dispatch("GET", f"/v1/sandboxes/{sid}/logs?entrypoint_cursor=", AUTH, b"")
        assert r.status == 200 and "entrypoint" not in json.loads(r.body)
    finally:
        provider.close()


def test_entrypoint_line_longer_than_a_read_does_not_stall(fake, guest, monkeypatch) -> None:
    import cathedral.sandbox_guest as sandbox_guest

    # Each partial prints as a 31-byte stamp and 20 bytes: a 100-byte read holds
    # one whole partial and the start of the next.
    monkeypatch.setattr(sandbox_guest, "ENTRYPOINT_LOG_PAGE", 100)
    sid = _room(guest)
    cid = _cid(guest, sid)
    parts = [c * 20 for c in "abcde"]
    for i, part in enumerate(parts):
        fake.add_log(cid, "stdout", part + ("\n" if i == len(parts) - 1 else ""), T0 + i)
    fake.add_log(cid, "stdout", "next\n", T0 + 5)

    cursor, out = "", ""
    for _ in range(20):
        page = guest.logs(sid, entrypoint_cursor=cursor)["entrypoint"]
        out += page["stdout"]
        cursor = page["next_cursor"]
        if not page["more"]:
            break
    assert out == "".join(parts) + "\nnext\n"
    again = guest.logs(sid, entrypoint_cursor=cursor)["entrypoint"]
    assert again["stdout"] == ""


def test_entrypoint_keeps_a_stamp_the_room_wrote_itself(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    own = "2025-11-13T02:13:19.000000000Z INFO started\n"  # earlier than docker's stamp
    fake.add_log(cid, "stdout", own, T0)
    assert guest.logs(sid, entrypoint_cursor="")["entrypoint"]["stdout"] == own
