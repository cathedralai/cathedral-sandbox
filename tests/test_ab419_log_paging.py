"""AB#419: process log offset paging and the room's entrypoint log.

Done when: a guest log read takes an offset, returns the next offset, and also
returns the entrypoint json-file log; a second read returns only new bytes.
"""

from __future__ import annotations

import json

import pytest

from cathedral import sandbox_guest
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
    assert first["next_cursor"] == f"{T0}:1:{T0}:1"
    fake.add_log(cid, "stdout", "b\n", T0)  # same ns as the cursor
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "b\n" and second["stderr"] == ""
    assert second["next_cursor"] == f"{T0}:2:{T0}:1"


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
    # docker writes a partial only when its 16 KiB buffer fills; the rest of the
    # line follows later with the same stamp.
    head = "x" * 16 * 1024
    fake.add_log(cid, "stdout", head, T0 + 1)
    fake.add_log(cid, "stderr", "other stream\n", T0 + 2)
    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "whole\n"
    # The other stream is not held back by stdout's unfinished line.
    assert first["stderr"] == "other stream\n"
    fake.add_log(cid, "stdout", "-rest\n", T0 + 1)
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == head + "-rest\n" and second["stderr"] == ""


def test_entrypoint_long_line_split_by_docker_is_joined(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    # json-file keeps a line over 16 KiB as partial messages with one shared
    # stamp; docker logs prints each with it and no newline between them.
    long_line = "".join(c * 16 * 1024 for c in "abc") + "end\n"
    fake.add_long_line(cid, "stdout", long_line, T0)
    fake.add_log(cid, "stdout", "next\n", T0 + 3)
    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == long_line + "next\n"
    fake.add_log(cid, "stdout", "last\n", T0 + 4)
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "last\n"


def test_entrypoint_docker_failure_keeps_the_rest_of_the_answer(fake, guest) -> None:
    sid = _room(guest)
    fake.set(logs_fail=True)
    doc = guest.logs(sid, entrypoint_cursor="")
    assert "No such container" in doc["entrypoint"]["error"]
    assert doc["sandbox_id"] == sid and "exec_history" in doc


@pytest.fixture
def sealed_hotel(fake, tmp_path, monkeypatch):
    """A hotel with customer-sealed secrets (AB#417): CATHEDRAL_SEALED_SECRETS_DIR set."""
    (tmp_path / "secrets").mkdir()
    monkeypatch.setenv("CATHEDRAL_SEALED_SECRETS_DIR", str(tmp_path / "secrets"))
    provider = DockerGuestProvider()
    try:
        yield provider
    finally:
        provider.close()


def _mark_at(provider, sid: str, ns: int, _monkeypatch=None) -> int:
    """What the receipts front does before a room's first secret file lands (AB#791)."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sandbox_guest.time, "time_ns", lambda: ns)
        return provider.mark_sealed(sid)


def test_ab791_never_sealed_room_on_a_sealed_hotel_returns_its_lines(fake, sealed_hotel) -> None:
    """Withholding is per room: a room that never had a sealed secret reads as on any hotel."""
    sid = _room(sealed_hotel)
    cid = _cid(sealed_hotel, sid)
    fake.add_log(cid, "stdout", "booting\n", T0)
    fake.add_log(cid, "stderr", "warn\n", T0 + 1)
    first = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "booting\n" and first["stderr"] == "warn\n"
    assert "error" not in first and "sealed_since_ns" not in first
    fake.add_log(cid, "stdout", "ready\n", T0 + 9)
    second = sealed_hotel.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["stdout"] == "ready\n" and "error" not in second


def test_ab791_room_sealed_before_any_output_is_withheld(fake, sealed_hotel, monkeypatch) -> None:
    sid = _room(sealed_hotel)
    cid = _cid(sealed_hotel, sid)
    mark = _mark_at(sealed_hotel, sid, T0, monkeypatch)
    fake.add_log(cid, "stdout", "secret-value\n", T0 + 1)
    fake.add_log(cid, "stderr", "secret-value\n", T0 + 2)
    page = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert page["error"].startswith("entrypoint_log_withheld")
    assert page["sealed_since_ns"] == mark == T0
    assert "stdout" not in page and "stderr" not in page and "secret-value" not in json.dumps(page)


def test_ab791_room_sealed_mid_life_returns_only_pre_install_lines_then_withheld(fake, sealed_hotel, monkeypatch) -> None:
    sid = _room(sealed_hotel)
    cid = _cid(sealed_hotel, sid)
    fake.add_log(cid, "stdout", "before 1\n", T0)
    fake.add_log(cid, "stderr", "before err\n", T0 + 1)
    fake.add_log(cid, "stdout", "before 2\n", T0 + 2)
    mark = _mark_at(sealed_hotel, sid, T0 + 5, monkeypatch)
    fake.add_log(cid, "stdout", "after secret-value\n", T0 + 5)  # at the mark: may have read the secret
    fake.add_log(cid, "stderr", "after secret-value\n", T0 + 6)
    first = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "before 1\nbefore 2\n" and first["stderr"] == "before err\n"
    assert first["sealed_since_ns"] == mark and "error" not in first and first["more"] is False
    second = sealed_hotel.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["error"].startswith("entrypoint_log_withheld") and second["sealed_since_ns"] == mark
    assert "secret-value" not in json.dumps(first) + json.dumps(second)
    # A later install does not move the switch point.
    assert _mark_at(sealed_hotel, sid, T0 + 50, monkeypatch) == mark


def test_ab791_mark_read_after_the_docker_read_cuts_lines_logged_meanwhile(fake, sealed_hotel, monkeypatch) -> None:
    """A secret that lands while docker logs runs: the mark is read after the read, so its lines go."""
    sid = _room(sealed_hotel)
    cid = _cid(sealed_hotel, sid)
    fake.add_log(cid, "stdout", "before\n", T0)
    fake.add_log(cid, "stdout", "after secret-value\n", T0 + 5)
    real = sealed_hotel._client.entrypoint_logs  # noqa: SLF001

    def read_then_install(*args, **kwargs):
        answer = real(*args, **kwargs)
        sealed_hotel._guests[sid].sealed_since_ns = T0 + 5  # noqa: SLF001
        return answer

    monkeypatch.setattr(sealed_hotel._client, "entrypoint_logs", read_then_install)  # noqa: SLF001
    page = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert page["stdout"] == "before\n" and page["sealed_since_ns"] == T0 + 5


def test_ab791_a_long_line_finished_after_the_install_is_not_served(fake, sealed_hotel, monkeypatch) -> None:
    """docker stamps a long line's parts with its first part's time: its end may be after the install."""
    sid = _room(sealed_hotel)
    cid = _cid(sealed_hotel, sid)
    fake.add_log(cid, "stdout", "before\n", T0)
    fake.add_long_line(cid, "stdout", "a" * 16 * 1024 + "secret-value\n", T0 + 1)
    _mark_at(sealed_hotel, sid, T0 + 5, monkeypatch)
    first = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert first["stdout"] == "before\n"
    second = sealed_hotel.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    assert second["error"].startswith("entrypoint_log_withheld")
    assert "secret-value" not in json.dumps(first) + json.dumps(second)


def test_ab791_a_long_line_followed_by_an_earlier_stamped_line_is_served(fake, sealed_hotel, monkeypatch) -> None:
    sid = _room(sealed_hotel)
    cid = _cid(sealed_hotel, sid)
    long_line = "b" * 16 * 1024 + "end\n"
    fake.add_long_line(cid, "stdout", long_line, T0)
    fake.add_log(cid, "stdout", "next\n", T0 + 1)
    _mark_at(sealed_hotel, sid, T0 + 5, monkeypatch)
    page = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert page["stdout"] == long_line + "next\n"


def test_ab791_a_secret_file_with_no_mark_withholds_the_whole_log(fake, sealed_hotel, tmp_path) -> None:
    """A front from before AB#791 writes no mark: no switch point is known, so nothing is served."""
    sid = _room(sealed_hotel)
    fake.add_log(_cid(sealed_hotel, sid), "stdout", "line\n", T0)
    (tmp_path / "secrets" / sid / "TOKEN").write_text("x")
    page = sealed_hotel.logs(sid, entrypoint_cursor="")["entrypoint"]
    assert page["error"].startswith("entrypoint_log_withheld") and page["sealed_since_ns"] == 0
    assert fake.calls_of("logs") == []


def test_ab791_a_sealed_env_overlay_marks_the_room_and_an_empty_one_does_not(fake, sealed_hotel, monkeypatch) -> None:
    sid = _room(sealed_hotel)
    sealed_hotel.set_env_overlay(sid, {})
    assert sealed_hotel._guests[sid].sealed_since_ns is None  # noqa: SLF001
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sandbox_guest.time, "time_ns", lambda: T0 + 3)
        sealed_hotel.set_env_overlay(sid, {"TOKEN": "x"})
    assert sealed_hotel._guests[sid].sealed_since_ns == T0 + 3  # noqa: SLF001


def test_ab791_mark_is_refused_on_a_hotel_without_sealed_secrets(guest) -> None:
    sid = _room(guest)
    with pytest.raises(SandboxOpError) as err:
        guest.mark_sealed(sid)
    assert err.value.code == "sealed_mark_not_supported"


def test_ab791_non_owner_is_refused_as_before_sealed_or_not(fake, sealed_hotel, monkeypatch) -> None:
    never, sealed = _room(sealed_hotel), _room(sealed_hotel)
    fake.add_log(_cid(sealed_hotel, never), "stdout", "mine\n", T0)
    _mark_at(sealed_hotel, sealed, T0, monkeypatch)
    sealed_hotel._inner._ctx.api_key = "someone-else"  # noqa: SLF001
    for sid in (never, sealed):
        with pytest.raises(SandboxOpError) as err:
            sealed_hotel.logs(sid, entrypoint_cursor="")
        assert err.value.http_status == 404 and err.value.code == "sandbox_not_found"
        with pytest.raises(SandboxOpError) as err:
            sealed_hotel.mark_sealed(sid)
        assert err.value.http_status == 404
    assert fake.calls_of("logs") == []


def test_ab791_server_mark_route_answers_the_switch_point(fake, sealed_hotel, monkeypatch) -> None:
    app = SandboxApplication(sealed_hotel)
    body = json.dumps({"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}})
    sid = json.loads(app.dispatch("POST", "/v1/sandboxes", AUTH, body.encode()).body)["id"]
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sandbox_guest.time, "time_ns", lambda: T0 + 7)
        resp = app.dispatch("POST", f"/v1/sandboxes/{sid}/sealed-mark", AUTH, b"{}")
    assert resp.status == 200 and json.loads(resp.body) == {"sandbox_id": sid, "sealed_since_ns": T0 + 7}


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
    # stdout hit the cap mid line at ns 3; stderr is whole and goes on to ns 5.
    out = line(base + 1, "o1") + line(base + 2, "o2") + "2025-11-13T02:13:20.000000003Z o3-cu"
    err = line(base + 1, "e1") + line(base + 5, "e5")
    page = entrypoint_log_page(out, err, (True, False), (0, 0, 0, 0), running=True)
    assert page["more"] is True and page["truncated"] is False
    assert page["stdout"] == "o1\no2\n" and page["stderr"] == "e1\ne5\n"
    # stdout's next read starts at its cut line, not at o2 again.
    assert page["next_cursor"] == f"{base + 3}:0:{base + 5}:1"
    # The next read (docker --since base+3, the earlier stream) returns the rest.
    out2 = line(base + 2, "o2") + line(base + 3, "o3-cut-line")
    nxt = entrypoint_log_page(out2, line(base + 5, "e5"), (False, False), parse_entrypoint_cursor(page["next_cursor"]))
    assert nxt["stdout"] == "o3-cut-line\n" and nxt["stderr"] == "" and nxt["more"] is False


def test_entrypoint_cut_inside_a_partial_stamp_drops_the_stamp_piece() -> None:
    stamp = "2025-11-13T02:13:20.000000000Z"
    out = f"{stamp} {'a' * 20}{stamp[:9]}"  # cut nine bytes into the next partial's stamp
    t0 = 1_763_000_000 * SEC
    page = entrypoint_log_page(out, "", (True, False), (t0, 0, t0, 0))
    assert page["stdout"] == "a" * 20 and page["truncated"] is True
    assert page["next_cursor"].startswith(f"{t0 + 1}:0:")


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

    # Partials print as a 31-byte stamp and 20 bytes, all with one stamp: a
    # 100-byte read holds the first partial and most of the second.
    monkeypatch.setattr(sandbox_guest, "ENTRYPOINT_LOG_PAGE", 100)
    sid = _room(guest)
    cid = _cid(guest, sid)
    fake.add_long_line(cid, "stdout", "".join(c * 20 for c in "abcde") + "\n", T0, chunk=20)
    fake.add_log(cid, "stdout", "next\n", T0 + 5)

    first = guest.logs(sid, entrypoint_cursor="")["entrypoint"]
    # The first read moves to the long line; the next starts at it.
    assert first["stdout"] == "" and first["more"] is True
    second = guest.logs(sid, entrypoint_cursor=first["next_cursor"])["entrypoint"]
    # --since cannot start inside a line, so what was read of it comes back once,
    # marked truncated, and the read after goes on past it.
    assert second["stdout"] == "a" * 20 + "b" * 18
    assert second["truncated"] is True and second["more"] is True
    third = guest.logs(sid, entrypoint_cursor=second["next_cursor"])["entrypoint"]
    assert third["stdout"] == "next\n" and third["truncated"] is False and third["more"] is False
    fourth = guest.logs(sid, entrypoint_cursor=third["next_cursor"])["entrypoint"]
    assert fourth["stdout"] == ""


def test_entrypoint_keeps_a_stamp_the_room_wrote_itself(fake, guest) -> None:
    sid = _room(guest)
    cid = _cid(guest, sid)
    own = "2025-11-13T02:13:19.000000000Z INFO started\n"  # earlier than docker's stamp
    fake.add_log(cid, "stdout", own, T0)
    assert guest.logs(sid, entrypoint_cursor="")["entrypoint"]["stdout"] == own


def test_entrypoint_a_lagging_stream_does_not_cut_the_other_streams_line(fake, guest, monkeypatch) -> None:
    import cathedral.sandbox_guest as sandbox_guest

    # The read starts at the earlier stream's place, so the stream ahead reads
    # its old lines again and its cap can land inside an ordinary new line.
    monkeypatch.setattr(sandbox_guest, "ENTRYPOINT_LOG_PAGE", 200)
    sid = _room(guest)
    cid = _cid(guest, sid)
    fake.add_log(cid, "stdout", "started\n", T0)
    expected = ""
    for i in range(20):
        line = f"err line {i:03d} padding\n"
        expected += line
        fake.add_log(cid, "stderr", line, T0 + 10 + i)

    cursor, out, err = "", "", ""
    for _ in range(60):
        page = guest.logs(sid, entrypoint_cursor=cursor)["entrypoint"]
        assert page["truncated"] is False
        out += page["stdout"]
        err += page["stderr"]
        cursor = page["next_cursor"]
        if not page["more"]:
            break
    assert out == "started\n" and err == expected


def _page_all(guest, sid: str, rounds: int = 40) -> tuple[str, str, bool]:
    cursor, out, err, truncated = "", "", "", False
    for _ in range(rounds):
        page = guest.logs(sid, entrypoint_cursor=cursor)["entrypoint"]
        out += page["stdout"]
        err += page["stderr"]
        truncated = truncated or page["truncated"]
        cursor = page["next_cursor"]
        if not page["more"]:
            return out, err, truncated
    raise AssertionError(f"paging did not finish: {cursor}")


def test_entrypoint_two_lines_over_a_read_together_are_not_cut(fake, guest, monkeypatch) -> None:
    import cathedral.sandbox_guest as sandbox_guest

    # Each line fits a read; two together do not. The read after the cut starts
    # at the cut line, not at the line already returned.
    monkeypatch.setattr(sandbox_guest, "ENTRYPOINT_LOG_PAGE", 200)
    sid = _room(guest)
    cid = _cid(guest, sid)
    lines = ["X" * 80 + "\n", "Y" * 80 + "\n", "z\n"]
    for i, line in enumerate(lines):
        fake.add_log(cid, "stdout", line, T0 + 10 * i)
    out, _, truncated = _page_all(guest, sid)
    assert out == "".join(lines) and truncated is False


@pytest.mark.parametrize("size", [137, 138, 148, 167, 168])
def test_entrypoint_cap_inside_the_next_stamp_does_not_stall(fake, guest, monkeypatch, size: int) -> None:
    import cathedral.sandbox_guest as sandbox_guest

    # 31-byte stamp + size + newline leaves the 200-byte cap inside the next
    # line's stamp (or right after its space).
    monkeypatch.setattr(sandbox_guest, "ENTRYPOINT_LOG_PAGE", 200)
    sid = _room(guest)
    cid = _cid(guest, sid)
    lines = ["X" * size + "\n", "short\n", "end\n"]
    for i, line in enumerate(lines):
        fake.add_log(cid, "stdout", line, T0 + 10 * i)
    out, _, truncated = _page_all(guest, sid)
    assert out == "".join(lines) and truncated is False
