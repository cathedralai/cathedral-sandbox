"""Host effects: health, the snapshot gate, the fetch, and the trust root on disk.

The first eight tests are #197's (the two defects its live TDX run found),
ported to the new function signatures.
"""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from cathedral import miner_update_cli as cli
from cathedral.miner_updater import MinerUpdateError
from tests.miner_update_support import trust_root_bytes

UNIT = "cathedral-test-miner.service"
CONTAINER = "cathedral-test-miner"


def _fake_run(unit_state: str, started: str):
    def fake_run(argv, timeout=300):
        class Result:
            returncode = 0
            stderr = ""
            stdout = unit_state if argv[0] == "systemctl" else f"true {started} img@sha256:x"

        return Result()

    return fake_run


def _iso(delta_seconds: float) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)
    return moment.isoformat().replace("+00:00", "Z")


def test_a_container_that_just_started_is_not_yet_running(monkeypatch):
    """A crash-looping container is up for a moment at a time."""

    monkeypatch.setattr(cli, "run", _fake_run("active", _iso(0)))
    monkeypatch.setattr(cli, "SETTLE_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(cli, "SETTLE_POLL_SECONDS", 0)
    assert cli.settled_image(UNIT, CONTAINER) is None


def test_a_container_up_past_the_dwell_is_running(monkeypatch):
    monkeypatch.setattr(cli, "run", _fake_run("active", _iso(-120)))
    assert cli.settled_image(UNIT, CONTAINER) == "img@sha256:x"


def test_an_activating_unit_is_not_running(monkeypatch):
    monkeypatch.setattr(cli, "run", _fake_run("activating", _iso(-120)))
    monkeypatch.setattr(cli, "SETTLE_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(cli, "SETTLE_POLL_SECONDS", 0)
    assert cli.settled_image(UNIT, CONTAINER) is None


def test_docker_nanosecond_timestamps_parse():
    assert cli._uptime_seconds("2026-09-09T09:00:00.123456789Z") > 0


def test_an_unparseable_start_time_fails_safe():
    assert cli._uptime_seconds("not-a-time") == 0.0


def test_restart_is_refused_near_snapshot_expiry(tmp_path):
    path = tmp_path / "validator-access.json"
    path.write_text(json.dumps({"expires_at": _iso(cli.MINIMUM_ACCESS_REMAINING_SECONDS - 30)}))
    assert cli.safe_to_activate(path) is False


def test_restart_is_allowed_with_margin(tmp_path):
    path = tmp_path / "validator-access.json"
    path.write_text(json.dumps({"expires_at": _iso(cli.MINIMUM_ACCESS_REMAINING_SECONDS + 60)}))
    assert cli.safe_to_activate(path) is True


def test_an_unreadable_snapshot_is_unsafe(tmp_path):
    assert cli.safe_to_activate(tmp_path / "missing.json") is False


def test_the_margin_covers_a_restart_settle_and_rollback():
    """F3: the swap's restart, the settle wait and the rollback restart all
    finish before the snapshot the margin was checked against can lapse."""

    swap = cli.DAEMON_RELOAD_TIMEOUT_SECONDS + cli.RESET_FAILED_TIMEOUT_SECONDS + cli.RESTART_TIMEOUT_SECONDS
    assert cli.MINIMUM_ACCESS_REMAINING_SECONDS >= swap + cli.SETTLE_TIMEOUT_SECONDS + cli.RESTART_TIMEOUT_SECONDS


# --- host effects never escape as tracebacks (F16) ------------------------------------------


def test_a_hung_command_becomes_a_refusal(monkeypatch):
    def hang(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=1)

    monkeypatch.setattr(cli.subprocess, "run", hang)
    with pytest.raises(MinerUpdateError, match="timed out"):
        cli.run(["docker", "inspect"], timeout=1)


def test_a_missing_binary_becomes_a_refusal(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(cli.subprocess, "run", missing)
    with pytest.raises(MinerUpdateError, match="could not be run"):
        cli.run(["docker", "inspect"], timeout=1)


def test_only_the_updaters_systemctl_verbs_are_allowed():
    with pytest.raises(MinerUpdateError, match="not an updater command"):
        cli.systemctl(["stop", UNIT])


# --- the fetch (F15) ----------------------------------------------------------------------------


class _Response:
    def __init__(self, chunks, *, status=200, length=None, clock=None):
        self.status = status
        self.headers = {} if length is None else {"Content-Length": str(length)}
        self._chunks = list(chunks)
        self._clock = clock

    def read1(self, size):
        if self._clock is not None:
            self._clock[0] += 30
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _opener(response):
    class Opener:
        def open(self, request, timeout):
            return response

    return lambda *handlers: Opener()


def test_fetch_refuses_plain_http():
    with pytest.raises(MinerUpdateError, match="https"):
        cli.fetch("http://updates.example.test/x.json", maximum_bytes=10, deadline_seconds=5)


def test_fetch_refuses_a_redirect():
    handler = cli._NoRedirects()
    with pytest.raises(MinerUpdateError, match="redirect"):
        handler.redirect_request(None, None, 302, "Found", {}, "http://elsewhere.example.test/")


def test_fetch_refuses_an_oversized_declared_length(monkeypatch):
    monkeypatch.setattr(cli.urllib.request, "build_opener", _opener(_Response([b"x"], length=11)))
    with pytest.raises(MinerUpdateError, match="size limit"):
        cli.fetch("https://updates.example.test/x.json", maximum_bytes=10, deadline_seconds=5)


def test_fetch_refuses_an_oversized_body(monkeypatch):
    monkeypatch.setattr(cli.urllib.request, "build_opener", _opener(_Response([b"x" * 6, b"x" * 6])))
    with pytest.raises(MinerUpdateError, match="size limit"):
        cli.fetch("https://updates.example.test/x.json", maximum_bytes=10, deadline_seconds=5)


def test_fetch_enforces_its_deadline_while_reading(monkeypatch):
    """A server that drips bytes cannot hold the lock past the deadline."""

    clock = [0.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    response = _Response([b"x"] * 100, clock=clock)
    monkeypatch.setattr(cli.urllib.request, "build_opener", _opener(response))
    with pytest.raises(MinerUpdateError, match="deadline"):
        cli.fetch("https://updates.example.test/x.json", maximum_bytes=1000, deadline_seconds=60)


def test_fetch_returns_a_bounded_body(monkeypatch):
    monkeypatch.setattr(cli.urllib.request, "build_opener", _opener(_Response([b"abc", b"de"])))
    assert cli.fetch("https://updates.example.test/x.json", maximum_bytes=10, deadline_seconds=5) == b"abcde"


# --- the trust root on disk (F7) ------------------------------------------------------------------


def _release_with_trust(tmp_path):
    release = tmp_path / "release"
    (release / "trust").mkdir(parents=True)
    path = release / "trust" / "release-keys.json"
    path.write_bytes(trust_root_bytes())
    os.chmod(path, 0o444)
    return release, path


def test_the_trust_root_loads_from_the_running_release(tmp_path):
    release, _path = _release_with_trust(tmp_path)
    keys = cli.load_own_trust_root(release, os.getuid())
    assert set(keys) == {"canary-1", "stable-1"}


def test_a_trust_root_another_user_could_write_is_refused(tmp_path):
    release, path = _release_with_trust(tmp_path)
    os.chmod(path, 0o666)
    with pytest.raises(MinerUpdateError, match="unusable"):
        cli.load_own_trust_root(release, os.getuid())


def test_a_trust_root_owned_by_someone_else_is_refused(tmp_path):
    release, _path = _release_with_trust(tmp_path)
    with pytest.raises(MinerUpdateError, match="unusable"):
        cli.load_own_trust_root(release, os.getuid() + 1)


def test_the_running_release_must_be_an_installed_tree(tmp_path, monkeypatch):
    from cathedral.miner_updater import HostPaths

    paths = HostPaths(root=tmp_path)
    monkeypatch.setenv(cli.RELEASE_ENV, str(tmp_path / "somewhere-else"))
    with pytest.raises(MinerUpdateError, match="not an installed release"):
        cli.running_release(paths)
