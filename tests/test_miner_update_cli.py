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


def _fake_run(unit_state: str, started: str, restarts: int = 0):
    def fake_run(argv, timeout=300):
        class Result:
            returncode = 0
            stderr = ""
            stdout = (
                f"ActiveState={unit_state}\nNRestarts={restarts}\n"
                if argv[0] == "systemctl"
                else f"true {started} img@sha256:x"
            )

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
    assert cli.settle(UNIT, CONTAINER) is None


def test_a_container_up_past_the_dwell_is_running(monkeypatch):
    monkeypatch.setattr(cli, "run", _fake_run("active", _iso(-120), restarts=4))
    seen = cli.settle(UNIT, CONTAINER)
    assert seen is not None and seen.image == "img@sha256:x" and seen.restarts == 4 and seen.active


def test_an_activating_unit_is_not_running(monkeypatch):
    monkeypatch.setattr(cli, "run", _fake_run("activating", _iso(-120)))
    monkeypatch.setattr(cli, "SETTLE_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(cli, "SETTLE_POLL_SECONDS", 0)
    assert cli.settle(UNIT, CONTAINER) is None


def test_docker_nanosecond_timestamps_parse():
    assert cli._uptime_seconds("2026-09-09T09:00:00.123456789Z") > 0


def test_an_unparseable_start_time_fails_safe():
    assert cli._uptime_seconds("not-a-time") == 0.0


def _snapshot(tmp_path, *, age: float, lifetime: float = 900):
    path = tmp_path / "validator-access.json"
    path.write_text(json.dumps({"generated_at": _iso(-age), "expires_at": _iso(lifetime - age)}))
    return path


def test_restart_is_refused_near_snapshot_expiry(tmp_path):
    assert cli.safe_to_activate(_snapshot(tmp_path, age=400)) is False


def test_restart_is_allowed_with_margin(tmp_path):
    assert cli.safe_to_activate(_snapshot(tmp_path, age=60)) is True


def test_a_gate_that_can_never_pass_is_reported(tmp_path):
    """Activation review P2 (#211): a snapshot too short for the margin."""

    from cathedral.miner_updater import GateImpossible

    with pytest.raises(GateImpossible, match="lengthen"):
        cli.safe_to_activate(_snapshot(tmp_path, age=0, lifetime=700))


def test_the_margin_fits_the_refreshed_snapshot_of_211():
    """#211 signs 900 s snapshots, and a healthy host's copy is at most 340 s old:
    two timer gaps of 120 + 15 + 5 s, the 30 s generated_at backdate and the
    30 s fetch deadline."""

    refresh_gap = 120 + 15 + 5
    assert cli.SNAPSHOT_REFRESH_ALLOWANCE_SECONDS == (refresh_gap + 30) + (refresh_gap + 30)
    assert cli.MINIMUM_ACCESS_REMAINING_SECONDS + cli.SNAPSHOT_REFRESH_ALLOWANCE_SECONDS <= 900


def test_a_snapshot_at_its_oldest_on_a_healthy_host_still_passes(tmp_path):
    assert cli.safe_to_activate(_snapshot(tmp_path, age=cli.SNAPSHOT_REFRESH_ALLOWANCE_SECONDS - 1)) is True


def test_the_restart_timeout_covers_a_stop_and_the_snapshot_fetch():
    """Activation re-review P3: TimeoutStopSec=30s, then #211's fetch unit
    (TimeoutStartSec=2min) that the TDX unit Wants= and is ordered After=."""

    assert cli.RESTART_TIMEOUT_SECONDS >= 30 + 120 + 30


def test_an_unreadable_snapshot_is_unsafe(tmp_path):
    assert cli.safe_to_activate(tmp_path / "missing.json") is False


def test_the_margin_covers_a_restart_settle_second_look_and_rollback():
    """F3: the swap's restart, the settle wait, the second look and the
    rollback restart all finish before the snapshot can lapse."""

    from cathedral.miner_updater import PROBATION_SAMPLE_SECONDS

    swap = cli.DAEMON_RELOAD_TIMEOUT_SECONDS + cli.RESET_FAILED_TIMEOUT_SECONDS + cli.RESTART_TIMEOUT_SECONDS
    needed = swap + cli.SETTLE_TIMEOUT_SECONDS + PROBATION_SAMPLE_SECONDS + cli.RESTART_TIMEOUT_SECONDS
    assert cli.MINIMUM_ACCESS_REMAINING_SECONDS >= needed


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


# --- the host trust set on disk (F7, trust review P0-1) -----------------------------------------


def _trust_file(tmp_path):
    from cathedral.miner_release import initial_trust_state
    from cathedral.miner_updater import write_trust_state

    path = tmp_path / "trust.json"
    write_trust_state(path, initial_trust_state(trust_root_bytes()))
    return path


def test_the_host_trust_set_loads(tmp_path):
    from cathedral.miner_updater import load_trust_state

    trust = load_trust_state(_trust_file(tmp_path), expected_uid=os.getuid())
    assert set(trust.keys) == {"canary-1", "stable-1"} and trust.generation == 1


def test_a_trust_set_another_user_could_write_is_refused(tmp_path):
    from cathedral.miner_updater import load_trust_state

    path = _trust_file(tmp_path)
    os.chmod(path, 0o666)
    with pytest.raises(MinerUpdateError, match="unavailable"):
        load_trust_state(path, expected_uid=os.getuid())


def test_a_trust_set_owned_by_someone_else_is_refused(tmp_path):
    from cathedral.miner_updater import load_trust_state

    with pytest.raises(MinerUpdateError, match="unavailable"):
        load_trust_state(_trust_file(tmp_path), expected_uid=os.getuid() + 1)


# --- untrusted responses and faults (trust review P0-1) -----------------------------------------


@pytest.mark.parametrize("error", ["incomplete", "http", "value"])
def test_a_malformed_response_is_a_refusal(monkeypatch, error):
    import http.client

    class Broken(_Response):
        def read1(self, size):
            if error == "incomplete":
                raise http.client.IncompleteRead(b"x", 10)
            if error == "http":
                raise http.client.BadStatusLine("garbage")
            raise ValueError("invalid literal for int() with base 16")

    monkeypatch.setattr(cli.urllib.request, "build_opener", _opener(Broken([b"x"])))
    with pytest.raises(MinerUpdateError, match="download failed"):
        cli.fetch("https://updates.example.test/x.json", maximum_bytes=10, deadline_seconds=5)


def test_main_turns_an_unexpected_exception_into_the_fault_status(monkeypatch, capsys):
    def explode(arguments, paths):
        raise KeyError("a bug")

    monkeypatch.setattr(cli, "_dispatch", explode)
    assert cli.main(["check"]) == 13
    assert json.loads(capsys.readouterr().out)["action"] == "fault"


def test_prepare_reads_the_state_schema_label(monkeypatch):
    from types import SimpleNamespace

    outputs = iter(
        [
            ("", 0),
            ("img@sha256:x\n", 0),
            ("linux/amd64\n", 0),
            ("snp-contract|2\n", 0),
        ]
    )

    def fake_run(argv, timeout=300):
        stdout, code = next(outputs)
        return SimpleNamespace(returncode=code, stdout=stdout, stderr="")

    monkeypatch.setattr(cli, "run", fake_run)
    release = SimpleNamespace(image="img@sha256:x", runtime_contract="snp-contract")
    profile = SimpleNamespace(contract_label="org.cathedral.test.runtime-contract")
    assert cli.prepare_image(release, profile) == 2


def test_the_running_release_must_be_an_installed_tree(tmp_path, monkeypatch):
    from cathedral.miner_updater import HostPaths

    paths = HostPaths(root=tmp_path)
    monkeypatch.setenv(cli.RELEASE_ENV, str(tmp_path / "somewhere-else"))
    with pytest.raises(MinerUpdateError, match="not an installed release"):
        cli.running_release(paths)
