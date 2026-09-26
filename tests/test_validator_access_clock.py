"""The replay store tolerates a bounded backward clock step and has a safe reset.

Every test drives time through an injected stepped clock. Replay safety must
not depend on the clock: a nonce the worker has accepted stays refused across
any step, while fresh nonces keep working after a small step or a reset.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import secrets
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sr25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from cathedral.cli import main as cathedral_main
from cathedral.common import ChannelBinding, ChannelBindingType
from cathedral.policy_registry import canonical_json
from cathedral.validator_access import (
    MAX_NETUID,
    MAX_REQUEST_CLOCK_STEP_BACK_SECONDS,
    MAX_REQUEST_FUTURE_SKEW_SECONDS,
    MAX_REQUEST_LIFETIME_SECONDS,
    REQUEST_CLOCK_LOG_INTERVAL_SECONDS,
    REQUEST_CLOCK_RESET_COMMAND,
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    ValidatorAccessError,
    ValidatorAccessState,
    ValidatorRequestAuthorizer,
    build_validator_request_header,
    load_sr25519_verifier,
    reset_request_clock_high_water,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)

T0 = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)
NETWORK = "finney"
# Any subnet works; nothing here may depend on a particular one.
NETUID = secrets.randbelow(MAX_NETUID + 1)
SNAPSHOT_SEED = secrets.token_bytes(32)
SNAPSHOT_KEY_ID = "clock-step-test"
TOLERANCE = MAX_REQUEST_CLOCK_STEP_BACK_SECONDS


def _ss58(public_key: bytes) -> str:
    payload = b"\x2a" + public_key
    data = payload + hashlib.blake2b(b"SS58PRE" + payload, digest_size=64).digest()[:2]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = int.from_bytes(data, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = alphabet[remainder] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + encoded


VALIDATOR_PAIR = sr25519.pair_from_seed(secrets.token_bytes(32))
VALIDATOR_HOTKEY = _ss58(VALIDATOR_PAIR[0])
WORKER_HOTKEY = _ss58(sr25519.pair_from_seed(secrets.token_bytes(32))[0])
BINDING = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, secrets.token_bytes(32))


class SteppedClock:
    """A wall clock the test moves forward and steps backward by hand."""

    def __init__(self, start: datetime) -> None:
        self.current = start

    def __call__(self) -> datetime:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)

    def step_back(self, seconds: int) -> None:
        self.current -= timedelta(seconds=seconds)


def _snapshot():
    generated_at = T0 - timedelta(minutes=10)
    document = {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": NETWORK,
        "netuid": NETUID,
        "block": 1_000,
        "block_hash": "0x" + "b" * 64,
        "block_is_finalized": True,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (generated_at + timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "minimum_stake_rao": 0,
        "validators": [
            {"hotkey": VALIDATOR_HOTKEY, "uid": 1, "validator_permit": True, "stake_rao": 1}
        ],
        "signing_key_id": SNAPSHOT_KEY_ID,
    }
    public_key = (
        ed25519.Ed25519PrivateKey.from_private_bytes(SNAPSHOT_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return verify_validator_access_snapshot(
        canonical_json(sign_validator_access_snapshot(document, SNAPSHOT_SEED)),
        {SNAPSHOT_KEY_ID: public_key},
        network=NETWORK,
        netuid=NETUID,
        required_minimum_stake_rao=0,
        now=generated_at,
    )


class Worker:
    """One worker process: it holds the state and authorizes signed requests."""

    def __init__(self, state_path: Path, clock: SteppedClock, *, log_clock=None) -> None:
        self.clock = clock
        if log_clock is None:
            self.state = ValidatorAccessState(str(state_path))
        else:
            self.state = ValidatorAccessState(str(state_path), log_clock=log_clock)
        self.authorizer = ValidatorRequestAuthorizer(
            _snapshot(),
            worker_hotkey=WORKER_HOTKEY,
            channel_binding=BINDING,
            state=self.state,
            signature_verifier=load_sr25519_verifier(),
        )

    def sign(self, *, lifetime: int = 60) -> str:
        """A validator signs a fresh request at the current (true) time."""

        issued_at = self.clock()
        return build_validator_request_header(
            validator_hotkey=VALIDATOR_HOTKEY,
            worker_hotkey=WORKER_HOTKEY,
            network=NETWORK,
            netuid=NETUID,
            method="POST",
            path="/v1/fleet",
            body=b"{}",
            channel_binding=BINDING,
            nonce=secrets.token_bytes(32),
            issued_at=issued_at,
            expires_at=issued_at + timedelta(seconds=lifetime),
            signer=lambda message: sr25519.sign(VALIDATOR_PAIR, message),
        )

    def accepts(self, header: str) -> bool:
        return self.authorizer.authorize(
            header, method="POST", path="/v1/fleet", body=b"{}", now=self.clock()
        )

    def stop(self) -> None:
        self.state.close()


def test_tolerance_is_the_sum_of_the_request_windows():
    assert TOLERANCE == MAX_REQUEST_LIFETIME_SECONDS + MAX_REQUEST_FUTURE_SKEW_SECONDS


def test_small_backward_step_accepts_new_nonces(tmp_path: Path):
    clock = SteppedClock(T0)
    worker = Worker(tmp_path / "access.sqlite", clock)
    assert worker.accepts(worker.sign(lifetime=60))
    clock.advance(100)
    assert worker.accepts(worker.sign(lifetime=60))  # prunes the first nonce

    clock.step_back(30)
    # The old ratchet refused both of these until the clock regained 30 s.
    assert worker.accepts(worker.sign(lifetime=60))
    # This one even expires before the clock high-water. It is still safe:
    # nothing that expires after the first nonce has been pruned.
    assert worker.accepts(worker.sign(lifetime=20))


def test_replayed_nonce_is_refused_across_a_backward_step(tmp_path: Path):
    clock = SteppedClock(T0)
    worker = Worker(tmp_path / "access.sqlite", clock)
    pruned = worker.sign(lifetime=60)
    assert worker.accepts(pruned)
    clock.advance(40)
    retained = worker.sign(lifetime=120)
    assert worker.accepts(retained)
    clock.advance(60)
    assert worker.accepts(worker.sign())  # prunes the first row after its expiry

    clock.step_back(50)
    # Both captured requests are inside their signed windows again by this
    # clock. One row was pruned and one is retained; both stay refused.
    assert not worker.accepts(pruned)
    assert not worker.accepts(retained)
    assert worker.accepts(worker.sign())


def test_large_backward_step_fails_closed_and_names_the_reset(tmp_path: Path, caplog):
    state_path = tmp_path / "access.sqlite"
    clock = SteppedClock(T0)
    worker = Worker(state_path, clock)
    assert worker.accepts(worker.sign(lifetime=60))
    clock.advance(200)
    assert worker.accepts(worker.sign(lifetime=60))

    clock.step_back(TOLERANCE + 1)
    fresh = worker.sign(lifetime=60)
    with caplog.at_level(logging.WARNING, logger="cathedral.validator_access"):
        assert not worker.accepts(fresh)
    message = caplog.text
    assert f"{TOLERANCE + 1} s behind" in message
    assert f"{TOLERANCE} s tolerance" in message
    assert f"{REQUEST_CLOCK_RESET_COMMAND} {state_path}" in message

    # One second later the step is exactly the tolerance, which is allowed.
    clock.advance(1)
    assert worker.accepts(worker.sign(lifetime=60))


def test_reset_is_refused_while_a_worker_holds_the_state(tmp_path: Path, capsys):
    state_path = tmp_path / "access.sqlite"
    clock = SteppedClock(T0)
    worker = Worker(state_path, clock)
    assert worker.accepts(worker.sign())

    with pytest.raises(ValidatorAccessError, match="held by a running worker"):
        reset_request_clock_high_water(str(state_path), now=clock())
    with pytest.raises(ValidatorAccessError, match="exclusive state lock"):
        worker.state.reset_request_clock(now=clock())
    assert (
        cathedral_main(
            ["worker", "reset-replay-clock", "--validator-access-state", str(state_path)]
        )
        == 2
    )
    assert "stop the worker first" in capsys.readouterr().err

    # A reset in progress also keeps a worker from starting.
    worker.stop()
    resetting = ValidatorAccessState(str(state_path), exclusive=True)
    with pytest.raises(ValidatorAccessError, match="locked by an operator reset"):
        ValidatorAccessState(str(state_path))
    resetting.close()
    ValidatorAccessState(str(state_path)).close()


def test_state_lock_must_be_an_owner_only_file(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    lock_path = tmp_path / "access.sqlite.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o644)
    with pytest.raises(ValidatorAccessError, match="lock must be an owner-only file"):
        ValidatorAccessState(str(state_path))

    lock_path.unlink()
    target = tmp_path / "elsewhere.lock"
    target.touch(mode=0o600)
    lock_path.symlink_to(target)
    with pytest.raises(ValidatorAccessError, match="lock must be an owner-only file"):
        ValidatorAccessState(str(state_path))


def test_reset_accepts_new_requests_and_old_nonces_stay_refused(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    clock = SteppedClock(T0)
    worker = Worker(state_path, clock)
    pruned = worker.sign(lifetime=60)
    assert worker.accepts(pruned)
    clock.advance(300)
    retained = worker.sign(lifetime=100)
    assert worker.accepts(retained)

    clock.step_back(250)
    blocked = worker.sign(lifetime=60)
    assert not worker.accepts(blocked)
    worker.stop()

    result = reset_request_clock_high_water(str(state_path), now=clock())
    assert result.clock_high_water_before == int((T0 + timedelta(seconds=300)).timestamp())
    assert result.clock_high_water_after == int(clock().timestamp())
    assert result.replay_floor == int((T0 + timedelta(seconds=60)).timestamp())
    assert result.retained_replay_records == 1

    restarted = Worker(state_path, clock)
    assert restarted.accepts(blocked)
    assert restarted.accepts(restarted.sign())
    # The pruned request is inside its signed window again by this clock.
    assert not restarted.accepts(pruned)
    # The retained request re-enters its window once the clock catches up.
    clock.advance(250)
    assert not restarted.accepts(retained)
    assert restarted.accepts(restarted.sign())


def test_forward_clock_behaviour_is_unchanged(tmp_path: Path):
    state = ValidatorAccessState(str(tmp_path / "access.sqlite"), max_replay_entries=2)
    clock = SteppedClock(T0)

    def record(nonce: str, lifetime: int) -> bool:
        return state.check_and_record_request(
            VALIDATOR_HOTKEY,
            nonce,
            now=clock(),
            expires_at=clock() + timedelta(seconds=lifetime),
        )

    assert record("01" * 32, 60)
    assert record("02" * 32, 60)
    assert not record("01" * 32, 60)  # replay
    clock.advance(1)
    assert not record("03" * 32, 60)  # bounded replay cache is full
    assert not record("04" * 32, 0)  # already expired
    clock.advance(60)
    assert record("03" * 32, 60)  # both earlier rows expired and were pruned
    assert not record("03" * 32, 60)

    # The clock high-water follows the clock forward.
    clock.advance(1_000)
    assert record("05" * 32, 60)
    clock.step_back(TOLERANCE + 1)
    assert not record("06" * 32, 60)
    clock.advance(1)
    assert record("06" * 32, 60)


def test_reset_leaves_state_that_was_never_stepped_back_alone(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    clock = SteppedClock(T0)
    worker = Worker(state_path, clock)
    assert worker.accepts(worker.sign())
    worker.stop()
    clock.advance(10)

    result = reset_request_clock_high_water(str(state_path), now=clock())
    assert result.clock_high_water_before == result.clock_high_water_after == int(T0.timestamp())
    assert result.retained_replay_records == 1


def test_reset_refuses_to_create_missing_state(tmp_path: Path, capsys):
    missing = tmp_path / "missing.sqlite"
    with pytest.raises(ValidatorAccessError, match="does not exist"):
        reset_request_clock_high_water(str(missing), now=T0)
    assert (
        cathedral_main(["worker", "reset-replay-clock", "--validator-access-state", str(missing)])
        == 2
    )
    assert "does not exist" in capsys.readouterr().err
    assert not missing.exists()


def _write_previous_release_state(state_path: Path, *, observed_at_epoch: int) -> None:
    connection = sqlite3.connect(state_path)
    connection.execute(
        """
        CREATE TABLE validator_request_clock_high_water (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            observed_at_epoch INTEGER NOT NULL
        )
        """
    )
    connection.execute(
        "INSERT INTO validator_request_clock_high_water VALUES (1, ?)", (observed_at_epoch,)
    )
    connection.commit()
    connection.close()
    state_path.chmod(0o600)


def test_state_from_an_older_release_keeps_its_ratchet_as_the_floor(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    high_water = int((T0 + timedelta(seconds=100)).timestamp())
    _write_previous_release_state(state_path, observed_at_epoch=high_water)

    clock = SteppedClock(T0 + timedelta(seconds=70))
    worker = Worker(state_path, clock)
    # The older release may have pruned anything that expired by its
    # ratchet, so only requests expiring after it are accepted.
    assert not worker.accepts(worker.sign(lifetime=30))
    assert worker.accepts(worker.sign(lifetime=31))
    row = sqlite3.connect(state_path).execute(
        "SELECT observed_at_epoch, wall_clock_high_water_epoch "
        "FROM validator_request_clock_high_water"
    ).fetchone()
    assert row == (high_water, high_water)


def _utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_reset_command(state_path: Path, capsys, caplog) -> tuple[dict, str]:
    with caplog.at_level(logging.WARNING, logger="cathedral.validator_access"):
        assert (
            cathedral_main(
                ["worker", "reset-replay-clock", "--validator-access-state", str(state_path)]
            )
            == 0
        )
    return json.loads(capsys.readouterr().out), caplog.text


def test_reset_command_reports_the_floor_and_when_requests_resume(
    tmp_path: Path, capsys, caplog
):
    state_path = tmp_path / "access.sqlite"
    ahead = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1_000)
    later = ahead + timedelta(seconds=100)
    state = ValidatorAccessState(str(state_path))
    assert state.check_and_record_request(
        VALIDATOR_HOTKEY, "0a" * 32, now=ahead, expires_at=ahead + timedelta(seconds=60)
    )
    assert state.check_and_record_request(
        VALIDATOR_HOTKEY, "0b" * 32, now=later, expires_at=later + timedelta(seconds=60)
    )
    state.close()

    output, log = _run_reset_command(state_path, capsys, caplog)
    floor = ahead + timedelta(seconds=60)
    resume = floor - timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS)
    assert output["clock_high_water_before"] == _utc(later)
    assert 1_090 <= output["backward_step_seconds"] <= 1_100
    assert output["retained_replay_records"] == 1
    assert output["replay_floor"] == _utc(floor)
    assert output["requests_resume_at"] == _utc(resume)
    assert f"replay floor {_utc(floor)} kept, never lowered" in log
    assert f"accepted from about {_utc(resume)}" in log


def test_reset_command_on_state_that_never_pruned(tmp_path: Path, capsys, caplog):
    state_path = tmp_path / "access.sqlite"
    ahead = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1_000)
    state = ValidatorAccessState(str(state_path))
    assert state.check_and_record_request(
        VALIDATOR_HOTKEY, "0a" * 32, now=ahead, expires_at=ahead + timedelta(seconds=60)
    )
    state.close()

    output, log = _run_reset_command(state_path, capsys, caplog)
    assert output["clock_high_water_before"] == _utc(ahead)
    assert output["replay_floor"] is None
    assert output["requests_resume_at"] is None
    assert "no request waits on the floor" in log


def test_long_forward_excursion_waits_for_the_floor_and_says_so(tmp_path: Path, caplog):
    """Worker and validator clocks both run 20 min fast, then are corrected."""

    state_path = tmp_path / "access.sqlite"
    excursion = 1_200
    clock = SteppedClock(T0 + timedelta(seconds=excursion))
    worker = Worker(state_path, clock)
    fast_pruned = worker.sign(lifetime=120)
    assert worker.accepts(fast_pruned)
    clock.advance(130)
    fast_retained = worker.sign(lifetime=120)
    assert worker.accepts(fast_retained)  # prunes the first; floor = its expiry
    floor = T0 + timedelta(seconds=excursion + 120)
    resume = floor - timedelta(seconds=MAX_REQUEST_LIFETIME_SECONDS)

    clock.step_back(excursion)  # both clocks are now correct
    assert not worker.accepts(worker.sign(lifetime=120))
    worker.stop()

    with caplog.at_level(logging.WARNING, logger="cathedral.validator_access"):
        result = reset_request_clock_high_water(str(state_path), now=clock())
    assert result.clock_high_water_after == int(clock().timestamp())
    assert result.replay_floor == int(floor.timestamp())
    assert result.requests_resume_at == int(resume.timestamp())
    assert f"replay floor {_utc(floor)} kept, never lowered" in caplog.text
    assert f"accepted from about {_utc(resume)}" in caplog.text
    caplog.clear()

    # The reset fixed the high-water, but the floor still refuses, and says so.
    restarted = Worker(state_path, clock)
    with caplog.at_level(logging.WARNING, logger="cathedral.validator_access"):
        assert not restarted.accepts(restarted.sign(lifetime=120))
    ahead = int((floor - clock()).total_seconds())
    assert f"replay floor {_utc(floor)}, which is {ahead} s ahead" in caplog.text
    assert f"accepted from about {_utc(resume)}" in caplog.text

    clock.current = resume - timedelta(seconds=1)
    assert not restarted.accepts(restarted.sign(lifetime=120))
    clock.current = resume + timedelta(seconds=1)
    assert restarted.accepts(restarted.sign(lifetime=120))
    assert not restarted.accepts(fast_pruned)
    assert not restarted.accepts(fast_retained)


def test_row_pruned_exactly_at_its_expiry_stays_refused(tmp_path: Path):
    clock = SteppedClock(T0)
    worker = Worker(tmp_path / "access.sqlite", clock)
    captured = worker.sign(lifetime=60)
    assert worker.accepts(captured)
    clock.advance(60)  # now == the captured request's expiry
    assert worker.accepts(worker.sign(lifetime=60))  # prunes it at exactly now == exp

    clock.step_back(30)
    assert not worker.accepts(captured)


def _replay_rows_and_floor(state_path: Path) -> tuple[list[str], list[str]]:
    connection = sqlite3.connect(state_path)
    try:
        rows = [line for line in connection.iterdump() if "validator_request_replays" in line]
        floor = [
            repr(row)
            for row in connection.execute(
                "SELECT observed_at_epoch FROM validator_request_clock_high_water"
            )
        ]
    finally:
        connection.close()
    return rows, floor


def test_reset_leaves_every_replay_row_and_the_floor_unchanged(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    state = ValidatorAccessState(str(state_path))

    def record(nonce: str, at: int, lifetime: int) -> bool:
        moment = T0 + timedelta(seconds=at)
        return state.check_and_record_request(
            VALIDATOR_HOTKEY, nonce, now=moment, expires_at=moment + timedelta(seconds=lifetime)
        )

    assert record("a1" * 32, 0, 30)
    assert record("b2" * 32, 40, 120)  # prunes a1: floor T0+30
    assert record("c3" * 32, 100, 120)  # high-water T0+100
    assert record("d4" * 32, 35, 10)  # a tolerated 65 s step back; expires T0+45
    state.close()
    before_rows, before_floor = _replay_rows_and_floor(state_path)
    for nonce in ("b2", "c3", "d4"):
        assert sum(nonce * 32 in line for line in before_rows) == 1
    assert before_floor == [repr((int((T0 + timedelta(seconds=30)).timestamp()),))]

    # The reset's clock is past d4's expiry and behind the high-water.
    result = reset_request_clock_high_water(str(state_path), now=T0 + timedelta(seconds=60))
    assert result.clock_high_water_after == int((T0 + timedelta(seconds=60)).timestamp())
    assert _replay_rows_and_floor(state_path) == (before_rows, before_floor)


def test_clock_refusal_logs_are_rate_limited(tmp_path: Path, caplog):
    log_now = [1_000.0]
    clock = SteppedClock(T0)
    worker = Worker(tmp_path / "access.sqlite", clock, log_clock=lambda: log_now[0])
    assert worker.accepts(worker.sign(lifetime=60))
    clock.advance(100)
    assert worker.accepts(worker.sign(lifetime=60))  # floor T0+60, high-water T0+100

    def lines(fragment: str) -> list[str]:
        return [r.getMessage() for r in caplog.records if fragment in r.getMessage()]

    with caplog.at_level(logging.WARNING, logger="cathedral.validator_access"):
        clock.step_back(60)  # T0+40: a 10 s request expires at or before the floor
        for _ in range(3):
            assert not worker.accepts(worker.sign(lifetime=10))
        clock.step_back(TOLERANCE)  # now beyond the tolerance
        for _ in range(3):
            assert not worker.accepts(worker.sign(lifetime=60))
        assert len(lines("replay floor")) == 1
        assert len(lines("behind the replay clock high-water")) == 1

        log_now[0] += REQUEST_CLOCK_LOG_INTERVAL_SECONDS - 1
        assert not worker.accepts(worker.sign(lifetime=60))
        assert len(lines("behind the replay clock high-water")) == 1

        log_now[0] += 1
        assert not worker.accepts(worker.sign(lifetime=60))
        step_lines = lines("behind the replay clock high-water")
        assert len(step_lines) == 2
        assert step_lines[0].endswith("(0 more refused since the last line)")
        assert step_lines[1].endswith("(3 more refused since the last line)")

        clock.advance(TOLERANCE)
        assert not worker.accepts(worker.sign(lifetime=10))
        floor_lines = lines("replay floor")
        assert len(floor_lines) == 2
        assert floor_lines[1].endswith("(2 more refused since the last line)")


def test_closed_state_refuses_to_authorize(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    clock = SteppedClock(T0)
    worker = Worker(state_path, clock)
    assert worker.accepts(worker.sign())
    worker.stop()
    assert worker.state.closed
    assert not worker.accepts(worker.sign())
    assert not worker.state.check_and_record_request(
        VALIDATOR_HOTKEY, "0c" * 32, now=clock(), expires_at=clock() + timedelta(seconds=60)
    )

    resetting = ValidatorAccessState(str(state_path), exclusive=True)
    resetting.close()
    with pytest.raises(ValidatorAccessError, match="exclusive state lock"):
        resetting.reset_request_clock(now=clock())


def test_lock_file_replaced_while_locking_is_refused(tmp_path: Path, monkeypatch):
    state_path = tmp_path / "access.sqlite"
    ValidatorAccessState(str(state_path)).close()
    lock_path = tmp_path / "access.sqlite.lock"
    real_flock = fcntl.flock

    def flock_then_replace(descriptor, operation):
        real_flock(descriptor, operation)
        lock_path.unlink()
        lock_path.touch(mode=0o600)

    monkeypatch.setattr(fcntl, "flock", flock_then_replace)
    with pytest.raises(ValidatorAccessError, match="replaced while locking"):
        ValidatorAccessState(str(state_path), exclusive=True)
    monkeypatch.setattr(fcntl, "flock", real_flock)
    ValidatorAccessState(str(state_path), exclusive=True).close()


def test_two_processes_migrating_older_state_at_once(tmp_path: Path, monkeypatch):
    """A second opener migrates while the first sits between check and add."""

    state_path = tmp_path / "access.sqlite"
    _write_previous_release_state(state_path, observed_at_epoch=int(T0.timestamp()))
    first_checked = threading.Event()
    second_done = threading.Event()
    guard = threading.Lock()
    pauses: list[bool] = []
    real_connect = sqlite3.connect

    class PausingConnection(sqlite3.Connection):
        def execute(self, sql, *args):
            result = super().execute(sql, *args)
            if "table_info(validator_request_clock_high_water)" not in sql:
                return result
            rows = result.fetchall()
            with guard:
                pause = not pauses
                pauses.append(True)
            if pause:
                first_checked.set()
                second_done.wait(timeout=0.5)
            return rows

    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: real_connect(*args, factory=PausingConnection, **kwargs),
    )
    errors: list[BaseException] = []
    states: list[ValidatorAccessState] = []

    def open_state(done: threading.Event | None) -> None:
        try:
            states.append(ValidatorAccessState(str(state_path)))
        except BaseException as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)
        finally:
            if done is not None:
                done.set()

    first = threading.Thread(target=open_state, args=(None,))
    first.start()
    assert first_checked.wait(timeout=5)
    second = threading.Thread(target=open_state, args=(second_done,))
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)
    monkeypatch.setattr(sqlite3, "connect", real_connect)
    assert errors == []
    assert len(states) == 2 and len(pauses) == 2
    for state in states:
        state.close()
    connection = sqlite3.connect(state_path)
    columns = [
        row[1]
        for row in connection.execute("PRAGMA table_info(validator_request_clock_high_water)")
    ]
    connection.close()
    assert columns.count("wall_clock_high_water_epoch") == 1
