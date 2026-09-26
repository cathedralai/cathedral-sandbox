"""The replay store tolerates a bounded backward clock step and has a safe reset.

Every test drives time through an injected stepped clock. Replay safety must
not depend on the clock: a nonce the worker has accepted stays refused across
any step, while fresh nonces keep working after a small step or a reset.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
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
    generated_at = T0 - timedelta(minutes=1)
    document = {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": NETWORK,
        "netuid": NETUID,
        "block": 1_000,
        "block_hash": "0x" + "b" * 64,
        "block_is_finalized": True,
        "generated_at": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (generated_at + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
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

    def __init__(self, state_path: Path, clock: SteppedClock) -> None:
        self.clock = clock
        self.state = ValidatorAccessState(str(state_path))
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


def test_reset_command_lowers_the_high_water_to_the_wall_clock(tmp_path: Path, capsys):
    state_path = tmp_path / "access.sqlite"
    ahead = datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1_000)
    state = ValidatorAccessState(str(state_path))
    assert state.check_and_record_request(
        VALIDATOR_HOTKEY, "0a" * 32, now=ahead, expires_at=ahead + timedelta(seconds=60)
    )
    state.close()

    assert (
        cathedral_main(
            ["worker", "reset-replay-clock", "--validator-access-state", str(state_path)]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["clock_high_water_before"] == ahead.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 990 <= output["backward_step_seconds"] <= 1_000
    assert output["retained_replay_records"] == 1
    assert output["replay_floor"] == "1970-01-01T00:00:00Z"


def test_state_from_an_older_release_keeps_its_ratchet_as_the_floor(tmp_path: Path):
    state_path = tmp_path / "access.sqlite"
    high_water = int((T0 + timedelta(seconds=100)).timestamp())
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
        "INSERT INTO validator_request_clock_high_water VALUES (1, ?)", (high_water,)
    )
    connection.commit()
    connection.close()
    state_path.chmod(0o600)

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
