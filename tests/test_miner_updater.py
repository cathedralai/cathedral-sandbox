"""Miner updater state machine checks.

Every host effect is faked, so the crash and rollback paths are exercised
without a confidential guest. These are local synthetic checks. They prove the
state machine, not that any real miner updated.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.miner_release import (
    CANONICAL_IMAGE_REPOSITORY,
    MINER_RELEASE_SCHEMA,
    SN39_SNP_MINER_PRODUCT,
)
from cathedral.miner_updater import (
    IMAGE_VARIABLE,
    STAGE_MAY_HAVE_RUN,
    STAGE_PREPARED,
    UPDATE_STATE_SCHEMA,
    MinerUpdateError,
    MinerUpdateHalted,
    MinerUpdaterHost,
    describe_status,
    read_env_assignments,
    rewrite_pin,
    update_once,
)
from cathedral.policy_registry import canonical_signed_bytes

KEY_ID = "sn39-miner-release-1"
OLD_DIGEST = "1" * 64
NEW_DIGEST = "2" * 64
OLD_IMAGE = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{OLD_DIGEST}"
NEW_IMAGE = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{NEW_DIGEST}"

# A realistic pin file: the image assignment sits among operator settings that
# must survive every rewrite untouched.
ENV_BODY = f"""# Cathedral SN39 SNP miner
{IMAGE_VARIABLE}={OLD_IMAGE}
CATHEDRAL_MINER_HOTKEY=5ERBwsMBUrvjCVcXu1B73m7Ne693DwKEi68q2ionAkWtdALT
CATHEDRAL_PUBLIC_ENDPOINT=https://167.150.153.139:8081
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=sha256:{'3' * 64}
"""


@pytest.fixture()
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture()
def trusted(key: Ed25519PrivateKey) -> dict[str, bytes]:
    return {
        KEY_ID: key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    }


def signed_release(key: Ed25519PrivateKey, *, sequence: int = 5, image: str = NEW_IMAGE) -> bytes:
    body = {
        "schema": MINER_RELEASE_SCHEMA,
        "product": SN39_SNP_MINER_PRODUCT,
        "channel": "stable",
        "sequence": sequence,
        "issued_unix": 1_000_000,
        "expires_unix": 2_000_000,
        "release": {
            "version": "2026.09.09",
            "image": image,
            "runtime_contract": "snp-signed-validator-fleet-v1",
            "launcher_sha256": "4" * 64,
            "promoted_canary": {"sequence": sequence + 1, "signed_sha256": "5" * 64},
        },
        "signing_key_id": KEY_ID,
    }
    signature = key.sign(canonical_signed_bytes(body))
    body["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(body, sort_keys=True).encode("utf-8")


class Recorder:
    """A fake host whose behaviour each test tunes."""

    def __init__(self, tmp: Path, metadata: bytes, trusted: dict[str, bytes]) -> None:
        self.env_path = tmp / "sn39-snp-miner.env"
        self.env_path.write_text(ENV_BODY, encoding="utf-8")
        self.state_path = tmp / "state" / "state.json"
        self.pause_path = tmp / "paused"
        self.lock_path = tmp / "state" / "updater.lock"
        self.metadata = metadata
        self.trusted = trusted
        self.restarts = 0
        self.prepared: list[str] = []
        self.healthy = True
        self.safe = True
        self.restart_raises = False

    def host(self) -> MinerUpdaterHost:
        def restart() -> None:
            self.restarts += 1
            if self.restart_raises:
                raise RuntimeError("systemctl failed")

        return MinerUpdaterHost(
            fetch_metadata=lambda: self.metadata,
            restart_service=restart,
            is_healthy=lambda: self.healthy,
            prepare_image=lambda release: self.prepared.append(release.image),
            safe_to_activate=lambda: self.safe,
            env_path=self.env_path,
            state_path=self.state_path,
            pause_path=self.pause_path,
            lock_path=self.lock_path,
            trusted_keys=self.trusted,
            now_unix=lambda: 1_500_000,
        )

    def pinned(self) -> str | None:
        return read_env_assignments(self.env_path).get(IMAGE_VARIABLE)


# --- the happy path ----------------------------------------------------


def test_a_valid_signed_upgrade_activates(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    outcome = update_once(recorder.host(), channel="stable")
    assert outcome.action == "activated"
    assert recorder.pinned() == NEW_IMAGE
    assert recorder.restarts == 1
    assert recorder.prepared == [NEW_IMAGE]


def test_the_update_preserves_identity_and_operator_settings(tmp_path, key, trusted):
    """The pin file carries the miner hotkey and endpoint. Losing them would
    change the miner's identity, so the rewrite must touch one line only."""

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    before = read_env_assignments(recorder.env_path)
    update_once(recorder.host(), channel="stable")
    after = read_env_assignments(recorder.env_path)
    assert after[IMAGE_VARIABLE] == NEW_IMAGE
    for name, value in before.items():
        if name != IMAGE_VARIABLE:
            assert after[name] == value
    assert "# Cathedral SN39 SNP miner" in recorder.env_path.read_text()


def test_running_the_same_release_twice_is_a_no_op(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    update_once(recorder.host(), channel="stable")
    outcome = update_once(recorder.host(), channel="stable")
    assert outcome.action == "current"
    assert recorder.restarts == 1


# --- refusals ----------------------------------------------------------


def test_a_bad_signature_changes_nothing(tmp_path, key, trusted):
    raw = bytearray(signed_release(key))
    document = json.loads(bytes(raw))
    document["release"]["version"] = "9999.99.99"
    recorder = Recorder(tmp_path, json.dumps(document).encode("utf-8"), trusted)
    with pytest.raises(MinerUpdateError, match="refused"):
        update_once(recorder.host(), channel="stable")
    assert recorder.pinned() == OLD_IMAGE
    assert recorder.restarts == 0


def test_a_stale_sequence_is_refused(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key, sequence=9), trusted)
    update_once(recorder.host(), channel="stable")
    # An older record arriving afterwards must not move the miner backwards.
    recorder.metadata = signed_release(key, sequence=8, image=OLD_IMAGE)
    with pytest.raises(MinerUpdateError, match="rolls back"):
        update_once(recorder.host(), channel="stable")
    assert recorder.pinned() == NEW_IMAGE


def test_equivocation_at_the_same_sequence_is_refused(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key, sequence=9), trusted)
    update_once(recorder.host(), channel="stable")
    other = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{'6' * 64}"
    recorder.metadata = signed_release(key, sequence=9, image=other)
    with pytest.raises(MinerUpdateError, match="equivocates"):
        update_once(recorder.host(), channel="stable")
    assert recorder.pinned() == NEW_IMAGE


def test_an_expired_record_is_refused(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    host = recorder.host()
    host.now_unix = lambda: 3_000_000
    with pytest.raises(MinerUpdateError, match="expired"):
        update_once(host, channel="stable")
    assert recorder.pinned() == OLD_IMAGE


def test_a_record_for_another_channel_is_refused(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    with pytest.raises(MinerUpdateError, match="different channel"):
        update_once(recorder.host(), channel="canary")
    assert recorder.pinned() == OLD_IMAGE


# --- gates -------------------------------------------------------------


def test_the_operator_pause_file_stops_everything(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.pause_path.write_text("paused by operator\n")
    outcome = update_once(recorder.host(), channel="stable")
    assert outcome.action == "paused"
    assert recorder.pinned() == OLD_IMAGE
    assert recorder.restarts == 0


def test_an_unsafe_moment_defers_instead_of_restarting(tmp_path, key, trusted):
    """The seam that will hold an in-flight customer command."""

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.safe = False
    outcome = update_once(recorder.host(), channel="stable")
    assert outcome.action == "deferred"
    assert recorder.pinned() == OLD_IMAGE
    assert recorder.restarts == 0
    # Deferring must not consume the release: it applies once safe.
    recorder.safe = True
    assert update_once(recorder.host(), channel="stable").action == "activated"


# --- failure and rollback ----------------------------------------------


def test_a_failed_pull_changes_nothing(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    host = recorder.host()
    def boom(release) -> None:
        raise RuntimeError("registry unreachable")
    host.prepare_image = boom
    with pytest.raises(MinerUpdateError, match="could not be prepared"):
        update_once(host, channel="stable")
    assert recorder.pinned() == OLD_IMAGE
    assert recorder.restarts == 0


def test_an_unhealthy_new_image_is_rolled_back(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.healthy = False
    with pytest.raises(MinerUpdateError, match="did not become healthy"):
        update_once(recorder.host(), channel="stable")
    assert recorder.pinned() == OLD_IMAGE
    # One restart onto the new image, one back onto the old one.
    assert recorder.restarts == 2


def test_a_failed_restart_restores_the_previous_image(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.restart_raises = True
    with pytest.raises(MinerUpdateError, match="restart failed"):
        update_once(recorder.host(), channel="stable")
    assert recorder.pinned() == OLD_IMAGE


# --- crash recovery ----------------------------------------------------


def _record_for(metadata: bytes, trusted: dict[str, bytes]) -> dict:
    """The channel record a real activation would have committed.

    Deriving it from the same signed bytes matters: a committed record whose
    digest disagreed with the record it came from would look like equivocation
    on the very next check.
    """

    from cathedral.miner_release import parse_miner_release

    release = parse_miner_release(metadata, trusted_keys=trusted)
    return {
        "sequence": release.sequence,
        "signed_sha256": release.signed_sha256,
        "image": release.image,
        "version": release.version,
        "runtime_contract": release.runtime_contract,
    }


def write_state(recorder: Recorder, state: dict) -> None:
    recorder.state_path.parent.mkdir(parents=True, exist_ok=True)
    recorder.state_path.write_text(json.dumps(state), encoding="utf-8")


def test_a_prepared_stage_is_cleared_and_retried(tmp_path, key, trusted):
    """prepared means the pin was never swapped, so nothing new can have run."""

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    write_state(
        recorder,
        {"schema": UPDATE_STATE_SCHEMA, "channels": {}, "stage": STAGE_PREPARED},
    )
    assert update_once(recorder.host(), channel="stable").action == "activated"


def test_an_interrupted_swap_that_never_landed_is_safe_to_retry(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    write_state(
        recorder,
        {
            "schema": UPDATE_STATE_SCHEMA,
            "channels": {},
            "stage": STAGE_MAY_HAVE_RUN,
            "pending": {
                "channel": "stable",
                "image": NEW_IMAGE,
                "previous_image": OLD_IMAGE,
            },
        },
    )
    # The pin still names the old image, so the swap never landed.
    assert update_once(recorder.host(), channel="stable").action == "activated"


def test_an_interrupted_activation_that_is_healthy_commits(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(recorder.env_path, NEW_IMAGE)
    write_state(
        recorder,
        {
            "schema": UPDATE_STATE_SCHEMA,
            "channels": {},
            "stage": STAGE_MAY_HAVE_RUN,
            "pending": {
                "channel": "stable",
                "image": NEW_IMAGE,
                "previous_image": OLD_IMAGE,
                "committed_record": _record_for(recorder.metadata, trusted),
            },
        },
    )
    outcome = update_once(recorder.host(), channel="stable")
    assert outcome.action == "current"
    assert recorder.restarts == 0


def test_an_interrupted_activation_that_is_unhealthy_halts(tmp_path, key, trusted):
    """The case that must never auto-roll-back.

    The new image may already have started and touched durable state, so
    reverting could discard work. The updater stops and asks for a human.
    """

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(recorder.env_path, NEW_IMAGE)
    recorder.healthy = False
    write_state(
        recorder,
        {
            "schema": UPDATE_STATE_SCHEMA,
            "channels": {},
            "stage": STAGE_MAY_HAVE_RUN,
            "pending": {
                "channel": "stable",
                "image": NEW_IMAGE,
                "previous_image": OLD_IMAGE,
            },
        },
    )
    with pytest.raises(MinerUpdateHalted, match="resolve it explicitly"):
        update_once(recorder.host(), channel="stable")
    assert recorder.pinned() == NEW_IMAGE
    assert recorder.restarts == 0


def test_an_unrecognisable_pin_during_recovery_halts(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(recorder.env_path, f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{'8' * 64}")
    write_state(
        recorder,
        {
            "schema": UPDATE_STATE_SCHEMA,
            "channels": {},
            "stage": STAGE_MAY_HAVE_RUN,
            "pending": {
                "channel": "stable",
                "image": NEW_IMAGE,
                "previous_image": OLD_IMAGE,
            },
        },
    )
    with pytest.raises(MinerUpdateHalted, match="matches neither"):
        update_once(recorder.host(), channel="stable")


# --- pin file handling -------------------------------------------------


def test_rewrite_collapses_a_duplicate_pin(tmp_path):
    path = tmp_path / "env"
    path.write_text(f"{IMAGE_VARIABLE}={OLD_IMAGE}\nX=1\n{IMAGE_VARIABLE}={NEW_IMAGE}\n")
    rewrite_pin(path, NEW_IMAGE)
    body = path.read_text()
    assert body.count(IMAGE_VARIABLE) == 1
    assert read_env_assignments(path)[IMAGE_VARIABLE] == NEW_IMAGE
    assert read_env_assignments(path)["X"] == "1"


def test_rewrite_appends_when_the_pin_is_absent(tmp_path):
    path = tmp_path / "env"
    path.write_text("X=1\n")
    rewrite_pin(path, NEW_IMAGE)
    assert read_env_assignments(path)[IMAGE_VARIABLE] == NEW_IMAGE


def test_a_missing_pin_file_is_a_clear_error(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.env_path.unlink()
    with pytest.raises(MinerUpdateError, match="pin file is missing"):
        update_once(recorder.host(), channel="stable")


def test_status_reports_version_without_secrets(tmp_path, key, trusted):
    recorder = Recorder(tmp_path, signed_release(key), trusted)
    update_once(recorder.host(), channel="stable")
    status = describe_status(recorder.host())
    assert status["pinned_image"] == NEW_IMAGE
    assert status["paused"] is False
    assert status["stage"] is None
    assert status["channels"]["stable"]["version"] == "2026.09.09"
    rendered = json.dumps(status)
    assert "5ERBws" not in rendered
    assert "ACCESS_KEYS_DIGEST" not in rendered


# --- concurrency -------------------------------------------------------


def test_a_second_concurrent_check_is_refused(tmp_path, key, trusted):
    """The timer and a manual run can overlap.

    Two processes rewriting the pin and restarting the unit is the interleaving
    that leaves a miner running neither version cleanly, so the second one is
    refused rather than queued.
    """

    import fcntl
    import os

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.lock_path.parent.mkdir(parents=True, exist_ok=True)
    held = os.open(recorder.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(MinerUpdateError, match="already running"):
            update_once(recorder.host(), channel="stable")
        assert recorder.pinned() == OLD_IMAGE
        assert recorder.restarts == 0
    finally:
        os.close(held)
    # Once the other run finishes, the update proceeds normally.
    assert update_once(recorder.host(), channel="stable").action == "activated"


def test_a_paused_miner_does_not_contend_for_the_lock(tmp_path, key, trusted):
    import fcntl
    import os

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    recorder.pause_path.write_text("x")
    recorder.lock_path.parent.mkdir(parents=True, exist_ok=True)
    held = os.open(recorder.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert update_once(recorder.host(), channel="stable").action == "paused"
    finally:
        os.close(held)


def test_the_pulled_image_carries_the_release_runtime_contract(tmp_path, key, trusted):
    """prepare_image receives the whole release so it can check the label.

    The launcher refuses a wrong runtime-contract label at startup. Catching it
    here turns a failed restart plus rollback into a refusal that never touches
    the running miner.
    """

    recorder = Recorder(tmp_path, signed_release(key), trusted)
    seen: list[str] = []
    host = recorder.host()
    host.prepare_image = lambda release: seen.append(release.runtime_contract)
    update_once(host, channel="stable")
    assert seen == ["snp-signed-validator-fleet-v1"]
