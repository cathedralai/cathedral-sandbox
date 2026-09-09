"""Miner updater state machine checks.

Every host effect is faked, so the crash, rollback and halt paths are exercised
without a confidential guest. These are local synthetic checks: they prove the
state machine, not that any real miner updated.

The central property under test is that the updater never infers *execution
history* from the pin file. A restored pin does not prove the released image
never ran, and a swapped pin does not prove it did.
"""

from __future__ import annotations

import base64
import fcntl
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.miner_release import (
    CANONICAL_IMAGE_REPOSITORY,
    MINER_RELEASE_SCHEMA,
    SN39_SNP_MINER_PRODUCT,
    parse_miner_release,
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
    read_state,
    rewrite_pin,
    update_once,
)
from cathedral.policy_registry import canonical_signed_bytes

KEY_ID = "sn39-miner-release-1"
OLD_IMAGE = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{'1' * 64}"
NEW_IMAGE = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{'2' * 64}"
OTHER_IMAGE = f"{CANONICAL_IMAGE_REPOSITORY}@sha256:{'6' * 64}"
CONTRACT = "snp-signed-validator-fleet-v1"

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


def signed_release(
    key: Ed25519PrivateKey,
    *,
    sequence: int = 5,
    image: str = NEW_IMAGE,
    contract: str = CONTRACT,
) -> bytes:
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
            "runtime_contract": contract,
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
    """A fake host whose behaviour each test tunes.

    `running` models what the miner container actually reports, which is the
    only notion of health the updater accepts. `durable` models the
    bind-mounted state a started image could have written to.
    """

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
        self.launcher_checked: list[str] = []
        self.durable = "digest-before"
        self.safe = True
        self.restart_raises = False
        self.launcher_raises = False
        # What comes back on restart. Default: whatever the pin now names.
        self.running: str | None = OLD_IMAGE
        self.running_follows_pin = True

    def _restart(self) -> None:
        self.restarts += 1
        if self.restart_raises:
            raise RuntimeError("systemctl failed")
        if self.running_follows_pin:
            self.running = self.pinned()

    def _verify_launcher(self, release) -> None:
        self.launcher_checked.append(release.runtime_contract)
        if self.launcher_raises:
            raise MinerUpdateError("installed launcher does not match")

    def host(self) -> MinerUpdaterHost:
        return MinerUpdaterHost(
            fetch_metadata=lambda: self.metadata,
            restart_service=self._restart,
            running_image=lambda: self.running,
            durable_digest=lambda: self.durable,
            prepare_image=lambda release: self.prepared.append(release.image),
            verify_launcher=self._verify_launcher,
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

    def state(self) -> dict:
        return read_state(self.state_path)


def write_state_file(recorder: Recorder, state: dict) -> None:
    recorder.state_path.parent.mkdir(parents=True, exist_ok=True)
    recorder.state_path.write_text(json.dumps(state), encoding="utf-8")


def record_for(metadata: bytes, trusted: dict[str, bytes]) -> dict:
    release = parse_miner_release(metadata, trusted_keys=trusted)
    return {
        "sequence": release.sequence,
        "signed_sha256": release.signed_sha256,
        "image": release.image,
        "version": release.version,
        "runtime_contract": release.runtime_contract,
    }


# --- the happy path ----------------------------------------------------


def test_a_valid_signed_upgrade_activates(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    outcome = update_once(r.host(), channel="stable")
    assert outcome.action == "activated"
    assert r.pinned() == NEW_IMAGE
    assert r.running == NEW_IMAGE
    assert r.prepared == [NEW_IMAGE]
    assert r.launcher_checked == [CONTRACT]
    assert r.state()["stage"] is None


def test_the_update_preserves_identity_and_operator_settings(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    before = read_env_assignments(r.env_path)
    update_once(r.host(), channel="stable")
    after = read_env_assignments(r.env_path)
    assert after[IMAGE_VARIABLE] == NEW_IMAGE
    for name, value in before.items():
        if name != IMAGE_VARIABLE:
            assert after[name] == value
    assert "# Cathedral SN39 SNP miner" in r.env_path.read_text()


def test_running_the_same_release_twice_is_a_no_op(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    update_once(r.host(), channel="stable")
    assert update_once(r.host(), channel="stable").action == "current"
    assert r.restarts == 1


# --- refusals ----------------------------------------------------------


def test_a_bad_signature_changes_nothing(tmp_path, key, trusted):
    document = json.loads(signed_release(key))
    document["release"]["version"] = "9999.99.99"
    r = Recorder(tmp_path, json.dumps(document).encode(), trusted)
    with pytest.raises(MinerUpdateError, match="refused"):
        update_once(r.host(), channel="stable")
    assert r.pinned() == OLD_IMAGE
    assert r.restarts == 0


def test_a_stale_sequence_is_refused(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key, sequence=9), trusted)
    update_once(r.host(), channel="stable")
    r.metadata = signed_release(key, sequence=8, image=OLD_IMAGE)
    with pytest.raises(MinerUpdateError, match="rolls back"):
        update_once(r.host(), channel="stable")
    assert r.pinned() == NEW_IMAGE


def test_equivocation_at_the_same_sequence_is_refused(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key, sequence=9), trusted)
    update_once(r.host(), channel="stable")
    r.metadata = signed_release(key, sequence=9, image=OTHER_IMAGE)
    with pytest.raises(MinerUpdateError, match="equivocates"):
        update_once(r.host(), channel="stable")
    assert r.pinned() == NEW_IMAGE


def test_a_failed_attempt_still_burns_its_sequence(tmp_path, key, trusted):
    """Finding 4. A failed activation must consume its sequence.

    Otherwise release B can reuse sequence 5 with a different image after
    release A failed at sequence 5, which defeats equivocation detection
    exactly when an attacker would want it to.
    """

    r = Recorder(tmp_path, signed_release(key, sequence=5, image=NEW_IMAGE), trusted)
    r.running_follows_pin = False  # the release never comes up
    with pytest.raises(MinerUpdateError):
        update_once(r.host(), channel="stable")
    assert r.state()["floors"]["stable"]["sequence"] == 5

    r.metadata = signed_release(key, sequence=5, image=OTHER_IMAGE)
    r.running_follows_pin = True
    with pytest.raises(MinerUpdateError, match="equivocates"):
        update_once(r.host(), channel="stable")


def test_a_failed_preparation_still_burns_its_sequence(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key, sequence=5), trusted)
    host = r.host()
    host.prepare_image = lambda release: (_ for _ in ()).throw(RuntimeError("registry down"))
    with pytest.raises(MinerUpdateError, match="could not be prepared"):
        update_once(host, channel="stable")
    assert r.state()["floors"]["stable"]["sequence"] == 5
    assert r.pinned() == OLD_IMAGE


def test_an_expired_record_is_refused(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    host = r.host()
    host.now_unix = lambda: 3_000_000
    with pytest.raises(MinerUpdateError, match="expired"):
        update_once(host, channel="stable")
    assert r.pinned() == OLD_IMAGE


def test_a_record_for_another_channel_is_refused(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    with pytest.raises(MinerUpdateError, match="different channel"):
        update_once(r.host(), channel="canary")
    assert r.pinned() == OLD_IMAGE


def test_an_incompatible_launcher_is_refused_before_the_swap(tmp_path, key, trusted):
    """Finding 5. Asked while the previous image is still serving."""

    r = Recorder(tmp_path, signed_release(key), trusted)
    r.launcher_raises = True
    with pytest.raises(MinerUpdateError, match="launcher"):
        update_once(r.host(), channel="stable")
    assert r.pinned() == OLD_IMAGE
    assert r.restarts == 0
    assert r.prepared == []


# --- pin file shapes ---------------------------------------------------


def test_a_systemd_style_spaced_assignment_is_recognised(tmp_path, key, trusted):
    """Finding 6. systemd accepts `NAME = value`.

    Failing to recognise it made previous_image null, which silently disabled
    rollback while still reporting restoration.
    """

    r = Recorder(tmp_path, signed_release(key), trusted)
    r.env_path.write_text(f"{IMAGE_VARIABLE} = {OLD_IMAGE}\nX=1\n", encoding="utf-8")
    assert read_env_assignments(r.env_path)[IMAGE_VARIABLE] == OLD_IMAGE
    assert update_once(r.host(), channel="stable").action == "activated"
    assert r.pinned() == NEW_IMAGE
    assert read_env_assignments(r.env_path)["X"] == "1"


def test_an_absent_pin_refuses_to_update(tmp_path, key, trusted):
    """Finding 6. Without a previous image there is nothing to roll back to."""

    r = Recorder(tmp_path, signed_release(key), trusted)
    r.env_path.write_text("X=1\n", encoding="utf-8")
    with pytest.raises(MinerUpdateError, match="names no current image"):
        update_once(r.host(), channel="stable")
    assert r.restarts == 0
    assert read_env_assignments(r.env_path).get(IMAGE_VARIABLE) is None


def test_a_missing_pin_file_is_a_clear_error(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    r.env_path.unlink()
    with pytest.raises(MinerUpdateError, match="pin file is missing"):
        update_once(r.host(), channel="stable")


# --- gates -------------------------------------------------------------


def test_the_operator_pause_file_stops_everything(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    r.pause_path.write_text("paused\n")
    assert update_once(r.host(), channel="stable").action == "paused"
    assert r.pinned() == OLD_IMAGE
    assert r.restarts == 0


def test_an_unsafe_moment_defers_instead_of_restarting(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    r.safe = False
    assert update_once(r.host(), channel="stable").action == "deferred"
    assert r.pinned() == OLD_IMAGE
    assert r.restarts == 0
    r.safe = True
    assert update_once(r.host(), channel="stable").action == "activated"


# --- rollback, and its limits ------------------------------------------


def test_a_release_that_wrote_nothing_is_rolled_back(tmp_path, key, trusted):
    """The only case where reverting is safe: positive evidence of no write."""

    r = Recorder(tmp_path, signed_release(key), trusted)
    r.running_follows_pin = False  # never comes up, and durable is untouched
    with pytest.raises(MinerUpdateError, match="previous image was restored"):
        update_once(r.host(), channel="stable")
    assert r.pinned() == OLD_IMAGE
    assert r.state()["stage"] is None


def test_a_release_that_may_have_written_is_never_rolled_back(tmp_path, key, trusted):
    """Finding 1, the blocker.

    A container can start, write the bind-mounted validator-access database,
    then exit. Not-running is not evidence it never ran. Starting the previous
    image against changed state is corruption, not a rollback.
    """

    r = Recorder(tmp_path, signed_release(key), trusted)

    def restart_then_write() -> None:
        r.restarts += 1
        r.durable = "digest-after"  # the released image wrote before dying
        r.running = None

    host = r.host()
    host.restart_service = restart_then_write
    with pytest.raises(MinerUpdateHalted, match="durable state changed"):
        update_once(host, channel="stable")
    # The pin is deliberately left naming the release, and the latch is set.
    assert r.pinned() == NEW_IMAGE
    assert r.state()["stage"] == STAGE_MAY_HAVE_RUN


def test_a_rollback_whose_restart_fails_halts_rather_than_claiming_success(
    tmp_path, key, trusted
):
    """Finding 3. The concrete trigger is systemd start rate limiting.

    The miner unit allows five starts per 300 seconds. A repeatedly failing
    release exhausts that, after which the rollback start is refused too. The
    old code still reported the previous image restored.
    """

    r = Recorder(tmp_path, signed_release(key), trusted)
    calls = {"n": 0}

    def restart() -> None:
        calls["n"] += 1
        r.restarts += 1
        if calls["n"] == 1:
            r.running = None  # release fails to come up
        else:
            raise RuntimeError("Start request repeated too quickly")

    host = r.host()
    host.restart_service = restart
    with pytest.raises(MinerUpdateHalted, match="may be running nothing"):
        update_once(host, channel="stable")
    assert r.state()["stage"] == STAGE_MAY_HAVE_RUN


def test_a_rollback_that_does_not_bring_the_old_image_back_halts(tmp_path, key, trusted):
    """Finding 3. Restoring the pin is not the same as restoring the miner."""

    r = Recorder(tmp_path, signed_release(key), trusted)
    r.running_follows_pin = False
    r.running = None  # nothing ever comes back
    with pytest.raises(MinerUpdateHalted, match="did not come back"):
        update_once(r.host(), channel="stable")
    assert r.state()["stage"] == STAGE_MAY_HAVE_RUN


# --- crash recovery ----------------------------------------------------


def may_have_run_state(*, image=NEW_IMAGE, previous=OLD_IMAGE, digest="digest-before", record=None):
    pending = {
        "channel": "stable",
        "image": image,
        "previous_image": previous,
        "durable_digest_before": digest,
    }
    if record is not None:
        pending["committed_record"] = record
    return {
        "schema": UPDATE_STATE_SCHEMA,
        "floors": {},
        "channels": {},
        "stage": STAGE_MAY_HAVE_RUN,
        "pending": pending,
    }


def test_a_prepared_stage_is_cleared_and_retried(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    write_state_file(
        r,
        {"schema": UPDATE_STATE_SCHEMA, "floors": {}, "channels": {},
         "stage": STAGE_PREPARED, "pending": None},
    )
    assert update_once(r.host(), channel="stable").action == "activated"


def test_an_interrupted_activation_that_is_running_commits(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(r.env_path, NEW_IMAGE)
    r.running = NEW_IMAGE
    write_state_file(r, may_have_run_state(record=record_for(r.metadata, trusted)))
    assert update_once(r.host(), channel="stable").action == "current"
    assert r.restarts == 0


def test_a_swapped_pin_with_the_old_image_running_does_not_commit(tmp_path, key, trusted):
    """Finding 2, and crash points C09 to C11.

    SIGKILL between rewriting the pin and issuing the restart leaves the new
    pin on disk with the *previous* container still serving. The old code
    checked only that the unit was active, committed the release, and then
    reported "current" for ever, so the upgrade never actually happened.
    """

    r = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(r.env_path, NEW_IMAGE)
    r.running = OLD_IMAGE  # the previous container, still up
    write_state_file(r, may_have_run_state())
    outcome = update_once(r.host(), channel="stable")
    # Recovery restores the pin, then the same run performs the real upgrade.
    assert outcome.action == "activated"
    assert r.pinned() == NEW_IMAGE
    assert r.running == NEW_IMAGE
    assert r.state()["channels"]["stable"]["image"] == NEW_IMAGE


def test_an_interrupted_activation_with_changed_state_halts(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(r.env_path, NEW_IMAGE)
    r.running = OLD_IMAGE
    r.durable = "digest-after"
    write_state_file(r, may_have_run_state())
    with pytest.raises(MinerUpdateHalted, match="cannot be resolved automatically"):
        update_once(r.host(), channel="stable")


def test_an_interrupted_activation_with_nothing_running_halts(tmp_path, key, trusted):
    """C12 and C16: neither version is serving. Never guess."""

    r = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(r.env_path, NEW_IMAGE)
    r.running = None
    write_state_file(r, may_have_run_state())
    with pytest.raises(MinerUpdateHalted, match="cannot be resolved automatically"):
        update_once(r.host(), channel="stable")


def test_a_restored_pin_alone_never_proves_the_release_did_not_run(tmp_path, key, trusted):
    """C16 to C18. A rollback can restore the pin and then fail to restart.

    The old code cleared the pending record purely because the pin looked old.
    Here the pin is old, but the released image is what is running.
    """

    r = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(r.env_path, OLD_IMAGE)
    r.running = NEW_IMAGE  # the release is what actually came up
    write_state_file(r, may_have_run_state(record=record_for(r.metadata, trusted)))
    outcome = update_once(r.host(), channel="stable")
    assert outcome.action == "activated"
    assert r.state()["channels"]["stable"]["image"] == NEW_IMAGE


def test_an_interrupted_activation_without_a_pending_record_halts(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    write_state_file(
        r,
        {"schema": UPDATE_STATE_SCHEMA, "floors": {}, "channels": {},
         "stage": STAGE_MAY_HAVE_RUN, "pending": None},
    )
    with pytest.raises(MinerUpdateHalted, match="not which release"):
        update_once(r.host(), channel="stable")


def test_a_missing_durable_fingerprint_is_treated_as_changed(tmp_path, key, trusted):
    """An unknown answer must never license a rollback."""

    r = Recorder(tmp_path, signed_release(key), trusted)
    rewrite_pin(r.env_path, NEW_IMAGE)
    r.running = OLD_IMAGE
    write_state_file(r, may_have_run_state(digest=""))
    with pytest.raises(MinerUpdateHalted):
        update_once(r.host(), channel="stable")


# --- concurrency -------------------------------------------------------


def test_a_second_concurrent_check_is_refused(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    r.lock_path.parent.mkdir(parents=True, exist_ok=True)
    held = os.open(r.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(MinerUpdateError, match="already running"):
            update_once(r.host(), channel="stable")
        assert r.pinned() == OLD_IMAGE
        assert r.restarts == 0
    finally:
        os.close(held)
    assert update_once(r.host(), channel="stable").action == "activated"


def test_a_paused_miner_does_not_contend_for_the_lock(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    r.pause_path.write_text("x")
    r.lock_path.parent.mkdir(parents=True, exist_ok=True)
    held = os.open(r.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert update_once(r.host(), channel="stable").action == "paused"
    finally:
        os.close(held)


# --- status ------------------------------------------------------------


def test_status_reports_version_without_secrets(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    update_once(r.host(), channel="stable")
    status = describe_status(r.host())
    assert status["pinned_image"] == NEW_IMAGE
    assert status["paused"] is False
    assert status["stage"] is None
    assert status["needs_operator"] is False
    assert status["channels"]["stable"]["version"] == "2026.09.09"
    rendered = json.dumps(status)
    assert "5ERBws" not in rendered
    assert "ACCESS_KEYS_DIGEST" not in rendered


def test_status_flags_a_host_that_needs_an_operator(tmp_path, key, trusted):
    r = Recorder(tmp_path, signed_release(key), trusted)
    write_state_file(r, may_have_run_state())
    status = describe_status(r.host())
    assert status["needs_operator"] is True
    assert status["stage"] == STAGE_MAY_HAVE_RUN
