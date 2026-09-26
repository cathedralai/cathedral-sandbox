"""Control-host refresh, worker fetch, and the expiry alarm.

Every chain read is stubbed and no test opens a network socket. Netuids are
drawn at random on each run: both commands must carry whatever subnet the
deployment names and nothing else.
"""

from __future__ import annotations

import errno
import importlib.util
import io
import json
import os
import random
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from cathedral.admission_policy import load_policy_keys
from cathedral.policy_registry import canonical_json
from cathedral.validator_access import (
    MAX_SNAPSHOT_BYTES,
    SignedValidatorSnapshotProvider,
    ValidatorAccessState,
    canonical_utc,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPO_ROOT / "scripts" / "cathedral_validator_access.py"
_SPEC = importlib.util.spec_from_file_location("cathedral_validator_access_refresh", TOOL_PATH)
access_tool = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(access_tool)

_RANDOM = random.SystemRandom()
NETUID = _RANDOM.randrange(1, 65_536)
OTHER_NETUID = (NETUID + _RANDOM.randrange(1, 65_536)) % 65_536
# No default network either: any valid chain name must be carried through.
NETWORK = "net-" + secrets.token_hex(4)
OTHER_NETWORK = NETWORK + "-other"
NOW = datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC)
KEY_ID = "cathedral-validator-access-1"
VALIDATOR_HOTKEY = "5Et6X7z87xENCREUnrQXfGahRraA3eo4KkAZEZP9KagmnTjD"
OTHER_HOTKEY = "5G4hdCSm7mQvP9z19pK3Bwzzvpf1NBBx3jioJBdJgEj4r8Pe"
BLOCK = 5_000_000
BLOCK_HASH = "0x" + "b" * 64
OLDER_HASH = "0x" + "a" * 64
SOURCE_URL = "https://control.example/validator-access.json"
UPDATE_FAILED = access_tool.EXIT_UPDATE_FAILED
ALARM = access_tool.EXIT_EXPIRY_ALARM
BACKDATE = timedelta(seconds=access_tool.GENERATED_AT_BACKDATE_SECONDS)


@dataclass(frozen=True)
class Deployment:
    signer: Path
    seed: Path
    seed_bytes: bytes
    control_keys: Path
    publish: Path
    published: Path
    worker: Path
    worker_keys: Path
    live: Path
    keys_digest: str


def _fields(text: str) -> dict[str, str]:
    return dict(line.split(" ", 1) for line in text.splitlines() if " " in line)


def _neuron(hotkey: str, uid: int, stake_rao: int = 2_000):
    return SimpleNamespace(
        hotkey=hotkey,
        uid=uid,
        validator_permit=True,
        total_stake=SimpleNamespace(rao=stake_rao),
    )


def _signed(
    seed: bytes,
    *,
    generated_at: datetime,
    valid_seconds: int = 900,
    block: int = BLOCK - 10,
    block_hash: str = OLDER_HASH,
    network: str = NETWORK,
    netuid: int = NETUID,
    minimum_stake_rao: int = 0,
    key_id: str = KEY_ID,
    hotkeys: tuple[str, ...] = (VALIDATOR_HOTKEY,),
) -> bytes:
    unsigned = access_tool.build_snapshot_document(
        [_neuron(hotkey, index) for index, hotkey in enumerate(hotkeys)],
        network=network,
        netuid=netuid,
        block=block,
        block_hash=block_hash,
        minimum_stake_rao=minimum_stake_rao,
        signing_key_id=key_id,
        generated_at=generated_at,
        valid_seconds=valid_seconds,
    )
    return canonical_json(access_tool.sign_validator_access_snapshot(unsigned, seed))


def _chain(
    monkeypatch,
    *,
    block: int = BLOCK,
    block_hash: str = BLOCK_HASH,
    hotkeys: tuple[str, ...] = (VALIDATOR_HOTKEY,),
) -> None:
    rows = [_neuron(hotkey, index) for index, hotkey in enumerate(hotkeys)]
    monkeypatch.setattr(
        access_tool, "_finalized_neurons", lambda network, netuid: (block, block_hash, rows)
    )


def _refresh_argv(
    d: Deployment, *extra: str, netuid: list[str] | None = None, network: str = NETWORK
) -> list[str]:
    return [
        "refresh",
        "--network",
        network,
        *(["--netuid", str(NETUID)] if netuid is None else netuid),
        "--minimum-stake-rao",
        "0",
        "--signing-key-id",
        KEY_ID,
        "--signing-key-file",
        str(d.seed),
        "--keys",
        str(d.control_keys),
        "--keys-digest",
        d.keys_digest,
        "--out",
        str(d.published),
        "--valid-seconds",
        "900",
        *extra,
    ]


def _fetch_argv(
    d: Deployment,
    *extra: str,
    source: str | None = None,
    netuid: list[str] | None = None,
    network: str = NETWORK,
) -> list[str]:
    return [
        "fetch",
        "--source",
        str(d.published) if source is None else source,
        "--network",
        network,
        *(["--netuid", str(NETUID)] if netuid is None else netuid),
        "--minimum-stake-rao",
        "0",
        "--keys",
        str(d.worker_keys),
        "--keys-digest",
        d.keys_digest,
        "--out",
        str(d.live),
        *extra,
    ]


def _place(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o644)


def _candidates(directory: Path) -> list[str]:
    return sorted(name for name in os.listdir(directory) if name.startswith("."))


class _FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, *, status: int = 200, length: str | None = None):
        super().__init__(body)
        self.status = status
        self.headers = {} if length is None else {"Content-Length": length}


def _serve(monkeypatch, response_or_error) -> list[str]:
    requested: list[str] = []

    class Opener:
        def open(self, request, timeout):
            requested.append(request.full_url)
            if isinstance(response_or_error, BaseException):
                raise response_or_error
            return response_or_error

    monkeypatch.setattr(access_tool, "_url_opener", lambda: Opener())
    return requested


@pytest.fixture(autouse=True)
def _deterministic_host(monkeypatch):
    # The worker requires root:root. The test account stands in for it, so the
    # same assertions hold whether or not the suite runs as root.
    monkeypatch.setattr(access_tool, "_snapshot_owner", lambda: (os.geteuid(), os.getegid()))
    monkeypatch.setattr(access_tool, "_now", lambda: NOW)
    monkeypatch.delenv("JOURNAL_STREAM", raising=False)


@pytest.fixture
def deployment(tmp_path: Path, capsys) -> Deployment:
    signer = tmp_path / "control" / "signer"
    signer.mkdir(parents=True)
    signer.chmod(0o700)
    publish = tmp_path / "control" / "publish"
    publish.mkdir()
    publish.chmod(0o755)
    worker = tmp_path / "worker" / "validator-access"
    worker.mkdir(parents=True)
    worker.chmod(0o700)
    seed = signer / "snapshot.seed"
    control_keys = signer / "snapshot-keys.json"
    assert (
        access_tool.main(
            [
                "init-key",
                "--signing-key-id",
                KEY_ID,
                "--signing-key-out",
                str(seed),
                "--keys-out",
                str(control_keys),
            ]
        )
        == 0
    )
    fields = _fields(capsys.readouterr().out)
    worker_keys = worker / "snapshot-keys.json"
    shutil.copyfile(control_keys, worker_keys)
    worker_keys.chmod(0o644)
    return Deployment(
        signer=signer,
        seed=seed,
        seed_bytes=access_tool._read_signing_seed(str(seed)),
        control_keys=control_keys,
        publish=publish,
        published=publish / "validator-access.json",
        worker=worker,
        worker_keys=worker_keys,
        live=worker / "validator-access.json",
        keys_digest=fields["keys_digest"],
    )


# --- control host: refresh --------------------------------------------------


def test_refresh_publishes_and_fetch_installs_what_the_running_worker_uses(
    deployment, tmp_path, monkeypatch, capsys
):
    d = deployment
    old = _signed(d.seed_bytes, generated_at=NOW - timedelta(seconds=300))
    _place(d.published, old)
    _place(d.live, old)
    live_inode = d.live.stat().st_ino
    trusted = load_policy_keys(str(d.worker_keys), production_mode=True, pinned_digest=d.keys_digest)
    state = tmp_path / "worker" / "state"
    state.mkdir(mode=0o700)
    worker_view = SignedValidatorSnapshotProvider(
        str(d.live),
        trusted,
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=0,
        state=ValidatorAccessState(str(state / "validator-access.sqlite")),
    )
    assert worker_view.load(now=NOW).block == BLOCK - 10
    _chain(monkeypatch)

    assert access_tool.main(_refresh_argv(d)) == 0
    published = _fields(capsys.readouterr().out)
    assert published["outcome"] == "installed"
    assert published["previous_expires_at"] == canonical_utc(NOW + timedelta(seconds=600))
    metadata = d.published.lstat()
    assert stat.S_IMODE(metadata.st_mode) == 0o644
    assert (metadata.st_uid, metadata.st_gid) == (os.geteuid(), os.getegid())

    # The worker holds no seed and never imports the chain client.
    monkeypatch.setitem(sys.modules, "bittensor", None)
    assert access_tool.main(_fetch_argv(d)) == 0

    fetched = _fields(capsys.readouterr().out)
    assert fetched["outcome"] == "installed"
    assert fetched["snapshot_digest"] == published["snapshot_digest"]
    assert fetched["expires_at"] == canonical_utc(NOW - BACKDATE + timedelta(seconds=900))
    assert d.live.read_bytes() == d.published.read_bytes()
    metadata = d.live.lstat()
    assert stat.S_IMODE(metadata.st_mode) == 0o644
    assert (metadata.st_uid, metadata.st_gid) == (os.geteuid(), os.getegid())
    assert metadata.st_ino != live_inode
    assert _candidates(d.worker) == [] and _candidates(d.publish) == []
    # The running worker re-verifies on the changed file identity; no restart.
    assert worker_view.load(now=NOW).block == BLOCK


def test_refresh_accepts_a_freshness_only_resign_at_the_same_finalized_block(
    deployment, monkeypatch, capsys
):
    _place(
        deployment.published,
        _signed(
            deployment.seed_bytes,
            generated_at=NOW - timedelta(seconds=300),
            block=BLOCK,
            block_hash=BLOCK_HASH,
        ),
    )
    _chain(monkeypatch)

    assert access_tool.main(_refresh_argv(deployment)) == 0
    fields = _fields(capsys.readouterr().out)
    assert fields["finalized_block"] == str(BLOCK)
    assert fields["generated_at"] == canonical_utc(NOW - BACKDATE)
    assert fields["expires_at"] == canonical_utc(NOW - BACKDATE + timedelta(seconds=900))


def test_a_refresh_candidate_that_fails_verification_is_never_published(
    deployment, monkeypatch, capsys
):
    published = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=60))
    _place(deployment.published, published)
    inode = deployment.published.stat().st_ino
    rogue_seed = secrets.token_bytes(32)
    monkeypatch.setattr(
        access_tool,
        "_capture_signed",
        lambda args, seed: (
            _signed(rogue_seed, generated_at=NOW, block=BLOCK, block_hash=BLOCK_HASH),
            None,
        ),
    )

    assert access_tool.main(_refresh_argv(deployment)) == UPDATE_FAILED

    assert deployment.published.read_bytes() == published
    assert deployment.published.stat().st_ino == inode
    assert _candidates(deployment.publish) == []
    error = capsys.readouterr().err
    assert "ERROR validator_access_refresh_failed" in error
    assert "signature verification failed" in error


@pytest.mark.parametrize(
    "binding",
    [{"netuid": OTHER_NETUID}, {"network": OTHER_NETWORK}],
    ids=["other-netuid", "other-network"],
)
def test_refresh_refuses_a_candidate_bound_to_another_subnet_or_network(
    deployment, monkeypatch, capsys, binding
):
    published = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=60))
    _place(deployment.published, published)
    monkeypatch.setattr(
        access_tool,
        "_capture_signed",
        lambda args, seed: (
            _signed(
                deployment.seed_bytes,
                generated_at=NOW,
                block=BLOCK,
                block_hash=BLOCK_HASH,
                **binding,
            ),
            None,
        ),
    )

    assert access_tool.main(_refresh_argv(deployment)) == UPDATE_FAILED

    assert deployment.published.read_bytes() == published
    assert _candidates(deployment.publish) == []
    assert "different network or netuid" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("block", "block_hash", "hotkeys", "valid_seconds", "refusal"),
    [
        (BLOCK - 1, "0x" + "c" * 64, (VALIDATOR_HOTKEY,), "900", "rollback"),
        (BLOCK, BLOCK_HASH, (VALIDATOR_HOTKEY, OTHER_HOTKEY), "900", "equivocation"),
        (BLOCK, "0x" + "d" * 64, (VALIDATOR_HOTKEY,), "900", "equivocation"),
        (BLOCK, BLOCK_HASH, (VALIDATOR_HOTKEY,), "600", "before the live"),
    ],
    ids=[
        "older-block",
        "changed-set-same-block",
        "changed-hash-same-block",
        "shorter-window-same-block",
    ],
)
def test_refresh_never_publishes_an_older_or_less_valid_snapshot(
    deployment, monkeypatch, capsys, block, block_hash, hotkeys, valid_seconds, refusal
):
    published = _signed(
        deployment.seed_bytes,
        generated_at=NOW - timedelta(seconds=100),
        block=BLOCK,
        block_hash=BLOCK_HASH,
    )
    _place(deployment.published, published)
    _chain(monkeypatch, block=block, block_hash=block_hash, hotkeys=hotkeys)

    assert (
        access_tool.main(_refresh_argv(deployment, "--valid-seconds", valid_seconds))
        == UPDATE_FAILED
    )

    assert deployment.published.read_bytes() == published
    assert _candidates(deployment.publish) == []
    assert refusal in capsys.readouterr().err


@pytest.mark.parametrize(
    ("valid_seconds", "age_seconds", "extra", "expected", "remaining"),
    [
        (900, 500, (), UPDATE_FAILED, 400),
        (900, 700, (), ALARM, 200),
        # Inside the code's 3600 s age ceiling, but under a third of its own life.
        (3600, 2500, (), ALARM, 1100),
        (900, 500, ("--alarm-below-seconds", "500"), ALARM, 400),
        (900, 950, (), ALARM, 0),
        (None, None, (), ALARM, 0),
    ],
    ids=["healthy", "close", "long-lived-close", "explicit-threshold", "expired", "missing"],
)
def test_refresh_alarm_is_keyed_on_the_published_snapshots_own_expires_at(
    deployment, monkeypatch, capsys, valid_seconds, age_seconds, extra, expected, remaining
):
    published = None
    if valid_seconds is not None:
        published = _signed(
            deployment.seed_bytes,
            generated_at=NOW - timedelta(seconds=age_seconds),
            valid_seconds=valid_seconds,
        )
        _place(deployment.published, published)

    def unreachable(network: str, netuid: int):
        raise ConnectionError("chain endpoint unreachable")

    monkeypatch.setattr(access_tool, "_finalized_neurons", unreachable)
    monkeypatch.setenv("JOURNAL_STREAM", "8:12345")

    assert access_tool.main(_refresh_argv(deployment, *extra)) == expected

    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1
    if expected == ALARM:
        assert lines[0].startswith("<3>ERROR validator_access_expiry_alarm")
    else:
        assert lines[0].startswith("<3>ERROR validator_access_refresh_failed")
    assert f"remaining_seconds={remaining} " in lines[0]
    assert "chain endpoint unreachable" in lines[0]
    if published is None:
        assert not deployment.published.exists()
    else:
        assert deployment.published.read_bytes() == published
    assert _candidates(deployment.publish) == []


def _open_publish_directory(d: Deployment) -> list[str]:
    d.publish.chmod(0o775)
    return []


def _seed_in_publish_directory(d: Deployment) -> list[str]:
    exposed = d.publish / "snapshot.seed"
    exposed.write_bytes(d.seed.read_bytes())
    exposed.chmod(0o600)
    return ["--signing-key-file", str(exposed)]


def _mismatched_seed(d: Deployment) -> list[str]:
    other = d.signer / "other.seed"
    other.write_text(access_tool.base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
    other.chmod(0o600)
    return ["--signing-key-file", str(other)]


def _wrong_keys_digest(d: Deployment) -> list[str]:
    return ["--keys-digest", "sha256:" + "0" * 64]


@pytest.mark.parametrize(
    ("arrange", "expected", "message"),
    [
        (_open_publish_directory, UPDATE_FAILED, "not writable by group or other"),
        (_seed_in_publish_directory, UPDATE_FAILED, "published to workers"),
        (_mismatched_seed, UPDATE_FAILED, "does not match the deployed"),
        (_wrong_keys_digest, ALARM, "digest does not match"),
    ],
    ids=["open-directory", "seed-in-publish", "seed-mismatch", "keys-digest"],
)
def test_refresh_refuses_an_unsafe_layout_before_touching_the_published_file(
    deployment, monkeypatch, capsys, arrange, expected, message
):
    published = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=60))
    _place(deployment.published, published)
    extra = arrange(deployment)
    _chain(monkeypatch)

    assert access_tool.main(_refresh_argv(deployment, *extra)) == expected

    assert deployment.published.read_bytes() == published
    assert not [n for n in _candidates(deployment.publish) if access_tool.CANDIDATE_MARKER in n]
    assert message in capsys.readouterr().err


def test_a_hung_chain_read_is_bounded_and_reported(deployment, monkeypatch, capsys):
    published = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=60))
    _place(deployment.published, published)
    monkeypatch.setattr(
        access_tool, "_finalized_neurons", lambda network, netuid: time.sleep(30)
    )
    started = time.monotonic()

    assert (
        access_tool.main(_refresh_argv(deployment, "--capture-timeout-seconds", "1"))
        == UPDATE_FAILED
    )

    assert time.monotonic() - started < 15
    assert deployment.published.read_bytes() == published
    assert "chain capture exceeded 1 seconds" in capsys.readouterr().err


# --- worker: fetch ------------------------------------------------------------


def test_fetch_installs_from_an_https_source(deployment, capsys, monkeypatch):
    fresh = _signed(deployment.seed_bytes, generated_at=NOW, block=BLOCK, block_hash=BLOCK_HASH)
    requested = _serve(monkeypatch, _FakeResponse(fresh, length=str(len(fresh))))

    assert access_tool.main(_fetch_argv(deployment, source=SOURCE_URL)) == 0

    assert requested == [SOURCE_URL]
    assert deployment.live.read_bytes() == fresh
    assert stat.S_IMODE(deployment.live.stat().st_mode) == 0o644
    assert _fields(capsys.readouterr().out)["previous_expires_at"] == "none"


def _other_key_id(d: Deployment) -> tuple[bytes, str]:
    return (
        _signed(
            d.seed_bytes,
            generated_at=NOW,
            block=BLOCK,
            block_hash=BLOCK_HASH,
            key_id="cathedral-validator-access-2",
        ),
        "signing key is not trusted",
    )


def _refusal(message: str, **fields) -> object:
    def build(d: Deployment) -> tuple[bytes, str]:
        values = {"generated_at": NOW, "block": BLOCK, "block_hash": BLOCK_HASH, **fields}
        seed = values.pop("seed", d.seed_bytes)
        return _signed(seed, **values), message

    return build


_FETCH_REFUSALS = {
    "bad-signature": _refusal(
        "signature verification failed", seed=secrets.token_bytes(32)
    ),
    "unknown-key-id": _other_key_id,
    "other-network": _refusal("different network or netuid", network=OTHER_NETWORK),
    "other-netuid": _refusal("different network or netuid", netuid=OTHER_NETUID),
    "other-stake-floor": _refusal("minimum stake does not match", minimum_stake_rao=1),
    "expired": _refusal(
        "outside its validity window", generated_at=NOW - timedelta(seconds=901)
    ),
    "older-than-live": _refusal("rollback", block=BLOCK - 20, block_hash="0x" + "c" * 64),
    "shorter-than-live-same-block": _refusal(
        "before the live", valid_seconds=600, block=BLOCK - 10, block_hash=OLDER_HASH
    ),
    "changed-set-same-block": _refusal(
        "equivocation",
        block=BLOCK - 10,
        block_hash=OLDER_HASH,
        hotkeys=(VALIDATOR_HOTKEY, OTHER_HOTKEY),
    ),
    "malformed": lambda d: (b'{"schema": ', "not valid UTF-8 JSON"),
    "empty": lambda d: (b"", "not valid UTF-8 JSON"),
    "oversized": lambda d: (b" " * (MAX_SNAPSHOT_BYTES + 1), "larger than"),
}


@pytest.mark.parametrize("transport", ["local", "https"])
@pytest.mark.parametrize("case", sorted(_FETCH_REFUSALS))
def test_fetch_refuses_and_leaves_the_live_file_untouched(
    deployment, monkeypatch, capsys, case, transport
):
    live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=100))
    _place(deployment.live, live)
    inode = deployment.live.stat().st_ino
    body, message = _FETCH_REFUSALS[case](deployment)
    if transport == "local":
        _place(deployment.published, body)
        source = None
    else:
        _serve(monkeypatch, _FakeResponse(body))
        source = SOURCE_URL

    assert access_tool.main(_fetch_argv(deployment, source=source)) == UPDATE_FAILED

    assert deployment.live.read_bytes() == live
    assert deployment.live.stat().st_ino == inode
    assert _candidates(deployment.worker) == []
    error = capsys.readouterr().err
    assert "ERROR validator_access_fetch_failed" in error
    assert message in error


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_FakeResponse(b"{}", length=str(MAX_SNAPSHOT_BYTES + 1)), "larger than"),
        (_FakeResponse(b"{}", status=204), "HTTP 204"),
        (ConnectionError("control host unreachable"), "control host unreachable"),
    ],
    ids=["declared-oversized", "not-200", "unreachable"],
)
def test_fetch_refuses_a_bad_https_answer(deployment, monkeypatch, capsys, response, message):
    live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=100))
    _place(deployment.live, live)
    _serve(monkeypatch, response)

    assert access_tool.main(_fetch_argv(deployment, source=SOURCE_URL)) == UPDATE_FAILED

    assert deployment.live.read_bytes() == live
    assert message in capsys.readouterr().err


def test_fetch_follows_no_redirect_away_from_https():
    handler = access_tool._HttpsOnlyRedirect()
    request = access_tool.urllib.request.Request(SOURCE_URL)

    with pytest.raises(SystemExit, match="away from https"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://control.example/x")


def test_fetch_reads_a_fifo_source_without_blocking(deployment, capsys):
    live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=100))
    _place(deployment.live, live)
    os.mkfifo(deployment.published)

    assert access_tool.main(_fetch_argv(deployment)) == UPDATE_FAILED

    assert deployment.live.read_bytes() == live
    assert "not a regular file" in capsys.readouterr().err


def test_fetch_of_the_same_bytes_changes_nothing(deployment, capsys):
    live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=100))
    _place(deployment.live, live)
    _place(deployment.published, live)
    inode = deployment.live.stat().st_ino

    assert access_tool.main(_fetch_argv(deployment)) == 0

    assert deployment.live.stat().st_ino == inode
    assert _fields(capsys.readouterr().out)["outcome"] == "unchanged"


@pytest.mark.parametrize(
    ("live_age", "source_age", "source", "expected", "remaining", "outcome"),
    [
        # The control host stopped publishing: the source still offers the live
        # bytes, and they are now close to expiry.
        (700, 700, "same", ALARM, 200, "unchanged"),
        # A newer snapshot is installed, but it too is close to expiry.
        (800, 650, "newer", ALARM, 250, "installed"),
        (100, None, "unreachable", UPDATE_FAILED, 800, None),
        (700, None, "unreachable", ALARM, 200, None),
        (None, None, "unreachable", ALARM, 0, None),
        (901, None, "unreachable", ALARM, 0, None),
    ],
    ids=[
        "stale-source",
        "installed-but-close",
        "unreachable-healthy",
        "unreachable-close",
        "unreachable-missing",
        "unreachable-expired",
    ],
)
def test_the_worker_alarm_is_keyed_on_the_live_snapshots_own_expires_at(
    deployment, monkeypatch, capsys, live_age, source_age, source, expected, remaining, outcome
):
    live = None
    if live_age is not None:
        live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=live_age))
        _place(deployment.live, live)
    if source == "same":
        _place(deployment.published, live)
    elif source == "newer":
        _place(
            deployment.published,
            _signed(
                deployment.seed_bytes,
                generated_at=NOW - timedelta(seconds=source_age),
                block=BLOCK,
                block_hash=BLOCK_HASH,
            ),
        )
    monkeypatch.setenv("JOURNAL_STREAM", "8:12345")

    assert access_tool.main(_fetch_argv(deployment)) == expected

    captured = capsys.readouterr()
    lines = captured.err.splitlines()
    assert len(lines) == 1
    if expected == ALARM:
        assert lines[0].startswith("<3>ERROR validator_access_expiry_alarm")
    else:
        assert lines[0].startswith("<3>ERROR validator_access_fetch_failed")
    assert "command=fetch " in lines[0]
    assert f"remaining_seconds={remaining} " in lines[0]
    if outcome is None:
        assert "error=" in lines[0]
    else:
        assert "error=" not in lines[0]
        assert _fields(captured.out)["outcome"] == outcome
    if source != "newer":
        assert (deployment.live.read_bytes() if live else None) == live


@pytest.mark.parametrize(
    "binding",
    [{"netuid": OTHER_NETUID}, {"network": OTHER_NETWORK}, {"minimum_stake_rao": 1}],
    ids=["other-netuid", "other-network", "other-stake-floor"],
)
def test_fetch_will_not_rebind_a_live_snapshot_for_another_binding(
    deployment, capsys, binding
):
    live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=60), **binding)
    _place(deployment.live, live)
    _place(
        deployment.published,
        _signed(deployment.seed_bytes, generated_at=NOW, block=BLOCK, block_hash=BLOCK_HASH),
    )

    # Nothing usable for the configured binding is live, so this is the alarm.
    assert access_tool.main(_fetch_argv(deployment)) == ALARM

    assert deployment.live.read_bytes() == live
    error = capsys.readouterr().err
    assert "ERROR validator_access_expiry_alarm" in error
    assert "refusing to rebind" in error


def _loosen_worker_directory(d: Deployment) -> list[str]:
    d.worker.chmod(0o750)
    return []


def _linked_live_file(d: Deployment) -> list[str]:
    target = d.worker.parent / "elsewhere.json"
    target.write_bytes(d.live.read_bytes())
    d.live.unlink()
    d.live.symlink_to(target)
    return []


def _source_is_the_live_file(d: Deployment) -> list[str]:
    return ["--source", str(d.live)]


@pytest.mark.parametrize(
    ("arrange", "expected", "message"),
    [
        (_loosen_worker_directory, UPDATE_FAILED, "mode 0700"),
        (_linked_live_file, ALARM, "not a regular file"),
        (_source_is_the_live_file, UPDATE_FAILED, "same path"),
        (_wrong_keys_digest, ALARM, "digest does not match"),
    ],
    ids=["open-directory", "linked-live", "source-is-live", "keys-digest"],
)
def test_fetch_refuses_an_unsafe_layout_before_touching_the_live_file(
    deployment, capsys, arrange, expected, message
):
    live = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=60))
    _place(deployment.live, live)
    _place(
        deployment.published,
        _signed(deployment.seed_bytes, generated_at=NOW, block=BLOCK, block_hash=BLOCK_HASH),
    )
    extra = arrange(deployment)
    before = os.readlink(deployment.live) if deployment.live.is_symlink() else None

    assert access_tool.main(_fetch_argv(deployment, *extra)) == expected

    if before is None:
        assert deployment.live.read_bytes() == live
    else:
        assert os.readlink(deployment.live) == before
    assert not [n for n in _candidates(deployment.worker) if access_tool.CANDIDATE_MARKER in n]
    assert message in capsys.readouterr().err


def test_refresh_publishes_a_newer_block_after_the_lifetime_is_lowered(
    deployment, monkeypatch, capsys
):
    # Lowering --valid-seconds shortens the new window. A newer block must
    # still win, or the published validator set freezes until the old expiry.
    _place(
        deployment.published,
        _signed(
            deployment.seed_bytes,
            generated_at=NOW - timedelta(seconds=60),
            block=BLOCK,
            block_hash=BLOCK_HASH,
        ),
    )
    _chain(monkeypatch, block=BLOCK + 1, block_hash="0x" + "e" * 64)

    assert access_tool.main(_refresh_argv(deployment, "--valid-seconds", "600")) == 0

    fields = _fields(capsys.readouterr().out)
    assert fields["finalized_block"] == str(BLOCK + 1)
    assert fields["expires_at"] < fields["previous_expires_at"]


def test_fetch_installs_a_newer_block_signed_by_a_control_host_whose_clock_stepped_back(
    deployment, capsys
):
    live = _signed(
        deployment.seed_bytes,
        generated_at=NOW - timedelta(seconds=100),
        block=BLOCK,
        block_hash=BLOCK_HASH,
    )
    _place(deployment.live, live)
    # Signed after the live file, by a clock running 300 s behind.
    stepped_back = _signed(
        deployment.seed_bytes,
        generated_at=NOW - timedelta(seconds=400),
        block=BLOCK + 3,
        block_hash="0x" + "f" * 64,
    )
    _place(deployment.published, stepped_back)

    assert access_tool.main(_fetch_argv(deployment)) == 0

    assert deployment.live.read_bytes() == stepped_back
    fields = _fields(capsys.readouterr().out)
    assert fields["finalized_block"] == str(BLOCK + 3)
    assert fields["expires_at"] < fields["previous_expires_at"]


def test_a_control_host_clock_running_slightly_fast_is_still_accepted_by_workers(
    deployment, tmp_path, monkeypatch, capsys
):
    # The worker refuses any generated_at after its own clock
    # (cathedral/validator_access.py, verify_validator_access_snapshot), so
    # refresh backdates generated_at. A control host 20 s fast still works.
    _chain(monkeypatch)
    monkeypatch.setattr(access_tool, "_now", lambda: NOW + timedelta(seconds=20))
    assert access_tool.main(_refresh_argv(deployment)) == 0
    published = _fields(capsys.readouterr().out)
    assert published["generated_at"] == canonical_utc(NOW + timedelta(seconds=20) - BACKDATE)

    monkeypatch.setattr(access_tool, "_now", lambda: NOW)
    assert access_tool.main(_fetch_argv(deployment)) == 0
    assert _fields(capsys.readouterr().out)["outcome"] == "installed"
    trusted = load_policy_keys(
        str(deployment.worker_keys), production_mode=True, pinned_digest=deployment.keys_digest
    )
    state = tmp_path / "worker" / "state"
    state.mkdir(mode=0o700)
    worker_view = SignedValidatorSnapshotProvider(
        str(deployment.live),
        trusted,
        network=NETWORK,
        netuid=NETUID,
        minimum_stake_rao=0,
        state=ValidatorAccessState(str(state / "validator-access.sqlite")),
    )
    assert worker_view.load(now=NOW).block == BLOCK


def test_fetch_never_overwrites_a_live_file_replaced_during_the_run(
    deployment, monkeypatch, capsys
):
    old = _signed(deployment.seed_bytes, generated_at=NOW - timedelta(seconds=300))
    _place(deployment.live, old)
    _place(
        deployment.published,
        _signed(deployment.seed_bytes, generated_at=NOW, block=BLOCK, block_hash=BLOCK_HASH),
    )
    # An operator's manual install lands a newer block while fetch is reading.
    concurrent = _signed(
        deployment.seed_bytes,
        generated_at=NOW - timedelta(seconds=10),
        block=BLOCK + 5,
        block_hash="0x" + "9" * 64,
    )
    real_read = access_tool._read_source

    def read_then_race(source, timeout):
        body = real_read(source, timeout)
        staged = deployment.worker / ".manual-install"
        _place(staged, concurrent)
        os.replace(staged, deployment.live)
        return body

    monkeypatch.setattr(access_tool, "_read_source", read_then_race)

    assert access_tool.main(_fetch_argv(deployment)) == UPDATE_FAILED

    assert deployment.live.read_bytes() == concurrent
    assert _candidates(deployment.worker) == []
    assert "changed during the update" in capsys.readouterr().err


@pytest.mark.parametrize(("seconds", "accepted"), [("599", False), ("600", True)])
def test_refresh_refuses_a_lifetime_under_ten_minutes(deployment, monkeypatch, seconds, accepted):
    _chain(monkeypatch)
    argv = _refresh_argv(deployment, "--valid-seconds", seconds)

    if accepted:
        assert access_tool.main(argv) == 0
    else:
        with pytest.raises(SystemExit) as refused:
            access_tool.main(argv)
        assert refused.value.code == 2
        assert not deployment.published.exists()


# --- shared: crash safety, write failure, arguments, units -------------------

_CRASH_DRIVER = """
import importlib.util, json, os, sys
from datetime import datetime
from types import SimpleNamespace

config = json.loads(sys.argv[1])
spec = importlib.util.spec_from_file_location("refresh_tool", config["tool"])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
now = datetime.fromisoformat(config["now"])
rows = [
    SimpleNamespace(hotkey=hotkey, uid=uid, validator_permit=True,
                    total_stake=SimpleNamespace(rao=2000))
    for hotkey, uid in config["rows"]
]
tool._now = lambda: now
tool._snapshot_owner = lambda: (os.geteuid(), os.getegid())
tool._finalized_neurons = lambda network, netuid: (config["block"], config["block_hash"], rows)

def killed_before_rename(*args, **kwargs):
    os._exit(70)

os.replace = killed_before_rename
sys.exit(tool.main(config["argv"]))
"""


@pytest.mark.parametrize("command", ["refresh", "fetch"])
def test_a_crash_between_write_and_rename_never_exposes_a_partial_target(
    deployment, tmp_path, monkeypatch, capsys, command
):
    d = deployment
    old = _signed(d.seed_bytes, generated_at=NOW - timedelta(seconds=300))
    fresh = _signed(d.seed_bytes, generated_at=NOW, block=BLOCK, block_hash=BLOCK_HASH)
    if command == "refresh":
        target, directory, argv = d.published, d.publish, _refresh_argv(d)
        _place(target, old)
    else:
        target, directory, argv = d.live, d.worker, _fetch_argv(d)
        _place(target, old)
        _place(d.published, fresh)
    inode = target.stat().st_ino
    driver = tmp_path / "crash_driver.py"
    driver.write_text(_CRASH_DRIVER)
    environment = {key: value for key, value in os.environ.items() if key != "JOURNAL_STREAM"}
    config = {
        "tool": str(TOOL_PATH),
        "now": NOW.isoformat(),
        "rows": [[VALIDATOR_HOTKEY, 0]],
        "block": BLOCK,
        "block_hash": BLOCK_HASH,
        "argv": argv,
    }

    crashed = subprocess.run(
        [sys.executable, str(driver), json.dumps(config)],
        capture_output=True,
        text=True,
        timeout=120,
        env=environment,
        check=False,
    )

    assert crashed.returncode == 70, crashed.stderr
    assert target.read_bytes() == old
    assert target.stat().st_ino == inode
    leftovers = _candidates(directory)
    assert len(leftovers) == 1
    assert leftovers[0].startswith(f".{target.name}{access_tool.CANDIDATE_MARKER}")

    _chain(monkeypatch)
    assert access_tool.main(argv) == 0
    assert _fields(capsys.readouterr().out)["stale_candidates_removed"] == "1"
    assert _candidates(directory) == []
    assert target.stat().st_ino != inode


@pytest.mark.parametrize("command", ["refresh", "fetch"])
def test_a_failed_candidate_write_leaves_no_file_behind(deployment, monkeypatch, capsys, command):
    d = deployment
    old = _signed(d.seed_bytes, generated_at=NOW - timedelta(seconds=60))
    if command == "refresh":
        target, directory, argv = d.published, d.publish, _refresh_argv(d)
    else:
        target, directory, argv = d.live, d.worker, _fetch_argv(d)
        _place(d.published, _signed(d.seed_bytes, generated_at=NOW, block=BLOCK,
                                    block_hash=BLOCK_HASH))
    _place(target, old)
    _chain(monkeypatch)
    real_write = os.write
    candidate_writes: list[int] = []

    def half_then_disk_full(descriptor, data):
        if not isinstance(data, memoryview):
            return real_write(descriptor, data)
        if candidate_writes:
            raise OSError(errno.ENOSPC, "No space left on device")
        candidate_writes.append(descriptor)
        return real_write(descriptor, data[: len(data) // 2])

    monkeypatch.setattr(access_tool.os, "write", half_then_disk_full)

    assert access_tool.main(argv) == UPDATE_FAILED

    assert candidate_writes
    assert target.read_bytes() == old
    assert _candidates(directory) == []
    assert "No space left on device" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["refresh", "fetch"])
@pytest.mark.parametrize(
    "netuid",
    [[], ["--netuid", ""], ["--netuid", "<NETUID>"], ["--netuid", "070"], ["--netuid", "65536"]],
    ids=["absent", "empty", "placeholder", "noncanonical", "out-of-range"],
)
def test_both_commands_require_an_explicit_canonical_netuid(deployment, command, netuid):
    argv = (_refresh_argv if command == "refresh" else _fetch_argv)(deployment, netuid=netuid)

    with pytest.raises(SystemExit) as refused:
        access_tool.main(argv)

    assert refused.value.code == 2
    assert not deployment.live.exists() and not deployment.published.exists()


@pytest.mark.parametrize("command", ["refresh", "fetch"])
@pytest.mark.parametrize(
    "network", ["<NETWORK>", "", "Upper", "net work"], ids=["placeholder", "empty", "upper", "space"]
)
def test_both_commands_require_an_explicit_network(deployment, command, network):
    build = _refresh_argv if command == "refresh" else _fetch_argv

    with pytest.raises(SystemExit) as refused:
        access_tool.main(build(deployment, network=network))

    assert refused.value.code == 2
    assert not deployment.live.exists() and not deployment.published.exists()


@pytest.mark.parametrize(
    "source",
    ["http://control.example/validator-access.json", "relative/validator-access.json",
     "ftp://control.example/x", "https:///no-host", "https://user:pw@control.example/x"],
)
def test_fetch_accepts_only_an_https_url_or_an_absolute_path(deployment, source):
    with pytest.raises(SystemExit) as refused:
        access_tool.main(_fetch_argv(deployment, source=source))

    assert refused.value.code == 2


def test_fetch_takes_no_seed_or_chain_option():
    fetch = access_tool.build_parser()._subparsers._group_actions[0].choices["fetch"]
    options = {option for action in fetch._actions for option in action.option_strings}

    assert not {option for option in options if "sign" in option or "seed" in option}
    assert "--source" in options and "--keys-digest" in options


@pytest.mark.parametrize("role", ["refresh", "fetch"])
def test_example_units_take_every_deploy_value_from_their_env_file(role):
    examples = REPO_ROOT / "examples" / "systemd"
    service = (examples / f"cathedral-validator-access-{role}.service").read_text()
    timer = (examples / f"cathedral-validator-access-{role}.timer").read_text()
    environment = (examples / f"validator-access-{role}.env.example").read_text()

    for text in (service, timer, environment):
        assert re.search(r"\bsn\d|netuid[\s=]+\d", text, re.IGNORECASE) is None
    assignments = dict(
        line.split("=", 1)
        for line in environment.splitlines()
        if line and not line.startswith("#")
    )
    assert assignments["CATHEDRAL_VALIDATOR_ACCESS_NETUID"] == "<NETUID>"
    # Neither value is pre-filled: no deployment may inherit a network by default.
    assert assignments["CATHEDRAL_VALIDATOR_ACCESS_NETWORK"] == "<NETWORK>"
    assert "--network ${CATHEDRAL_VALIDATOR_ACCESS_NETWORK}" in service
    for text in (service, timer, environment):
        assert "finney" not in text.lower()
    assert set(re.findall(r"\$\{([A-Z_]+)\}", service)) == set(assignments)
    assert f"scripts/cathedral_validator_access.py {role}" in service
    assert "--netuid ${CATHEDRAL_VALIDATOR_ACCESS_NETUID}" in service
    assert "\nType=oneshot\n" in service
    assert "\nCapabilityBoundingSet=\n" in service
    # Exit 1 is a logged, retried hiccup; only the exit-3 alarm fails the unit
    # and pages through the alert template.
    assert "\nSuccessExitStatus=1\n" in service
    assert "\nOnFailure=cathedral-validator-access-alert@%n.service\n" in service
    assert "\nOnUnitActiveSec=2min\n" in timer
    assert "\nRandomizedDelaySec=" in timer
    if role == "fetch":
        # The worker holds no seed and reads no chain.
        lowered = (service + environment).lower()
        for forbidden in ("signing_key", "--signing", ".seed", "signer", "read_only"):
            assert forbidden not in lowered, forbidden
        assert "\nUser=root\n" in service
        assert "\nReadWritePaths=/etc/cathedral/validator-access\n" in service
        # Uid 0 must not reach a daemon that trusts it by peer uid.
        assert "\nRestrictAddressFamilies=AF_INET AF_INET6\n" in service
        hidden = " ".join(
            line.split("=", 1)[1]
            for line in service.splitlines()
            if line.startswith("InaccessiblePaths=")
        )
        for socket_path in (
            "-/run/dbus",
            "-/run/systemd/private",
            "-/var/run/docker.sock",
            "-/run/docker.sock",
        ):
            assert socket_path in hidden.split(), socket_path
    else:
        assert "\nUser=root\n" not in service
        assert "/etc/cathedral/validator-access\n" not in service
        assert "\nLimitCORE=0\n" in service


def test_the_alert_template_runs_the_operator_paging_hook():
    alert = (REPO_ROOT / "examples" / "systemd" / "cathedral-validator-access-alert@.service")
    text = alert.read_text()

    assert "\nType=oneshot\n" in text
    assert "\nExecStart=/usr/local/sbin/cathedral-validator-access-page %i\n" in text


def test_shipped_miner_units_start_after_the_snapshot_fetch():
    units = sorted((REPO_ROOT / "examples" / "systemd").glob("cathedral-*-miner.service"))
    assert units

    for unit in units:
        header = unit.read_text().split("[Service]", 1)[0]
        for directive in ("After", "Wants"):
            values = " ".join(
                line.split("=", 1)[1]
                for line in header.splitlines()
                if line.startswith(f"{directive}=")
            ).split()
            assert "cathedral-validator-access-fetch.service" in values, (unit.name, directive)
