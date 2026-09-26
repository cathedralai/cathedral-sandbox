#!/usr/bin/env python3
"""Capture, sign, rotate, verify, refresh, and fetch Cathedral validator-access snapshots.

Chain reads and the signing seed stay on the miner's control host (`capture`,
`refresh`). The worker receives one bounded signed artifact (`fetch`) and has
no Bittensor RPC client, wallet, or seed.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.admission_policy import load_policy_keys  # noqa: E402
from cathedral.policy_registry import canonical_json, parse_registry_json  # noqa: E402
from cathedral.validator_access import (  # noqa: E402
    DEFAULT_SNAPSHOT_MAX_AGE_SECONDS,
    MAX_NETUID,
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_VALIDITY_SECONDS,
    MAX_STAKE_RAO,
    MAX_VALIDATORS,
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    ValidatorAccessError,
    ValidatorAccessSnapshot,
    bittensor_account_id,
    canonical_utc,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)

_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_UID_HOTKEY_RE = re.compile(r"^(0|[1-9][0-9]{0,4})=([1-9A-HJ-NP-Za-km-z]{32,128})$")
_NETUID_RE = re.compile(r"^(0|[1-9][0-9]{0,4})$")
_NETWORK_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Every installed snapshot is a 0644 regular file. On a worker the launcher also
# requires owner root:root inside a root:root 0700 directory.
SNAPSHOT_FILE_MODE = 0o644
WORKER_DIRECTORY_MODE = 0o700
CANDIDATE_MARKER = ".candidate."
EXIT_UPDATE_FAILED = 1
EXIT_EXPIRY_ALARM = 3
# Workers refuse any snapshot whose generated_at is after their own clock
# (cathedral/validator_access.py, verify_validator_access_snapshot). Backdating
# lets a control host whose clock runs up to this much fast still be accepted.
GENERATED_AT_BACKDATE_SECONDS = 30
# A refreshed snapshot must outlive a few missed two-minute runs.
MINIMUM_REFRESH_VALID_SECONDS = 600

_T = TypeVar("_T")


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_signing_seed(path: str) -> bytes:
    target = Path(path)
    before = target.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_mode & 0o077
        or before.st_uid != os.geteuid()
    ):
        raise SystemExit("signing key must be an owner-only regular file")
    descriptor = os.open(
        target,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise SystemExit("signing key changed during read")
        raw = os.read(descriptor, 129)
    finally:
        os.close(descriptor)
    if len(raw) > 128:
        raise SystemExit("signing key file is too large")
    try:
        seed = base64.b64decode(raw.decode("ascii").strip(), validate=True)
    except Exception:
        raise SystemExit("signing key must be a canonical base64 seed") from None
    if len(seed) != 32 or base64.b64encode(seed).decode("ascii") != raw.decode("ascii").strip():
        raise SystemExit("signing key must contain one canonical 32-byte seed")
    return seed


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _fsync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_new(path: Path, encoded: bytes, mode: int) -> None:
    parent = path.parent.resolve()
    metadata = parent.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        raise SystemExit("key output parent directory must be owner-controlled")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            mode,
        )
    except FileExistsError as exc:
        raise SystemExit(f"refusing to overwrite {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            os.fchmod(handle.fileno(), mode)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    _fsync_parent(path)


def cmd_init_key(args: argparse.Namespace) -> int:
    """Create the private artifact key and digest-pinned public key file."""

    if _KEY_ID_RE.fullmatch(args.signing_key_id) is None:
        raise SystemExit("signing key id must match [a-z0-9][a-z0-9._-]{0,127}")
    seed_path = Path(args.signing_key_out)
    keys_path = Path(args.keys_out)
    if seed_path.absolute() == keys_path.absolute():
        raise SystemExit("signing key and public key outputs must be different paths")
    seed = secrets.token_bytes(32)
    public_base64 = base64.b64encode(_public_key(seed)).decode("ascii")
    keys_document = canonical_json({args.signing_key_id: public_base64})
    _create_new(seed_path, base64.b64encode(seed) + b"\n", 0o600)
    try:
        _create_new(keys_path, keys_document, 0o644)
    except BaseException:
        seed_path.unlink(missing_ok=True)
        _fsync_parent(seed_path)
        raise
    print(f"signing_key_id {args.signing_key_id}")
    print(f"public_key_base64 {public_base64}")
    print(f"keys_digest {_digest(keys_document)}")
    print(f"private_seed_written_to {seed_path}")
    print(f"public_keys_written_to {keys_path}")
    return 0


def _atomic_replace(path: Path, encoded: bytes) -> None:
    parent = path.parent.resolve()
    parent_metadata = parent.stat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_mode & 0o022
    ):
        raise SystemExit("snapshot parent directory must be owner-controlled")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or stat.S_ISLNK(existing.st_mode)
        or existing.st_uid != os.geteuid()
        or existing.st_mode & 0o022
    ):
        raise SystemExit("existing snapshot path is not an owner-controlled regular file")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            os.fchmod(handle.fileno(), 0o644)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _finalized_neurons(network: str, netuid: int) -> tuple[int, str, list[object]]:
    """Read exact-balance neuron rows at one finalized block."""

    import bittensor  # noqa: PLC0415

    subtensor = bittensor.Subtensor(network=network)
    substrate = getattr(subtensor, "substrate", None)
    finalized_head = getattr(substrate, "get_chain_finalised_head", None)
    block_number = getattr(substrate, "get_block_number", None)
    if not callable(finalized_head) or not callable(block_number):
        raise SystemExit("this Bittensor build cannot resolve a finalized head")
    raw_hash = finalized_head()
    block = block_number(raw_hash)
    if isinstance(block, bool) or not isinstance(block, int) or block <= 0:
        raise SystemExit("finalized head did not resolve to a block number")
    block_hash = str(raw_hash).lower()
    if not block_hash.startswith("0x") or len(block_hash) != 66:
        raise SystemExit("finalized head did not resolve to a canonical block hash")
    neurons = list(subtensor.neurons_lite(netuid, block=block))
    if not neurons:
        raise SystemExit("finalized metagraph returned no neurons")
    return block, block_hash, neurons


def build_snapshot_document(
    neurons: list[object],
    *,
    network: str,
    netuid: int,
    block: int,
    block_hash: str,
    minimum_stake_rao: int,
    signing_key_id: str,
    generated_at: datetime,
    valid_seconds: int,
) -> dict[str, object]:
    """Filter the finalized view to exact permit and stake-qualified rows."""

    if (
        isinstance(minimum_stake_rao, bool)
        or not isinstance(minimum_stake_rao, int)
        or not 0 <= minimum_stake_rao <= MAX_STAKE_RAO
    ):
        raise SystemExit("minimum stake must be a nonnegative Rao integer")
    if isinstance(valid_seconds, bool) or not 0 < valid_seconds <= 3600:
        raise SystemExit("snapshot validity must be between 1 and 3600 seconds")
    rows: list[dict[str, object]] = []
    for neuron in neurons:
        if getattr(neuron, "validator_permit", None) is not True:
            continue
        hotkey = getattr(neuron, "hotkey", None)
        try:
            bittensor_account_id(hotkey)
        except ValueError as exc:
            raise SystemExit("finalized metagraph contains an invalid validator hotkey") from exc
        uid = getattr(neuron, "uid", None)
        balance = getattr(neuron, "total_stake", None)
        stake_rao = getattr(balance, "rao", None)
        if isinstance(uid, bool) or not isinstance(uid, int) or not 0 <= uid <= 65_535:
            raise SystemExit("finalized metagraph contains an invalid validator uid")
        if (
            isinstance(stake_rao, bool)
            or not isinstance(stake_rao, int)
            or not 0 <= stake_rao <= MAX_STAKE_RAO
        ):
            raise SystemExit("Bittensor did not expose validator stake as exact Rao")
        if stake_rao < minimum_stake_rao:
            continue
        rows.append(
            {
                "hotkey": hotkey,
                "uid": uid,
                "validator_permit": True,
                "stake_rao": stake_rao,
            }
        )
    rows.sort(key=lambda row: str(row["hotkey"]))
    if not rows:
        raise SystemExit("no finalized validators meet the permit and stake gates")
    if len(rows) > MAX_VALIDATORS:
        raise SystemExit(f"more than {MAX_VALIDATORS} validators meet the access gates")
    hotkeys = [str(row["hotkey"]) for row in rows]
    if len(set(hotkeys)) != len(hotkeys):
        raise SystemExit("finalized metagraph contains duplicate validator hotkeys")
    uids = [int(row["uid"]) for row in rows]
    if len(set(uids)) != len(uids):
        raise SystemExit("finalized metagraph contains duplicate validator uids")
    return {
        "schema": VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
        "network": network,
        "netuid": netuid,
        "block": block,
        "block_hash": block_hash,
        "block_is_finalized": True,
        "generated_at": canonical_utc(generated_at),
        "expires_at": canonical_utc(generated_at + timedelta(seconds=valid_seconds)),
        "minimum_stake_rao": minimum_stake_rao,
        "validators": rows,
        "signing_key_id": signing_key_id,
    }


def _capture_signed(
    args: argparse.Namespace, seed: bytes
) -> tuple[bytes, ValidatorAccessSnapshot]:
    """Read one finalized view, sign it, and self-verify the canonical bytes."""

    block, block_hash, neurons = _finalized_neurons(args.network, args.netuid)
    required_rows: dict[int, str] = {}
    for value in args.require_uid_hotkey:
        match = _UID_HOTKEY_RE.fullmatch(value)
        if match is None:
            raise SystemExit("required UID mapping must use canonical UID=HOTKEY syntax")
        uid = int(match.group(1))
        hotkey = match.group(2)
        if uid > 65_535:
            raise SystemExit("required UID mapping is outside the u16 range")
        bittensor_account_id(hotkey)
        if uid in required_rows and required_rows[uid] != hotkey:
            raise SystemExit("required UID mapping repeats a UID with another hotkey")
        required_rows[uid] = hotkey
    for uid, hotkey in required_rows.items():
        matches = [
            neuron
            for neuron in neurons
            if type(getattr(neuron, "uid", None)) is int
            and getattr(neuron, "uid") == uid
        ]
        if len(matches) != 1 or getattr(matches[0], "hotkey", None) != hotkey:
            raise SystemExit(f"required finalized UID mapping changed: {uid}={hotkey}")
    generated_at = _now() - timedelta(seconds=GENERATED_AT_BACKDATE_SECONDS)
    unsigned = build_snapshot_document(
        neurons,
        network=args.network,
        netuid=args.netuid,
        block=block,
        block_hash=block_hash,
        minimum_stake_rao=args.minimum_stake_rao,
        signing_key_id=args.signing_key_id,
        generated_at=generated_at,
        valid_seconds=args.valid_seconds,
    )
    qualified = unsigned["validators"]
    assert isinstance(qualified, list)
    hotkeys = {str(row["hotkey"]) for row in qualified if isinstance(row, dict)}
    missing = sorted(set(args.require_hotkey) - hotkeys)
    if missing:
        raise SystemExit("required validator hotkeys are not qualified: " + ", ".join(missing))
    signed = sign_validator_access_snapshot(unsigned, seed)
    encoded = canonical_json(signed)
    snapshot = verify_validator_access_snapshot(
        encoded,
        {args.signing_key_id: _public_key(seed)},
        network=args.network,
        netuid=args.netuid,
        required_minimum_stake_rao=args.minimum_stake_rao,
        now=generated_at,
        max_age_seconds=args.max_age_seconds,
    )
    return encoded, snapshot


def cmd_capture(args: argparse.Namespace) -> int:
    seed = _read_signing_seed(args.signing_key_file)
    encoded, snapshot = _capture_signed(args, seed)
    _atomic_replace(Path(args.out), encoded)
    print(f"snapshot_digest {_digest(encoded)}")
    print(f"finalized_block {snapshot.block}")
    print(f"finalized_block_hash {snapshot.block_hash}")
    print(f"qualified_validators {len(snapshot.validators)}")
    print(f"expires_at {canonical_utc(snapshot.expires_at)}")
    print(f"written_to {args.out}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    keys = load_policy_keys(
        args.keys,
        production_mode=True,
        pinned_digest=args.keys_digest,
    )
    try:
        encoded = Path(args.snapshot).read_bytes()
    except OSError as exc:
        raise SystemExit("unable to read validator snapshot") from exc
    snapshot = verify_validator_access_snapshot(
        encoded,
        keys,
        network=args.network,
        netuid=args.netuid,
        required_minimum_stake_rao=args.minimum_stake_rao,
        max_age_seconds=args.max_age_seconds,
    )
    missing = sorted(set(args.require_hotkey) - set(snapshot.validators))
    if missing:
        raise SystemExit("required validator hotkeys are not qualified: " + ", ".join(missing))
    print(f"snapshot_digest {_digest(encoded)}")
    print(f"finalized_block {snapshot.block}")
    print(f"qualified_validators {len(snapshot.validators)}")
    print(f"expires_at {canonical_utc(snapshot.expires_at)}")
    return 0


# --- Unattended refresh and fetch --------------------------------------------
#
# The seed never leaves the control host. There, `refresh` signs a fresh
# finalized view and atomically replaces a published file. On each worker,
# `fetch` pulls that self-authenticating file from an https URL or a local path,
# verifies it against the pinned public keys and the worker's own binding, and
# atomically replaces the launcher's live file. Both write a candidate beside
# the target, verify the bytes on disk, refuse a rebind, rollback, equivocation,
# or shorter window, set owner and mode, fsync, and rename. The worker
# re-verifies on its next request because the file identity changed.
#
# Any failure leaves the target untouched, logs at error priority, and exits 1;
# the example units count that as success and retry. When the target's own
# expires_at is under the alarm threshold, or it is missing, expired, bound
# elsewhere, or does not verify, the run logs the expiry alarm and exits 3
# instead, even if this run installed or re-read a snapshot.


def _snapshot_owner() -> tuple[int, int]:
    """Return the uid and gid the launcher requires on the worker's live file."""

    return 0, 0


def _output_owner(args: argparse.Namespace) -> tuple[int, int]:
    if args.command == "fetch":
        return _snapshot_owner()
    return os.geteuid(), os.getegid()


def _journal(priority: int, line: str) -> None:
    """Write one stderr line, prefixed with its syslog priority under systemd."""

    prefix = f"<{priority}>" if os.environ.get("JOURNAL_STREAM") else ""
    print(prefix + line, file=sys.stderr, flush=True)


def _quote(value: object) -> str:
    text = " ".join(str(value).split())
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _reason(error: BaseException) -> str:
    if isinstance(error, SystemExit):
        return str(error.code)
    return f"{type(error).__name__}: {error}" if str(error) else type(error).__name__


class _Deadline(BaseException):
    """A hung read. Not an Exception, so a library retry loop cannot absorb it."""


def _call_with_deadline(seconds: int, label: str, function: Callable[[], _T]) -> _T:
    def expired(signum: int, frame: object) -> None:
        del signum, frame
        raise _Deadline(f"{label} exceeded {seconds} seconds")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(seconds)
    try:
        return function()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_up_to(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        chunk = os.read(descriptor, limit - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _read_live_snapshot(
    path: Path, uid: int, *, directory_fd: int | None = None
) -> tuple[bytes, tuple[int, int, int, int, int]] | None:
    """Read the target under the worker's file checks; None when absent."""

    target: str | Path = path.name if directory_fd is not None else path
    try:
        before = os.lstat(target, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_uid != uid:
        raise SystemExit(f"live snapshot is not a regular file owned by uid {uid}: {path}")
    if before.st_size > MAX_SNAPSHOT_BYTES:
        raise SystemExit(f"live snapshot exceeds its size limit: {path}")
    descriptor = os.open(
        target,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        after = os.fstat(descriptor)
        if _identity(after) != _identity(before):
            raise SystemExit(f"live snapshot changed during read: {path}")
        encoded = _read_up_to(descriptor, MAX_SNAPSHOT_BYTES + 1)
    finally:
        os.close(descriptor)
    return encoded, _identity(before)


def _authenticate_snapshot(
    encoded: bytes, keys: Mapping[str, bytes]
) -> ValidatorAccessSnapshot:
    """Verify signature and structure at the snapshot's own generation time.

    Freshness is judged separately, from ``expires_at``, so an expired but
    authentic live file still anchors the rollback checks and the alarm.
    """

    document = parse_registry_json(encoded)
    network = document.get("network")
    netuid = document.get("netuid")
    minimum_stake_rao = document.get("minimum_stake_rao")
    generated_at = document.get("generated_at")
    if (
        not isinstance(network, str)
        or type(netuid) is not int
        or type(minimum_stake_rao) is not int
        or not isinstance(generated_at, str)
        or _TIME_RE.fullmatch(generated_at) is None
    ):
        raise ValidatorAccessError("snapshot binding fields are malformed")
    try:
        signed_at = datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValidatorAccessError("snapshot generated_at is invalid") from exc
    return verify_validator_access_snapshot(
        encoded,
        keys,
        network=network,
        netuid=netuid,
        required_minimum_stake_rao=minimum_stake_rao,
        now=signed_at,
        max_age_seconds=MAX_SNAPSHOT_VALIDITY_SECONDS,
    )


def _binding_problem(snapshot: ValidatorAccessSnapshot, args: argparse.Namespace) -> str | None:
    found = (snapshot.network, snapshot.netuid, snapshot.minimum_stake_rao)
    if found == (args.network, args.netuid, args.minimum_stake_rao):
        return None
    return (
        f"live snapshot is bound to network {snapshot.network} netuid {snapshot.netuid} "
        f"minimum stake {snapshot.minimum_stake_rao} Rao, not the configured network "
        f"{args.network} netuid {args.netuid} minimum stake {args.minimum_stake_rao} Rao"
    )


def _usable_at(snapshot: ValidatorAccessSnapshot, now: datetime) -> bool:
    return snapshot.generated_at <= now < snapshot.expires_at


def _verify_for_install(
    encoded: bytes,
    keys: Mapping[str, bytes],
    args: argparse.Namespace,
    live: ValidatorAccessSnapshot | None,
) -> ValidatorAccessSnapshot:
    """Verify under the configured binding, then mirror the worker's high-water rule.

    A newer finalized block always wins once it verifies, even with an earlier
    expiry: a stepped-back control-host clock or a lowered lifetime must not
    freeze an old validator set. Only a same-block re-sign may not shorten a
    usable window.
    """

    now = _now()
    candidate = verify_validator_access_snapshot(
        encoded,
        keys,
        network=args.network,
        netuid=args.netuid,
        required_minimum_stake_rao=args.minimum_stake_rao,
        now=now,
    )
    if live is None:
        return candidate
    if candidate.block < live.block:
        raise SystemExit(
            f"candidate finalized block {candidate.block} is older than the live "
            f"snapshot's block {live.block}; the worker would refuse it as a rollback"
        )
    if candidate.block == live.block and (
        candidate.block_hash != live.block_hash
        or candidate.authorization_digest != live.authorization_digest
    ):
        raise SystemExit(
            f"candidate changes the validator set at the live snapshot's block {live.block}; "
            "the worker would refuse it as equivocation"
        )
    if (
        candidate.block == live.block
        and _usable_at(live, now)
        and candidate.expires_at < live.expires_at
    ):
        raise SystemExit(
            f"candidate expires at {canonical_utc(candidate.expires_at)}, before the live "
            f"snapshot's {canonical_utc(live.expires_at)}"
        )
    return candidate


def _open_output_directory(path: Path, owner: tuple[int, int], exact_mode: int | None) -> int:
    """Open, check, and exclusively lock the target's directory."""

    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if exact_mode is not None:
            if (metadata.st_uid, metadata.st_gid) != owner or mode != exact_mode:
                raise SystemExit(
                    f"snapshot directory must be owned by {owner[0]}:{owner[1]} with mode "
                    f"{exact_mode:04o}: {path}"
                )
        elif metadata.st_uid != owner[0] or mode & 0o022:
            raise SystemExit(
                f"output directory must be owned by uid {owner[0]} and not writable by "
                f"group or other: {path}"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another validator-access update is running") from None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _remove_stale_candidates(directory_fd: int, name: str, uid: int) -> int:
    """Remove candidates a killed run left behind. They never reach the target."""

    prefix = f".{name}{CANDIDATE_MARKER}"
    removed = 0
    for entry in os.listdir(directory_fd):
        if not entry.startswith(prefix):
            continue
        metadata = os.lstat(entry, dir_fd=directory_fd)
        if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid:
            os.unlink(entry, dir_fd=directory_fd)
            removed += 1
    if removed:
        os.fsync(directory_fd)
    return removed


def _load_live_for_update(
    directory_fd: int, out: Path, uid: int, keys: Mapping[str, bytes], args: argparse.Namespace
) -> tuple[ValidatorAccessSnapshot | None, tuple[int, int, int, int, int] | None, bytes | None]:
    loaded = _read_live_snapshot(out, uid, directory_fd=directory_fd)
    if loaded is None:
        return None, None, None
    encoded, identity = loaded
    live: ValidatorAccessSnapshot | None = None
    try:
        live = _authenticate_snapshot(encoded, keys)
    except ValueError as exc:
        # The worker cannot use a file that does not verify under the pinned
        # keys, so a verified candidate may replace it.
        _journal(4, f"WARNING validator_access_live_unverified reason={_quote(exc)}")
    if live is not None:
        problem = _binding_problem(live, args)
        if problem is not None:
            raise SystemExit(
                problem + "; refusing to rebind. Fix the configuration, or move the live "
                "file aside if the change is deliberate"
            )
    return live, identity, encoded


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write to the candidate snapshot")
        view = view[written:]


def _require_live_unchanged(
    directory_fd: int, name: str, expected: tuple[int, int, int, int, int] | None
) -> None:
    try:
        current: tuple[int, int, int, int, int] | None = _identity(
            os.lstat(name, dir_fd=directory_fd)
        )
    except FileNotFoundError:
        current = None
    if current != expected:
        raise SystemExit("live snapshot changed during the update; leaving it in place")


def _install_candidate(
    directory_fd: int,
    name: str,
    encoded: bytes,
    keys: Mapping[str, bytes],
    args: argparse.Namespace,
    live: ValidatorAccessSnapshot | None,
    live_identity: tuple[int, int, int, int, int] | None,
    owner: tuple[int, int],
) -> ValidatorAccessSnapshot:
    """Write, verify on disk, and atomically rename one candidate beside the target."""

    temporary = f".{name}{CANDIDATE_MARKER}{secrets.token_hex(8)}"
    descriptor = os.open(
        temporary,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=directory_fd,
    )
    installed = False
    try:
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        written = os.pread(descriptor, MAX_SNAPSHOT_BYTES + 1, 0)
        if written != encoded:
            raise SystemExit("candidate snapshot did not read back byte for byte")
        candidate = _verify_for_install(written, keys, args, live)
        os.fchown(descriptor, *owner)
        os.fchmod(descriptor, SNAPSHOT_FILE_MODE)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != owner
            or stat.S_IMODE(metadata.st_mode) != SNAPSHOT_FILE_MODE
            or metadata.st_size != len(encoded)
        ):
            raise SystemExit("candidate snapshot does not carry the required owner and mode")
        _require_live_unchanged(directory_fd, name, live_identity)
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        installed = True
        os.fsync(directory_fd)
    finally:
        os.close(descriptor)
        if not installed:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
    return candidate


def _refresh(
    args: argparse.Namespace, keys: Mapping[str, bytes]
) -> tuple[ValidatorAccessSnapshot, ValidatorAccessSnapshot | None, int]:
    """Control host: sign a fresh view and replace the published file."""

    owner = _output_owner(args)
    out = Path(args.out).absolute()
    if Path(args.signing_key_file).resolve().is_relative_to(out.parent.resolve()):
        raise SystemExit(
            "the signing seed must not live in the output directory; that directory "
            "is published to workers"
        )
    directory_fd = _open_output_directory(out.parent, owner, None)
    try:
        removed = _remove_stale_candidates(directory_fd, out.name, owner[0])
        seed = _read_signing_seed(args.signing_key_file)
        if keys.get(args.signing_key_id) != _public_key(seed):
            raise SystemExit(
                "the signing seed does not match the deployed public key for "
                f"{args.signing_key_id}"
            )
        live, live_identity, _ = _load_live_for_update(
            directory_fd, out, owner[0], keys, args
        )
        encoded, _ = _call_with_deadline(
            args.capture_timeout_seconds, "chain capture", lambda: _capture_signed(args, seed)
        )
        candidate = _install_candidate(
            directory_fd, out.name, encoded, keys, args, live, live_identity, owner
        )
    finally:
        os.close(directory_fd)
    return candidate, live, removed


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urlsplit(newurl).scheme != "https":
            raise SystemExit("snapshot source redirected away from https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _url_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_HttpsOnlyRedirect())


def _oversized() -> SystemExit:
    return SystemExit(f"snapshot source is larger than {MAX_SNAPSHOT_BYTES} bytes")


def _read_https_source(url: str, timeout: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": "cathedral-validator-access-fetch",
        },
    )
    with _url_opener().open(request, timeout=timeout) as response:
        status = getattr(response, "status", None)
        if status != 200:
            raise SystemExit(f"snapshot source answered HTTP {status}")
        length = response.headers.get("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > MAX_SNAPSHOT_BYTES):
            raise _oversized()
        body = response.read(MAX_SNAPSHOT_BYTES + 1)
    if len(body) > MAX_SNAPSHOT_BYTES:
        raise _oversized()
    return body


def _read_local_source(path: str) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"snapshot source is not a regular file: {path}")
        if metadata.st_size > MAX_SNAPSHOT_BYTES:
            raise _oversized()
        body = _read_up_to(descriptor, MAX_SNAPSHOT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(body) > MAX_SNAPSHOT_BYTES:
        raise _oversized()
    return body


def _read_source(source: str, timeout: int) -> bytes:
    if source.startswith("https://"):
        return _read_https_source(source, timeout)
    return _read_local_source(source)


def _fetch(
    args: argparse.Namespace, keys: Mapping[str, bytes]
) -> tuple[ValidatorAccessSnapshot | None, ValidatorAccessSnapshot | None, int]:
    """Worker: pull a signed snapshot and replace the launcher's live file.

    Returns ``(None, live, removed)`` when the source still offers the live bytes.
    """

    owner = _output_owner(args)
    if (os.geteuid(), os.getegid()) != owner:
        raise SystemExit(
            f"run fetch as {owner[0]}:{owner[1]}; the launcher requires a root-owned "
            "live snapshot"
        )
    out = Path(args.out).absolute()
    if not args.source.startswith("https://") and Path(args.source).resolve() == out.resolve():
        raise SystemExit("the snapshot source and the live file are the same path")
    directory_fd = _open_output_directory(out.parent, owner, WORKER_DIRECTORY_MODE)
    try:
        removed = _remove_stale_candidates(directory_fd, out.name, owner[0])
        live, live_identity, live_encoded = _load_live_for_update(
            directory_fd, out, owner[0], keys, args
        )
        encoded = _call_with_deadline(
            args.fetch_timeout_seconds,
            "snapshot fetch",
            lambda: _read_source(args.source, args.fetch_timeout_seconds),
        )
        if live_encoded is not None and encoded == live_encoded:
            return None, live, removed
        # Refuse before any untrusted byte reaches the live directory, then
        # verify again what landed on disk.
        _verify_for_install(encoded, keys, args, live)
        candidate = _install_candidate(
            directory_fd, out.name, encoded, keys, args, live, live_identity, owner
        )
    finally:
        os.close(directory_fd)
    return candidate, live, removed


def _assess_live(
    args: argparse.Namespace, keys: Mapping[str, bytes] | None
) -> tuple[ValidatorAccessSnapshot | None, str | None]:
    """Return the authentic, correctly bound target snapshot, or why there is none."""

    if keys is None:
        return None, "the deployed public-key file did not load"
    try:
        loaded = _read_live_snapshot(Path(args.out), _output_owner(args)[0])
    except (OSError, SystemExit) as exc:
        return None, _reason(exc)
    if loaded is None:
        return None, "no live snapshot"
    try:
        live = _authenticate_snapshot(loaded[0], keys)
    except ValueError as exc:
        return None, f"live snapshot does not verify: {exc}"
    problem = _binding_problem(live, args)
    if problem is not None:
        return None, problem
    return live, None


def _expiry_check(
    args: argparse.Namespace, keys: Mapping[str, bytes] | None, error: BaseException | None
) -> int:
    """Judge the target by its own expires_at after every run, failed or not."""

    now = _now()
    live, problem = _assess_live(args, keys)
    threshold = args.alarm_below_seconds
    remaining = 0
    expires_at = "none"
    if live is not None:
        expires_at = canonical_utc(live.expires_at)
        if threshold is None:
            lifetime = int((live.expires_at - live.generated_at).total_seconds())
            threshold = max(1, lifetime // 3)
        if _usable_at(live, now):
            remaining = int((live.expires_at - now).total_seconds())
        elif now >= live.expires_at:
            problem = "live snapshot has expired"
        else:
            problem = "live snapshot is dated after this host's clock"
    alarm = problem is not None or threshold is None or remaining < threshold
    if error is None and not alarm:
        return 0
    fields = (
        f"command={args.command} remaining_seconds={remaining} "
        f"alarm_below_seconds={'auto' if threshold is None else threshold} "
        f"expires_at={expires_at} live={args.out}"
    )
    if error is not None:
        fields += f" error={_quote(_reason(error))}"
    if problem is not None:
        fields += f" live_problem={_quote(problem)}"
    if alarm:
        _journal(
            3,
            "ERROR validator_access_expiry_alarm: the live validator-access snapshot is "
            "close to or past expires_at and nothing fresher was installed; every "
            "protected route closes at expiry " + fields,
        )
        return EXIT_EXPIRY_ALARM
    # Error priority, so journal filters see it; exit 1 alone does not page.
    _journal(
        3,
        f"ERROR validator_access_{args.command}_failed: the live snapshot was left in "
        "place " + fields,
    )
    return EXIT_UPDATE_FAILED


def _run_update(
    args: argparse.Namespace,
    update: Callable[
        [argparse.Namespace, Mapping[str, bytes]],
        tuple[ValidatorAccessSnapshot | None, ValidatorAccessSnapshot | None, int],
    ],
) -> int:
    keys: dict[str, bytes] | None = None
    try:
        keys = load_policy_keys(args.keys, production_mode=True, pinned_digest=args.keys_digest)
        candidate, live, removed = update(args, keys)
    except (Exception, SystemExit, _Deadline) as exc:  # noqa: BLE001
        # Every failure, including an unexpected one, must reach the expiry check.
        return _expiry_check(args, keys, exc)
    if candidate is None:
        print("outcome unchanged")
    else:
        print("outcome installed")
        print(f"snapshot_digest {candidate.digest}")
        print(f"finalized_block {candidate.block}")
        print(f"qualified_validators {len(candidate.validators)}")
        print(f"generated_at {canonical_utc(candidate.generated_at)}")
        print(f"expires_at {canonical_utc(candidate.expires_at)}")
        print(f"previous_expires_at {canonical_utc(live.expires_at) if live else 'none'}")
    print(f"stale_candidates_removed {removed}")
    print(f"written_to {args.out}")
    return _expiry_check(args, keys, None)


def cmd_refresh(args: argparse.Namespace) -> int:
    return _run_update(args, _refresh)


def cmd_fetch(args: argparse.Namespace) -> int:
    return _run_update(args, _fetch)


def _source(value: str) -> str:
    if value.startswith("https://"):
        parts = urlsplit(value)
        if not parts.hostname or parts.username or parts.password or parts.fragment:
            raise argparse.ArgumentTypeError("source URL needs a host and no credentials")
        return value
    if not value.startswith("/") or "\x00" in value:
        raise argparse.ArgumentTypeError("source must be an https:// URL or an absolute path")
    return value


def _network(value: str) -> str:
    # Same rule as the worker's verifier. A "<NETWORK>" placeholder cannot pass.
    if _NETWORK_RE.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "network must be a lowercase chain name such as the one the worker image checks"
        )
    return value


def _netuid(value: str) -> int:
    if _NETUID_RE.fullmatch(value) is None or int(value) > MAX_NETUID:
        raise argparse.ArgumentTypeError(
            f"netuid must be a canonical integer from 0 to {MAX_NETUID}"
        )
    return int(value)


def _seconds(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]{0,3}", value) is None or int(value) > 3600:
        raise argparse.ArgumentTypeError("seconds must be an integer from 1 to 3600")
    return int(value)


def _refresh_valid_seconds(value: str) -> int:
    seconds = _seconds(value)
    if seconds < MINIMUM_REFRESH_VALID_SECONDS:
        raise argparse.ArgumentTypeError(
            f"refresh validity must be at least {MINIMUM_REFRESH_VALID_SECONDS} seconds"
        )
    return seconds


def _alarm_threshold(value: str) -> int | None:
    return None if value == "auto" else _seconds(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init_key = sub.add_parser(
        "init-key", help="create the snapshot signing seed and pinned public key file"
    )
    init_key.add_argument("--signing-key-id", required=True)
    init_key.add_argument("--signing-key-out", required=True)
    init_key.add_argument("--keys-out", required=True)
    init_key.set_defaults(func=cmd_init_key)

    capture = sub.add_parser("capture", help="capture and atomically rotate a signed snapshot")
    capture.add_argument("--network", required=True)
    capture.add_argument("--netuid", required=True, type=int)
    capture.add_argument("--minimum-stake-rao", required=True, type=int)
    capture.add_argument("--signing-key-id", required=True)
    capture.add_argument("--signing-key-file", required=True)
    capture.add_argument("--out", required=True)
    capture.add_argument("--valid-seconds", type=int, default=900)
    capture.add_argument(
        "--max-age-seconds",
        type=int,
        default=DEFAULT_SNAPSHOT_MAX_AGE_SECONDS,
    )
    capture.add_argument("--require-hotkey", action="append", default=[])
    capture.add_argument("--require-uid-hotkey", action="append", default=[])
    capture.set_defaults(func=cmd_capture)

    verify = sub.add_parser("verify", help="verify a deployed snapshot and pinned keys")
    verify.add_argument("--snapshot", required=True)
    verify.add_argument("--keys", required=True)
    verify.add_argument("--keys-digest", required=True)
    verify.add_argument("--network", required=True)
    verify.add_argument("--netuid", required=True, type=int)
    verify.add_argument("--minimum-stake-rao", required=True, type=int)
    verify.add_argument(
        "--max-age-seconds",
        type=int,
        default=DEFAULT_SNAPSHOT_MAX_AGE_SECONDS,
    )
    verify.add_argument("--require-hotkey", action="append", default=[])
    verify.set_defaults(func=cmd_verify)

    alarm_help = (
        "raise the expiry alarm (exit 3) when the live snapshot has less than this many "
        "seconds left; auto is one third of its own lifetime"
    )
    refresh = sub.add_parser(
        "refresh",
        help=(
            "control host: capture, verify against the deployed keys, and atomically "
            "replace the published snapshot"
        ),
    )
    refresh.add_argument("--network", required=True, type=_network)
    refresh.add_argument("--netuid", required=True, type=_netuid)
    refresh.add_argument("--minimum-stake-rao", required=True, type=int)
    refresh.add_argument("--signing-key-id", required=True)
    refresh.add_argument("--signing-key-file", required=True)
    refresh.add_argument("--keys", required=True, help="the deployed snapshot-keys.json")
    refresh.add_argument("--keys-digest", required=True, help="the worker's pinned keys digest")
    refresh.add_argument("--out", required=True, help="the published validator-access.json")
    refresh.add_argument("--valid-seconds", type=_refresh_valid_seconds, default=900)
    refresh.add_argument(
        "--alarm-below-seconds", type=_alarm_threshold, default="auto", help=alarm_help
    )
    refresh.add_argument("--capture-timeout-seconds", type=_seconds, default=120)
    refresh.add_argument("--require-hotkey", action="append", default=[])
    refresh.add_argument("--require-uid-hotkey", action="append", default=[])
    refresh.set_defaults(func=cmd_refresh, max_age_seconds=DEFAULT_SNAPSHOT_MAX_AGE_SECONDS)

    fetch = sub.add_parser(
        "fetch",
        help=(
            "worker: pull a signed snapshot, verify it against the pinned keys, and "
            "atomically replace the live file; holds no seed and reads no chain"
        ),
    )
    fetch.add_argument(
        "--source", required=True, type=_source, help="an https:// URL or an absolute path"
    )
    fetch.add_argument("--network", required=True, type=_network)
    fetch.add_argument("--netuid", required=True, type=_netuid)
    fetch.add_argument("--minimum-stake-rao", required=True, type=int)
    fetch.add_argument("--keys", required=True, help="the deployed snapshot-keys.json")
    fetch.add_argument("--keys-digest", required=True, help="the worker's pinned keys digest")
    fetch.add_argument("--out", required=True, help="the live validator-access.json")
    fetch.add_argument(
        "--alarm-below-seconds", type=_alarm_threshold, default="auto", help=alarm_help
    )
    fetch.add_argument("--fetch-timeout-seconds", type=_seconds, default=30)
    fetch.set_defaults(func=cmd_fetch)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
