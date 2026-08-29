#!/usr/bin/env python3
"""Capture, sign, rotate, and verify Cathedral validator-access snapshots.

Chain reads happen only in this host-side operator command. The worker receives
one bounded signed artifact and has no Bittensor RPC client or wallet.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import secrets
import stat
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.admission_policy import load_policy_keys  # noqa: E402
from cathedral.policy_registry import canonical_json  # noqa: E402
from cathedral.validator_access import (  # noqa: E402
    DEFAULT_SNAPSHOT_MAX_AGE_SECONDS,
    MAX_STAKE_RAO,
    MAX_VALIDATORS,
    VALIDATOR_ACCESS_SNAPSHOT_SCHEMA,
    bittensor_account_id,
    canonical_utc,
    sign_validator_access_snapshot,
    verify_validator_access_snapshot,
)

_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


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


def cmd_capture(args: argparse.Namespace) -> int:
    seed = _read_signing_seed(args.signing_key_file)
    block, block_hash, neurons = _finalized_neurons(args.network, args.netuid)
    generated_at = _now()
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
