#!/usr/bin/env python3
"""Offline root tooling for signed central access (docs/CENTRAL_POOL_ACCESS.md).

The central access verifier (cathedral/central_access.py) trusts an offline
Ed25519 root that delegates, for at most 24 hours, the central routes to one
online central key, and withdraws delegations by signed revocation list. This
tool is what the root holder runs, on the offline host:

  keygen    mint an Ed25519 seed (mode 0600, create-only) for the root or the
            central service; for a root, also write the key file miners pin
            and print its digest;
  delegate  sign one delegation to a central public key, check it against the
            pinned root key file before writing it, and record it in the
            root's append-only ledger, which refuses a sequence that does not
            increase (the worker refuses a delegation older than one it has
            accepted);
  revoke    sign a revocation list, carrying every entry of the previous list
            forward under a higher sequence, and check it before writing it;
  verify    check a delegation or a revocation list against the pinned root
            key file, as a worker would.

Seeds are never printed. The tool installs nothing and overwrites nothing: it
writes new files the operator reviews and moves into place.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.central_access import (
    CENTRAL_ROUTES,
    MAX_DELEGATION_SECONDS,
    CentralAccessError,
    load_central_root_keys,
    sign_delegation,
    sign_revocations,
    verify_delegation,
    verify_revocations,
)
from cathedral.policy_registry import canonical_json, parse_registry_json

_KEY_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_LEDGER_BYTES = 16 * 1024 * 1024
MAX_SEQUENCE = (1 << 63) - 1


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _key_id(value: str) -> str:
    if _KEY_ID_RE.fullmatch(value) is None:
        raise SystemExit("key id must match [a-z0-9][a-z0-9._-]{0,63}")
    return value


def _sequence(value: int, label: str) -> int:
    if not 1 <= value <= MAX_SEQUENCE:
        raise SystemExit(f"{label} must be a positive 63-bit integer")
    return value


def _fsync_parent(path: Path) -> None:
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _write_new(path: Path, data: bytes, mode: int) -> None:
    """Create-only, non-symlink, fsynced write; never replaces anything."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError:
        raise SystemExit(f"refusing to overwrite {path}") from None
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())
    _fsync_parent(path)


def _open_private(path: Path, flags: int) -> int:
    """Open an owner-only regular file without following a symlink."""

    descriptor = os.open(path, flags | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SystemExit(f"{path} must be a regular file")
        if opened.st_mode & 0o077:
            raise SystemExit(f"{path} must not be group or world accessible")
        if opened.st_uid != os.geteuid():
            raise SystemExit(f"{path} must be owned by the invoking user")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _load_seed(path: str) -> bytes:
    """Load a canonical base64 32-byte seed from an owner-only file."""

    try:
        descriptor = _open_private(Path(path), os.O_RDONLY)
    except OSError:
        raise SystemExit("signing key must be a readable regular non-symlink file") from None
    try:
        raw = os.read(descriptor, 129)
    finally:
        os.close(descriptor)
    if len(raw) > 128:
        raise SystemExit("signing key file is too large for a 32-byte seed")
    try:
        text = raw.decode("ascii").strip()
        seed = base64.b64decode(text, validate=True)
    except (UnicodeDecodeError, binascii.Error, ValueError):
        raise SystemExit("signing key must be a canonical 32-byte base64 seed") from None
    if len(seed) != 32 or base64.b64encode(seed).decode("ascii") != text:
        raise SystemExit("signing key must be a canonical 32-byte base64 seed")
    return seed


def _read_document(path: str, label: str) -> dict[str, object]:
    try:
        with open(path, "rb") as handle:
            encoded = handle.read(MAX_DOCUMENT_BYTES + 1)
    except OSError:
        raise SystemExit(f"unable to read {label}") from None
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise SystemExit(f"{label} exceeds the {MAX_DOCUMENT_BYTES}-byte limit")
    try:
        document = parse_registry_json(encoded)
    except ValueError:
        raise SystemExit(f"{label} is not valid JSON") from None
    if not isinstance(document, dict) or encoded.rstrip(b"\n") != canonical_json(document):
        raise SystemExit(f"{label} must be one canonical JSON object")
    return document


def _pinned_root_key(args: argparse.Namespace, seed: bytes) -> dict[str, bytes]:
    """Load the key file miners pin and check this seed is the named root."""

    try:
        keys = load_central_root_keys(args.root_keys, pinned_digest=args.root_keys_digest)
    except CentralAccessError as exc:
        raise SystemExit(str(exc)) from None
    if keys.get(args.root_key_id) != _public_key(seed):
        raise SystemExit(
            "the signing key is not the root key the pinned key file names "
            f"{args.root_key_id!r}; miners would refuse what it signs"
        )
    return keys


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------


def _read_ledger(path: Path) -> list[dict[str, object]]:
    """Every delegation this root signed, oldest first; empty if none yet."""

    try:
        descriptor = _open_private(path, os.O_RDONLY)
    except FileNotFoundError:
        return []
    except OSError:
        raise SystemExit("delegation ledger must be a readable regular non-symlink file") from None
    with os.fdopen(descriptor, "rb") as handle:
        encoded = handle.read(MAX_LEDGER_BYTES + 1)
    if len(encoded) > MAX_LEDGER_BYTES:
        raise SystemExit("delegation ledger exceeds its size limit")
    if encoded and not encoded.endswith(b"\n"):
        raise SystemExit("delegation ledger ends in a partial record")
    records: list[dict[str, object]] = []
    previous = 0
    for line in encoded.splitlines():
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SystemExit("delegation ledger holds a malformed record") from None
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("sequence"), int)
            or isinstance(record.get("sequence"), bool)
            or not isinstance(record.get("digest"), str)
            or _DIGEST_RE.fullmatch(record["digest"]) is None
            or record["sequence"] <= previous
        ):
            raise SystemExit("delegation ledger records must have increasing sequences")
        previous = record["sequence"]
        records.append(record)
    return records


def _append_ledger(path: Path, record: dict[str, object]) -> None:
    descriptor = _open_private(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
    with os.fdopen(descriptor, "ab") as handle:
        handle.write(canonical_json(record) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    _fsync_parent(path)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    key_id = _key_id(args.key_id)
    if args.role == "root" and args.keys_out is None:
        raise SystemExit("a root key needs --keys-out, the key file miners pin")
    if args.role == "central" and args.keys_out is not None:
        raise SystemExit("a central key has no key file; the root delegates to it")
    seed = secrets.token_bytes(32)
    public = base64.b64encode(_public_key(seed)).decode("ascii")
    seed_path = Path(args.seed_out)
    _write_new(seed_path, base64.b64encode(seed) + b"\n", 0o600)
    print(f"role {args.role}")
    print(f"key_id {key_id}")
    print(f"public_key_base64 {public}")
    if args.keys_out is not None:
        keys_document = canonical_json({key_id: public})
        try:
            _write_new(Path(args.keys_out), keys_document, 0o644)
        except BaseException:
            # A root seed whose public key was never published is a live
            # secret with no use: do not leave it behind.
            seed_path.unlink(missing_ok=True)
            _fsync_parent(seed_path)
            raise
        print(f"root_keys_digest {_digest(keys_document)}")
    print(f"private seed written to {seed_path} (mode 0600, never printed)")
    return 0


def cmd_delegate(args: argparse.Namespace) -> int:
    _key_id(args.root_key_id)
    sequence = _sequence(args.sequence, "--sequence")
    if not args.route:
        raise SystemExit("name at least one --route to delegate")
    unknown = sorted(set(args.route) - CENTRAL_ROUTES)
    if unknown:
        raise SystemExit(f"not a central route: {', '.join(unknown)}")
    if not 1 <= args.valid_hours <= MAX_DELEGATION_SECONDS // 3600:
        raise SystemExit(f"--valid-hours must be 1 to {MAX_DELEGATION_SECONDS // 3600}")
    try:
        central_key = base64.b64decode(args.central_public_key, validate=True)
    except (binascii.Error, ValueError):
        raise SystemExit("--central-public-key must be canonical base64") from None
    if (
        len(central_key) != 32
        or base64.b64encode(central_key).decode("ascii") != args.central_public_key
    ):
        raise SystemExit("--central-public-key must be a 32-byte canonical base64 key")

    seed = _load_seed(args.root_key_file)
    keys = _pinned_root_key(args, seed)
    if central_key in keys.values():
        raise SystemExit("the central key must not be a root key")
    ledger = Path(args.ledger)
    records = _read_ledger(ledger)
    if records and sequence <= int(records[-1]["sequence"]):
        raise SystemExit(
            f"--sequence must exceed {records[-1]['sequence']}, the last one this root "
            "signed; a worker refuses a delegation older than one it has accepted"
        )
    out = Path(args.out)
    if out.exists() or out.is_symlink():
        raise SystemExit(f"refusing to overwrite {out}")

    issued_at = _now()
    expires_at = issued_at + timedelta(hours=args.valid_hours)
    try:
        document = sign_delegation(
            root_key_id=args.root_key_id,
            root_seed=seed,
            central_key=central_key,
            routes=args.route,
            network=args.network,
            netuid=args.netuid,
            sequence=sequence,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        delegation = verify_delegation(
            document, keys, network=args.network, netuid=args.netuid, now=issued_at
        )
    except CentralAccessError as exc:
        raise SystemExit(f"delegation refused: {exc}") from None

    # Record the sequence before the file exists, so a failed write can only
    # burn a sequence, never let one be signed twice.
    _append_ledger(
        ledger,
        {
            "sequence": sequence,
            "digest": delegation.digest,
            "root_key_id": args.root_key_id,
            "central_key_base64": args.central_public_key,
            "routes": sorted(delegation.routes),
            "network": args.network,
            "netuid": args.netuid,
            "issued_at": _iso(issued_at),
            "expires_at": _iso(expires_at),
        },
    )
    _write_new(out, canonical_json(document), 0o644)
    print(f"delegation_digest {delegation.digest}")
    print(f"sequence {sequence}")
    print(f"routes {','.join(sorted(delegation.routes))}")
    print(f"subnet {args.network}/{args.netuid}")
    print(f"expires_at {_iso(expires_at)}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    _key_id(args.root_key_id)
    sequence = _sequence(args.sequence, "--sequence")
    seed = _load_seed(args.root_key_file)
    keys = _pinned_root_key(args, seed)

    revoked = set(args.revoke)
    malformed = sorted(item for item in revoked if _DIGEST_RE.fullmatch(item) is None)
    if malformed:
        raise SystemExit(f"not a delegation digest: {', '.join(malformed)}")
    if args.revoke_sequence:
        if args.ledger is None:
            raise SystemExit("--revoke-sequence needs the --ledger that recorded it")
        by_sequence = {
            record["sequence"]: record["digest"] for record in _read_ledger(Path(args.ledger))
        }
        missing = sorted(set(args.revoke_sequence) - set(by_sequence))
        if missing:
            raise SystemExit(f"no delegation with sequence {missing} in the ledger")
        revoked.update(str(by_sequence[number]) for number in args.revoke_sequence)

    if args.previous is not None:
        try:
            previous_sequence, previous = verify_revocations(
                _read_document(args.previous, "previous revocation list"),
                keys,
                minimum_sequence=1,
            )
        except CentralAccessError as exc:
            raise SystemExit(f"previous revocation list refused: {exc}") from None
        if sequence <= previous_sequence:
            raise SystemExit(
                f"--sequence must exceed {previous_sequence}, the previous list's; "
                "a worker keeps the list in force until a newer one arrives"
            )
        revoked.update(previous)
    elif not args.first_list:
        raise SystemExit(
            "pass --previous with the list in force, so its revocations carry "
            "forward, or --first-list when no list has been published"
        )
    if not revoked and not args.allow_empty:
        raise SystemExit("an empty list revokes nothing; pass --allow-empty to mean it")
    out = Path(args.out)
    if out.exists() or out.is_symlink():
        raise SystemExit(f"refusing to overwrite {out}")

    try:
        document = sign_revocations(
            root_key_id=args.root_key_id,
            root_seed=seed,
            sequence=sequence,
            issued_at=_now(),
            revoked=sorted(revoked),
        )
        verify_revocations(document, keys, minimum_sequence=sequence)
    except CentralAccessError as exc:
        raise SystemExit(f"revocation list refused: {exc}") from None
    _write_new(out, canonical_json(document), 0o644)
    print(f"revocations_sequence {sequence}")
    print(f"revoked {len(revoked)}")
    print(f"revocations_digest {_digest(canonical_json(document))}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        keys = load_central_root_keys(args.root_keys, pinned_digest=args.root_keys_digest)
        if args.delegation is not None:
            if args.network is None or args.netuid is None:
                raise SystemExit("checking a delegation needs the worker's --network and --netuid")
            delegation = verify_delegation(
                _read_document(args.delegation, "delegation"),
                keys,
                network=args.network,
                netuid=args.netuid,
                now=_now(),
            )
            print("CENTRAL_DELEGATION_VALID")
            print(f"delegation_digest {delegation.digest}")
            print(f"root_key_id {delegation.root_key_id}")
            print(f"sequence {delegation.sequence}")
            print(f"routes {','.join(sorted(delegation.routes))}")
            print(f"expires_at {_iso(delegation.expires_at)}")
        else:
            sequence, revoked = verify_revocations(
                _read_document(args.revocations, "revocation list"), keys, minimum_sequence=1
            )
            print("CENTRAL_REVOCATIONS_VALID")
            print(f"revocations_sequence {sequence}")
            print(f"revoked {len(revoked)}")
    except CentralAccessError as exc:
        print(f"CENTRAL_ACCESS_INVALID {exc}")
        return 1
    return 0


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def _pinned_keys_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root-keys", required=True, help="the root key file miners pin")
    parser.add_argument("--root-keys-digest", required=True, metavar="sha256:HEX")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cathedral_central_access.py",
        description="Offline root tooling for signed central access to opted-in miners.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="mint a root or central Ed25519 seed")
    keygen.add_argument("--role", choices=("root", "central"), required=True)
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--seed-out", required=True, help="mode-0600 seed, never shared")
    keygen.add_argument("--keys-out", help="root only: the key file miners pin")
    keygen.set_defaults(func=cmd_keygen)

    delegate = sub.add_parser("delegate", help="sign one delegation to a central key")
    delegate.add_argument("--root-key-file", required=True)
    delegate.add_argument("--root-key-id", required=True)
    _pinned_keys_arguments(delegate)
    delegate.add_argument("--central-public-key", required=True, metavar="BASE64")
    delegate.add_argument(
        "--route", action="append", default=[], help="repeatable; a central route to grant"
    )
    delegate.add_argument("--network", required=True)
    delegate.add_argument("--netuid", type=int, required=True)
    delegate.add_argument("--sequence", type=int, required=True, help="must exceed the last")
    delegate.add_argument("--valid-hours", type=int, default=24)
    delegate.add_argument("--ledger", required=True, help="owner-only record of every delegation")
    delegate.add_argument("--out", required=True)
    delegate.set_defaults(func=cmd_delegate)

    revoke = sub.add_parser("revoke", help="sign a revocation list")
    revoke.add_argument("--root-key-file", required=True)
    revoke.add_argument("--root-key-id", required=True)
    _pinned_keys_arguments(revoke)
    revoke.add_argument("--sequence", type=int, required=True, help="must exceed the previous")
    revoke.add_argument(
        "--revoke", action="append", default=[], metavar="sha256:HEX", help="repeatable"
    )
    revoke.add_argument(
        "--revoke-sequence", action="append", type=int, default=[], help="repeatable; from --ledger"
    )
    revoke.add_argument("--ledger")
    revoke.add_argument("--previous", help="the revocation list in force")
    revoke.add_argument("--first-list", action="store_true", help="no list was published before")
    revoke.add_argument("--allow-empty", action="store_true")
    revoke.add_argument("--out", required=True)
    revoke.set_defaults(func=cmd_revoke)

    verify = sub.add_parser("verify", help="check a delegation or revocation list")
    _pinned_keys_arguments(verify)
    target = verify.add_mutually_exclusive_group(required=True)
    target.add_argument("--delegation")
    target.add_argument("--revocations")
    verify.add_argument("--network")
    verify.add_argument("--netuid", type=int)
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
