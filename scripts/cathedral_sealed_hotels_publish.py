#!/usr/bin/env python3
"""Sign the next cathedral_sealed_hotels_v1 release (AB#382 work package 2 publisher).

Runs on the machine that holds the signing key (today: the ops server, local
interim key; later: AWS KMS through the same signer config). It reads no
network.

    cathedral_sealed_hotels_publish.py \\
      --signer-config /path/signers.json --purpose sealed_hotels \\
      --pins docs/keys/sealed-hotels-pins.json \\
      --inventory inventory.json \\
      --state /var/lib/cathedral-sealed-hotels/publisher-state.json \\
      --out-dir /path/out

``inventory.json`` is the reviewed hotel and build inventory:

    {"hotels": {"<enrolled hotel ID>": {"chip_id": "<128 hex>", "measurements": ["<96 hex>", ...]}}}

Durable state (the last release number and digest) lives outside the
repository, mode 600, written atomically with a directory sync, so a release
number is never reused with another digest. A missing state file is an error
unless ``--init-state`` is given together with an explicit ``--release N``
above every release ever published (``--release 1`` for the very first one). The next release
number is the recorded one plus 1; ``--release N`` may only go higher.

Outputs (never overwritten): ``<out-dir>/release-<N>.json`` (exact signed
bytes) and ``<out-dir>/<sha256 hex>.json`` (the same bytes, immutable name).
The new release is verified against the pin file before state is committed.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from cathedral.sealed_hotels import (  # noqa: E402
    SealedHotelsError,
    build_unsigned,
    check_successor,
    parse_pins,
    sign_envelope,
    strict_json,
    verify_envelope,
)
from cathedral.signer import SignerError, signer_from_config  # noqa: E402

STATE_SCHEMA = "cathedral_sealed_hotels_publisher_state_v1"
_STATE_KEYS = frozenset({"schema", "last_release", "last_digest", "last_generated_at", "key_id"})


def _fail(message: str) -> None:
    raise SystemExit(f"refusing: {message}")


def _inside_repository(path: Path) -> bool:
    resolved = path.resolve()
    return resolved == REPOSITORY_ROOT or REPOSITORY_ROOT in resolved.parents


def read_state(path: Path) -> dict[str, object] | None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        _fail(f"state {path} is not a regular file")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        _fail(f"state {path} must be owned by the running user with mode 600")
    try:
        state = strict_json(path.read_bytes(), limit=64 * 1024, what="publisher state")
    except SealedHotelsError as exc:
        _fail(f"state {path} is corrupt ({exc}); never reset it silently")
    if frozenset(state) != _STATE_KEYS or state["schema"] != STATE_SCHEMA:
        _fail(f"state {path} has the wrong schema or fields; never reset it silently")
    release = state["last_release"]
    if isinstance(release, bool) or not isinstance(release, int) or release < 1:
        _fail(f"state {path} last_release is not a positive integer; never reset it silently")
    if not isinstance(state["last_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", state["last_digest"]):
        _fail(f"state {path} last_digest is malformed; never reset it silently")
    return state


def write_state(path: Path, state: dict[str, object]) -> None:
    payload = json.dumps(state, sort_keys=True, indent=2).encode("ascii") + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_new(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        _fail(f"output already exists, never overwrite a signed release: {path}")
    path.chmod(0o644)


def load_inventory(path: Path) -> dict[str, object]:
    try:
        inventory = strict_json(path.read_bytes(), limit=64 * 1024, what="inventory")
    except (OSError, SealedHotelsError) as exc:
        _fail(f"inventory: {exc}")
    if frozenset(inventory) != {"hotels"} or not isinstance(inventory["hotels"], dict):
        _fail('inventory must be exactly {"hotels": {...}}')
    return inventory["hotels"]  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--signer-config", required=True, type=Path)
    parser.add_argument("--purpose", default="sealed_hotels")
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--init-state", action="store_true", help="create missing state; needs --release above every release ever published")
    parser.add_argument("--release", type=int, help="explicit release number, above the recorded one")
    parser.add_argument("--lifetime-hours", type=int, default=24)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    if _inside_repository(args.state):
        _fail("publisher state must live outside the repository")
    # valid_until is a hard limit separate from the 24 hour maximum age (decision 2).
    if not 1 <= args.lifetime_hours <= 24 * 14:
        _fail("lifetime must be between 1 hour and 14 days")
    if not args.out_dir.is_dir():
        _fail(f"output directory {args.out_dir} does not exist")
    try:
        pins = parse_pins(args.pins.read_bytes())
    except (OSError, SealedHotelsError) as exc:
        _fail(f"pin file: {exc}")
    hotels = load_inventory(args.inventory)

    args.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = args.state.with_name(f".{args.state.name}.lock")
    lock = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _fail("another publisher run holds the state lock")
        state = read_state(args.state)
        if state is None and not args.init_state:
            _fail(f"no publisher state at {args.state}; pass --init-state only for the first release")
        if state is not None and args.init_state:
            _fail("--init-state given but publisher state already exists")
        if state is None and args.release is None:
            # Lost state must never silently restart at 1: the operator names a
            # release above every release ever published.
            _fail("--init-state needs an explicit --release above every release ever published")
        last_release = int(state["last_release"]) if state else 0
        release = args.release if args.release is not None else last_release + 1
        if release <= last_release:
            _fail(f"release {release} is not above the recorded release {last_release}")

        try:
            signer = signer_from_config(args.signer_config, args.purpose)
        except SignerError as exc:
            _fail(f"signer: {exc}")
        pin = pins.get(signer.key_id)
        if pin is None:
            _fail(f"signer key {signer.key_id!r} is not in the pin file")
        if signer.public_key_raw() != pin.public_key:
            _fail(f"signer key {signer.key_id!r} does not match its pin")

        now = datetime.now(UTC).replace(microsecond=0)
        try:
            unsigned = build_unsigned(
                release=release,
                generated_at=now,
                valid_from=now,
                valid_until=now + timedelta(hours=args.lifetime_hours),
                key_id=signer.key_id,
                hotels=hotels,  # type: ignore[arg-type]
            )
            envelope = sign_envelope(unsigned, signer)
            verified = verify_envelope(envelope, pins, now=now)
            previous = (last_release, str(state["last_digest"])) if state else None
            check_successor(previous, verified)
        except (SealedHotelsError, SignerError) as exc:
            _fail(str(exc))

        digest_hex = hashlib.sha256(envelope).hexdigest()
        release_path = args.out_dir / f"release-{release}.json"
        immutable_path = args.out_dir / f"{digest_hex}.json"
        for path in (release_path, immutable_path):
            if path.exists():
                _fail(f"output already exists, never overwrite a signed release: {path}")
        # Commit the high-water first: a crash after this burns the number, never reuses it.
        write_state(
            args.state,
            {
                "schema": STATE_SCHEMA,
                "last_release": release,
                "last_digest": verified.digest,
                "last_generated_at": unsigned["generated_at"],
                "key_id": signer.key_id,
            },
        )
        _write_new(release_path, envelope)
        _write_new(immutable_path, envelope)
    finally:
        os.close(lock)
    print(
        json.dumps(
            {
                "release": release,
                "digest": verified.digest,
                "key_id": signer.key_id,
                "key_fingerprint_sha256": pin.fingerprint,
                "generated_at": unsigned["generated_at"],
                "valid_until": unsigned["valid_until"],
                "bytes": len(envelope),
                "release_file": str(release_path),
                "immutable_file": str(immutable_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
