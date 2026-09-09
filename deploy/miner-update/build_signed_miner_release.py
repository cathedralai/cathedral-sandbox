#!/usr/bin/env python3
"""Sign one SN39 miner release record, offline.

Run this on the machine that holds the miner release private key, never in CI
and never on a miner host. It reads no network and writes one JSON file.

A canary names an image directly. A stable record promotes an existing canary
and must name it, so a stable release can always be traced to the canary that
was tested. Promotion re-signs the same image; it never rebuilds it.

    # canary
    python build_signed_miner_release.py canary \\
      --private-key /secure/offline/sn39-miner-release-private-key.pem \\
      --signing-key-id sn39-miner-release-1 \\
      --image ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:<64hex> \\
      --runtime-contract snp-signed-validator-fleet-v1 \\
      --launcher /reviewed/scripts/run_sn39_snp_miner.sh \\
      --version 2026.09.09 --sequence 5 --lifetime-seconds 604800 \\
      --out /secure/signed/miner-canary.json

    # stable, promoting that canary unchanged
    python build_signed_miner_release.py stable \\
      --private-key /secure/offline/sn39-miner-release-private-key.pem \\
      --signing-key-id sn39-miner-release-1 \\
      --promote /secure/signed/miner-canary.json \\
      --sequence 4 --lifetime-seconds 604800 \\
      --out /secure/signed/miner-stable.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from cathedral.miner_release import (  # noqa: E402
    CANONICAL_IMAGE_REPOSITORY,
    MINER_RELEASE_SCHEMA,
    SN39_SNP_MINER_PRODUCT,
    parse_miner_release,
)
from cathedral.policy_registry import canonical_signed_bytes  # noqa: E402

PASSPHRASE_ENV = "CATHEDRAL_MINER_RELEASE_PASSPHRASE"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _fail(message: str) -> None:
    raise SystemExit(f"refusing to sign: {message}")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink():
        _fail("the private key path is a symlink")
    try:
        mode = path.stat().st_mode & 0o777
    except OSError as exc:
        _fail(f"the private key cannot be read: {exc}")
    if mode & 0o077:
        _fail(f"the private key is group or world accessible (mode {mode:04o})")
    data = path.read_bytes()
    # Release keys are stored encrypted at rest. The passphrase comes from the
    # environment so it never appears in the command line or shell history.
    passphrase = os.environ.get(PASSPHRASE_ENV)
    try:
        key = serialization.load_pem_private_key(
            data, password=passphrase.encode("utf-8") if passphrase else None
        )
    except TypeError:
        _fail(f"the private key is encrypted; set {PASSPHRASE_ENV}")
    except ValueError as exc:
        _fail(f"the private key could not be loaded: {exc}")
    if not isinstance(key, Ed25519PrivateKey):
        _fail("the private key is not Ed25519")
    return key


def _public_key_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _sign(body: dict[str, object], key: Ed25519PrivateKey) -> bytes:
    signature = key.sign(canonical_signed_bytes(body))
    signed = dict(body)
    signed["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(signed, sort_keys=True, indent=2).encode("ascii") + b"\n"


def _write(path: Path, payload: bytes) -> None:
    if path.exists():
        _fail(f"output already exists, never overwrite a signed record: {path}")
    path.write_bytes(payload)
    path.chmod(0o644)


def build(arguments: argparse.Namespace) -> int:
    key = _load_private_key(Path(arguments.private_key))
    issued = int(arguments.issued_unix or time.time())
    expires = issued + int(arguments.lifetime_seconds)

    if arguments.channel == "canary":
        image = arguments.image
        if not image.startswith(CANONICAL_IMAGE_REPOSITORY + "@sha256:"):
            _fail("the image must be digest-pinned to the canonical repository")
        if _SHA256_RE.fullmatch(image.split("@sha256:", 1)[1]) is None:
            _fail("the image must use one immutable lowercase sha256 digest")
        launcher = Path(arguments.launcher).read_bytes()
        release: dict[str, object] = {
            "version": arguments.version,
            "image": image,
            "runtime_contract": arguments.runtime_contract,
            "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
        }
    else:
        promoted_raw = Path(arguments.promote).read_bytes()
        # Verify the canary against its own public key before promoting it, so
        # a corrupted or foreign file can never become stable.
        trusted = {arguments.signing_key_id: bytes.fromhex(_public_key_hex(key))}
        canary = parse_miner_release(promoted_raw, trusted_keys=trusted)
        if canary.channel != "canary":
            _fail("the promoted record is not a canary")
        release = {
            "version": canary.version,
            "image": canary.image,
            "runtime_contract": canary.runtime_contract,
            "launcher_sha256": canary.launcher_sha256,
            "promoted_canary": {
                "sequence": canary.sequence,
                "signed_sha256": canary.signed_sha256,
            },
        }

    body = {
        "schema": MINER_RELEASE_SCHEMA,
        "product": SN39_SNP_MINER_PRODUCT,
        "channel": arguments.channel,
        "sequence": int(arguments.sequence),
        "issued_unix": issued,
        "expires_unix": expires,
        "release": release,
        "signing_key_id": arguments.signing_key_id,
    }
    payload = _sign(body, key)

    # Verify what we just produced, with the same parser a miner will use.
    verified = parse_miner_release(
        payload, trusted_keys={arguments.signing_key_id: bytes.fromhex(_public_key_hex(key))}
    )
    _write(Path(arguments.out), payload)
    print(
        json.dumps(
            {
                "channel": verified.channel,
                "sequence": verified.sequence,
                "version": verified.version,
                "image": verified.image,
                "signed_sha256": verified.signed_sha256,
                "signing_key_id": verified.signing_key_id,
                "public_key_hex": _public_key_hex(key),
                "out": str(arguments.out),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("channel", choices=["canary", "stable"])
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--lifetime-seconds", required=True, type=int)
    parser.add_argument("--out", required=True)
    parser.add_argument("--issued-unix", type=int, default=None)
    # canary only
    parser.add_argument("--image")
    parser.add_argument("--runtime-contract")
    parser.add_argument("--launcher")
    parser.add_argument("--version")
    # stable only
    parser.add_argument("--promote")
    arguments = parser.parse_args(argv)

    if arguments.channel == "canary":
        missing = [
            name
            for name in ("image", "runtime_contract", "launcher", "version")
            if getattr(arguments, name) is None
        ]
        if missing:
            parser.error(f"canary requires: {', '.join(sorted(missing))}")
        if arguments.promote is not None:
            parser.error("--promote is only valid for stable")
    else:
        if arguments.promote is None:
            parser.error("stable requires --promote naming the signed canary")
        for name in ("image", "runtime_contract", "launcher", "version"):
            if getattr(arguments, name) is not None:
                parser.error(f"--{name.replace('_', '-')} is only valid for canary")
    return build(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
