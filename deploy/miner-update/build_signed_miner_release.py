#!/usr/bin/env python3
"""Build a miner host bundle and sign a miner release record, offline.

Run on the machine that holds the release private key, never in CI and never
on a miner host. It reads no network.

    # 0. once per key: print the trust-root entry to commit in
    #    deploy/miner-update/release-keys.json
    build_signed_miner_release.py trust-entry --private-key K --key-id ID --channels canary

    # 1. build the bundle for one product from this checkout
    build_signed_miner_release.py bundle --product snp-miner --out-dir DIR

    # 2. sign a canary that names the image and that bundle
    build_signed_miner_release.py canary --private-key K --signing-key-id ID \\
      --product snp-miner --network NETWORK --netuid NETUID \\
      --image ghcr.io/cathedralai/<repository>@sha256:<64hex> --state-schema 2 \\
      --bundle-archive DIR/<archive> --bundle-url https://.../<archive> \\
      --version V --sequence S --lifetime-seconds 604800 --out canary.json

    # 3. promote that exact canary to stable, signed with the stable key. It
    #    rebuilds the tree from this checkout and refuses unless it matches.
    build_signed_miner_release.py stable --private-key K2 --signing-key-id ID2 \\
      --promote canary.json --bundle-archive DIR/<archive> \\
      --sequence S2 --lifetime-seconds 604800 --out stable.json

The state schema is the image's org.cathedral.state-schema label, which is
cathedral.validator_access.DURABLE_STATE_SCHEMA at the commit it was built from.

Private keys must be encrypted PEM (the passphrase is read from
CATHEDRAL_MINER_RELEASE_PASSPHRASE). Records live at most 14 days and may not
be issued more than 300 seconds in the future: the same rules the host
enforces. Output files are never overwritten.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from cathedral.miner_bundle import (  # noqa: E402
    REPOSITORY_TRUST_ROOT,
    TREE_LAUNCHER,
    TREE_TRUST_ROOT,
    assemble_tree,
    build_archive,
    extract_archive,
    release_tree_sha256,
    sha256_bytes,
)
from cathedral.miner_products import product_by_name, read_launcher_profile  # noqa: E402
from cathedral.miner_release import (  # noqa: E402
    CHANNELS,
    MINER_RELEASE_SCHEMA,
    MinerReleaseError,
    check_validity_window,
    https_url,
    load_trust_root,
    parse_miner_release,
    signed_bytes,
    split_image,
    strict_json,
)

PASSPHRASE_ENV = "CATHEDRAL_MINER_RELEASE_PASSPHRASE"


def _fail(message: str) -> None:
    raise SystemExit(f"refusing: {message}")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    if path.is_symlink():
        _fail("the private key path is a symlink")
    try:
        mode = path.stat().st_mode & 0o777
        data = path.read_bytes()
    except OSError as exc:
        _fail(f"the private key cannot be read: {exc}")
    if mode & 0o077:
        _fail(f"the private key is group or world accessible (mode {mode:04o})")
    try:
        serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pass  # encrypted, as required
    except ValueError as exc:
        _fail(f"the private key could not be loaded: {exc}")
    else:
        _fail("the private key is not encrypted; release keys are stored encrypted at rest")
    passphrase = os.environ.get(PASSPHRASE_ENV)
    if not passphrase:
        _fail(f"set {PASSPHRASE_ENV} to the private key's passphrase")
    try:
        key = serialization.load_pem_private_key(data, password=passphrase.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        _fail(f"the private key could not be decrypted: {exc}")
    if not isinstance(key, Ed25519PrivateKey):
        _fail("the private key is not Ed25519")
    return key


def _public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def _write_new(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError:
        _fail(f"output already exists, never overwrite a signed artifact: {path}")
    path.chmod(0o644)


def _sign(body: dict[str, object], key: Ed25519PrivateKey) -> bytes:
    signature = key.sign(signed_bytes(body))
    document = dict(body)
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(document, sort_keys=True, indent=2).encode("ascii") + b"\n"


class _Bundle:
    """An archive, extracted and hashed exactly as a host will."""

    def __init__(self, archive_path: Path) -> None:
        self.archive = archive_path.read_bytes()
        self.archive_sha256 = sha256_bytes(self.archive)
        self._work = tempfile.TemporaryDirectory()
        self.tree = Path(self._work.name) / "tree"
        extract_archive(self.archive, self.tree)
        self.tree_sha256 = release_tree_sha256(self.tree)
        self.profile = read_launcher_profile(self.tree / TREE_LAUNCHER)
        self.trust = load_trust_root((self.tree / TREE_TRUST_ROOT).read_bytes())

    def require_key(self, key_id: str, public_hex: str, channel: str) -> None:
        entry = self.trust.get(key_id)
        if entry is None or entry.public_key.hex() != public_hex or channel not in entry.channels:
            _fail(
                f"the bundle's trust root does not let {key_id} sign {channel}; every host "
                "probe would refuse this release"
            )


def _window(arguments: argparse.Namespace) -> tuple[int, int]:
    now = int(time.time())
    issued = int(arguments.issued_unix) if arguments.issued_unix is not None else now
    expires = issued + int(arguments.lifetime_seconds)
    try:
        check_validity_window(issued, expires, now_unix=now)
    except MinerReleaseError as exc:
        _fail(str(exc))
    return issued, expires


def _emit(payload: bytes, arguments: argparse.Namespace, key: Ed25519PrivateKey, trusted) -> int:
    document = strict_json(payload, label="signed record")
    verified = parse_miner_release(
        payload,
        trusted_keys=trusted,
        expected_product=document["product"],
        expected_network=document["network"],
        expected_netuid=document["netuid"],
        expected_channel=document["channel"],
        now_unix=max(int(time.time()), document["issued_unix"]),
    )
    _write_new(Path(arguments.out), payload)
    print(
        json.dumps(
            {
                "product": verified.product,
                "network": verified.network,
                "netuid": verified.netuid,
                "channel": verified.channel,
                "sequence": verified.sequence,
                "version": verified.version,
                "image": verified.image,
                "state_schema": verified.state_schema,
                "tree_sha256": verified.bundle.tree_sha256,
                "signed_sha256": verified.signed_sha256,
                "signing_key_id": verified.signing_key_id,
                "public_key_sha256": "sha256:" + hashlib.sha256(bytes.fromhex(_public_hex(key))).hexdigest(),
                "expires_unix": verified.expires_unix,
                "out": str(arguments.out),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_trust_entry(arguments: argparse.Namespace) -> int:
    key = _load_private_key(Path(arguments.private_key))
    channels = [channel.strip() for channel in arguments.channels.split(",") if channel.strip()]
    if not channels or any(channel not in CHANNELS for channel in channels):
        _fail("--channels must list canary and/or stable")
    print(json.dumps({arguments.key_id: {"public_key_hex": _public_hex(key), "channels": channels}}, indent=2))
    return 0


def command_bundle(arguments: argparse.Namespace) -> int:
    product = product_by_name(arguments.product)
    trust = Path(arguments.trust_root) if arguments.trust_root else REPOSITORY_ROOT / REPOSITORY_TRUST_ROOT
    with tempfile.TemporaryDirectory() as work:
        tree = Path(work) / "tree"
        assemble_tree(REPOSITORY_ROOT, product, tree, trust_root=trust)
        tree_sha256 = release_tree_sha256(tree)
        archive = build_archive(tree)
        launcher_sha256 = sha256_bytes((tree / TREE_LAUNCHER).read_bytes())
    out_dir = Path(arguments.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"cathedral-miner-bundle-{product.product}-{tree_sha256}.tar.gz"
    _write_new(path, archive)
    print(
        json.dumps(
            {
                "product": product.product,
                "archive": str(path),
                "archive_sha256": sha256_bytes(archive),
                "tree_sha256": tree_sha256,
                "launcher_sha256": launcher_sha256,
                "trust_root_sha256": sha256_bytes(trust.read_bytes()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def command_canary(arguments: argparse.Namespace) -> int:
    product = product_by_name(arguments.product)
    key = _load_private_key(Path(arguments.private_key))
    bundle = _Bundle(Path(arguments.bundle_archive))
    if bundle.profile.runtime_contract != product.runtime_contract:
        _fail("the bundle's launcher is for another product")
    try:
        repository, _digest = split_image(arguments.image)
        https_url(arguments.bundle_url, "--bundle-url")
    except MinerReleaseError as exc:
        _fail(str(exc))
    if repository != bundle.profile.image_repository:
        _fail("the image is not in the repository the bundle's launcher requires")
    bundle.require_key(arguments.signing_key_id, _public_hex(key), "canary")
    _announce_trust("canary hosts will trust", (bundle.tree / TREE_TRUST_ROOT).read_bytes(), bundle.trust)
    issued, expires = _window(arguments)
    body = {
        "schema": MINER_RELEASE_SCHEMA,
        "product": product.product,
        "network": arguments.network,
        "netuid": int(arguments.netuid),
        "channel": "canary",
        "sequence": int(arguments.sequence),
        "issued_unix": issued,
        "expires_unix": expires,
        "release": {
            "version": arguments.version,
            "image": arguments.image,
            "runtime_contract": bundle.profile.runtime_contract,
            "state_schema": int(arguments.state_schema),
            "bundle": {
                "url": arguments.bundle_url,
                "archive_sha256": bundle.archive_sha256,
                "tree_sha256": bundle.tree_sha256,
            },
        },
        "signing_key_id": arguments.signing_key_id,
    }
    return _emit(_sign(body, key), arguments, key, bundle.trust)


def _announce_trust(label: str, trust_bytes: bytes, trust) -> None:
    """Print what the stable hosts will trust, before anything is signed."""

    print(f"{label}: trust root sha256 {sha256_bytes(trust_bytes)}", file=sys.stderr)
    for key_id, entry in sorted(trust.items()):
        print(
            f"  {key_id}: {entry.fingerprint} may sign {', '.join(sorted(entry.channels))}",
            file=sys.stderr,
        )


def _rebuild(product_name: str, trust_path: Path) -> str:
    """The tree this signer's own checkout builds for a product."""

    with tempfile.TemporaryDirectory() as work:
        tree = Path(work) / "tree"
        assemble_tree(REPOSITORY_ROOT, product_by_name(product_name), tree, trust_root=trust_path)
        return release_tree_sha256(tree)


def command_stable(arguments: argparse.Namespace) -> int:
    key = _load_private_key(Path(arguments.private_key))
    bundle = _Bundle(Path(arguments.bundle_archive))
    raw = Path(arguments.promote).read_bytes()
    document = strict_json(raw, label="canary record")
    trust_path = Path(arguments.trust_root) if arguments.trust_root else REPOSITORY_ROOT / REPOSITORY_TRUST_ROOT
    # A canary key must never put code or a stable key onto stable hosts. So
    # the stable signer rebuilds the tree from its own reviewed checkout and
    # trust root, and promotes only a canary whose bundle is exactly that tree
    # (trust review P1-2). Only then is the canary verified, against that root.
    if not isinstance(document, dict) or not isinstance(document.get("product"), str):
        _fail("the canary record names no product")
    rebuilt = _rebuild(document["product"], trust_path)
    if rebuilt != bundle.tree_sha256:
        _fail(
            f"the canary's bundle tree {bundle.tree_sha256} does not match this checkout's "
            f"rebuild {rebuilt}; promote only what this checkout builds"
        )
    _announce_trust("stable hosts will trust", trust_path.read_bytes(), bundle.trust)
    try:
        canary = parse_miner_release(
            raw,
            trusted_keys=bundle.trust,
            expected_product=document.get("product"),
            expected_network=document.get("network"),
            expected_netuid=document.get("netuid"),
            expected_channel="canary",
            now_unix=int(time.time()),
        )
    except MinerReleaseError as exc:
        _fail(f"the canary does not verify: {exc}")
    if (canary.bundle.archive_sha256, canary.bundle.tree_sha256) != (
        bundle.archive_sha256,
        bundle.tree_sha256,
    ):
        _fail("--bundle-archive is not the canary's bundle")
    bundle.require_key(arguments.signing_key_id, _public_hex(key), "stable")
    issued, expires = _window(arguments)
    body = {
        "schema": MINER_RELEASE_SCHEMA,
        "product": canary.product,
        "network": canary.network,
        "netuid": canary.netuid,
        "channel": "stable",
        "sequence": int(arguments.sequence),
        "issued_unix": issued,
        "expires_unix": expires,
        "release": {
            "version": canary.version,
            "image": canary.image,
            "runtime_contract": canary.runtime_contract,
            "state_schema": canary.state_schema,
            "bundle": {
                "url": canary.bundle.url,
                "archive_sha256": canary.bundle.archive_sha256,
                "tree_sha256": canary.bundle.tree_sha256,
            },
            "promoted_canary": {
                "sequence": canary.sequence,
                "signed_sha256": canary.signed_sha256,
                "image": canary.image,
                "tree_sha256": canary.bundle.tree_sha256,
            },
        },
        "signing_key_id": arguments.signing_key_id,
    }
    return _emit(_sign(body, key), arguments, key, bundle.trust)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    entry = commands.add_parser("trust-entry")
    entry.add_argument("--private-key", required=True)
    entry.add_argument("--key-id", required=True)
    entry.add_argument("--channels", required=True)

    bundle = commands.add_parser("bundle")
    bundle.add_argument("--product", required=True)
    bundle.add_argument("--out-dir", required=True)
    bundle.add_argument("--trust-root", default=None)

    for name in ("canary", "stable"):
        signer = commands.add_parser(name)
        signer.add_argument("--private-key", required=True)
        signer.add_argument("--signing-key-id", required=True)
        signer.add_argument("--bundle-archive", required=True)
        signer.add_argument("--sequence", required=True, type=int)
        signer.add_argument("--lifetime-seconds", required=True, type=int)
        signer.add_argument("--issued-unix", type=int, default=None)
        signer.add_argument("--out", required=True)
        if name == "canary":
            signer.add_argument("--product", required=True)
            signer.add_argument("--network", required=True)
            signer.add_argument("--netuid", required=True, type=int)
            signer.add_argument("--image", required=True)
            signer.add_argument("--state-schema", required=True, type=int)
            signer.add_argument("--bundle-url", required=True)
            signer.add_argument("--version", required=True)
        else:
            signer.add_argument("--promote", required=True)
            signer.add_argument("--trust-root", default=None)

    arguments = parser.parse_args(argv)
    handlers = {
        "trust-entry": command_trust_entry,
        "bundle": command_bundle,
        "canary": command_canary,
        "stable": command_stable,
    }
    try:
        return handlers[arguments.command](arguments)
    except MinerReleaseError as exc:
        _fail(str(exc))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
