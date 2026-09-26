"""Shared fixtures for the miner updater tests.

The harness host keeps every file effect real (bundle trees, activation
directories, symlink flips, state) under a temporary root, and fakes only
docker and systemd: a restart makes the miner container report the image of
whatever ``miner/current`` names, unless the test marks that image broken.

The netuid is drawn at random per session so no test depends on one value.
Launcher-specific names (repository, container, image variable) are read from
the repository's real launchers at run time.
"""

from __future__ import annotations

import base64
import json
import os
import random
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.miner_bundle import (
    TREE_LAUNCHER,
    TREE_TRUST_ROOT,
    assemble_tree,
    atomic_symlink,
    build_archive,
    install_directory,
    link_target,
    release_tree_sha256,
    sha256_bytes,
)
from cathedral.miner_products import SNP_MINER, MinerProduct, read_launcher_profile
from cathedral.miner_release import (
    MINER_RELEASE_SCHEMA,
    TRUST_ROOT_SCHEMA,
    load_trust_root,
    signed_bytes,
)
from cathedral.miner_updater import (
    CONFIG_SCHEMA,
    LEGACY,
    HostConfig,
    HostPaths,
    MinerUpdateError,
    MinerUpdaterHost,
    UpdateOutcome,
    probe_release,
    read_activation_profile,
    read_state,
    update_once,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

NETWORK = "testnet"
NETUID = random.SystemRandom().randrange(1, 65535)
OTHER_NETUID = (NETUID % 65535) + 1

NOW = 1_800_000_000
DAY = 24 * 60 * 60

CANARY_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
STABLE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))

DEFAULT_TRUST = {"canary-1": (CANARY_KEY, ["canary"]), "stable-1": (STABLE_KEY, ["stable"])}
MINER_UNIT = "cathedral-test-miner.service"
CHANNEL_URL = "https://127.0.0.1:9/miner/stable.json"  # a closed port: no test contacts a host
BUNDLE_URL = "https://127.0.0.1:9/miner/bundle.tar.gz"


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ).hex()


def trust_root_bytes(keys: dict[str, tuple[Ed25519PrivateKey, list[str]]] = DEFAULT_TRUST) -> bytes:
    return json.dumps(
        {
            "schema": TRUST_ROOT_SCHEMA,
            "keys": {
                key_id: {"public_key_hex": public_hex(key), "channels": channels}
                for key_id, (key, channels) in keys.items()
            },
        },
        sort_keys=True,
    ).encode("ascii")


def trusted(keys=DEFAULT_TRUST):
    return load_trust_root(trust_root_bytes(keys))


def _writable(path: Path) -> None:
    os.chmod(path, 0o644)


def build_tree(
    destination: Path,
    *,
    product: MinerProduct = SNP_MINER,
    trust: dict | None = None,
    launcher_suffix: bytes = b"",
    replace_modules: dict[str, bytes] | None = None,
) -> str:
    """Assemble a bundle tree from this checkout, optionally changed, and return its digest."""

    trust_file = destination.parent / f".{destination.name}.trust.json"
    trust_file.write_bytes(trust_root_bytes(trust or DEFAULT_TRUST))
    assemble_tree(REPO_ROOT, product, destination, trust_root=trust_file)
    trust_file.unlink()
    if launcher_suffix:
        launcher = destination / TREE_LAUNCHER
        _writable(launcher)
        launcher.write_bytes(launcher.read_bytes() + launcher_suffix)
        os.chmod(launcher, 0o555)
    for name, body in (replace_modules or {}).items():
        module = destination / "updater" / "cathedral" / name
        _writable(module)
        module.write_bytes(body)
        os.chmod(module, 0o444)
    return release_tree_sha256(destination)


def build_bundle(work: Path, **kwargs) -> tuple[bytes, str, str]:
    """(archive bytes, archive sha256, tree sha256) for a bundle built from this checkout."""

    index = 0
    while (work / f"bundle-{index}").exists():
        index += 1
    tree = work / f"bundle-{index}"
    tree_sha256 = build_tree(tree, **kwargs)
    archive = build_archive(tree)
    return archive, sha256_bytes(archive), tree_sha256


def sign_record(
    *,
    image: str,
    archive_sha256: str,
    tree_sha256: str,
    sequence: int = 5,
    channel: str = "stable",
    key: Ed25519PrivateKey | None = None,
    key_id: str | None = None,
    state_schema: int = 1,
    version: str = "2026.09.26",
    issued: int = NOW - 60,
    lifetime: int = 7 * DAY,
    product: str = "snp-miner",
    network: str = NETWORK,
    netuid: int | None = None,
    bundle_url: str = BUNDLE_URL,
    mutate: Callable[[dict], None] | None = None,
) -> bytes:
    if key is None:
        key = STABLE_KEY if channel == "stable" else CANARY_KEY
    if key_id is None:
        key_id = "stable-1" if channel == "stable" else "canary-1"
    release: dict[str, object] = {
        "version": version,
        "image": image,
        "runtime_contract": "snp-signed-validator-fleet-v1"
        if product == "snp-miner"
        else "signed-validator-fleet-v1",
        "state_schema": state_schema,
        "bundle": {"url": bundle_url, "archive_sha256": archive_sha256, "tree_sha256": tree_sha256},
    }
    if channel == "stable":
        release["promoted_canary"] = {
            "sequence": max(1, sequence - 1),
            "signed_sha256": "5" * 64,
            "image": image,
            "tree_sha256": tree_sha256,
        }
    body: dict[str, object] = {
        "schema": MINER_RELEASE_SCHEMA,
        "product": product,
        "network": network,
        "netuid": NETUID if netuid is None else netuid,
        "channel": channel,
        "sequence": sequence,
        "issued_unix": issued,
        "expires_unix": issued + lifetime,
        "release": release,
        "signing_key_id": key_id,
    }
    if mutate is not None:
        mutate(body)
    signature = key.sign(signed_bytes(body))
    body["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return json.dumps(body, sort_keys=True).encode("utf-8")


def config_document(**overrides) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": CONFIG_SCHEMA,
        "product": "snp-miner",
        "network": NETWORK,
        "netuid": NETUID,
        "channel": "stable",
        "channel_url": CHANNEL_URL,
        "miner_unit": MINER_UNIT,
        "minimum_sequence": 0,
    }
    document.update(overrides)
    return document


class Harness:
    """A miner host under a temporary root, with docker and systemd faked."""

    def __init__(self, tmp_path: Path, *, channel: str = "stable", minimum_sequence: int = 0) -> None:
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.paths = HostPaths(root=tmp_path / "root")
        self.config = HostConfig.from_document(
            config_document(channel=channel, minimum_sequence=minimum_sequence)
        )
        self.now = NOW

        # The updater the bootstrap installed.
        self.tree_a = self.install_updater_tree()
        atomic_symlink(self.paths.updater_current, f"releases/{self.tree_a}")
        self.profile = read_launcher_profile(
            self.paths.updater_releases / self.tree_a / TREE_LAUNCHER
        )
        self.old_image = self.image("1")
        self.new_image = self.image("2")

        # The miner as the operator installed it: its own launcher and pin.
        legacy = self.paths.miner_legacy
        legacy.mkdir(parents=True)
        (legacy / "unit.conf").write_bytes(b"")
        (legacy / "profile.json").write_text(json.dumps({"container": self.profile.container}))
        atomic_symlink(self.paths.miner_current, LEGACY)
        self.legacy_image = self.old_image

        self.paths.config_dir.mkdir(parents=True)
        self.paths.config_file.write_text(json.dumps(self.config.as_document()))

        self.running: dict[str, str | None] = {self.profile.container: self.old_image}
        self.broken_images: set[str] = set()
        # When set, anything started from a release (not legacy) fails to come
        # up: a broken launcher rather than a broken image.
        self.managed_fails = False
        self.systemctl_calls: list[tuple[str, ...]] = []
        self.restart_raises = False
        self.prepare_raises = False
        self.prepared: list[str] = []
        self.safe: list[bool] = [True]
        self.metadata = b""
        self.bundles: dict[str, bytes] = {}
        self.fetches = 0
        self.on_prepare: Callable[[], None] | None = None
        self.on_restart: Callable[[str | None], None] | None = None

    # --- building releases -------------------------------------------------------

    def image(self, digit: str) -> str:
        return f"{self.profile.image_repository}@sha256:{digit * 64}"

    def install_updater_tree(self, **kwargs) -> str:
        staging = self.work / f"installed-{len(list(self.work.iterdir()))}"
        tree = build_tree(staging, **kwargs)
        install_directory(staging, tree_sha256=tree, releases=self.paths.updater_releases)
        return tree

    def release(self, *, image: str | None = None, bundle: dict | None = None, **kwargs) -> bytes:
        """Sign a record naming a bundle built with ``bundle`` options, and publish it."""

        archive, archive_sha256, tree_sha256 = build_bundle(self.work, **(bundle or {}))
        self.bundles[archive_sha256] = archive
        kwargs.setdefault("issued", self.now - 60)
        record = sign_record(
            image=image or self.new_image,
            archive_sha256=archive_sha256,
            tree_sha256=tree_sha256,
            **kwargs,
        )
        self.metadata = record
        return record

    # --- fake host effects -----------------------------------------------------

    def _systemctl(self, arguments) -> None:
        self.systemctl_calls.append(tuple(arguments))
        if arguments[0] != "restart":
            return
        if self.restart_raises:
            raise MinerUpdateError("systemctl restart failed")
        target = link_target(self.paths.miner_current)
        profile = read_activation_profile(self.paths, target)
        image = self.legacy_image if target == LEGACY else profile["image"]
        failed = image in self.broken_images or (self.managed_fails and target != LEGACY)
        self.running[str(profile["container"])] = None if failed else image
        if self.on_restart is not None:
            self.on_restart(image)

    def _prepare(self, release, profile) -> None:
        if self.on_prepare is not None:
            self.on_prepare()
        if self.prepare_raises:
            raise MinerUpdateError("docker pull failed")
        self.prepared.append(release.image)

    def _safe(self) -> bool:
        return self.safe.pop(0) if len(self.safe) > 1 else self.safe[0]

    def _fetch_metadata(self) -> bytes:
        self.fetches += 1
        return self.metadata

    def _probe(self, release_dir: Path, record: Path):
        return probe_release(self.host(running_tree=release_dir.name), record.read_bytes())

    def _handoff(self, release_dir: Path, fd: int):
        child = self.host(running_tree=release_dir.name)
        child.handoff_depth = 1
        child.lock_fd = fd
        outcome = update_once(child)
        return outcome.exit_status, outcome.as_dict()

    def host(self, *, running_tree: str | None = None, **overrides) -> MinerUpdaterHost:
        if running_tree is None:
            running_tree = str(link_target(self.paths.updater_current)).split("/")[-1]
        keys = load_trust_root(
            (self.paths.updater_releases / running_tree / TREE_TRUST_ROOT).read_bytes()
        )
        fields = dict(
            config=self.config,
            paths=self.paths,
            trusted_keys=keys,
            running_tree=running_tree,
            fetch_metadata=self._fetch_metadata,
            fetch_bundle=lambda bundle: self.bundles[bundle.archive_sha256],
            probe_updater=self._probe,
            handoff=self._handoff,
            prepare_image=self._prepare,
            systemctl=self._systemctl,
            current_image=lambda container: self.running.get(container),
            settled_image=lambda container: self.running.get(container),
            safe_to_activate=self._safe,
            now_unix=lambda: self.now,
            expected_uid=os.getuid(),
        )
        fields.update(overrides)
        return MinerUpdaterHost(**fields)

    # --- observations -------------------------------------------------------------

    def check(self, **overrides) -> UpdateOutcome:
        return update_once(self.host(**overrides))

    def state(self) -> dict:
        return read_state(self.paths.state_file)

    def active(self) -> str | None:
        return link_target(self.paths.miner_current)

    def restarts(self) -> int:
        return sum(1 for call in self.systemctl_calls if call[0] == "restart")

    def running_image(self) -> str | None:
        return self.running.get(self.profile.container)

    def updater_current(self) -> str | None:
        target = link_target(self.paths.updater_current)
        return target.split("/")[-1] if target else None


__all__ = [name for name in dir() if not name.startswith("_")]
