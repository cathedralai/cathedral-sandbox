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
    initial_trust_state,
    load_trust_root,
    signed_bytes,
)
from cathedral.miner_updater import (
    CONFIG_SCHEMA,
    LEGACY,
    STAGE_PROBATION,
    HostConfig,
    HostPaths,
    MinerUpdateError,
    MinerUpdaterHost,
    Observation,
    UpdateOutcome,
    probe_release,
    read_activation_profile,
    read_state,
    update_once,
    write_trust_state,
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
    """A miner host under a temporary root, with docker and systemd faked.

    The fake miner keeps, per container, the image it runs (None when down),
    when it started, and the unit's restart count. A restart starts whatever
    ``miner/current`` selects. It fails to come up when the image is broken,
    when ``managed_fails`` is set and a release (not legacy) is selected, or
    when its launcher needs the registry and the registry is down. The legacy
    launcher pulls on every start; a release's launcher pulls only when the
    image is not already local, as the repository's launchers now do.
    """

    def __init__(self, tmp_path: Path, *, channel: str = "stable", minimum_sequence: int = 0) -> None:
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.paths = HostPaths(root=tmp_path / "root")
        self.config = HostConfig.from_document(
            config_document(channel=channel, minimum_sequence=minimum_sequence)
        )
        self.now = NOW

        # The updater the bootstrap installed, and the host trust set it wrote.
        self.tree_a = self.install_updater_tree()
        atomic_symlink(self.paths.updater_current, f"releases/{self.tree_a}")
        self.paths.state_dir.mkdir(parents=True, exist_ok=True)
        write_trust_state(self.paths.trust_file, initial_trust_state(trust_root_bytes()))
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

        container = self.profile.container
        self.running: dict[str, str | None] = {container: self.old_image}
        self.started: dict[str, float] = {container: float(NOW - 86_400)}
        self.nrestarts = 0
        self.operator_stopped = False
        self.broken_images: set[str] = set()
        self.managed_fails = False
        self.registry_up = True
        self.local_images: set[str] = {self.old_image}
        self.labels: dict[str, int | None] = {}
        self.boot = "boot-1"
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
        self.after_sleep: Callable[[], None] | None = None

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

    def _launcher_needs_registry(self, target: str, image: str) -> bool:
        if target == LEGACY:
            return True  # the operator's own launcher pulls on every start
        text = (self.paths.miner_dir / target / "launcher").read_text()
        guarded = "if ! docker image inspect" in text
        return not guarded or image not in self.local_images

    def _systemctl(self, arguments) -> None:
        self.systemctl_calls.append(tuple(arguments))
        if arguments[0] == "reset-failed":
            self.nrestarts = 0  # systemd's reset-failed zeroes NRestarts
        if arguments[0] != "restart":
            return
        if self.restart_raises:
            raise MinerUpdateError("systemctl restart failed")
        self.operator_stopped = False
        self.now += 1
        target = link_target(self.paths.miner_current)
        profile = read_activation_profile(self.paths, target)
        image = self.legacy_image if target == LEGACY else str(profile["image"])
        failed = (
            image in self.broken_images
            or (self.managed_fails and target != LEGACY)
            or (self._launcher_needs_registry(target, image) and not self.registry_up)
        )
        container = str(profile["container"])
        self.running[container] = None if failed else image
        self.started[container] = float(self.now)
        if self.on_restart is not None:
            self.on_restart(image)

    def _prepare(self, release, profile):
        if self.on_prepare is not None:
            self.on_prepare()
        if self.prepare_raises or not self.registry_up:
            raise MinerUpdateError("docker pull failed")
        self.prepared.append(release.image)
        self.local_images.add(release.image)
        return self.labels.get(release.image, release.state_schema)

    def _unit_state(self) -> str:
        if self.operator_stopped:
            return "inactive"
        target = link_target(self.paths.miner_current)
        container = str(read_activation_profile(self.paths, target)["container"])
        return "active" if self.running.get(container) else "failed"

    def _observe(self, container: str) -> Observation | None:
        image = self.running.get(container)
        if image is None or self.operator_stopped:
            return None
        return Observation(
            image=image,
            started_at=self.started.get(container, 0.0),
            restarts=self.nrestarts,
            active=True,
        )

    def _sleep(self, seconds: float) -> None:
        self.now += int(seconds)
        if self.after_sleep is not None:
            self.after_sleep()

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
        fields = dict(
            config=self.config,
            paths=self.paths,
            running_tree=running_tree,
            fetch_metadata=self._fetch_metadata,
            fetch_bundle=lambda bundle: self.bundles[bundle.archive_sha256],
            probe_updater=self._probe,
            handoff=self._handoff,
            prepare_image=self._prepare,
            systemctl=self._systemctl,
            unit_state=self._unit_state,
            observe=self._observe,
            settle=self._observe,
            safe_to_activate=self._safe,
            now_unix=lambda: self.now,
            sleep=self._sleep,
            boot_id=lambda: self.boot,
            expected_uid=os.getuid(),
        )
        fields.update(overrides)
        return MinerUpdaterHost(**fields)

    # --- observations -------------------------------------------------------------

    def check(self, **overrides) -> UpdateOutcome:
        return update_once(self.host(**overrides))

    def commit(self, **overrides) -> UpdateOutcome:
        """One check, then the next check that confirms probation."""

        first = self.check(**overrides)
        if self.state()["miner"]["stage"] == STAGE_PROBATION:
            self.now += 3600
            return self.check(**overrides)
        return first

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
