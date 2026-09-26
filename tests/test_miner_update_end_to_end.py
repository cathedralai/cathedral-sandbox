"""The offline signer, the bootstrap and the updater, together.

Replaces #197's ``acceptance.sh``, which passed only because it checked
records signed now against a 2017 clock (review finding F6). Here the signer
runs as its own process with an encrypted key, the bootstrap installs from a
checkout, and the updater applies the signed stable record under the real
clock. docker and systemd are faked; nothing contacts a host.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from cathedral.miner_bootstrap import install
from cathedral.miner_bundle import TREE_TRUST_ROOT, link_target
from cathedral.miner_products import SNP_MINER, find_launcher, read_launcher_profile
from cathedral.miner_release import load_trust_root
from cathedral.miner_updater import (
    LEGACY,
    HostConfig,
    HostPaths,
    MinerUpdaterHost,
    read_activation_profile,
    update_once,
)
from tests.miner_update_support import (
    CANARY_KEY,
    NETUID,
    NETWORK,
    OTHER_KEY,
    REPO_ROOT,
    STABLE_KEY,
    config_document,
    trust_root_bytes,
)
from tests.test_miner_bootstrap import MANAGED_FILES

SIGNER = REPO_ROOT / "deploy" / "miner-update" / "build_signed_miner_release.py"
PASSPHRASE = "correct horse battery staple"
BUNDLE_URL = "https://127.0.0.1:9/miner/bundle.tar.gz"


def _key_file(directory: Path, name: str, key, *, encrypted: bool = True) -> Path:
    path = directory / f"{name}.pem"
    algorithm = (
        serialization.BestAvailableEncryption(PASSPHRASE.encode())
        if encrypted
        else serialization.NoEncryption()
    )
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm)
    )
    os.chmod(path, 0o600)
    return path


def _sign(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SIGNER), *arguments],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "CATHEDRAL_MINER_RELEASE_PASSPHRASE": PASSPHRASE},
    )
    if check:
        assert result.returncode == 0, result.stderr[-2000:]
    return result


@pytest.fixture()
def world(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    trust = tmp_path / "release-keys.json"
    trust.write_bytes(trust_root_bytes())
    built = json.loads(
        _sign("bundle", "--product", "snp-miner", "--out-dir", str(tmp_path / "out"), "--trust-root", str(trust)).stdout
    )
    repository = read_launcher_profile(find_launcher(REPO_ROOT, SNP_MINER)).image_repository
    return {
        "tmp": tmp_path,
        "trust": trust,
        "bundle": built,
        "canary_key": _key_file(keys, "canary", CANARY_KEY),
        "stable_key": _key_file(keys, "stable", STABLE_KEY),
        "image": f"{repository}@sha256:{'2' * 64}",
    }


def _canary(world, *extra: str, out: str = "canary.json", check: bool = True):
    return _sign(
        "canary",
        "--private-key", str(world["canary_key"]),
        "--signing-key-id", "canary-1",
        "--product", "snp-miner",
        "--network", NETWORK,
        "--netuid", str(NETUID),
        "--image", world["image"],
        "--state-schema", "1",
        "--bundle-archive", world["bundle"]["archive"],
        "--bundle-url", BUNDLE_URL,
        "--version", "2026.09.26",
        "--sequence", "1",
        "--lifetime-seconds", str(7 * 24 * 3600),
        "--out", str(world["tmp"] / out),
        *extra,
        check=check,
    )


def _stable(world, *extra: str, key: str = "stable_key", key_id: str = "stable-1", check: bool = True):
    return _sign(
        "stable",
        "--private-key", str(world[key]),
        "--signing-key-id", key_id,
        "--promote", str(world["tmp"] / "canary.json"),
        "--bundle-archive", world["bundle"]["archive"],
        "--sequence", "2",
        "--lifetime-seconds", str(7 * 24 * 3600),
        "--out", str(world["tmp"] / "stable.json"),
        *extra,
        check=check,
    )


def test_a_signed_release_installs_on_a_bootstrapped_host(world):
    tmp = world["tmp"]
    _canary(world)
    signed = json.loads(_stable(world).stdout)
    assert signed["channel"] == "stable" and signed["netuid"] == NETUID

    # Bootstrap a host from a checkout of this commit carrying the same trust root.
    source = tmp / "src"
    for relative in MANAGED_FILES:
        (source / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / relative, source / relative)
    (source / "scripts").mkdir()
    launcher = find_launcher(REPO_ROOT, SNP_MINER)
    shutil.copy(launcher, source / "scripts" / launcher.name)
    shutil.copy(world["trust"], source / "deploy/miner-update/release-keys.json")
    paths = HostPaths(root=tmp / "root")
    config = HostConfig.from_document(config_document())
    report = install(
        source,
        paths=paths,
        keys_sha256=hashlib.sha256(world["trust"].read_bytes()).hexdigest(),
        config=config,
        unit_exec_start=lambda unit: launcher,
        systemctl=lambda arguments: None,
    )
    # A host bootstrapped at a commit runs byte-for-byte the tree that commit's bundle ships.
    assert report["installed_tree"] == world["bundle"]["tree_sha256"]

    running: dict[str, str | None] = {read_launcher_profile(launcher).container: "legacy@sha256:" + "1" * 64}

    def systemctl(arguments):
        if arguments[0] == "restart":
            target = link_target(paths.miner_current)
            profile = read_activation_profile(paths, target)
            running[str(profile["container"])] = profile.get("image")

    tree = report["installed_tree"]
    host = MinerUpdaterHost(
        config=config,
        paths=paths,
        trusted_keys=load_trust_root((paths.updater_releases / tree / TREE_TRUST_ROOT).read_bytes()),
        running_tree=tree,
        fetch_metadata=lambda: (tmp / "stable.json").read_bytes(),
        fetch_bundle=lambda bundle: Path(world["bundle"]["archive"]).read_bytes(),
        probe_updater=lambda release, record: {},
        handoff=lambda release, fd: (1, None),
        prepare_image=lambda release, profile: None,
        systemctl=systemctl,
        current_image=running.get,
        settled_image=running.get,
        safe_to_activate=lambda: True,
        now_unix=lambda: int(time.time()),
        expected_uid=os.getuid(),
    )
    outcome = update_once(host)
    assert outcome.action == "activated", outcome.reason
    assert link_target(paths.miner_current) != LEGACY
    assert (paths.miner_current / "release.env").read_text().count(world["image"]) == 1
    assert (paths.miner_current / "launcher").read_bytes() == launcher.read_bytes()


def test_the_trust_entry_matches_the_committed_format(world):
    entry = json.loads(
        _sign("trust-entry", "--private-key", str(world["stable_key"]), "--key-id", "stable-1", "--channels", "stable").stdout
    )
    expected = json.loads(trust_root_bytes())["keys"]["stable-1"]
    assert entry == {"stable-1": expected}


def test_the_signer_refuses_an_unencrypted_key(world):
    world["canary_key"] = _key_file(world["tmp"], "plain", CANARY_KEY, encrypted=False)
    result = _canary(world, check=False)
    assert result.returncode != 0 and "not encrypted" in result.stderr


def test_the_signer_refuses_a_lifetime_over_14_days(world):
    result = _canary(world, "--lifetime-seconds", str(15 * 24 * 3600), check=False)
    assert result.returncode != 0 and "14 days" in result.stderr


def test_the_signer_refuses_a_record_issued_in_the_future(world):
    result = _canary(world, "--issued-unix", str(int(time.time()) + 3600), check=False)
    assert result.returncode != 0 and "not valid yet" in result.stderr


def test_the_signer_never_overwrites_a_signed_record(world):
    _canary(world)
    result = _canary(world, check=False)
    assert result.returncode != 0 and "never overwrite" in result.stderr


def test_the_signer_refuses_an_image_outside_the_launchers_repository(world):
    world["image"] = f"ghcr.io/cathedralai/some-other-repository@sha256:{'2' * 64}"
    result = _canary(world, check=False)
    assert result.returncode != 0 and "repository" in result.stderr


def test_the_signer_refuses_a_key_the_bundle_would_not_trust(world):
    _canary(world)
    world["other_key"] = _key_file(world["tmp"], "other", OTHER_KEY)
    result = _stable(world, key="other_key", key_id="other-1", check=False)
    assert result.returncode != 0 and "trust root" in result.stderr


def test_a_canary_key_cannot_promote_to_stable(world):
    _canary(world)
    result = _stable(world, key="canary_key", key_id="canary-1", check=False)
    assert result.returncode != 0 and "stable" in result.stderr
