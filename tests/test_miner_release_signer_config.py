"""build_signed_miner_release.py --signer-config and the committed trust root (AB#349).

Every key here is a throwaway generated in-test. The committed
deploy/miner-update/release-keys.json carries only public keys.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from functools import partial
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import signer as signer_module
from cathedral.miner_bootstrap import BootstrapError, install
from cathedral.miner_bundle import REPOSITORY_TRUST_ROOT
from cathedral.miner_products import SNP_MINER, find_launcher, read_launcher_profile
from cathedral.miner_release import load_trust_root, parse_miner_release
from cathedral.miner_updater import HostConfig, HostPaths, load_trust_state
from tests.miner_update_support import (
    CANARY_KEY,
    NETUID,
    NETWORK,
    REPO_ROOT,
    config_document,
    trust_root_bytes,
)
from tests.test_miner_bootstrap import MANAGED_FILES
from tests.test_signer import FakeKms

SIGNER = REPO_ROOT / "deploy" / "miner-update" / "build_signed_miner_release.py"
PASSPHRASE = "throwaway passphrase for a test key"
BUNDLE_URL = "https://127.0.0.1:9/miner/bundle.tar.gz"
COMMITTED_CANARY_KEY_ID = "miner-canary-local-1"
COMMITTED_CANARY_PUBLIC_HEX = "a805f5e29a058372d51122e9c5b2554c97e485199c7273a6966d6c838296d1e1"
WEEK = 7 * 24 * 3600


def _write_secret(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def _pem(path: Path, key: Ed25519PrivateKey, *, encrypted: bool = True) -> Path:
    algorithm = (
        serialization.BestAvailableEncryption(PASSPHRASE.encode())
        if encrypted
        else serialization.NoEncryption()
    )
    return _write_secret(
        path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm)
    )


def _run(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "CATHEDRAL_MINER_RELEASE_PASSPHRASE"}
    result = subprocess.run(
        [sys.executable, str(SIGNER), *arguments], capture_output=True, text=True, timeout=120, env=env
    )
    if check:
        assert result.returncode == 0, result.stderr[-2000:]
    return result


@pytest.fixture()
def world(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir(mode=0o700)
    pem = _pem(keys / "canary.pem", CANARY_KEY)
    passphrase = _write_secret(keys / "canary.passphrase", PASSPHRASE.encode() + b"\n")
    config = _write_secret(
        tmp_path / "signers.json",
        json.dumps(
            {
                "miner_canary": {
                    "backend": "local_file",
                    "key_id": "canary-1",
                    "path": str(pem),
                    "passphrase_path": str(passphrase),
                }
            }
        ).encode(),
    )
    trust = tmp_path / "release-keys.json"
    trust.write_bytes(trust_root_bytes())
    built = json.loads(
        _run("bundle", "--product", "snp-miner", "--out-dir", str(tmp_path / "out"), "--trust-root", str(trust)).stdout
    )
    repository = read_launcher_profile(find_launcher(REPO_ROOT, SNP_MINER)).image_repository
    return {
        "tmp": tmp_path,
        "keys": keys,
        "pem": pem,
        "passphrase": passphrase,
        "config": config,
        "trust": trust,
        "bundle": built,
        "image": f"{repository}@sha256:{'2' * 64}",
        "issued": int(time.time()),
    }


def _canary_arguments(world, *, out: str) -> list[str]:
    return [
        "--product", "snp-miner", "--network", NETWORK, "--netuid", str(NETUID),
        "--image", world["image"], "--state-schema", "2",
        "--bundle-archive", world["bundle"]["archive"], "--bundle-url", BUNDLE_URL,
        "--version", "2026.11.17", "--sequence", "1", "--lifetime-seconds", str(WEEK),
        "--issued-unix", str(world["issued"]), "--out", str(world["tmp"] / out),
    ]


def _canary(world, *source: str, out: str = "canary.json", check: bool = True):
    return _run("canary", *source, *_canary_arguments(world, out=out), check=check)


def test_signer_config_signs_a_canary_the_host_verifier_accepts(world):
    summary = json.loads(_canary(world, "--signer-config", str(world["config"])).stdout)
    raw = (world["tmp"] / "canary.json").read_bytes()
    release = parse_miner_release(
        raw,
        trusted_keys=load_trust_root(world["trust"].read_bytes()),
        expected_product="snp-miner",
        expected_network=NETWORK,
        expected_netuid=NETUID,
        expected_channel="canary",
        now_unix=int(time.time()),
    )
    assert release.signing_key_id == "canary-1" == summary["signing_key_id"]
    assert release.version == "2026.11.17"
    # Neither the passphrase nor any private key material reaches the output.
    assert PASSPHRASE not in raw.decode() and "PRIVATE" not in raw.decode()


def test_signer_config_and_private_key_produce_the_same_record(world):
    """Ed25519 is deterministic: both paths sign the same body to the same bytes."""

    _canary(world, "--signer-config", str(world["config"]), out="by-config.json")
    env = {**os.environ, "CATHEDRAL_MINER_RELEASE_PASSPHRASE": PASSPHRASE}
    result = subprocess.run(
        [sys.executable, str(SIGNER), "canary", "--private-key", str(world["pem"]),
         "--signing-key-id", "canary-1", *_canary_arguments(world, out="by-key.json")],
        capture_output=True, text=True, timeout=120, env=env,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert (world["tmp"] / "by-config.json").read_bytes() == (world["tmp"] / "by-key.json").read_bytes()


def test_the_private_key_path_still_needs_a_key_id(world):
    result = _canary(world, "--private-key", str(world["pem"]), check=False)
    assert result.returncode != 0 and "needs a key id" in result.stderr


def test_private_key_and_signer_config_are_exclusive(world):
    result = _canary(
        world, "--private-key", str(world["pem"]), "--signer-config", str(world["config"]), check=False
    )
    assert result.returncode != 0 and "not allowed with" in result.stderr


def test_a_signing_key_id_other_than_the_configured_one_is_refused(world):
    result = _canary(world, "--signer-config", str(world["config"]), "--signing-key-id", "stable-1", check=False)
    assert result.returncode != 0 and "is not the configured key canary-1" in result.stderr
    assert not (world["tmp"] / "canary.json").exists()


def test_a_configured_key_the_trust_root_does_not_list_under_its_id_is_refused(world):
    _pem(world["pem"], Ed25519PrivateKey.generate())
    result = _canary(world, "--signer-config", str(world["config"]), check=False)
    assert result.returncode != 0 and "does not equal the pinned public key" in result.stderr
    assert not (world["tmp"] / "canary.json").exists()


def test_a_canary_signer_config_cannot_sign_stable(world):
    _canary(world, "--signer-config", str(world["config"]))
    result = _run(
        "stable", "--signer-config", str(world["config"]), "--promote", str(world["tmp"] / "canary.json"),
        "--bundle-archive", world["bundle"]["archive"], "--trust-root", str(world["trust"]),
        "--sequence", "2", "--lifetime-seconds", str(WEEK), "--out", str(world["tmp"] / "stable.json"),
        check=False,
    )
    assert result.returncode != 0 and "no signer is configured for purpose 'miner_stable'" in result.stderr
    forced = _run(
        "stable", "--signer-config", str(world["config"]), "--purpose", "miner_canary",
        "--promote", str(world["tmp"] / "canary.json"),
        "--bundle-archive", world["bundle"]["archive"], "--trust-root", str(world["trust"]),
        "--sequence", "2", "--lifetime-seconds", str(WEEK), "--out", str(world["tmp"] / "stable.json"),
        check=False,
    )
    assert forced.returncode != 0 and "does not let canary-1 sign stable" in forced.stderr
    assert not (world["tmp"] / "stable.json").exists()


def test_signer_config_refuses_an_unencrypted_key(world):
    _pem(world["pem"], CANARY_KEY, encrypted=False)
    result = _canary(world, "--signer-config", str(world["config"]), check=False)
    assert result.returncode != 0 and "not encrypted" in result.stderr


def test_signer_config_refuses_a_group_readable_key(world):
    os.chmod(world["pem"], 0o640)
    result = _canary(world, "--signer-config", str(world["config"]), check=False)
    assert result.returncode != 0 and "group or world accessible" in result.stderr


def test_trust_entry_from_a_signer_config_matches_the_committed_format(world):
    entry = json.loads(
        _run("trust-entry", "--signer-config", str(world["config"]), "--channels", "canary").stdout
    )
    assert entry == {"canary-1": json.loads(trust_root_bytes())["keys"]["canary-1"]}


def _load_builder():
    spec = importlib.util.spec_from_file_location("build_signed_miner_release_under_test", SIGNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _kms_config(world) -> Path:
    return _write_secret(
        world["tmp"] / "kms-signers.json",
        json.dumps(
            {
                "miner_canary": {
                    "backend": "aws_kms",
                    "key_id": "canary-1",
                    "key_arn": "arn:aws:kms:us-east-1:000000000000:key/test",
                    "region": "us-east-1",
                }
            }
        ).encode(),
    )


def test_an_aws_kms_signer_is_pinned_to_the_trust_root_key(world, monkeypatch):
    """The move to KMS is a config change; the bundle's trust root pins the KMS key."""

    builder = _load_builder()
    kms = FakeKms(CANARY_KEY)
    monkeypatch.setattr(
        builder, "signer_from_config", partial(signer_module.signer_from_config, kms_client_factory=lambda region: kms)
    )
    assert builder.main(["canary", "--signer-config", str(_kms_config(world)), *_canary_arguments(world, out="kms.json")]) == 0
    assert any(call == "Sign" for call, _ in kms.calls)
    raw = (world["tmp"] / "kms.json").read_bytes()
    parse_miner_release(
        raw,
        trusted_keys=load_trust_root(world["trust"].read_bytes()),
        expected_product="snp-miner", expected_network=NETWORK, expected_netuid=NETUID,
        expected_channel="canary", now_unix=int(time.time()),
    )


def test_an_aws_kms_key_that_is_not_the_trusted_key_never_signs(world, monkeypatch):
    builder = _load_builder()
    kms = FakeKms(Ed25519PrivateKey.generate())
    monkeypatch.setattr(
        builder, "signer_from_config", partial(signer_module.signer_from_config, kms_client_factory=lambda region: kms)
    )
    with pytest.raises(SystemExit, match="does not equal the pinned public key"):
        builder.main(["canary", "--signer-config", str(_kms_config(world)), *_canary_arguments(world, out="kms.json")])
    assert not any(call == "Sign" for call, _ in kms.calls)
    assert not (world["tmp"] / "kms.json").exists()


# --- the committed trust root -------------------------------------------------------


def _committed_root() -> bytes:
    return (REPO_ROOT / REPOSITORY_TRUST_ROOT).read_bytes()


def test_the_committed_trust_root_is_the_local_canary_key_only():
    keys = load_trust_root(_committed_root())
    assert set(keys) == {COMMITTED_CANARY_KEY_ID}
    entry = keys[COMMITTED_CANARY_KEY_ID]
    assert entry.public_key.hex() == COMMITTED_CANARY_PUBLIC_HEX
    # No stable key in the local phase: a stable key is created directly in KMS.
    assert entry.channels == frozenset({"canary"})


def _checkout_with_committed_root(tmp_path: Path) -> Path:
    checkout = tmp_path / "src"
    for relative in [*MANAGED_FILES, REPOSITORY_TRUST_ROOT]:
        (checkout / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / relative, checkout / relative)
    (checkout / "scripts").mkdir()
    launcher = find_launcher(REPO_ROOT, SNP_MINER)
    shutil.copy(launcher, checkout / "scripts" / launcher.name)
    return checkout


def _bootstrap(tmp_path: Path, channel: str):
    checkout = _checkout_with_committed_root(tmp_path)
    paths = HostPaths(root=tmp_path / "root")
    install(
        checkout,
        paths=paths,
        keys_sha256=hashlib.sha256(_committed_root()).hexdigest(),
        config=HostConfig.from_document(config_document(channel=channel)),
        unit_exec_start=lambda unit: find_launcher(REPO_ROOT, SNP_MINER),
        systemctl=lambda arguments: None,
    )
    return paths


def test_a_canary_host_bootstraps_from_the_committed_canary_only_root(tmp_path):
    paths = _bootstrap(tmp_path, "canary")
    trust = load_trust_state(paths.trust_file, expected_uid=os.getuid())
    assert set(trust.keys) == {COMMITTED_CANARY_KEY_ID}
    assert trust.trust_root_sha256 == hashlib.sha256(_committed_root()).hexdigest()


def test_a_stable_host_refuses_the_committed_canary_only_root(tmp_path):
    with pytest.raises(BootstrapError, match="stable channel"):
        _bootstrap(tmp_path, "stable")


def test_the_docs_announce_the_committed_root_digest_and_key():
    docs = (REPO_ROOT / "docs" / "MINER_AUTO_UPDATE.md").read_text()
    assert hashlib.sha256(_committed_root()).hexdigest() in docs
    pem = (REPO_ROOT / "docs" / "keys" / f"{COMMITTED_CANARY_KEY_ID}.pub.pem").read_bytes()
    public = serialization.load_pem_public_key(pem).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert public.hex() == COMMITTED_CANARY_PUBLIC_HEX
