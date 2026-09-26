"""The one-time bootstrap: a pinned trust root, deploy config without defaults,
and an enrolment that leaves the running miner unchanged."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from cathedral.miner_bootstrap import BootstrapError, install
from cathedral.miner_bundle import link_target, release_tree_sha256
from cathedral.miner_products import AUDIT_MINER, SNP_MINER, find_launcher, read_launcher_profile
from cathedral.miner_updater import (
    CONFIG_SCHEMA,
    LEGACY,
    HostConfig,
    HostPaths,
    MinerUpdateError,
    load_config,
)
from tests.miner_update_support import (
    CANARY_KEY,
    DEFAULT_TRUST,
    OTHER_KEY,
    REPO_ROOT,
    config_document,
    trust_root_bytes,
)

MANAGED_FILES = [
    "cathedral/__init__.py",
    *(f"cathedral/{name}" for name in (
        "miner_release.py",
        "miner_products.py",
        "miner_bundle.py",
        "miner_updater.py",
        "miner_update_cli.py",
    )),
    "deploy/miner-update/miner-unit.conf",
    "deploy/miner-update/cathedral-miner-update",
    "deploy/miner-update/cathedral-miner-update.service",
    "deploy/miner-update/cathedral-miner-update.timer",
    "deploy/miner-update/cathedral-miner-update-alert@.service",
]


@pytest.fixture()
def source(tmp_path) -> Path:
    """A checkout of this commit, with a committed trust root."""

    checkout = tmp_path / "src"
    for relative in MANAGED_FILES:
        (checkout / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / relative, checkout / relative)
    (checkout / "scripts").mkdir()
    for product in (SNP_MINER, AUDIT_MINER):
        launcher = find_launcher(REPO_ROOT, product)
        shutil.copy(launcher, checkout / "scripts" / launcher.name)
    (checkout / "deploy/miner-update/release-keys.json").write_bytes(trust_root_bytes())
    return checkout


def _keys_sha256(source: Path) -> str:
    return hashlib.sha256((source / "deploy/miner-update/release-keys.json").read_bytes()).hexdigest()


def _install(source: Path, root: Path, *, exec_start: Path | None = None, **config):
    calls: list[tuple[str, ...]] = []
    launcher = exec_start or find_launcher(REPO_ROOT, SNP_MINER)
    report = install(
        source,
        paths=HostPaths(root=root),
        keys_sha256=config.pop("keys_sha256", None) or _keys_sha256(source),
        config=HostConfig.from_document(config_document(**config)),
        unit_exec_start=lambda unit: launcher,
        systemctl=lambda arguments: calls.append(tuple(arguments)),
    )
    return report, calls


def test_the_bootstrap_enrols_without_changing_the_miner(source, tmp_path):
    root = tmp_path / "root"
    report, calls = _install(source, root)
    paths = HostPaths(root=root)
    tree = report["installed_tree"]
    assert link_target(paths.updater_current) == f"releases/{tree}"
    assert release_tree_sha256(paths.updater_releases / tree) == tree
    # The legacy release is the unit's own launcher; the drop-in is empty until a release activates.
    assert link_target(paths.miner_current) == LEGACY
    assert (paths.miner_legacy / "unit.conf").read_bytes() == b""
    profile = json.loads((paths.miner_legacy / "profile.json").read_text())
    assert profile["container"] == read_launcher_profile(find_launcher(REPO_ROOT, SNP_MINER)).container
    dropin = paths.dropin("cathedral-test-miner.service")
    assert dropin.is_symlink() and Path(os.readlink(dropin)) == paths.miner_current / "unit.conf"
    assert dropin.read_bytes() == b""
    # The timer is installed but not enabled: only daemon-reload ran.
    assert calls == [("daemon-reload",)]
    assert (paths.systemd_dir / "cathedral-miner-update.timer").is_file()
    assert (paths.systemd_dir / "cathedral-miner-update-alert@.service").is_file()
    # The host trust set is the pinned root, in state, outside every bundle.
    from cathedral.miner_updater import load_trust_state

    trust = load_trust_state(paths.trust_file, expected_uid=os.getuid())
    assert trust.generation == 1 and set(trust.keys) == {"canary-1", "stable-1"}
    assert link_target(paths.updater_previous) is None
    assert os.access(paths.shim, os.X_OK)
    config = load_config(paths.config_file, expected_uid=os.getuid())
    assert config.netuid == config_document()["netuid"]


def test_the_trust_root_is_pinned_by_digest(source, tmp_path):
    with pytest.raises(BootstrapError, match="not the pinned"):
        _install(source, tmp_path / "root", keys_sha256="0" * 64)
    assert not (tmp_path / "root" / "usr").exists()


def test_a_revision_without_a_trust_root_is_refused(source, tmp_path):
    (source / "deploy/miner-update/release-keys.json").unlink()
    with pytest.raises(BootstrapError, match="no miner release trust root"):
        _install(source, tmp_path / "root", keys_sha256="0" * 64)


def test_a_trust_root_with_no_key_for_the_channel_is_refused(source, tmp_path):
    (source / "deploy/miner-update/release-keys.json").write_bytes(
        trust_root_bytes({"canary-1": (CANARY_KEY, ["canary"])})
    )
    with pytest.raises(BootstrapError, match="stable channel"):
        _install(source, tmp_path / "root")


def test_a_unit_running_another_products_launcher_is_refused(source, tmp_path):
    with pytest.raises(BootstrapError, match="another product"):
        _install(source, tmp_path / "root", exec_start=find_launcher(REPO_ROOT, AUDIT_MINER))


def test_a_unit_running_an_unrecognised_program_is_refused(source, tmp_path):
    program = tmp_path / "program"
    program.write_text("#!/bin/sh\nexec sleep infinity\n")
    with pytest.raises(BootstrapError, match="recognised miner launcher"):
        _install(source, tmp_path / "root", exec_start=program)


def test_a_fresh_host_with_the_shipped_unit_is_enrolled(source, tmp_path):
    """The shipped audit-miner unit already runs the managed launcher (F8)."""

    root = tmp_path / "root"
    managed = HostPaths(root=root).miner_current / "launcher"
    report, _calls = _install(source, root, exec_start=managed, product="audit-miner")
    profile = json.loads((HostPaths(root=root).miner_legacy / "profile.json").read_text())
    assert profile["container"] == read_launcher_profile(find_launcher(REPO_ROOT, AUDIT_MINER)).container
    assert report["config"]["product"] == "audit-miner"


def test_a_second_bootstrap_leaves_no_fallback_to_the_tree_it_replaces(source, tmp_path):
    """Trust review P0-1(c): a re-bootstrap removes `previous` rather than pointing it
    at the tree the operator is replacing."""

    root = tmp_path / "root"
    first, _ = _install(source, root)
    paths = HostPaths(root=root)
    from cathedral.miner_bundle import atomic_symlink

    atomic_symlink(paths.updater_previous, f"releases/{first['installed_tree']}")
    module = source / "cathedral" / "miner_updater.py"
    module.write_text(module.read_text() + "\n# a later revision\n")
    second, _ = _install(source, root)
    assert second["installed_tree"] != first["installed_tree"]
    assert link_target(paths.updater_previous) is None
    assert link_target(paths.miner_current) == LEGACY


def test_a_re_bootstrap_after_a_compromise_leaves_the_old_key_untrusted(source, tmp_path):
    root = tmp_path / "root"
    _install(source, root)
    paths = HostPaths(root=root)
    from cathedral.miner_updater import load_trust_state

    # The stable key is compromised: the operator re-bootstraps with a new stable key.
    replaced = {"canary-1": DEFAULT_TRUST["canary-1"], "stable-2": (OTHER_KEY, ["stable"])}
    (source / "deploy/miner-update/release-keys.json").write_bytes(trust_root_bytes(replaced))
    report, _ = _install(source, root)
    trust = load_trust_state(paths.trust_file, expected_uid=os.getuid())
    assert "stable-1" not in trust.keys and report["revoked_keys"] == ["stable-1"]
    # A later bootstrap from an old revision cannot bring it back.
    (source / "deploy/miner-update/release-keys.json").write_bytes(trust_root_bytes())
    with pytest.raises(BootstrapError, match="revoked key"):
        _install(source, root)
    assert "stable-1" not in load_trust_state(paths.trust_file, expected_uid=os.getuid()).keys


def test_a_revocation_holds_even_if_the_rest_of_the_bootstrap_fails(source, tmp_path):
    root = tmp_path / "root"
    _install(source, root)
    paths = HostPaths(root=root)
    from cathedral.miner_updater import load_trust_state

    replaced = {"canary-1": DEFAULT_TRUST["canary-1"], "stable-2": (OTHER_KEY, ["stable"])}
    (source / "deploy/miner-update/release-keys.json").write_bytes(trust_root_bytes(replaced))
    (source / "deploy/miner-update/miner-unit.conf").unlink()  # the tree cannot be assembled
    with pytest.raises(OSError):
        _install(source, root)
    assert "stable-1" not in load_trust_state(paths.trust_file, expected_uid=os.getuid()).keys


def test_the_minimum_sequence_has_no_default():
    """Trust review P3."""

    from cathedral import miner_bootstrap

    with pytest.raises(SystemExit):
        miner_bootstrap.main(
            [
                "install",
                "--source", "/nonexistent",
                "--keys-sha256", "0" * 64,
                "--product", "snp-miner",
                "--network", "testnet",
                "--netuid", str(config_document()["netuid"]),
                "--channel", "stable",
                "--channel-url", "https://updates.example.test/x.json",
                "--miner-unit", "cathedral-test-miner.service",
            ]
        )


@pytest.mark.parametrize("missing", ["network", "netuid", "miner_unit", "channel_url", "product"])
def test_deploy_config_has_no_defaults(missing):
    document = config_document()
    del document[missing]
    with pytest.raises(MinerUpdateError, match="fields are invalid"):
        HostConfig.from_document(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("netuid", -1),
        ("netuid", 65536),
        ("netuid", True),
        ("network", "Test Net"),
        ("channel", "beta"),
        ("channel_url", "http://updates.example.test/x.json"),
        ("miner_unit", "../../etc/passwd"),
        ("product", "gpu-miner"),
    ],
)
def test_deploy_config_values_are_validated(field, value):
    with pytest.raises(MinerUpdateError):
        HostConfig.from_document(config_document(**{field: value}))


def test_a_config_another_user_could_write_is_refused(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema": CONFIG_SCHEMA, **config_document()}))
    os.chmod(path, 0o666)
    with pytest.raises(MinerUpdateError, match="unavailable"):
        load_config(path, expected_uid=os.getuid())
