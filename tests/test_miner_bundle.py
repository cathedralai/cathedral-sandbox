"""The signed host bundle: layout, digests, extraction, and what the launchers declare."""

from __future__ import annotations

import gzip
import io
import os
import re
import tarfile
from pathlib import Path

import pytest

from cathedral.miner_bundle import (
    UPDATER_MODULES,
    BundleError,
    build_archive,
    extract_archive,
    install_tree,
    release_tree_sha256,
    sha256_bytes,
)
from cathedral.miner_products import (
    PRODUCTS,
    LauncherProfileError,
    find_launcher,
    parse_launcher_profile,
    read_launcher_profile,
)
from cathedral.miner_updater import HostPaths
from tests.miner_update_support import REPO_ROOT, build_tree

# A subnet-numbered name, in any casing, anywhere in the updater (review
# finding F9). Written as a pattern so this file names no number itself.
SUBNET_NUMBERED = re.compile(r"\bsn\d+|sn\d+[_-]|_sn\d+|sn\d+\b", re.IGNORECASE)


def _archive(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for info, body in members:
                archive.addfile(info, io.BytesIO(body) if body is not None else None)
    return buffer.getvalue()


def _file(name: str, body: bytes = b"x", mode: int = 0o444) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(body)
    info.mode = mode
    return info, body


# --- digests and archives ---------------------------------------------------------------


def test_the_archive_is_deterministic_and_round_trips(tmp_path):
    tree = tmp_path / "tree"
    digest = build_tree(tree)
    first, second = build_archive(tree), build_archive(tree)
    assert first == second
    extract_archive(first, tmp_path / "out")
    assert release_tree_sha256(tmp_path / "out") == digest


def test_the_executable_bit_is_part_of_the_tree_digest(tmp_path):
    tree = tmp_path / "tree"
    digest = build_tree(tree)
    launcher = tree / "miner" / "launcher"
    os.chmod(launcher, 0o444)
    assert release_tree_sha256(tree) != digest


def test_a_tree_with_a_symlink_is_refused(tmp_path):
    tree = tmp_path / "tree"
    build_tree(tree)
    (tree / "link").symlink_to("/etc/passwd")
    with pytest.raises(BundleError, match="symlink"):
        release_tree_sha256(tree)


@pytest.mark.parametrize(
    "member",
    [
        _file("/etc/evil"),
        _file("../evil"),
        _file("a/../../evil"),
    ],
)
def test_unsafe_member_paths_are_refused(tmp_path, member):
    with pytest.raises(BundleError, match="unsafe"):
        extract_archive(_archive([member]), tmp_path / "out")


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_non_regular_members_are_refused(tmp_path, kind):
    info = tarfile.TarInfo("thing")
    info.type = kind
    info.linkname = "/etc/passwd"
    with pytest.raises(BundleError, match="non-regular"):
        extract_archive(_archive([(info, None)]), tmp_path / "out")


def test_extraction_is_bounded(tmp_path, monkeypatch):
    from cathedral import miner_bundle

    monkeypatch.setattr(miner_bundle, "MAX_TREE_FILES", 2)
    members = [_file(f"f{index}") for index in range(3)]
    with pytest.raises(BundleError, match="limits"):
        extract_archive(_archive(members), tmp_path / "out")


def test_install_refuses_a_wrong_archive_or_tree_digest(tmp_path):
    tree = tmp_path / "tree"
    digest = build_tree(tree)
    archive = build_archive(tree)
    common = dict(releases=tmp_path / "releases", expected_uid=os.getuid())
    with pytest.raises(BundleError, match="archive digest"):
        install_tree(archive, archive_sha256="0" * 64, tree_sha256=digest, **common)
    with pytest.raises(BundleError, match="tree digest"):
        install_tree(archive, archive_sha256=sha256_bytes(archive), tree_sha256="0" * 64, **common)
    assert not (tmp_path / "releases" / ("0" * 64)).exists()


def test_install_is_idempotent_and_detects_a_modified_tree(tmp_path):
    tree = tmp_path / "tree"
    digest = build_tree(tree)
    archive = build_archive(tree)
    common = dict(
        archive_sha256=sha256_bytes(archive),
        tree_sha256=digest,
        releases=tmp_path / "releases",
        expected_uid=os.getuid(),
    )
    installed = install_tree(archive, **common)
    assert install_tree(archive, **common) == installed
    unit = installed / "miner" / "unit.conf"
    os.chmod(unit, 0o644)
    unit.write_text("[Service]\nExecStart=/bin/sh\n")
    os.chmod(unit, 0o444)
    with pytest.raises(BundleError, match="no longer matches"):
        install_tree(archive, **common)


# --- what the bundle carries --------------------------------------------------------------


def test_the_bundle_carries_the_updater_launcher_unit_and_trust_root(tmp_path):
    tree = tmp_path / "tree"
    build_tree(tree)
    files = {path.relative_to(tree).as_posix() for path in tree.rglob("*") if path.is_file()}
    expected = {f"updater/cathedral/{name}" for name in UPDATER_MODULES}
    expected |= {"updater/cathedral/__init__.py", "miner/launcher", "miner/unit.conf", "trust/release-keys.json"}
    assert files == expected


def test_the_updater_names_no_subnet_number():
    """F9: subnet-neutral names in the updater's code, units, docs and tests."""

    checked = [REPO_ROOT / "cathedral" / name for name in UPDATER_MODULES]
    checked += [
        REPO_ROOT / "cathedral" / "miner_bootstrap.py",
        REPO_ROOT / "docs" / "MINER_AUTO_UPDATE.md",
        REPO_ROOT / "examples" / "systemd" / "cathedral-audit-miner.service",
        REPO_ROOT / "examples" / "systemd" / "audit-miner.env.example",
    ]
    checked += sorted((REPO_ROOT / "deploy" / "miner-update").iterdir())
    checked += [
        REPO_ROOT / "tests" / name
        for name in (
            "miner_update_support.py",
            "test_miner_bootstrap.py",
            "test_miner_bundle.py",
            "test_miner_release.py",
            "test_miner_self_update.py",
            "test_miner_update_cli.py",
            "test_miner_update_end_to_end.py",
            "test_miner_update_unit.py",
            "test_miner_updater.py",
        )
    ]
    for path in checked:
        assert not SUBNET_NUMBERED.search(path.name), path
        if path.is_file():
            match = SUBNET_NUMBERED.search(path.read_text(encoding="utf-8"))
            assert match is None, f"{path.relative_to(REPO_ROOT)}: {match.group(0) if match else ''}"


# --- launchers and products (F8) -----------------------------------------------------------


@pytest.mark.parametrize("product", sorted(PRODUCTS))
def test_each_product_has_exactly_one_launcher_declaring_its_contract(product):
    launcher = find_launcher(REPO_ROOT, PRODUCTS[product])
    profile = read_launcher_profile(launcher)
    assert profile.runtime_contract == PRODUCTS[product].runtime_contract
    assert profile.image_repository.startswith("ghcr.io/cathedralai/")
    assert profile.image_variable.endswith("_IMAGE")
    assert profile.container.startswith("cathedral-")
    assert profile.contract_label.endswith(".runtime-contract")


def test_the_launchers_describe_different_products():
    profiles = [read_launcher_profile(find_launcher(REPO_ROOT, product)) for product in PRODUCTS.values()]
    for field in ("image_repository", "container", "image_variable"):
        assert len({getattr(profile, field) for profile in profiles}) == len(profiles)


def test_an_ambiguous_launcher_is_refused():
    launcher = find_launcher(REPO_ROOT, PRODUCTS["snp-miner"]).read_text()
    doubled = launcher.replace("readonly CONTAINER_NAME=", "readonly CONTAINER_NAME='other'\nreadonly CONTAINER_NAME=", 1)
    with pytest.raises(LauncherProfileError, match="exactly one CONTAINER_NAME"):
        parse_launcher_profile(doubled)


def _unit(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values.setdefault(key, []).append(value)
    return values


def test_every_product_has_a_shipped_unit():
    """F8: the audit miner had no unit in the repository, so it was not installable."""

    units = sorted((REPO_ROOT / "examples" / "systemd").glob("*miner.service"))
    managed = str(HostPaths().miner_current / "launcher")
    audit = _unit(REPO_ROOT / "examples" / "systemd" / "cathedral-audit-miner.service")
    assert audit["ExecStart"] == [managed]
    assert "/etc/cathedral/audit-miner.env" in audit["EnvironmentFile"]
    assert (REPO_ROOT / "examples" / "systemd" / "audit-miner.env.example").is_file()
    snp = [unit for unit in units if unit.name.endswith("-snp-miner.service")]
    assert len(snp) == 1
    assert _unit(snp[0])["ExecStart"][0].startswith("/usr/local/sbin/")


def test_the_audit_env_example_does_not_pin_an_image():
    text = (REPO_ROOT / "examples" / "systemd" / "audit-miner.env.example").read_text()
    assert "_IMAGE=" not in text


def test_install_renames_within_one_directory(tmp_path, monkeypatch):
    """The staging tree sits beside its target, so the rename never crosses filesystems."""

    tree = tmp_path / "tree"
    digest = build_tree(tree)
    archive = build_archive(tree)
    renames = []
    real_rename = os.rename

    def recording_rename(source, destination):
        renames.append((Path(source).parent, Path(destination).parent))
        return real_rename(source, destination)

    monkeypatch.setattr(os, "rename", recording_rename)
    install_tree(
        archive,
        archive_sha256=sha256_bytes(archive),
        tree_sha256=digest,
        releases=tmp_path / "releases",
        expected_uid=os.getuid(),
    )
    assert renames and all(source == destination for source, destination in renames)
