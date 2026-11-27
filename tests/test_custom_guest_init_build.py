"""Recipe guards for the dedicated guest init, unlock tool and initrd. No boot, no SNP."""
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "room-kit"))
sys.path.insert(0, str(Path(__file__).parent))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load("custom_helper_build", "build_custom_guest_helper.py")
initrd = load("custom_initrd_make", "make_custom_guest_initrd.py")
root_builder = load("custom_root_build", "build_custom_guest_root.py")
from test_custom_guest_initrd import elf  # noqa: E402

PIN = "11" * 32
PIN2 = "22" * 32


@pytest.fixture
def local_go(monkeypatch):
    go = shutil.which("go")
    if go is None:
        pytest.skip("go toolchain required")
    version = subprocess.run([go, "env", "GOVERSION"], capture_output=True, text=True, check=True).stdout.strip()
    # CI pins go1.26.11 and the real constant applies there. Locally any Go can cross-compile
    # the three mains, so the pin check is not what is under test here.
    monkeypatch.setattr(helper, "GO_VERSION", version)
    return go


def test_three_mains_build_twice_identically_with_pins_linked(local_go, tmp_path):
    outputs = {k: tmp_path / k for k in ("attest", "init", "data")}
    result = helper.build(local_go, outputs["attest"], outputs["init"], outputs["data"], PIN, PIN2)
    blobs = {k: p.read_bytes() for k, p in outputs.items()}
    assert result["rebuild_identical"] and result["init"]["sha256"] == hashlib.sha256(blobs["init"]).hexdigest()
    attest_sha = hashlib.sha256(blobs["attest"]).hexdigest()
    # The init carries exactly the digests it must demand at boot.
    assert PIN.encode() in blobs["init"] and attest_sha.encode() in blobs["init"]
    assert PIN2.encode() in blobs["data"] and PIN.encode() not in blobs["data"]
    assert PIN.encode() not in blobs["attest"]
    # A different pin is a different measured init.
    other = helper.build(local_go, tmp_path / "a2", tmp_path / "i2", None, "33" * 32, None)
    assert other["init"]["sha256"] != result["init"]["sha256"]
    assert other["sha256"] == result["sha256"]  # attest does not depend on the init's pins


@pytest.mark.parametrize("bad", [None, "", "00" * 32, "AB" * 32, "11" * 31, "zz" * 32])
def test_init_and_data_refuse_missing_or_malformed_pins(local_go, tmp_path, bad):
    with pytest.raises(ValueError):
        helper.build(local_go, tmp_path / "a", tmp_path / "i", None, bad, None)
    with pytest.raises(ValueError):
        helper.build(local_go, tmp_path / "a", None, tmp_path / "d", None, bad)
    assert not (tmp_path / "a").exists() and not (tmp_path / "i").exists() and not (tmp_path / "d").exists()


def stage_inputs(tmp_path, **override):
    files = {"cathedral-init": elf(), "veritysetup": elf()}
    files.update(override)
    paths = {}
    for name, data in files.items():
        path = tmp_path / name
        path.write_bytes(data)
        paths[name] = path
    return paths


def test_recipe_lists_exactly_init_and_veritysetup():
    assert initrd.load_recipe() == {"init": "cathedral-init", "usr/lib/cathedral/veritysetup": "veritysetup"}


def test_initrd_builds_reproducibly_from_the_recipe(tmp_path):
    paths = stage_inputs(tmp_path)
    result = initrd.build(paths, initrd.load_recipe(), tmp_path / "initrd.zst", tmp_path / "closure.json")
    closure = json.loads((tmp_path / "closure.json").read_text())
    assert closure == {"init": hashlib.sha256(elf()).hexdigest(),
                       "usr/lib/cathedral/veritysetup": hashlib.sha256(elf()).hexdigest()}
    assert result["double_build_identical"] and result["closure"] == closure
    # The standalone checker accepts what the recipe produced.
    import custom_guest_initrd as archive
    archive.unpack((tmp_path / "initrd.zst").read_bytes(), archive.load_closure(tmp_path / "closure.json"))


def test_initrd_refuses_extra_missing_dynamic_or_symlinked_inputs(tmp_path):
    recipe = initrd.load_recipe()
    paths = stage_inputs(tmp_path)
    with pytest.raises(ValueError, match="inputs must be exactly"):
        initrd.assemble({**paths, "cryptsetup": paths["veritysetup"]}, recipe)
    with pytest.raises(ValueError, match="inputs must be exactly"):
        initrd.assemble({"cathedral-init": paths["cathedral-init"]}, recipe)
    dynamic = stage_inputs(tmp_path / "dyn" if (tmp_path / "dyn").mkdir() is None else tmp_path,
                           veritysetup=elf(extra_type=3))
    with pytest.raises(ValueError, match="PT_INTERP"):
        initrd.assemble(dynamic, recipe)
    linked = dict(paths)
    link_dir = tmp_path / "link"
    link_dir.mkdir()
    (link_dir / "veritysetup").symlink_to(paths["veritysetup"])
    linked["veritysetup"] = link_dir / "veritysetup"
    with pytest.raises(ValueError, match="not a regular file"):
        initrd.assemble(linked, recipe)
    (tmp_path / "text").write_text("#!/bin/sh\n")
    with pytest.raises(ValueError):
        initrd.assemble({**paths, "veritysetup": tmp_path / "text"}, recipe)
    assert not (tmp_path / "initrd.zst").exists()


def test_recipe_cannot_add_paths_outside_the_closure_rules(tmp_path):
    for executables in ({"init": "cathedral-init", "usr/bin/ssh": "ssh"},
                        {"init": "cathedral-init", "../x": "x"},
                        {"usr/lib/cathedral/veritysetup": "veritysetup"},
                        {"init": "cathedral-init", "usr/lib/cathedral/a": "cathedral-init"}):
        path = tmp_path / "recipe.json"
        path.write_text(json.dumps({"schema": initrd.SCHEMA, "executables": executables}))
        with pytest.raises(ValueError):
            initrd.load_recipe(path)
        path.unlink()
    path.write_text(json.dumps({"schema": "other", "executables": {"init": "cathedral-init"}}))
    with pytest.raises(ValueError):
        initrd.load_recipe(path)


def root_tree(tmp_path, mke2fs=True, mnt=True):
    root = tmp_path / "root"
    for name in ("sbin/init", "usr/sbin/sshd", "usr/bin/ip") + (("usr/sbin/mke2fs",) if mke2fs else ()):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELFsynthetic")
    (root / "etc/ssh").mkdir(parents=True)
    (root / "etc/shadow").write_text("root:!:20000:0:99999:7:::\n")
    (root / "root/.ssh").mkdir(parents=True)
    if mnt:
        (root / "mnt").mkdir()
    return root


def test_root_installs_data_tools_together_with_the_pinned_cryptsetup(tmp_path):
    root = root_tree(tmp_path)
    root_builder.configure(root, b"attest", "aa" * 32, b"data-tool", b"static-cryptsetup")
    assert (root / "usr/bin/cathedral-data").read_bytes() == b"data-tool"
    assert (root / "usr/lib/cathedral/cryptsetup").read_bytes() == b"static-cryptsetup"
    assert (root / "usr/bin/cathedral-data").stat().st_mode & 0o777 == 0o755
    # Not installed unless asked: an image without a data disk carries no unlock tool.
    plain = root_tree(tmp_path / "plain" if (tmp_path / "plain").mkdir() is None else tmp_path)
    root_builder.configure(plain, b"attest", "aa" * 32)
    assert not (plain / "usr/bin/cathedral-data").exists()


def test_root_refuses_half_installed_data_tools_and_missing_mke2fs(tmp_path):
    with pytest.raises(ValueError, match="together"):
        root_builder.configure(root_tree(tmp_path), b"attest", "aa" * 32, b"data", None)
    with pytest.raises(ValueError, match="together"):
        root_builder.configure(root_tree(tmp_path / "b" if (tmp_path / "b").mkdir() is None else tmp_path),
                               b"attest", "aa" * 32, None, b"crypt")
    sub = tmp_path / "c"
    sub.mkdir()
    with pytest.raises(ValueError, match="mke2fs"):
        root_builder.configure(root_tree(sub, mke2fs=False), b"attest", "aa" * 32, b"data", b"crypt")
    sub = tmp_path / "d"
    sub.mkdir()
    with pytest.raises(ValueError, match="/mnt"):
        root_builder.configure(root_tree(sub, mnt=False), b"attest", "aa" * 32, b"data", b"crypt")
