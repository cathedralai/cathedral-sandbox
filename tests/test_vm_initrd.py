"""AB#999 VM1b: the VM initrd recipe (room-kit/vm/build-vm-initrd.py).

Archive and closure rules only: no boot, no SNP claim. The Go mains are really built (twice); the
init is the testdata stub until cmd/cathedral-vm-init lands, and the four static C tools are
stand-ins (the stub's bytes under four names), since the tools build runs in its own CI job.

- an extra file, a dynamic ELF, a missing listed module or a wrong digest fails the check;
- a double build is identical; the archive is the same bytes twice;
- an untagged build has no vmcuttest hook, and a build with the tag is refused;
- an unpinned closure is refused.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import stat
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "room-kit"
MODULE = KIT / "custom-guest"
sys.path.insert(0, str(KIT))
import custom_guest_initrd as base  # noqa: E402

spec = importlib.util.spec_from_file_location("build_vm_initrd", KIT / "vm" / "build-vm-initrd.py")
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)

RELEASE = "6.8.0-100-generic"
PREFIX = f"usr/lib/modules/{RELEASE}/"
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="go is needed to build the mains")

MODULE_FILES = {
    "modules.dep": (
        "kernel/drivers/virtio/virtio.ko.zst:\n"
        "kernel/drivers/virtio/virtio_ring.ko.zst: kernel/drivers/virtio/virtio.ko.zst\n"
        "kernel/drivers/block/virtio_blk.ko.zst: kernel/drivers/virtio/virtio_ring.ko.zst kernel/drivers/virtio/virtio.ko.zst\n"
        "kernel/drivers/md/dm-crypt.ko.zst:\n"
        "kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst:\n"
    ),
    "modules.builtin": "kernel/drivers/md/dm-verity.ko\nkernel/drivers/firmware/qemu_fw_cfg.ko\nkernel/drivers/net/virtio_net.ko\n",
    "kernel/drivers/virtio/virtio.ko.zst": "m1",
    "kernel/drivers/virtio/virtio_ring.ko.zst": "m2",
    "kernel/drivers/block/virtio_blk.ko.zst": "m3",
    "kernel/drivers/md/dm-crypt.ko.zst": "m4",
    "kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst": "m5",
}


def zstd_or_skip():
    try:
        base.zstd_module()
    except (ImportError, ValueError):
        pytest.skip("python-zstandard 0.25.0 is needed to pack")


@pytest.fixture(scope="module")
def stub_bytes(tmp_path_factory) -> bytes:
    out = tmp_path_factory.mktemp("stub") / "stub"
    return recipe.go_build(MODULE, "./testdata/vm-init-stub", out)


def unpinned_closure() -> dict:
    closure = json.loads((KIT / "vm" / "vm_initrd_closure.json").read_text())
    closure["go_mains"]["init"] = "./testdata/vm-init-stub"
    closure["kernel_release"] = RELEASE
    return closure


@pytest.fixture
def staged(tmp_path, stub_bytes):
    tools, modules = tmp_path / "tools", tmp_path / "modules"
    tools.mkdir()
    for name in ("cryptsetup", "veritysetup", "mke2fs", "resize2fs"):
        (tools / name).write_bytes(stub_bytes)
    for rel, text in MODULE_FILES.items():
        path = modules / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    closure = unpinned_closure()
    path = tmp_path / "closure.json"
    path.write_text(json.dumps(closure))
    return {"closure_path": path, "closure": closure, "tools": tools, "modules": modules, "tmp": tmp_path}


def pin(staged) -> dict:
    files = recipe.gather(staged["closure"], MODULE, staged["tools"], staged["modules"])
    pinned = recipe.pinned_view(staged["closure"], files)
    recipe.check_closure_shape(pinned)
    staged["files"] = files
    return pinned


def elf(interp=False, needed=False) -> bytes:
    count = 1 + interp + needed
    payload = 64 + count * 56
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 62, 1, 0x400000 + payload, 64, 0, 0,
                         64, 56, count, 0, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0, payload + 16, payload + 16, 4096)
    if interp:
        ph += struct.pack("<IIQQQQQQ", 3, 4, payload, 0, 0, 16, 16, 8)
    if needed:
        ph += struct.pack("<IIQQQQQQ", 2, 4, payload, 0, 0, 16, 16, 8)
    return header + ph + struct.pack("<qQ", 1 if needed else 0, 0)


def test_the_checked_in_closure_is_unpinned_and_refused():
    closure = recipe.load_closure(KIT / "vm" / "vm_initrd_closure.json")
    assert closure["status"] == "unpinned"
    with pytest.raises(ValueError, match="unpinned"):
        recipe.require_pinned(closure)
    with pytest.raises(ValueError):
        recipe.build_raw({}, closure)


def test_archive_roundtrip_load_order_and_generated_files(staged):
    pinned = pin(staged)
    files = staged["files"]
    raw = recipe.build_raw(files, pinned)
    assert recipe.build_raw(dict(reversed(list(files.items()))), pinned) == raw  # input order never matters
    digests = recipe.verify_raw(raw, pinned)
    listing = digests[recipe.MODULES_LIST_PATH]
    assert hashlib.sha256(files[PREFIX + "modules.dep"]).hexdigest() == pinned["modules"][PREFIX + "modules.dep"]
    gen = recipe.generated_files(pinned, files[PREFIX + "modules.dep"], files[PREFIX + "modules.builtin"])
    names = [Path(line).name for line in gen[recipe.MODULES_LIST_PATH].decode().splitlines()]
    # Dependencies first; built-in modules (dm-verity, qemu_fw_cfg, virtio_net) have no file.
    assert names == ["sev-guest.ko.zst", "dm-crypt.ko.zst", "virtio.ko.zst", "virtio_ring.ko.zst", "virtio_blk.ko.zst"]
    assert listing == hashlib.sha256(gen[recipe.MODULES_LIST_PATH]).hexdigest()
    manifest = json.loads(gen[recipe.CLOSURE_PATH])
    assert manifest["executables"] == pinned["executables"] and manifest["kernel_release"] == RELEASE


def test_a_double_build_is_identical_and_packs_the_same_bytes(staged):
    zstd_or_skip()
    pinned = pin(staged)
    first = recipe.pack(recipe.build_raw(staged["files"], pinned), pinned)
    again = pin(staged)
    assert again == pinned  # the mains and the tools build to the same digests
    assert recipe.pack(recipe.build_raw(staged["files"], again), again) == first
    assert recipe.unpack(first, pinned) == recipe.build_raw(staged["files"], pinned)


def test_cli_pin_build_check(staged, capsys):
    zstd_or_skip()
    pinned = pin(staged)
    closure_path = staged["tmp"] / "pinned.json"
    closure_path.write_text(json.dumps(pinned))
    archive = staged["tmp"] / "vm-initrd.cpio.zst"
    common = ["--closure", str(closure_path), "--module-dir", str(MODULE), "--tools", str(staged["tools"]),
              "--modules", str(staged["modules"])]
    assert recipe.main(["build", *common, "--archive", str(archive)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "archive_verified"
    assert recipe.main(["check", "--closure", str(closure_path), "--archive", str(archive)]) == 0
    with pytest.raises(ValueError):  # an existing archive path is never overwritten
        recipe.main(["build", *common, "--archive", str(archive)])


def test_an_extra_file_fails_the_check(staged):
    pinned = pin(staged)
    raw = recipe.build_raw(staged["files"], pinned)
    for extra in ("usr/lib/cathedral/extra", PREFIX + "extra.ko.zst", "etc/passwd"):
        tampered = raw[:-len(base.entry("TRAILER!!!", 0, b"", 0))] + base.entry(extra, stat.S_IFREG | 0o644, b"x", 9999) \
            + base.entry("TRAILER!!!", 0, b"", 0)
        with pytest.raises(ValueError):
            recipe.verify_raw(tampered, pinned)
    files = dict(staged["files"], **{"usr/lib/cathedral/extra": staged["files"]["init"]})
    with pytest.raises(ValueError, match="differ from the pinned closure"):
        recipe.build_raw(files, pinned)


@pytest.mark.parametrize("kind", ["interp", "needed", "not_elf"])
def test_a_dynamic_or_non_elf_executable_fails_the_check(staged, kind):
    pinned = pin(staged)
    bad = {"interp": elf(interp=True), "needed": elf(needed=True), "not_elf": b"#!/bin/sh\n"}[kind]
    files = dict(staged["files"], **{"usr/lib/cathedral/cryptsetup": bad})
    closure = json.loads(json.dumps(pinned))
    closure["executables"]["usr/lib/cathedral/cryptsetup"] = hashlib.sha256(bad).hexdigest()
    with pytest.raises(ValueError):
        recipe.build_raw(files, closure)


def test_a_missing_listed_module_fails_the_check(staged):
    pinned = pin(staged)
    files = dict(staged["files"])
    del files[PREFIX + "kernel/drivers/block/virtio_blk.ko.zst"]
    with pytest.raises(ValueError):
        recipe.build_raw(files, pinned)
    # An archive that really lacks it, assembled by hand, fails the check too.
    raw = recipe.build_raw(staged["files"], pinned)
    cut = raw.replace(b"virtio_blk.ko.zst\0", b"virtio_blk.ko.zsX\0")
    with pytest.raises(ValueError):
        recipe.verify_raw(cut, pinned)


def test_a_boot_module_that_is_neither_a_file_nor_built_in_fails(staged):
    closure = json.loads(json.dumps(staged["closure"]))
    closure["boot_modules"].append("no-such-module")
    dep, builtin = MODULE_FILES["modules.dep"], MODULE_FILES["modules.builtin"]
    with pytest.raises(ValueError, match="neither"):
        recipe.load_order(closure, dep, builtin)


def test_a_wrong_digest_or_changed_module_fails(staged):
    pinned = pin(staged)
    bad = dict(staged["files"])
    bad[PREFIX + "kernel/drivers/md/dm-crypt.ko.zst"] = b"changed"
    with pytest.raises(ValueError, match="hash mismatch"):
        recipe.build_raw(bad, pinned)
    wrong = json.loads(json.dumps(pinned))
    wrong["executables"]["usr/lib/cathedral/mke2fs"] = "0" * 64
    with pytest.raises(ValueError, match="hash mismatch"):
        recipe.build_raw(staged["files"], wrong)


def test_an_untagged_build_has_no_cut_hook_and_a_tagged_build_is_refused(staged, tmp_path, stub_bytes):
    assert recipe.CUT_HOOK_MARKER not in stub_bytes
    mains = recipe.build_go_mains(staged["closure"], MODULE)
    assert all(recipe.CUT_HOOK_MARKER not in data for data in mains.values())
    # The same stub built with the tag carries it in its build info.
    env = recipe.go_env()
    out = tmp_path / "tagged"
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-tags=vmcuttest", "-o", str(out),
                    "./testdata/vm-init-stub"], cwd=MODULE, env=env, check=True)
    tagged = out.read_bytes()
    assert recipe.CUT_HOOK_MARKER in tagged
    pinned = pin(staged)
    closure = json.loads(json.dumps(pinned))
    closure["executables"]["init"] = hashlib.sha256(tagged).hexdigest()
    with pytest.raises(ValueError, match="vmcuttest"):
        recipe.build_raw(dict(staged["files"], init=tagged), closure)


def test_the_go_environment_drops_caller_flags(monkeypatch):
    monkeypatch.setenv("GOFLAGS", "-tags=vmcuttest")
    monkeypatch.setenv("CGO_ENABLED", "1")
    monkeypatch.setenv("CC", "evil")
    env = recipe.go_env()
    assert env["GOFLAGS"] == "-mod=readonly" and env["CGO_ENABLED"] == "0" and "CC" not in env


def test_a_link_or_special_file_in_the_module_tree_is_refused(staged):
    pinned = pin(staged)
    link = staged["modules"] / "kernel" / "link.ko.zst"
    link.symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="link"):
        recipe.read_modules(pinned, staged["modules"])


def test_a_duplicate_closure_key_is_refused():
    with pytest.raises(ValueError, match="duplicate"):
        recipe.parse_closure(b'{"schema":"cathedral.vm.initrd-closure/v1","schema":"x"}')
