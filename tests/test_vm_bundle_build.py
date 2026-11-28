"""The VM bundle build workflow's own scripts: every download resolves to a pin, and the summary
refuses lanes that differ and says where (the real builds run in .github/workflows/vm-bundle-build.yml)."""
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import fetch_vm_bundle_inputs as fetch  # noqa: E402

SUMMARY = REPO / "scripts" / "vm_bundle_build_summary.py"
WORKFLOW = REPO / ".github" / "workflows" / "vm-bundle-build.yml"


def test_every_input_has_an_https_url_and_a_sha256():
    pins = fetch.plan()
    assert set(pins["host"]) == {"mmdebstrap_1.5.7-3_all.deb"}
    assert set(pins["ovmf"]) == {"ovmf_2024.02-2ubuntu0.10_all.deb"}
    assert set(pins["go"]) == {"go1.26.11.linux-amd64.tar.gz"}
    # The same Go as the reference build (#808), from go.dev's published sha256.
    assert pins["go"]["go1.26.11.linux-amd64.tar.gz"][1] == \
        "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec"
    assert all(name.startswith("zstandard-0.25.0-cp314-") for name in pins["python"])
    # The debs come from the bundle's own snapshot, so the firmware and the roots share one id.
    snapshot = next(line.split(":", 1)[1].strip() for line in WORKFLOW.read_text().splitlines()
                    if line.strip().startswith("VM_BUNDLE_SNAPSHOT:"))
    for group in ("host", "ovmf"):
        for url, _ in pins[group].values():
            assert url.startswith(f"https://snapshot.ubuntu.com/ubuntu/{snapshot}/pool/")


def _tar(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _lanes(root, second=None):
    second = second or {}
    for lane in ("first", "second"):
        tools = root / f"tools-{lane}"
        bundle = root / f"bundle-{lane}"
        tools.mkdir(parents=True)
        bundle.mkdir(parents=True)
        for name in ("cryptsetup", "veritysetup", "mke2fs", "resize2fs"):
            (tools / name).write_bytes(b"\x7fELF " + name.encode())
        (tools / "toolchain.txt").write_text(f"gcc lane {lane}\n")
        files = {
            "kernel-release": b"6.8.0-151-generic\n",
            "boot-modules.txt": b"sev-guest module kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst\n"
                                b"virtio_blk built-in\n",
            "base-root.verity": b"ab" * 32 + b"\n",
            "base-root.data-bytes": b"8192\n",
            "base-root.tree.txt": b'f 0644 0:0 1 1 3 aa "etc/hostname"\n',
            "modules.tar": _tar({"6.8.0-151-generic/modules.dep": b"a.ko:\n"}),
            "pinned-closure.json": json.dumps({
                "kernel_release": "6.8.0-151-generic", "executables": {"init": "11" * 32},
                "modules": {"usr/lib/modules/6.8.0-151-generic/modules.builtin": "22" * 32}}).encode(),
            "toolchain.txt": f"image lane {lane}\n".encode(),
        }
        if lane == "second":
            files.update(second)
        for name, data in files.items():
            (bundle / name).write_bytes(data)


def _compare(tmp_path):
    return subprocess.run([sys.executable, str(SUMMARY), "compare", "--lanes", str(tmp_path / "lanes"),
                           "--out", str(tmp_path / "out")], capture_output=True, text=True)


def test_identical_lanes_publish_with_digests(tmp_path):
    _lanes(tmp_path / "lanes")
    r = _compare(tmp_path)
    assert r.returncode == 0, r.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["kernel_release"] == "6.8.0-151-generic"
    assert summary["boot_modules"][1] == "virtio_blk built-in"
    assert summary["closure_digests"] == {"init": "11" * 32,
                                          "usr/lib/modules/6.8.0-151-generic/modules.builtin": "22" * 32}
    assert summary["lanes_byte_identical"] and not summary["boot_verified"]
    assert not summary["toolchains_identical"]  # recorded, not compared
    assert "tools/mke2fs" in summary["files"] and "base-root.tree.txt" in summary["files"]
    sums = (tmp_path / "out" / "SHA256SUMS").read_text()
    assert "  tools/veritysetup\n" in sums and "  modules.tar\n" in sums


def test_a_differing_text_file_fails_and_shows_the_line(tmp_path):
    _lanes(tmp_path / "lanes", {"base-root.tree.txt": b'f 0644 0:0 2 1 3 aa "etc/hostname"\n'})
    r = _compare(tmp_path)
    assert r.returncode != 0 and not (tmp_path / "out").exists()
    assert "bundle base-root.tree.txt differs between lanes" in r.stderr
    assert '+f 0644 0:0 2 1 3 aa "etc/hostname"' in r.stderr


def test_a_differing_tar_names_the_member(tmp_path):
    _lanes(tmp_path / "lanes", {"modules.tar": _tar({"6.8.0-151-generic/modules.dep": b"b.ko:\n"})})
    r = _compare(tmp_path)
    assert r.returncode != 0
    assert "bundle modules.tar differs" in r.stderr and "member 6.8.0-151-generic/modules.dep" in r.stderr


def test_a_file_in_one_lane_only_fails(tmp_path):
    _lanes(tmp_path / "lanes", {"measurement.json": b"{}"})
    r = _compare(tmp_path)
    assert r.returncode != 0 and "bundle measurement.json: only in lane second" in r.stderr


def test_a_differing_tool_fails(tmp_path):
    _lanes(tmp_path / "lanes")
    (tmp_path / "lanes" / "tools-second" / "mke2fs").write_bytes(b"\x7fELF other")
    r = _compare(tmp_path)
    assert r.returncode != 0 and "tools mke2fs differs between lanes" in r.stderr


def test_tree_lists_links_without_following_them(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hostname").write_text("cathedral-vm\n")
    os.symlink("/etc/shadow", root / "etc" / "link")
    r = subprocess.run([sys.executable, str(SUMMARY), "tree", str(root)], capture_output=True, text=True, check=True)
    lines = r.stdout.splitlines()
    assert lines[0].startswith("d ") and lines[0].endswith('"etc"')
    assert any(line.startswith("l ") and '"/etc/shadow" "etc/link"' in line for line in lines)
    assert any(line.startswith("f 0") and '"etc/hostname"' in line for line in lines)


@pytest.mark.parametrize("needle", [
    "permissions:\n  contents: read\n",
    "pull_request:",
])
def test_workflow_shape(needle):
    assert needle in WORKFLOW.read_text()


def test_workflow_has_no_expression_inside_run_and_pins_actions_by_commit():
    text = WORKFLOW.read_text()
    assert "secrets." not in text and "pull_request_target" not in text
    in_run = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("run: |") or stripped.startswith("run: "):
            in_run = True
            indent = len(line) - len(line.lstrip())
            assert "${{" not in stripped, line
            continue
        if in_run and stripped and len(line) - len(line.lstrip()) <= indent:
            in_run = False
        if in_run:
            assert "${{" not in line, line
        if stripped.startswith("- uses:") or stripped.startswith("uses:"):
            ref = stripped.split("@", 1)[1].split()[0]
            assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref), line


# ---- the pinned state (commit 2): closure, locks and workflow agree --------------------------

LOCKS = REPO / "room-kit" / "vm" / "locks"
CLOSURE = REPO / "room-kit" / "vm" / "vm_initrd_closure.json"


def _workflow_env(name):
    return next(line.split(":", 1)[1].strip().strip('"') for line in WORKFLOW.read_text().splitlines()
                if line.strip().startswith(name + ":"))


def _lock(name):
    return [line.split(" ") for line in (LOCKS / name).read_text().splitlines()]


def test_locks_have_the_lock_tool_shape():
    for name in ("base-root.packages.lock", "kernel.packages.lock"):
        entries = _lock(name)
        assert entries and all(len(e) == 4 and len(e[3]) == 64 for e in entries), name
        assert [e[0] for e in entries] == sorted(e[0] for e in entries), name


def test_kernel_lock_holds_one_kernel_and_its_extra_modules_of_the_named_release():
    release = _workflow_env("VM_BUNDLE_KERNEL_RELEASE")
    names = {e[0]: e[1] for e in _lock("kernel.packages.lock")}
    images = sorted(n for n in names if n.startswith("linux-image-") and n != "linux-image-virtual")
    assert images == [f"linux-image-{release}"]
    assert f"linux-modules-{release}" in names and f"linux-modules-extra-{release}" in names
    assert names["linux-image-virtual"] == names[f"linux-image-{release}"]


def test_base_root_lock_has_no_kernel_bootloader_or_guest_agent():
    forbidden = ("linux-image-", "linux-modules-", "linux-headers-", "grub", "initramfs-tools", "cloud-init",
                 "qemu-guest-agent")
    assert not [e[0] for e in _lock("base-root.packages.lock") if e[0].startswith(forbidden)]


def test_closure_is_pinned_to_the_locked_kernel_with_the_whole_module_tree():
    closure = json.loads(CLOSURE.read_text())
    release = _workflow_env("VM_BUNDLE_KERNEL_RELEASE")
    assert closure["status"] == "pinned" and closure["kernel_release"] == release
    prefix = f"usr/lib/modules/{release}/"
    files = {p.removeprefix(prefix) for p in closure["modules"]}
    boot = {"kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst", "kernel/drivers/virt/coco/tsm.ko.zst",
            "kernel/drivers/firmware/qemu_fw_cfg.ko.zst", "kernel/drivers/md/dm-verity.ko.zst",
            "kernel/drivers/md/dm-bufio.ko.zst", "kernel/drivers/md/dm-crypt.ko.zst",
            "kernel/arch/x86/crypto/aesni-intel.ko.zst", "kernel/crypto/crypto_simd.ko.zst",
            "kernel/crypto/cryptd.ko.zst"}
    assert boot <= files and "modules.dep" in files
    # The customer root keeps linux-modules whole (overlay, nf_tables, wireguard for Docker and
    # firewalls); extra adds only the boot set, so nothing from its wireless tree is here.
    assert {"kernel/fs/overlayfs/overlay.ko.zst", "kernel/net/netfilter/nf_tables.ko.zst",
            "kernel/drivers/net/wireguard/wireguard.ko.zst"} <= files
    assert len([f for f in files if f.endswith(".ko.zst")]) > 900
    assert not [f for f in files if f.startswith("kernel/drivers/net/wireless/")]
    assert set(closure["executables"]) == {"init", "usr/lib/cathedral/cathedral-vm",
                                           "usr/lib/cathedral/cathedral-vm-attest", "usr/lib/cathedral/cryptsetup",
                                           "usr/lib/cathedral/mke2fs", "usr/lib/cathedral/resize2fs",
                                           "usr/lib/cathedral/veritysetup"}


def test_closure_boots_the_modules_the_kernel_step_checks_in_order():
    closure = json.loads(CLOSURE.read_text())
    build = (REPO / "room-kit" / "vm" / "build-bundle.sh").read_text()
    line = next(l for l in build.splitlines() if l.startswith("KERNEL_MODULES="))
    assert closure["boot_modules"] == line.split("=", 1)[1].strip('"').split()
    assert "aesni_intel" in closure["boot_modules"]
    assert 'if closure["boot_modules"] != names:' in WORKFLOW.read_text()


def test_toolchains_compare_without_the_runner_image_line():
    sys.path.insert(0, str(REPO / "scripts"))
    import vm_bundle_build_summary as summary
    assert summary.same_toolchain("image: ubuntu26 1\ngo 1.26.11\n", "image: ubuntu26 2\ngo 1.26.11\n")
    assert not summary.same_toolchain("image: ubuntu26 1\ngo 1.26.11\n", "image: ubuntu26 1\ngo 1.26.12\n")


def test_summary_records_the_built_commit_event_ref_and_epoch(tmp_path):
    _lanes(tmp_path / "lanes")
    for lane in ("first", "second"):
        (tmp_path / "lanes" / f"bundle-{lane}" / "source-date-epoch").write_text("1795823010\n")
    env = dict(os.environ, SOURCE_SHA="57ef14113bb9d6e989b41dbbf28b60d7a4e46459", GITHUB_SHA="bb20398",
               GITHUB_EVENT_NAME="pull_request", GITHUB_REF="refs/pull/817/merge")
    r = subprocess.run([sys.executable, str(SUMMARY), "compare", "--lanes", str(tmp_path / "lanes"),
                        "--out", str(tmp_path / "out")], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["source_commit"] == "57ef14113bb9d6e989b41dbbf28b60d7a4e46459"
    assert (summary["event"], summary["ref"], summary["source_date_epoch"]) == \
        ("pull_request", "refs/pull/817/merge", "1795823010")


def test_workflow_builds_the_head_commit_on_pinned_runners():
    text = WORKFLOW.read_text()
    assert "SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}" in text
    assert text.count("ref: ${{ env.SOURCE_SHA }}") == 3
    assert "ubuntu-latest" not in text


def test_workflow_builds_against_the_committed_locks():
    text = WORKFLOW.read_text()
    assert _workflow_env("VM_BUNDLE_LOCK_UPDATE") == "0"
    assert "VM_BUNDLE_BASE_LOCK=$GITHUB_WORKSPACE/room-kit/vm/locks/base-root.packages.lock" in text
    assert "VM_BUNDLE_KERNEL_LOCK=$GITHUB_WORKSPACE/room-kit/vm/locks/kernel.packages.lock" in text


def test_a_pinned_run_reports_the_committed_closure(tmp_path):
    _lanes(tmp_path / "lanes")
    for lane in ("first", "second"):
        (tmp_path / "lanes" / f"bundle-{lane}" / "pinned-closure.json").unlink()
        (tmp_path / "lanes" / f"bundle-{lane}" / "measurement.json").write_text(
            json.dumps({"expected_measurement": "ab" * 48, "identity_sha256": "cd" * 32}))
    r = _compare(tmp_path)
    assert r.returncode == 0, r.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    closure = json.loads(CLOSURE.read_text())
    assert summary["closure_digests"]["init"] == closure["executables"]["init"]
    assert summary["closure_module_files"] == len(closure["modules"])
    assert "ab" * 48 in (tmp_path / "out" / "summary.md").read_text()
