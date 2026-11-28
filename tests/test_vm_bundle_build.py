"""The VM bundle build workflow's own scripts: every download resolves to a pin, and the summary
refuses lanes that differ and says where (the real builds run in .github/workflows/vm-bundle-build.yml)."""
import hashlib
import io
import json
import os
import shutil
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
    assert set(pins["ovmf"]) == {"ovmf-amdsev_2025.11-3ubuntu7.3_all.deb"}
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


def _unpinned(tmp_path):
    path = tmp_path / "unpinned-pin.json"
    path.write_text(json.dumps({"schema": "cathedral.vm.base-root-pin/v1", "status": "unpinned"}))
    return path


def _compare(tmp_path, pin=None, env=None):
    pin = pin or _unpinned(tmp_path)
    return subprocess.run([sys.executable, str(SUMMARY), "compare", "--lanes", str(tmp_path / "lanes"),
                           "--out", str(tmp_path / "out"), "--pin", str(pin)], capture_output=True, text=True,
                          env=env)


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
    # No directory size: it follows the build host's history, not the image.
    assert lines[0].split()[5] == "-"
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
    # The customer root keeps linux-modules whole: Docker needs overlay, veth and bridge, and
    # nft, ufw and WireGuard need nf_tables and wireguard. The cut once left only the boot set;
    # this keeps that gap from coming back. Extra adds only the boot set, so none of its
    # wireless tree is here.
    assert {"kernel/fs/overlayfs/overlay.ko.zst", "kernel/net/netfilter/nf_tables.ko.zst",
            "kernel/drivers/net/veth.ko.zst", "kernel/drivers/net/wireguard/wireguard.ko.zst",
            "kernel/net/bridge/bridge.ko.zst"} <= files
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


def test_initrd_check_boots_the_published_initrd_and_runs_the_real_disk_step():
    # B2's boot 2 failed at F3 in the initramfs (no /run for cryptsetup's lock) after every runner
    # test had passed: the check runs the initrd's own cryptsetup where the init runs it.
    text = WORKFLOW.read_text()
    job = text.split("\n  initrd-check:\n", 1)[1]
    assert "    needs: summary\n" in job and "name: vm-bundle\n" in job
    assert '"$RUNNER_TEMP/vm-bundle/vmlinuz"' in job and '"$RUNNER_TEMP/vm-bundle/initrd.cpio.zst"' in job
    assert "rdinit=/vm-initrd-check CATHEDRAL_INITRD_CHECK=1 -- -test.v -test.run=^TestInitrdDiskCheck\\$" in job
    for serial in ("cathedral-root", "cathedral-base", "cathedral-mailbox"):
        assert f"serial={serial}" in job
    assert "grep -qx 'INITRD-CHECK: PASS'" in job
    check = (REPO / "room-kit" / "custom-guest" / "cmd" / "cathedral-vm-init" / "initrd_check_linux_amd64_test.go").read_text()
    assert "func TestInitrdDiskCheck(t *testing.T) {" in check
    assert 'initrdCheckPass = "INITRD-CHECK: PASS"' in check
    # The real platform's Disk, so the init's own /run step is what makes the lock path.
    assert "out, err := p.Disk(ctx, vmdisk.Config{" in check
    assert "if _, err := os.Lstat(lockParent); !errors.Is(err, os.ErrNotExist) {" in check


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
    r = _compare(tmp_path, env=env)
    assert r.returncode == 0, r.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["source_commit"] == "57ef14113bb9d6e989b41dbbf28b60d7a4e46459"
    assert (summary["event"], summary["ref"], summary["source_date_epoch"]) == \
        ("pull_request", "refs/pull/817/merge", "1795823010")


def test_workflow_builds_the_head_commit_on_pinned_runners():
    text = WORKFLOW.read_text()
    assert "SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}" in text
    assert text.count("ref: ${{ env.SOURCE_SHA }}") == 4
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


def test_summary_reports_the_initrd_size(tmp_path):
    _lanes(tmp_path / "lanes", {"initrd.cpio.zst": b"z" * 1234})
    (tmp_path / "lanes" / "bundle-first" / "initrd.cpio.zst").write_bytes(b"z" * 1234)
    r = _compare(tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads((tmp_path / "out" / "summary.json").read_text())["initrd_bytes"] == 1234
    assert "- Initrd: 1234 bytes" in (tmp_path / "out" / "summary.md").read_text()


# ---- the base root pin (AB#1022 PR A): every commit builds the pinned base root --------------

PIN = REPO / "room-kit" / "vm" / "base_root_pin.json"
BASE_LOCK = LOCKS / "base-root.packages.lock"
import vm_bundle_build_summary as summary_mod  # noqa: E402


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _epoch(pin, snapshot="20261126T000000Z", lock=BASE_LOCK):
    return subprocess.run([sys.executable, "-I", str(SUMMARY), "epoch", "--snapshot", snapshot, "--lock", str(lock),
                           "--pin", str(pin)], capture_output=True, text=True)


def test_the_committed_pin_is_bundle_a9585311s_base_root_and_matches_this_tree():
    pin = summary_mod.load_pin(PIN)
    assert pin["status"] == "pinned"
    # Run 46095917678 at main 82c964b4: its epoch is that commit's time.
    assert (pin["source_date_epoch"], pin["snapshot"], pin["from_run"]) == \
        (1795831236, "20261126T000000Z", "46095917678")
    assert pin["base_root_raw_sha256"] == "0a200cc3d608a8dcbe04c3a4b7384fe311b94d88b50c62071bfcb968852368e9"
    assert pin["base_root_verity"] == "4504476434ccff04fff2c167674f1e952f4772e4516acf621346db4763a2e7d4"
    assert pin["base_root_data_bytes"] == 771751936
    assert pin["snapshot"] == _workflow_env("VM_BUNDLE_SNAPSHOT")
    assert pin["base_root_packages_lock_sha256"] == _sha(BASE_LOCK.read_bytes())
    # The recipe guard: an edit to any base-root input needs a new pin (and a new first bundle).
    # If this fails, run "scripts/vm_bundle_build_summary.py recipe" and read README "Base root pin".
    assert pin["recipe_sha256"] == summary_mod.recipe_sha256()


def test_epoch_gives_the_pinned_epoch():
    r = _epoch(PIN)
    assert r.returncode == 0, r.stderr
    assert r.stdout == "pinned 1795831236\n"


def test_epoch_unpinned_leaves_the_commit_time_to_the_workflow(tmp_path):
    r = _epoch(_unpinned(tmp_path))
    assert r.returncode == 0 and r.stdout == "unpinned\n"


@pytest.mark.parametrize("field, value, message", [
    ("snapshot", "20261127T000000Z", "VM_BUNDLE_SNAPSHOT is 20261126T000000Z"),
    ("base_root_packages_lock_sha256", "00" * 32, "the base lock's sha256 is"),
    ("recipe_sha256", "00" * 32, "the base-root recipe's sha256 is"),
])
def test_epoch_refuses_a_pin_for_another_snapshot_lock_or_recipe(tmp_path, field, value, message):
    pin = json.loads(PIN.read_text())
    pin[field] = value
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(pin))
    r = _epoch(path)
    assert r.returncode != 0 and r.stdout == ""
    assert message in r.stderr and "needs a new pin" in r.stderr


@pytest.mark.parametrize("field, value", [
    ("status", "maybe"), ("schema", "cathedral.vm.base-root-pin/v2"), ("source_date_epoch", "1795831236"),
    ("base_root_data_bytes", 4097), ("base_root_verity", "AB" * 32), ("from_run", ""),
])
def test_a_malformed_pin_is_refused(tmp_path, field, value):
    pin = json.loads(PIN.read_text())
    pin[field] = value
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(pin))
    with pytest.raises(ValueError):
        summary_mod.load_pin(path)


def _pinned_lanes(tmp_path, raw=b"base root", second=None):
    base = {"base-root.raw": raw, "base-root.packages.lock": b"lock\n", "source-date-epoch": b"1795831236\n"}
    _lanes(tmp_path / "lanes", dict(base, **(second or {})))
    for name, data in base.items():
        (tmp_path / "lanes" / "bundle-first" / name).write_bytes(data)
    pin = {"schema": "cathedral.vm.base-root-pin/v1", "status": "pinned", "source_date_epoch": 1795831236,
           "snapshot": "20261126T000000Z", "base_root_packages_lock_sha256": _sha(b"lock\n"),
           "base_root_raw_sha256": _sha(b"base root"), "base_root_verity": "ab" * 32, "base_root_data_bytes": 8192,
           "from_run": "1", "recipe_sha256": "cd" * 32}
    path = tmp_path / "pin.json"
    path.write_text(json.dumps(pin))
    return path, pin


def test_a_base_root_equal_to_the_pin_publishes_and_says_pinned(tmp_path):
    path, _ = _pinned_lanes(tmp_path)
    r = _compare(tmp_path, path, env=dict(os.environ, VM_BUNDLE_SNAPSHOT="20261126T000000Z"))
    assert r.returncode == 0, r.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["base_root_pin"] == "pinned" and summary["base_root_to_pin"] is None
    assert "- Base root pin: pinned (run 1)" in (tmp_path / "out" / "summary.md").read_text()


@pytest.mark.parametrize("change, named", [
    ({"raw": b"another base root"}, "base-root.raw sha256"),
    ({"verity": "ef" * 32}, "base_root_verity"),
    ({"data_bytes": 4096}, "base_root_data_bytes"),
    ({"epoch": 1795831237}, "source_date_epoch"),
    ({"lock": "00" * 32}, "base-root.packages.lock sha256"),
    ({"snapshot": "20261127T000000Z"}, "snapshot"),
])
def test_lanes_that_agree_on_another_base_root_publish_nothing(tmp_path, change, named):
    raw = change.get("raw", b"base root")
    path, pin = _pinned_lanes(tmp_path, raw=raw, second={"base-root.raw": raw})
    pin["base_root_verity"] = change.get("verity", pin["base_root_verity"])
    pin["base_root_data_bytes"] = change.get("data_bytes", pin["base_root_data_bytes"])
    pin["source_date_epoch"] = change.get("epoch", pin["source_date_epoch"])
    pin["base_root_packages_lock_sha256"] = change.get("lock", pin["base_root_packages_lock_sha256"])
    path.write_text(json.dumps(pin))
    env = dict(os.environ, VM_BUNDLE_SNAPSHOT=change.get("snapshot", "20261126T000000Z"))
    r = _compare(tmp_path, path, env=env)
    assert r.returncode != 0 and not (tmp_path / "out").exists()
    assert "not the pinned one" in r.stderr and named in r.stderr


def test_lanes_that_differ_fail_before_the_pin_is_read(tmp_path):
    path, _ = _pinned_lanes(tmp_path, second={"base-root.raw": b"other lane"})
    r = _compare(tmp_path, path)
    assert r.returncode != 0 and "bundle base-root.raw differs between lanes" in r.stderr


def test_an_unpinned_run_prints_the_pin_to_commit(tmp_path):
    _pinned_lanes(tmp_path)
    env = dict(os.environ, VM_BUNDLE_SNAPSHOT="20261126T000000Z", GITHUB_RUN_ID="42")
    r = _compare(tmp_path, env=env)
    assert r.returncode == 0, r.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    to_pin = summary["base_root_to_pin"]
    assert summary["base_root_pin"] == "unpinned"
    assert to_pin["base_root_raw_sha256"] == _sha(b"base root") and to_pin["source_date_epoch"] == 1795831236
    assert (to_pin["from_run"], to_pin["recipe_sha256"]) == ("42", summary_mod.recipe_sha256())
    # What it prints is a pin load_pin accepts.
    (tmp_path / "printed.json").write_text(json.dumps(to_pin))
    assert summary_mod.load_pin(tmp_path / "printed.json")["status"] == "pinned"


def _recipe_tree(tmp_path):
    root = tmp_path / "repo"
    for name in (summary_mod.RECIPE_SCRIPT, *summary_mod.RECIPE_FILES, summary_mod.RECIPE_HOST_INPUT[0]):
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / name, root / name)
    return root


@pytest.mark.parametrize("name", [*summary_mod.RECIPE_FUNCTIONS])
def test_an_edit_to_any_recipe_function_moves_the_recipe(tmp_path, name):
    root = _recipe_tree(tmp_path)
    script = root / summary_mod.RECIPE_SCRIPT
    text = script.read_text()
    body = summary_mod.shell_function(text, name)
    script.write_text(text.replace(body, body.replace(f"{name}() {{", f"{name}() {{ :;", 1), 1))
    assert summary_mod.recipe_sha256(root) != summary_mod.recipe_sha256(REPO)


def test_an_edit_to_the_package_list_tools_or_mmdebstrap_moves_the_recipe(tmp_path):
    base = summary_mod.recipe_sha256(REPO)
    edits = [
        (summary_mod.RECIPE_SCRIPT, "BASE_PKGS=systemd,", "BASE_PKGS=systemd,jq,"),
        ("scripts/vm_initrd_tools_inputs.json", "{", "{ "),
        ("scripts/build_vm_initrd_tools.py", "import", "import  "),
        ("scripts/vm_bundle_build_inputs.json", "d4acfd32", "00acfd32"),
    ]
    for path, old, new in edits:
        root = _recipe_tree(tmp_path / path.replace("/", "_"))
        text = (root / path).read_text()
        assert old in text, path
        (root / path).write_text(text.replace(old, new, 1))
        assert summary_mod.recipe_sha256(root) != base, path


def test_an_edit_outside_the_base_root_recipe_does_not_move_it(tmp_path):
    root = _recipe_tree(tmp_path)
    script = root / summary_mod.RECIPE_SCRIPT
    text = script.read_text()
    kernel = summary_mod.shell_function(text, "build_kernel")
    script.write_text(text.replace(kernel, kernel.replace("build_kernel() {", "build_kernel() { :;", 1), 1))
    assert summary_mod.recipe_sha256(root) == summary_mod.recipe_sha256(REPO)


def test_a_renamed_recipe_function_is_an_error(tmp_path):
    root = _recipe_tree(tmp_path)
    script = root / summary_mod.RECIPE_SCRIPT
    script.write_text(script.read_text().replace("host_leaks() {", "host_leaks_v2() {", 1))
    with pytest.raises(ValueError, match="no shell function host_leaks"):
        summary_mod.recipe_sha256(root)


def test_workflow_takes_the_epoch_from_the_pin_and_the_commit_time_only_when_unpinned():
    text = WORKFLOW.read_text()
    step = text.split("- name: bundle.env", 1)[1].split("- name:", 1)[0]
    assert "vm_bundle_build_summary.py epoch --snapshot \"$VM_BUNDLE_SNAPSHOT\"" in step
    assert "--lock room-kit/vm/locks/base-root.packages.lock" in step
    assert 'if [ "$pin_status" = unpinned ]; then epoch=$(git log -1 --format=%ct); fi' in step
    assert step.count("git log -1 --format=%ct") == 1
    assert "SOURCE_DATE_EPOCH=$epoch" in step
    # The summary checks against the committed pin, never one a step names.
    assert "vm_bundle_build_summary.py compare --lanes" in text and "--pin" not in text
