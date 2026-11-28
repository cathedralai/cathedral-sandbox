"""The reference build workflow's own scripts: every download resolves to a pin, and the
summary refuses lanes that differ (the real builds run in .github/workflows/reference-build.yml)."""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import fetch_reference_build_inputs as fetch  # noqa: E402

SUMMARY = REPO / "scripts" / "reference_build_summary.py"


def test_every_input_has_a_url_and_a_sha256():
    pins = fetch.plan()
    verity = json.loads((REPO / "scripts" / "custom_guest_verity_inputs.json").read_text())
    assert set(pins["verity"]) == set(verity)
    assert all(pins["verity"][name][1] == sha for name, sha in verity.items())
    assert set(pins["kernel"]) == {"linux-source-7.0.0_7.0.0-44.44_all.deb"}
    kernel_recipe = (REPO / "scripts" / "build_custom_guest_kernel.sh").read_text()
    assert f"expected={pins['kernel']['linux-source-7.0.0_7.0.0-44.44_all.deb'][1]}" in kernel_recipe
    assert set(pins["go"]) == {"go1.26.11.linux-amd64.tar.gz"}
    assert all(name.startswith("zstandard-0.25.0-") for name in pins["python"])
    assert {name.split("_")[0] for name in pins["kernel-host"]} == {"bc", "libelf-dev", "libelf1t64", "zlib1g-dev", "libzstd-dev"}


def lanes(root, attest_second=b"attest"):
    image = bytearray(0x400)
    image[0x202:0x206] = b"HdrS"
    struct.pack_into("<H", image, 0x20E, 0x100)
    image[0x300:0x31A] = b"7.0.0-cathedral-custom-v1\0"
    init, verity = b"\x7fELF init", b"\x7fELF veritysetup"
    closure = {"init": hashlib.sha256(init).hexdigest(),
               "usr/lib/cathedral/veritysetup": hashlib.sha256(verity).hexdigest()}
    for lane, attest in (("first", b"attest"), ("second", attest_second)):
        kernel = root / f"kernel-{lane}"
        kernel.mkdir(parents=True)
        (kernel / "vmlinuz").write_bytes(bytes(image))
        for name in ("kernel.config", "embedded.config"):
            (kernel / name).write_text("CONFIG_IKCONFIG=y\n")
        (kernel / "toolchain.txt").write_text("gcc 15.2.0\n")
        initrd = root / f"initrd-{lane}"
        initrd.mkdir()
        for name, data in (("initrd.cpio.zst", b"archive"), ("cathedral-init", init), ("veritysetup", verity),
                           ("cathedral-attest", attest), ("cathedral-data", b"data"), ("cryptsetup", b"crypt")):
            (initrd / name).write_bytes(data)
        (initrd / "closure.json").write_text(json.dumps(closure))
        (initrd / "toolchain.txt").write_text("go1.26.11\n")
    return closure


def run(root, out, version="v1"):
    return subprocess.run([sys.executable, str(SUMMARY), "--lanes", str(root), "--initrd-version", version,
                           "--out", str(out)], capture_output=True, text=True)


def test_identical_lanes_give_the_published_set(tmp_path):
    closure = lanes(tmp_path / "lanes")
    result = run(tmp_path / "lanes", tmp_path / "out")
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summary["kernel_version"] == "7.0.0-cathedral-custom-v1"
    assert summary["closure"] == closure and summary["boot_verified"] is False
    assert "cathedral-custom-initrd-v1.cpio.zst" in summary["files"]
    listing = (tmp_path / "out" / "closure-list.txt").read_text()
    assert listing == "".join(f"{closure[p]}  {p}\n" for p in sorted(closure))
    assert summary["files"]["closure-list.txt"]["sha256"] == hashlib.sha256(listing.encode()).hexdigest()


def test_lanes_that_differ_are_refused(tmp_path):
    lanes(tmp_path / "lanes", attest_second=b"other")
    result = run(tmp_path / "lanes", tmp_path / "out")
    assert result.returncode != 0 and "cathedral-attest differs between lanes" in result.stderr
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("version", ["../v1", "", "v1/x"])
def test_a_version_outside_the_name_rule_is_refused(tmp_path, version):
    lanes(tmp_path / "lanes")
    assert run(tmp_path / "lanes", tmp_path / "out", version).returncode != 0


def test_handoff_check_boots_the_built_reference_initrd_and_hands_off_for_real():
    # AB#1027: cathedral-init handed the owner root /proc and /sys read-only, as the VM init did in
    # B3. The check boots this run's kernel and initrd and passes only from inside the check root.
    text = (REPO / ".github" / "workflows" / "reference-build.yml").read_text()
    job = text.split("\n  handoff-check:\n", 1)[1]
    # v2 is the first reference initrd with the writable hand-off; v1 stays as published.
    assert "  INITRD_VERSION: ${{ inputs.initrd_version || 'v2' }}\n" in text and "        default: v2\n" in text
    assert "    needs: summary\n" in job and "name: reference-build\n" in job
    assert '"$RUNNER_TEMP/reference/vmlinuz"' in job
    assert '"$RUNNER_TEMP/reference/cathedral-custom-initrd-$INITRD_VERSION.cpio.zst"' in job
    assert "rdinit=/handoff-check CATHEDRAL_HANDOFF_CHECK=1 -- -test.v -test.run=^TestReferenceHandoffCheck\\$" in job
    assert "grep -qx 'HANDOFF-CHECK: PASS'" in job
    check = (REPO / "room-kit" / "custom-guest" / "internal" / "bootstate" / "handoff_check_linux_amd64_test.go").read_text()
    assert 'handoffCheckPass = "HANDOFF-CHECK: PASS"' in check and check.count("fmt.Println(handoffCheckPass)") == 1
    # The real kernel views and the real hand-off, with only the SNP restrictions left out.
    assert "prepareKernelViews(kernelOperations{directory: bootDirectory, mount: syscall.Mount," in check
    assert "err := (&ReadyRoot{ready: true}).Exec()" in check
    assert "if os.Getpid() == 1 && len(os.Args) == 1 && os.Args[0] == handoffCheckInit {" in check
    assert 'writeKernelFile("/proc/self/oom_score_adj", "-250\\n")' in check
    assert 'writeKernelFile("/sys/devices/virtual/mem/null/uevent", "change\\n")' in check
