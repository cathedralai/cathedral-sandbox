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
