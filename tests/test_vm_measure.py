"""AB#999 PR VM1a: vm_measure.py against the shared vectors (VM runtime spec r2 6.1 to 6.3, 13.1 T2).

The vectors (tests/fixtures/vm_measure_v1.json) were made without vm_measure.py: identity,
cmdline and HOST_DATA by hand, measurements by a literal sev-snp-measure 0.0.12 argv. The
measurement tests need that tool (requirements/vm-measure.txt, in the dev extra); they skip
without it locally and fail without it in CI.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import vm_measure_support as support

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "room-kit" / "vm"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vm = _load("vm_measure_under_test", KIT / "vm_measure.py")
VEC = support.load()
IDS = VEC["identities"]
VERITY = "1" * 64


def identity_raw(name: str) -> bytes:
    return IDS[name]["identity_utf8"].encode("ascii")


@pytest.fixture
def tool() -> str:
    path = vm.default_tool()
    try:
        vm.check_tool(path)
    except vm.Refusal:
        if os.environ.get("CI"):
            pytest.fail("sev-snp-measure 0.0.12 must be installed in CI (dev extra)")
        pytest.skip("sev-snp-measure 0.0.12 is not installed")
    return path


@pytest.fixture
def bundle(tmp_path):
    def make(family: str = "genoa") -> Path:
        return support.materialize(VEC, tmp_path / f"bundle-{family}", family)
    return make


# ---- identity, cmdline, HOST_DATA ------------------------------------------------

@pytest.mark.parametrize("name", sorted(IDS))
def test_identity_vector(name):
    v = IDS[name]
    raw = vm.identity_document(v["vm_id"], v["ssh_key_line"], VERITY, 8192, salt_hex=v["salt_hex"])
    assert raw == identity_raw(name)
    assert vm.identity_sha256(raw) == v["identity_sha256"] == hashlib.sha256(raw).hexdigest()
    assert vm.cmdline(VEC["cmdline_template"], v["identity_sha256"]) == v["cmdline"]
    hd = vm.host_data(raw)
    assert hd.hex() == v["host_data_hex"]
    assert base64.b64encode(hd).decode() == v["host_data_b64"]
    # Independent: sha256(domain || sha256(identity)), the D 8.5 shape with the VM domain.
    assert hashlib.sha256(b"cathedral-vm-v1\0" + hashlib.sha256(raw).digest()).hexdigest() == v["host_data_hex"]


def test_vector_constants_equal_code():
    assert VEC["cmdline_template"] == vm.CMDLINE_TEMPLATE_V1
    assert bytes.fromhex(VEC["host_data_domain_hex"]) == vm.HOST_DATA_DOMAIN == b"cathedral-vm-v1\0"


def test_host_data_domain_is_not_a_dedicated_domain():
    receipts = _load("room_receipts_domains", REPO / "room-kit" / "room_receipts.py")
    assert vm.HOST_DATA_DOMAIN not in (receipts.DEDICATED_HOST_DATA_DOMAIN, receipts.DEDICATED_V2_HOST_DATA_DOMAIN)


def test_host_data_formats_match_the_report_verifier_and_qemu():
    # verify_guest_report.py (#774) wants 64 hex; launch-guest.sh passes base64 of the 32 bytes.
    hd = vm.host_data(identity_raw("a"))
    assert len(hd) == 32 and len(hd.hex()) == 64 and hd.hex() == hd.hex().lower()
    assert base64.b64decode(IDS["a"]["host_data_b64"], validate=True) == hd


def test_cmdline_is_deterministic_and_names_only_its_identity():
    a, b = IDS["a"], IDS["b"]
    assert vm.cmdline(vm.CMDLINE_TEMPLATE_V1, a["identity_sha256"]) == vm.cmdline(vm.CMDLINE_TEMPLATE_V1, a["identity_sha256"])
    assert a["cmdline"] != b["cmdline"]
    assert vm.identity_from_cmdline(a["cmdline"]) == a["identity_sha256"]
    assert a["cmdline"].endswith(" cathedral.vm=" + a["identity_sha256"])
    assert a["cmdline"].count("cathedral.vm=") == 1


def test_cmdline_tokens_are_pinned():
    tokens = IDS["a"]["cmdline"].split(" ")
    assert tokens[:-1] == [
        "console=ttyS0", "loglevel=4", "panic=-1", "systemd.import_credentials=no", "systemd.getty_auto=0",
        "systemd.mask=getty@.service", "systemd.mask=serial-getty@.service", "systemd.mask=autovt@.service",
        "systemd.mask=console-getty.service", "systemd.mask=qemu-guest-agent.service"]
    assert tokens[-1] == "cathedral.vm=" + IDS["a"]["identity_sha256"]
    line = IDS["a"]["cmdline"]
    assert len(line) <= vm.CMDLINE_MAX and all(0x21 <= ord(c) <= 0x7E for c in line.replace(" ", ""))
    assert not [t for t in tokens if t.startswith(("init=", "rdinit=", "root="))]


@pytest.mark.parametrize("mutate", [
    lambda s: s + "\n",
    lambda s: s + " ",
    lambda s: s.replace(" ", "  ", 1),
    lambda s: "initrd=initrd " + s,
    lambda s: s[:-1],
    lambda s: s[:-64] + s[-64:].upper(),
    lambda s: s.replace("loglevel=4", "loglevel=7"),
    lambda s: s.replace(" systemd.mask=qemu-guest-agent.service", ""),
    lambda s: s.replace("panic=-1", "panic=-1 rdinit=/bin/sh"),
    lambda s: s.replace("cathedral.vm=", "cathedral.vm=0"),
])
def test_cmdline_refuses_any_other_line(mutate):
    with pytest.raises(vm.Refusal):
        vm.identity_from_cmdline(mutate(IDS["a"]["cmdline"]))


def test_cmdline_refuses_another_template():
    with pytest.raises(vm.Refusal):
        vm.cmdline(vm.CMDLINE_TEMPLATE_V1.replace("loglevel=4", "loglevel=7"), IDS["a"]["identity_sha256"])
    with pytest.raises(vm.Refusal):
        vm.cmdline(vm.CMDLINE_TEMPLATE_V1, IDS["a"]["identity_sha256"].upper())


def _doc(name="a") -> dict:
    return json.loads(identity_raw(name))


def _enc(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


@pytest.mark.parametrize("raw", [
    json.dumps(_doc(), sort_keys=True).encode(),                      # spaces: not canonical
    json.dumps(dict(reversed(list(_doc().items()))), separators=(",", ":")).encode(),  # key order
    identity_raw("a") + b"\n",
    _enc({**_doc(), "extra": 1}),
    _enc({k: v for k, v in _doc().items() if k != "salt_hex"}),
    _enc({**_doc(), "version": 2}),
    _enc({**_doc(), "version": "1"}),
    _enc({**_doc(), "version": True}),
    _enc({**_doc(), "schema": "cathedral.vm.identity/v2"}),
    _enc({**_doc(), "vm_id": "vm-0123456789AB"}),
    _enc({**_doc(), "vm_id": "cg-0123456789ab"}),
    _enc({**_doc(), "salt_hex": "00" * 15}),
    _enc({**_doc(), "salt_hex": "AA" * 16}),
    _enc({**_doc(), "ssh_public_key": _doc()["ssh_public_key"] + " test@example"}),
    _enc({**_doc(), "ssh_public_key": "ssh-dss " + _doc()["ssh_public_key"].split()[1]}),
    _enc({**_doc(), "ssh_public_key": "ssh-rsa " + _doc()["ssh_public_key"].split()[1]}),
    _enc({**_doc(), "base_root_verity": "1" * 63}),
    _enc({**_doc(), "base_root_data_bytes": 8193}),
    _enc({**_doc(), "base_root_data_bytes": 8192.0}),
    _enc({**_doc(), "base_root_data_bytes": [8192]}),
    json.dumps({**_doc(), "vm_id": "vm-0123456789éb"}, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False).encode(),
    b"",
])
def test_identity_refusals(raw):
    with pytest.raises(vm.Refusal):
        vm.parse_identity(raw)
    with pytest.raises(vm.Refusal):
        vm.host_data(raw)


def test_identity_salt_comes_from_the_csprng():
    v = IDS["a"]
    one = vm.parse_identity(vm.identity_document(v["vm_id"], v["ssh_key_line"], VERITY, 8192))
    two = vm.parse_identity(vm.identity_document(v["vm_id"], v["ssh_key_line"], VERITY, 8192))
    assert one["salt_hex"] != two["salt_hex"] and len(one["salt_hex"]) == 32


def test_key_types_equal_the_vm_host():
    ctl = _load("vm_ctl_key_types", KIT / "vm_ctl.py")
    assert vm.KEY_TYPES == ctl.KEY_TYPES
    line = IDS["a"]["ssh_key_line"]
    assert vm.ssh_public_key(line) == ctl.check_key(line)


# ---- bundle manifest -------------------------------------------------------------

MANIFEST_FIELDS = dict(label="test-genoa", cpu_family="genoa", qemu_version="10.2.1",
                       kernel_release="6.8.0-1-generic", initrd_version="vm1-test", snapshot="20261101T000000Z",
                       base_root_verity=VERITY, base_root_data_bytes=8192, ovmf_source="test:synthetic-ovmf-v1")


@pytest.mark.parametrize("family", ["genoa", "turin"])
def test_manifest_vector_and_writer(bundle, tmp_path, family):
    d = bundle(family)
    assert vm.check_bundle(d) == {"bundle": VEC["bundles"][family]["bundle_id"], "label": "test-" + family}
    fresh = tmp_path / ("fresh-" + family)
    fresh.mkdir()
    for name in vm.BUNDLE_FILES:
        shutil.copyfile(d / name, fresh / name)
    fields = {**MANIFEST_FIELDS, "label": "test-" + family, "cpu_family": family}
    assert vm.write_manifest(fresh, **fields) == VEC["bundles"][family]["bundle_id"]
    assert (fresh / "manifest.json").read_bytes() == (d / "manifest.json").read_bytes()
    with pytest.raises(FileExistsError):
        vm.write_manifest(fresh, **fields)


def _manifest(family="genoa") -> dict:
    return json.loads(VEC["bundles"][family]["manifest_utf8"])


@pytest.mark.parametrize("doc", [
    {**_manifest(), "extra": "x"},
    {k: v for k, v in _manifest().items() if k != "ovmf_source"},
    {**_manifest(), "cpu_model": "EPYC-v4"},
    {**_manifest("turin"), "cpu_model": "EPYC-Genoa-v1"},
    {**_manifest(), "cpu_family": "milan"},
    {**_manifest(), "cmdline_template": _manifest()["cmdline_template"].replace("loglevel=4", "loglevel=7")},
    {**_manifest(), "policy": "0xB0000"},
    {**_manifest(), "sev_snp_measure": "0.0.13"},
    {**_manifest(), "base_root_data_bytes": 12288},
    {**_manifest(), "kernel_release": "6.8.0"},
    {**_manifest(), "snapshot": "2026-11-01"},
    {**_manifest(), "sha256": {k: v for k, v in _manifest()["sha256"].items() if k != "base-root.raw"}},
    {**_manifest(), "bytes": {**_manifest()["bytes"], "vmlinuz": 0}},
])
def test_manifest_refusals(doc):
    with pytest.raises(vm.Refusal):
        vm.parse_manifest(_enc(doc))


def test_check_bundle_refuses_a_changed_or_linked_file(bundle):
    d = bundle()
    raw = (d / "base-root.raw").read_bytes()
    (d / "base-root.raw").write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(vm.Refusal, match="base-root.raw"):
        vm.check_bundle(d)
    (d / "base-root.raw").write_bytes(raw)
    vm.check_bundle(d)
    (d / "vmlinuz").rename(d / "vmlinuz.real")
    (d / "vmlinuz").symlink_to(d / "vmlinuz.real")
    with pytest.raises(vm.Refusal, match="vmlinuz"):
        vm.check_bundle(d)


# ---- expected measurement --------------------------------------------------------

def test_measure_argv_is_the_install_sealed_form():
    assert vm.measure_argv("T", 4, "EPYC-Genoa-v1", "o", "k", "i", "a b") == [
        "T", "--mode", "snp", "--vcpus", "4", "--vcpu-type", "EPYC-Genoa-v1",
        "--ovmf", "o", "--kernel", "k", "--initrd", "i", "--append", "a b"]


@pytest.mark.parametrize("v", VEC["measurements"], ids=lambda v: f"{v['identity']}-{v['cpu_family']}-{v['vcpus']}")
def test_measurement_vectors(bundle, tool, v):
    d = bundle(v["cpu_family"])
    got = vm.launch_values(d, identity_raw(v["identity"]), v["vcpus"], v["cpu_family"], tool)
    ident = IDS[v["identity"]]
    assert got == {"bundle": VEC["bundles"][v["cpu_family"]]["bundle_id"], "identity_sha256": ident["identity_sha256"],
                   "cmdline": ident["cmdline"], "host_data": ident["host_data_hex"],
                   "host_data_b64": ident["host_data_b64"], "vcpus": v["vcpus"], "cpu_family": v["cpu_family"],
                   "cpu_model": v["cpu_model"], "policy": "0x30000", "sev_snp_measure": "0.0.12",
                   "expected_measurement": v["expected_measurement"]}


def test_measurement_cross_checked_by_a_direct_sev_snp_measure_call(bundle, tool):
    v = VEC["measurements"][0]
    d = bundle(v["cpu_family"])
    direct = subprocess.run(
        [tool, "--mode", "snp", "--vcpus", str(v["vcpus"]), "--vcpu-type", v["cpu_model"],
         "--ovmf", str(d / "OVMF.amdsev.fd"), "--kernel", str(d / "vmlinuz"),
         "--initrd", str(d / "initrd.cpio.zst"), "--append", IDS[v["identity"]]["cmdline"]],
        check=True, capture_output=True, text=True).stdout.strip()
    assert direct == v["expected_measurement"]
    assert vm.launch_values(d, identity_raw(v["identity"]), v["vcpus"], v["cpu_family"], tool)[
        "expected_measurement"] == direct


def _vector(identity, family, vcpus):
    return next(m["expected_measurement"] for m in VEC["measurements"]
                if (m["identity"], m["cpu_family"], m["vcpus"]) == (identity, family, vcpus))


def test_an_identity_change_changes_the_measurement(bundle, tool):
    assert _vector("a", "genoa", 4) != _vector("b", "genoa", 4)
    v = IDS["a"]
    fresh = vm.identity_document(v["vm_id"], v["ssh_key_line"], VERITY, 8192)  # same key, new salt
    got = vm.launch_values(bundle(), fresh, 4, "genoa", tool)["expected_measurement"]
    assert got not in (_vector("a", "genoa", 4), _vector("b", "genoa", 4))


def test_genoa_and_turin_differ_and_so_do_vcpu_counts():
    assert _vector("a", "genoa", 4) != _vector("a", "turin", 4)
    assert _vector("a", "genoa", 4) != _vector("a", "genoa", 2)
    assert len({m["expected_measurement"] for m in VEC["measurements"]}) == len(VEC["measurements"])


def test_a_bundle_for_another_family_is_refused_before_measuring(bundle, tmp_path):
    never = tmp_path / "never-run"
    with pytest.raises(vm.Refusal, match="another CPU family"):
        vm.launch_values(bundle("genoa"), identity_raw("a"), 4, "turin", str(never))
    with pytest.raises(vm.Refusal, match="cpu_family"):
        vm.launch_values(bundle("genoa"), identity_raw("a"), 4, "milan", str(never))


@pytest.mark.parametrize("vcpus", [0, 65, -1])
def test_vcpu_bounds(bundle, tmp_path, vcpus):
    with pytest.raises(vm.Refusal, match="vcpus"):
        vm.launch_values(bundle(), identity_raw("a"), vcpus, "genoa", str(tmp_path / "never-run"))


def _fake_tool(tmp_path: Path, version: str, output: str) -> str:
    path = tmp_path / "fake-sev-snp-measure"
    path.write_text(f'#!/bin/sh\nif [ "$1" = --version ]; then echo "sev-snp-measure {version}"; exit 0; fi\n'
                    f'echo "$@" > "{tmp_path}/argv"\necho "{output}"\n')
    path.chmod(0o755)
    return str(path)


def test_another_tool_version_is_refused(bundle, tmp_path):
    fake = _fake_tool(tmp_path, "0.0.11", "0" * 96)
    with pytest.raises(vm.Refusal, match="0.0.12 is required"):
        vm.launch_values(bundle(), identity_raw("a"), 4, "genoa", fake)
    assert not (tmp_path / "argv").exists()


def test_tool_output_must_be_one_measurement(bundle, tmp_path):
    fake = _fake_tool(tmp_path, "0.0.12", "not a measurement")
    with pytest.raises(vm.Refusal, match="sev-snp-measure failed"):
        vm.launch_values(bundle(), identity_raw("a"), 4, "genoa", fake)
    argv = (tmp_path / "argv").read_text()
    # The tool saw private copies, not the bundle directory, and the per-VM cmdline.
    assert "/bundle-genoa/" not in argv and IDS["a"]["identity_sha256"] in argv


def test_a_measured_file_changed_after_the_manifest_is_refused(bundle, tmp_path):
    d = bundle()
    (d / "initrd.cpio.zst").write_bytes(b"another initrd")
    fake = _fake_tool(tmp_path, "0.0.12", "0" * 96)
    with pytest.raises(vm.Refusal, match="initrd.cpio.zst"):
        vm.launch_values(d, identity_raw("a"), 4, "genoa", fake)
    assert not (tmp_path / "argv").exists()


# ---- command line ----------------------------------------------------------------

def _cli(*args: str) -> tuple[int, dict]:
    r = subprocess.run([sys.executable, "-I", str(KIT / "vm_measure.py"), *args], capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout)


def test_cli_identity_then_launch(bundle, tmp_path):
    d = bundle()
    key = tmp_path / "id.pub"
    key.write_text(IDS["a"]["ssh_key_line"] + "\n")
    out = tmp_path / "vm-identity.json"
    code, res = _cli("identity", "--bundle", str(d), "--vm-id", "vm-0123456789ab", "--ssh-key-file", str(key),
                     "--out", str(out), "--salt-hex", IDS["a"]["salt_hex"])
    assert code == 0 and res == {"identity_sha256": IDS["a"]["identity_sha256"], "vm_id": "vm-0123456789ab"}
    assert out.read_bytes() == identity_raw("a")
    code, res = _cli("identity", "--bundle", str(d), "--vm-id", "vm-0123456789ab", "--ssh-key-file", str(key),
                     "--out", str(out))
    assert code == 2 and res["error"] == "refused"  # the identity is written once, never replaced
    assert out.read_bytes() == identity_raw("a")
    fake = _fake_tool(tmp_path, "0.0.12", "ab" * 48)
    code, res = _cli("launch", "--bundle", str(d), "--identity", str(out), "--vcpus", "4", "--cpu-family", "genoa",
                     "--tool", fake)
    assert code == 0 and res["expected_measurement"] == "ab" * 48
    assert res["host_data"] == IDS["a"]["host_data_hex"] and res["bundle"] == VEC["bundles"]["genoa"]["bundle_id"]
    code, res = _cli("check-bundle", str(d))
    assert code == 0 and res["bundle"] == VEC["bundles"]["genoa"]["bundle_id"]


# ---- build recipe ----------------------------------------------------------------

BUILD = KIT / "build-bundle.sh"


def test_build_script_parses():
    subprocess.run(["bash", "-n", str(BUILD)], check=True)


def _assignment(name: str) -> str:
    for line in BUILD.read_text().splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    raise AssertionError(f"{name} not set in build-bundle.sh")


def test_base_root_package_set():
    pkgs = _assignment("BASE_PKGS").split(",")
    assert "openssh-server" in pkgs
    forbidden = ("linux-", "cloud-init", "qemu-guest-agent", "grub", "initramfs-tools")
    assert not [p for p in pkgs if p.startswith(forbidden)]
    assert _assignment("KERNEL_PKGS") == "linux-image-virtual"


def test_build_script_refuses_unknown_commands(tmp_path):
    r = subprocess.run(["bash", str(BUILD), "everything", str(tmp_path / "none.env")], capture_output=True, text=True)
    assert r.returncode == 2 and "usage" in r.stderr
