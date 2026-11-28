"""AB#999 PR VM1a: vm_measure.py against the shared vectors (VM runtime spec r2 6.1 to 6.3, 13.1 T2).

The vectors (tests/fixtures/vm_measure_v1.json) were made without vm_measure.py: identity,
cmdline and HOST_DATA by hand, measurements by a literal sev-snp-measure 0.0.12 argv. The
measurement tests need that tool, installed by hash (requirements/vm-measure.txt). CI passes
its path as CATHEDRAL_SEV_SNP_MEASURE; without it they skip locally and fail in CI.
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
    path = os.environ.get("CATHEDRAL_SEV_SNP_MEASURE")
    if os.environ.get("CI") and not path:
        pytest.fail("CI must pass the hash-installed sev-snp-measure as CATHEDRAL_SEV_SNP_MEASURE")
    path = path or vm.default_tool()
    try:
        vm.check_tool(path)
    except vm.Refusal:
        if os.environ.get("CI"):
            pytest.fail(f"sev-snp-measure 0.0.12 is not at {path}")
        pytest.skip("sev-snp-measure 0.0.12 is not installed (requirements/vm-measure.txt)")
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
        "systemd.mask=console-getty.service", "systemd.mask=emergency.service", "systemd.mask=rescue.service",
        "systemd.mask=debug-shell.service", "systemd.mask=qemu-guest-agent.service"]
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
    lambda s: s.replace(" systemd.mask=emergency.service", ""),
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
    {**_manifest(), "cpu_model": "EPYC-Genoa-v1"},
    {**_manifest("turin"), "cpu_model": "EPYC-Genoa-v1"},
    {**_manifest(), "cpu_model": "EPYC-v1"},   # same signature as EPYC-v4, still not the accepted name
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
    assert vm.measure_argv("T", 4, "EPYC-v4", "o", "k", "i", "a b") == [
        "T", "--mode", "snp", "--vcpus", "4", "--vcpu-type", "EPYC-v4",
        "--ovmf", "o", "--kernel", "k", "--initrd", "i", "--append", "a b"]


@pytest.mark.parametrize("v", VEC["measurements"], ids=lambda v: f"{v['identity']}-{v['cpu_family']}-{v['vcpus']}")
def test_measurement_vectors(bundle, tool, v):
    d = bundle(v["cpu_family"])
    got = vm.launch_values(d, identity_raw(v["identity"]), v["vcpus"], v["cpu_family"], tool)
    ident = IDS[v["identity"]]
    assert got == {"bundle": VEC["bundles"][v["cpu_family"]]["bundle_id"], "identity_sha256": ident["identity_sha256"],
                   "cmdline": ident["cmdline"], "host_data": ident["host_data_hex"],
                   "host_data_b64": ident["host_data_b64"], "vcpus": v["vcpus"], "cpu_family": v["cpu_family"],
                   "cpu_model": v["cpu_model"], "cpu_signature": vm.CPU_SIGNATURES[v["cpu_model"]],
                   "policy": "0x30000", "sev_snp_measure": "0.0.12",
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


def test_every_vm_runs_epyc_v4_until_the_tool_supports_turin():
    # Toby, 27 Nov 12:19Z: EPYC-v4 is the default and the only accepted model.
    assert vm.CPU_MODEL == "EPYC-v4" and set(vm.CPU_MODELS.values()) == {"EPYC-v4"}
    assert {m["cpu_model"] for m in VEC["measurements"]} == {"EPYC-v4"}
    assert {json.loads(b["manifest_utf8"])["cpu_model"] for b in VEC["bundles"].values()} == {"EPYC-v4"}
    # One model, so a Genoa and a Turin bundle of the same files measure the same.
    assert _vector("a", "genoa", 4) == _vector("a", "turin", 4)


def test_vcpu_counts_and_identities_change_the_measurement():
    assert _vector("a", "genoa", 4) != _vector("a", "genoa", 2)
    by_input = {(m["identity"], m["vcpus"]): m["expected_measurement"] for m in VEC["measurements"]}
    assert len(set(by_input.values())) == len(by_input)


def _direct(tool: str, d: Path, cpu: list[str], line: str, vcpus: int = 4) -> str:
    return subprocess.run([tool, "--mode", "snp", "--vcpus", str(vcpus), *cpu, "--ovmf", str(d / "OVMF.amdsev.fd"),
                           "--kernel", str(d / "vmlinuz"), "--initrd", str(d / "initrd.cpio.zst"), "--append", line],
                          check=True, capture_output=True, text=True).stdout.strip()


def test_the_measurement_binds_the_cpu_signature_not_the_model(bundle, tool):
    # Documents a limit, not a feature: QEMU models with one CPUID signature measure the
    # same, though their feature sets differ (the CPUID page is outside the digest).
    # The launch values name the signature; the VM init must check features (VM1b).
    d, line = bundle(), IDS["a"]["cmdline"]
    v4 = _direct(tool, d, ["--vcpu-type", "EPYC-v4"], line)
    assert v4 == _vector("a", "turin", 4)
    assert _direct(tool, d, ["--vcpu-type", "EPYC-v1"], line) == v4
    assert _direct(tool, d, ["--vcpu-type", "EPYC-Genoa-v1"], line) != v4
    # CPU_SIGNATURES is the signature the tool measures for each model.
    for model, sig in vm.CPU_SIGNATURES.items():
        family, cpu_model, stepping = (str(int(x, 16)) for x in sig.split(":"))
        by_sig = _direct(tool, d, ["--vcpu-family", family, "--vcpu-model", cpu_model, "--vcpu-stepping", stepping], line)
        assert by_sig == _direct(tool, d, ["--vcpu-type", model], line)
    assert set(vm.CPU_SIGNATURES) == set(vm.CPU_MODELS.values())


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


@pytest.mark.parametrize("args", [
    ["everything", "none.env"],
    ["base-root", "none.env", "--fast"],
    ["manifest", "none.env", "--verify-reproducible"],
    ["kernel"],
    ["kernel", "none.env", "--verify-reproducible", "extra"],
])
def test_build_script_refuses_bad_arguments(tmp_path, args):
    r = subprocess.run(["bash", str(BUILD), *args], capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 2 and "usage" in r.stderr


def _e2fsprogs_floor(tmp_path: Path, banner: str) -> subprocess.CompletedProcess:
    text = BUILD.read_text()
    block = text[text.index("# >>> e2fsprogs floor"):text.index("# <<< e2fsprogs floor")]
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    (fake / "mke2fs").write_text(f"#!/bin/sh\necho '{banner}' >&2\necho '\tUsing EXT2FS Library version x' >&2\n")
    (fake / "mke2fs").chmod(0o755)
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", block + "\ne2fsprogs_floor && echo floor-ok"], capture_output=True, text=True,
                          env=env)


@pytest.mark.parametrize("banner,ok", [
    ("mke2fs 1.47.1 (20-May-2024)", True),
    ("mke2fs 1.47.2 (1-Jan-2025)", True),
    ("mke2fs 1.48 (1-Jan-2027)", True),
    ("mke2fs 1.47.0 (5-Feb-2023)", False),
    ("mke2fs 1.46.5 (30-Dec-2021)", False),
    ("mke2fs 1.47.1-rc1 (1-May-2024)", False),
    ("something else", False),
])
def test_e2fsprogs_floor(tmp_path, banner, ok):
    r = _e2fsprogs_floor(tmp_path, banner)
    assert (r.returncode == 0 and "floor-ok" in r.stdout) is ok
    if not ok:
        assert "older than 1.47.1" in r.stderr


def test_mkfs_runs_with_source_date_epoch_after_the_floor():
    text = BUILD.read_text()
    base = text[text.index("build_base_root() {"):text.index("# ---------------------------------------------------------------- kernel")]
    assert base.index("e2fsprogs_floor") < base.index("pinned_root base-root")
    mkfs = next(line for line in base.splitlines() if '"$MKE2FS" -t ext4' in line)
    assert "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" in mkfs and "LC_ALL=C" in mkfs
    # No host /etc/mke2fs.conf: the compiled-in defaults of the pinned mke2fs.
    assert "MKE2FS_CONFIG=$B/no-mke2fs.conf" in mkfs
    assert "E2FSPROGS_FAKE_TIME=" not in base


def test_both_roots_take_all_three_pockets_of_one_snapshot():
    text = BUILD.read_text()
    root = text[text.index("pinned_root() {"):text.index("# ---------------------------------------------------------------- base root")]
    assert 'for pocket in "$SUITE" "$SUITE-updates" "$SUITE-security"; do' in root
    assert 'sources+=("deb [signed-by=$KEYRING] $MIRROR $pocket main universe")' in root
    assert '"${sources[@]}"' in root and "--components" not in root
    assert "MIRROR=https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT" in text


def _host_leaks(tmp_path, files):
    text = BUILD.read_text()
    block = text[text.index("host_leaks() {"):text.index("# ---------------------------------------------------------------- base root")]
    root = tmp_path / "root"
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    (root / "var").mkdir(exist_ok=True)
    script = 'die() { echo "$*" >&2; exit 1; }\n' + block + f'\nhost_leaks {root} && echo clean'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def test_host_leaks_passes_a_root_without_host_files(tmp_path):
    r = _host_leaks(tmp_path, {"etc/hostname": b"cathedral-vm\n", "etc/os-release": b"NAME=Ubuntu\n"})
    assert r.returncode == 0 and "clean" in r.stdout, r.stderr


def test_host_leaks_refuses_a_copy_of_the_host_resolv_conf(tmp_path):
    host = Path("/etc/resolv.conf")
    if not host.is_file() or host.stat().st_size == 0:
        pytest.skip("this host has no resolv.conf")
    r = _host_leaks(tmp_path, {"etc/.resolv.conf.systemd-resolved.bak": host.read_bytes()})
    assert r.returncode != 0
    assert "copy of a build host file: etc/.resolv.conf.systemd-resolved.bak" in r.stderr


def test_base_root_removes_the_resolved_backup_before_the_image():
    text = BUILD.read_text()
    base = text[text.index("build_base_root() {"):text.index("# ---------------------------------------------------------------- kernel")]
    assert 'rm -f "$R/etc/.resolv.conf.systemd-resolved.bak"' in base
    assert base.index("host_leaks") < base.index('"$MKE2FS" -t ext4')


def test_kernel_step_takes_the_extra_modules_of_the_named_release():
    assert _assignment("KERNEL_EXTRA_PKG") == "linux-modules-extra"
    text = BUILD.read_text()
    kernel = text[text.index("build_kernel() {"):text.index("# ---------------------------------------------------------------- manifest")]
    assert 'pinned_root kernel "$KERNEL_PKGS,$KERNEL_EXTRA_PKG-$KERNEL_RELEASE"' in kernel
    assert '[ "$kver" = "$KERNEL_RELEASE" ]' in kernel


def _module_cut_script() -> str:
    text = BUILD.read_text()
    start = text.index("\n", text.index('python3 -I - "$tree" "$B/boot-modules.txt"')) + 1
    start = text.index("\n", start) + 1  # the "|| die" line
    return text[start:text.index("\nEOF\n", start) + 1]


RELEASE_DIR = "6.8.0-151-generic"
# linux-modules (the whole tree ships) and linux-modules-extra (only the boot set ships).
PACKAGE_FILES = {
    "kernel/drivers/md/dm-verity.ko.zst": "kernel/drivers/md/dm-bufio.ko.zst",
    "kernel/drivers/md/dm-bufio.ko.zst": "",
    "kernel/drivers/md/dm-crypt.ko.zst": "",
    "kernel/arch/x86/crypto/aesni-intel.ko.zst": "kernel/crypto/crypto_simd.ko.zst kernel/crypto/cryptd.ko.zst",
    "kernel/crypto/crypto_simd.ko.zst": "kernel/crypto/cryptd.ko.zst",
    "kernel/crypto/cryptd.ko.zst": "",
    "kernel/fs/overlayfs/overlay.ko.zst": "",
    "kernel/net/netfilter/nf_tables.ko.zst": "",
}
EXTRA_FILES = {
    "kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst": "kernel/drivers/virt/coco/tsm.ko.zst",
    "kernel/drivers/virt/coco/tsm.ko.zst": "",
    "kernel/drivers/firmware/qemu_fw_cfg.ko.zst": "",
    "kernel/drivers/net/wireless/foo.ko.zst": "kernel/sound/core/snd.ko.zst",
    "kernel/sound/core/snd.ko.zst": "",
}
BOOT_LISTING = ("sev-guest module kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst\n"
                "dm-verity module kernel/drivers/md/dm-verity.ko.zst\n"
                "aesni_intel module kernel/arch/x86/crypto/aesni-intel.ko.zst\n"
                "dm-crypt module kernel/drivers/md/dm-crypt.ko.zst\n"
                "qemu_fw_cfg module kernel/drivers/firmware/qemu_fw_cfg.ko.zst\n"
                "virtio_blk built-in\nvirtio_net built-in\n")


def _cut(tmp_path, listing=BOOT_LISTING):
    tree = tmp_path / "usr/lib/modules" / RELEASE_DIR
    files = {**PACKAGE_FILES, **EXTRA_FILES}
    for rel in files:
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(b"ko")
    (tree / "modules.dep").write_text("".join(f"{rel}: {needs}".rstrip() + "\n" for rel, needs in files.items()))
    (tree / "modules.order").write_text("".join(rel.removesuffix(".zst") + "\n" for rel in files))
    for index in ("modules.builtin", "modules.builtin.modinfo", "modules.alias", "modules.dep.bin"):
        (tree / index).write_text("x\n")
    (tree / "vdso" / ".build-id" / "3e").mkdir(parents=True)
    (tree / "vdso" / "vdso64.so").write_bytes(b"elf")
    os.symlink("../../vdso64.so", tree / "vdso" / ".build-id" / "3e" / "e2.debug")
    # dpkg's list of linux-modules: its files, its directories and its one link, under /lib.
    shipped = list(PACKAGE_FILES) + ["modules.builtin", "modules.builtin.modinfo", "modules.order",
                                     "vdso", "vdso/vdso64.so", "vdso/.build-id/3e/e2.debug", "kernel"]
    package = tmp_path / f"linux-modules-{RELEASE_DIR}.list"
    package.write_text("".join(f"/lib/modules/{RELEASE_DIR}/{rel}\n" for rel in shipped) + "/boot/vmlinuz\n")
    boot = tmp_path / "boot-modules.txt"
    boot.write_text(listing)
    r = subprocess.run([sys.executable, "-I", "-", str(tree), str(boot), str(package)], input=_module_cut_script(),
                       capture_output=True, text=True)
    return r, tree


def test_module_cut_ships_the_package_tree_and_only_the_boot_set_of_extra(tmp_path):
    r, tree = _cut(tmp_path)
    assert r.returncode == 0, r.stderr
    left = sorted(p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file() or p.is_symlink())
    extra_kept = ["kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst", "kernel/drivers/virt/coco/tsm.ko.zst",
                  "kernel/drivers/firmware/qemu_fw_cfg.ko.zst"]
    # The depmod outputs go too (depmod rebuilds them), and so do the links.
    assert left == sorted(list(PACKAGE_FILES) + extra_kept +
                          ["modules.builtin", "modules.builtin.modinfo", "modules.order", "vdso/vdso64.so"])
    assert not (tree / "kernel/sound").exists() and not (tree / "vdso/.build-id").exists()
    kept = set(PACKAGE_FILES) | set(extra_kept)
    assert (tree / "modules.order").read_text().splitlines() == \
        [rel.removesuffix(".zst") for rel in {**PACKAGE_FILES, **EXTRA_FILES} if rel in kept]


def test_module_cut_refuses_a_boot_module_modules_dep_does_not_know(tmp_path):
    r, _ = _cut(tmp_path, "vfio module kernel/drivers/vfio/vfio.ko.zst\n")
    assert r.returncode != 0 and "modules.dep has no entry" in r.stderr


def test_module_cut_refuses_a_package_list_of_another_tree(tmp_path):
    r, tree = _cut(tmp_path)
    assert r.returncode == 0
    tree2 = tmp_path / "other" / "6.8.0-152-generic"
    tree2.mkdir(parents=True)
    (tree2 / "modules.dep").write_text("")
    (tree2 / "modules.order").write_text("")
    boot = tmp_path / "empty-boot.txt"
    boot.write_text("virtio_blk built-in\n")
    r = subprocess.run([sys.executable, "-I", "-", str(tree2), str(boot), str(tmp_path / f"linux-modules-{RELEASE_DIR}.list")],
                       input=_module_cut_script(), capture_output=True, text=True)
    assert r.returncode != 0 and "lists no file of this tree" in r.stderr


def test_kernel_step_requires_aes_ni_for_dm_crypt():
    modules = _assignment("KERNEL_MODULES").strip('"').split()
    assert modules.index("aesni_intel") < modules.index("dm-crypt")
    assert "CRYPTO_AES_NI_INTEL" in _assignment("KERNEL_CONFIG_YM")
    text = BUILD.read_text()
    kernel = text[text.index("build_kernel() {"):text.index("# ---------------------------------------------------------------- manifest")]
    assert "grep -qx 'CONFIG_CRYPTO_AES_NI_INTEL=y'" in kernel and "grep -q '^aesni_intel module '" in kernel
    assert _assignment("KERNEL_TREE_PKG") == "linux-modules"


def test_kernel_step_records_built_in_boot_modules():
    text = BUILD.read_text()
    kernel = text[text.index("build_kernel() {"):text.index("# ---------------------------------------------------------------- manifest")]
    assert "modules.builtin" in kernel and '"$B/boot-modules.txt"' in kernel
    assert "build/boot-modules.txt" in text[text.index("step_outputs() {"):]
