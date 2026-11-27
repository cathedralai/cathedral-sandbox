"""AB#999 VM5: pre-launch gates, the host change gate and the SEV baseline compare in enforce mode
(VM runtime spec r2 8.3, 13.1 T4). No root, no /dev/sev: a host tree in tmp (VM_GATES_ROOT), a fake
QEMU binary, and the SEV status read replaced by a dict parsed with sev_status.py itself."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "room-kit" / "vm"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gates = load("vm_gates", KIT / "vm_gates.py")
sev = load("sev_status_for_vm_gates", REPO / "ops" / "custom-guest" / "sev_status.py")

TCB = "0103030800000076"


def snp_bytes(guests=1):
    return (bytes([1, 58, 1, 1]) + (10).to_bytes(4, "little") + (0).to_bytes(4, "little")
            + guests.to_bytes(4, "little") + bytes.fromhex(TCB) + bytes.fromhex(TCB))


def sev_bytes(guests=1):
    return bytes([1, 58, 2]) + (1 | 0x100).to_bytes(4, "little") + bytes([10]) + guests.to_bytes(4, "little")


STATUS = {"snp": sev.parse_snp(snp_bytes()), "sev": sev.parse_sev(sev_bytes())}
QEMU_SCRIPT = '#!/bin/sh\n[ -n "$QEMU_RAN" ] && : > "$QEMU_RAN"\necho "QEMU emulator version 10.2.1 (test build)"\n'
RELEASE = "6.8.0-48-generic"


class Host:
    def __init__(self, tmp: Path, monkeypatch):
        self.root, self.vms = tmp / "host", tmp / "vms"
        self.monkeypatch = monkeypatch
        monkeypatch.setenv("VM_GATES_ROOT", str(self.root))
        monkeypatch.setenv("VM_ROOT", str(self.vms))
        self.qemu_ran = tmp / "qemu-ran"
        monkeypatch.setenv("QEMU_RAN", str(self.qemu_ran))
        self.qemu = self.root / "usr/bin/qemu-system-x86_64"
        self.write(self.qemu, QEMU_SCRIPT, 0o755)
        self.write(self.root / "proc/sys/kernel/osrelease", RELEASE + "\n")
        self.boot("boot-1")
        self.bundle = self.make_bundle({"OVMF.amdsev.fd": b"ovmf", "vmlinuz": b"kernel",
                                        "initrd.cpio.zst": b"initrd", "base-root.raw": b"root" * 4096})
        self.make_vm("vm1", self.bundle, 2)
        self.host_file({"bundles": [self.bundle], "verified": {self.bundle: [self.build([2])]}})
        self.sev = copy.deepcopy(STATUS)
        self.write(self.baseline, json.dumps(STATUS, sort_keys=True) + "\n", 0o600)
        monkeypatch.setattr(gates, "read_sev", lambda: copy.deepcopy(self.sev))

    baseline = property(lambda self: self.root / gates.BASELINE)
    latch = property(lambda self: self.root / gates.LATCH)
    host_path = property(lambda self: self.root / gates.HOST_FILE)

    @staticmethod
    def write(path: Path, text, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or path.exists():
            path.unlink()
        (path.write_bytes if isinstance(text, bytes) else path.write_text)(text)
        path.chmod(mode)

    def boot(self, boot_id: str) -> None:
        self.write(self.root / "proc/sys/kernel/random/boot_id", boot_id + "\n")

    def build(self, vcpus, **over) -> dict:
        entry = {"qemu_sha256": hashlib.sha256(self.qemu.read_bytes()).hexdigest(), "qemu_version": "10.2.1",
                 "kernel_release": RELEASE, "vcpus": vcpus}
        entry.update(over)
        return entry

    def make_bundle(self, files: dict, manifest_extra: dict | None = None) -> str:
        manifest = {"version": 1, "label": "test",
                    "sha256": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()},
                    "bytes": {n: len(b) for n, b in files.items()}}
        manifest.update(manifest_extra or {})
        raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        bid = hashlib.sha256(raw).hexdigest()
        d = self.vms / "bundles" / bid
        d.mkdir(parents=True)
        for name, data in files.items():
            (d / name).write_bytes(data)
        (d / "manifest.json").write_bytes(raw)
        return bid

    def make_vm(self, name: str, bundle: str, vcpus: int, **over) -> None:
        env = {"VM_NAME": name, "VM_DIR": str(self.vms / name), "VM_VCPUS": str(vcpus), "VM_MEM_GIB": "4",
               "VM_BUNDLE": bundle, "VM_SLOT": "0"}
        env.update(over)
        self.write(self.vms / name / "vm.env", "".join(f"{k}='{v}'\n" for k, v in env.items() if v is not None))

    def host_file(self, doc, mode: int = 0o644) -> None:
        self.write(self.host_path, doc if isinstance(doc, str) else json.dumps(doc), mode)

    def run(self, *argv: str, capsys) -> tuple[int, dict, str]:
        code = gates.main(list(argv))
        captured = capsys.readouterr()
        lines = captured.out.splitlines()
        assert len(lines) == 1, captured.out
        return code, json.loads(lines[0]), captured.err


@pytest.fixture
def host(tmp_path, monkeypatch):
    return Host(tmp_path, monkeypatch)


def refused(host, capsys, error, *argv):
    code, doc, err = host.run(*(argv or ("check", "vm1")), capsys=capsys)
    assert (code, doc["ok"], doc["error"]) == (gates.EXIT[error], False, error), doc
    assert err.count("\n") == 1 and err.startswith(f"vm-gates: {error}: "), err
    return doc["detail"]


# ---- interface ------------------------------------------------------------------------------

def test_exit_codes_are_distinct_and_clear_of_the_unit_codes():
    codes = list(gates.EXIT.values())
    assert len(set(codes)) == len(codes) == 8
    # 0 pass, 1 internal, 2 usage; 75 (relaunch) and 78 (launcher refusal) belong to the unit.
    assert not set(codes) & {0, 1, 2, 75, 78}


def test_all_gates_pass(host, capsys):
    code, doc, err = host.run("check", "vm1", capsys=capsys)
    assert (code, doc, err) == (0, {"ok": True, "name": "vm1", "bundle": host.bundle, "host_build": "verified"}, "")


def test_check_api_raises_the_refusal(host):
    host.host_path.unlink()
    with pytest.raises(gates.GateRefusal) as e:
        gates.check("vm1")
    assert (e.value.error, e.value.code) == ("vm_host_not_enabled", 11)


def test_usage_and_internal_errors_refuse(host, capsys, monkeypatch):
    code, doc, _ = host.run("check", capsys=capsys)
    assert (code, doc["error"]) == (2, "usage")
    code, doc, _ = host.run("baseline", "--force", capsys=capsys)
    assert (code, doc["error"]) == (2, "usage")
    monkeypatch.setattr(gates, "vm_of", lambda name: 1 / 0)
    code, doc, err = host.run("check", "vm1", capsys=capsys)
    assert (code, doc["error"], err.count("\n")) == (1, "internal", 1)


def test_wrapper_runs_isolated_python_and_keeps_the_exit_code(host):
    assert subprocess.run(["bash", "-n", str(KIT / "vm-gates.sh")]).returncode == 0
    host.host_path.unlink()
    r = subprocess.run([str(KIT / "vm-gates.sh"), "check", "vm1"], capture_output=True, text=True,
                       env=dict(os.environ), timeout=60)
    assert r.returncode == 11, r
    assert json.loads(r.stdout)["error"] == "vm_host_not_enabled"
    assert r.stderr.startswith("vm-gates: vm_host_not_enabled: ") and r.stderr.count("\n") == 1


# ---- gate 10: the VM ------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["vm2", "../vm1", ".history", "VM1", ""])
def test_unknown_or_bad_vm_name(host, capsys, name):
    refused(host, capsys, "vm_invalid", "check", name)


@pytest.mark.parametrize("over", [{"VM_BUNDLE": None}, {"VM_BUNDLE": "ab" * 31}, {"VM_NAME": "vm9"},
                                  {"VM_VCPUS": "0"}, {"VM_VCPUS": "65"}, {"VM_VCPUS": "2x"}])
def test_vm_env_without_valid_fields(host, capsys, over):
    host.make_vm("vm1", host.bundle, 2, **over)
    refused(host, capsys, "vm_invalid")


def test_vm_env_writable_by_others(host, capsys):
    (host.vms / "vm1" / "vm.env").chmod(0o666)
    assert "not group or world writable" in refused(host, capsys, "vm_invalid")


# ---- gate 11: the host file -----------------------------------------------------------------

def test_no_host_file_refuses_every_launch(host, capsys):
    host.host_path.unlink()
    assert "is missing" in refused(host, capsys, "vm_host_not_enabled")


@pytest.mark.parametrize("doc", [
    "not json", "[]", {}, {"bundles": "x"}, {"bundles": ["ABC"]},
    {"bundles": [], "verified": []},
    {"bundles": [], "verified": {"ab" * 32: [{"qemu_sha256": "ab" * 32}]}},
    {"bundles": [], "verified": {"ab" * 32: [{"qemu_sha256": "ab" * 32, "qemu_version": "10.2.1",
                                             "kernel_release": RELEASE, "vcpus": [2], "extra": 1}]}},
    {"bundles": [], "verified": {"ab" * 32: [{"qemu_sha256": "ab" * 32, "qemu_version": "10.2.1",
                                             "kernel_release": RELEASE, "vcpus": [True]}]}},
    {"bundles": [], "verified": {"ab" * 32: [{"qemu_sha256": "ab" * 32, "qemu_version": "10.2.1",
                                             "kernel_release": RELEASE, "vcpus": []}]}},
    {"bundles": [], "canary_vms": ["Bad Name"]},
])
def test_invalid_host_file_refuses_the_whole_host(host, capsys, doc):
    if isinstance(doc, dict) and "bundles" in doc:
        doc["bundles"] = doc["bundles"] or [host.bundle]
    host.host_file(doc)
    refused(host, capsys, "vm_host_not_enabled")


def test_host_file_unsafe(host, capsys):
    host.host_path.chmod(0o664)
    refused(host, capsys, "vm_host_not_enabled")
    real = host.host_path.with_name("real.json")
    host.host_path.chmod(0o644)
    host.host_path.rename(real)
    host.host_path.symlink_to(real)
    refused(host, capsys, "vm_host_not_enabled")


def test_host_file_keeps_other_owners_keys(host, capsys):
    doc = json.loads(host.host_path.read_text())
    doc["launcher_note"] = "a key another reader owns"
    host.host_file(doc)
    assert host.run("check", "vm1", capsys=capsys)[0] == 0


# ---- gate 12: bundle enabled ----------------------------------------------------------------

def test_bundle_not_enabled(host, capsys):
    other = host.make_bundle({"vmlinuz": b"another kernel"})
    host.make_vm("vm1", other, 2)
    assert other[:16] in refused(host, capsys, "vm_bundle_not_enabled")


# ---- gate 14: the host change gate ----------------------------------------------------------

def test_qemu_binary_swapped_same_version(host, capsys):
    # Same --version output, another binary: an Ubuntu rebuild of one upstream version looks like this.
    host.write(host.qemu, QEMU_SCRIPT + "# rebuilt\n", 0o755)
    assert "is not a verified build" in refused(host, capsys, "vm_host_changed")


def test_kernel_release_changed(host, capsys):
    host.write(host.root / "proc/sys/kernel/osrelease", "6.8.0-49-generic\n")
    assert "6.8.0-49-generic" in refused(host, capsys, "vm_host_changed")


def test_vcpu_count_without_a_canary(host, capsys):
    host.make_vm("vm1", host.bundle, 4)
    assert "4 vCPUs" in refused(host, capsys, "vm_host_changed")


def test_build_verified_for_another_bundle_only(host, capsys):
    other = host.make_bundle({"vmlinuz": b"another kernel"})
    host.make_vm("vm2", other, 2)
    host.host_file({"bundles": [host.bundle, other], "verified": {host.bundle: [host.build([2])]}})
    refused(host, capsys, "vm_host_changed", "check", "vm2")


def test_qemu_or_kernel_unreadable(host, capsys):
    (host.root / "proc/sys/kernel/osrelease").unlink()
    assert "kernel release" in refused(host, capsys, "vm_host_changed")
    host.write(host.root / "proc/sys/kernel/osrelease", RELEASE + "\n")
    host.qemu.unlink()
    assert "cannot read" in refused(host, capsys, "vm_host_changed")


def test_check_never_runs_qemu(host, capsys):
    assert host.run("check", "vm1", capsys=capsys)[0] == 0
    assert not host.qemu_ran.exists()


def test_canary_starts_on_an_unverified_build_and_nothing_else_does(host, capsys):
    host.write(host.qemu, QEMU_SCRIPT + "# upgraded\n", 0o755)
    host.make_vm("canary1", host.bundle, 2)
    host.host_file({"bundles": [host.bundle], "verified": {host.bundle: []}, "canary_vms": ["canary1"]})
    code, doc, _ = host.run("check", "canary1", capsys=capsys)
    assert (code, doc["host_build"]) == (0, "canary")
    refused(host, capsys, "vm_host_changed")  # vm1, a customer VM, is not a canary
    host.sev["snp"]["vlek_en"] = 1  # a canary skips only the host build gate
    refused(host, capsys, "sev_platform_changed", "check", "canary1")


def test_host_build_prints_a_verified_entry(host, capsys):
    code, doc, _ = host.run("host-build", capsys=capsys)
    assert code == 0 and host.qemu_ran.exists()
    entry = host.build([2])
    del entry["vcpus"]
    assert doc == entry
    assert gates.valid_build({**doc, "vcpus": [2]})


# ---- gates 15 to 17: SEV status against the baseline ----------------------------------------

def test_sev_tool_is_the_custom_guest_one():
    """One SEV reader and compare for both products (D 5.9 tool, #780): no second field list here."""
    assert Path(gates.sev_tool().__file__).resolve() == REPO / "ops" / "custom-guest" / "sev_status.py"
    source = (KIT / "vm_gates.py").read_text()
    for fields in sev.COMPARED.values():
        for f in fields:
            assert f'"{f}"' not in source, f


def test_baseline_missing_or_invalid(host, capsys):
    host.baseline.unlink()
    refused(host, capsys, "sev_baseline_missing")
    host.write(host.baseline, json.dumps({"snp": {"api_major": 1}, "sev": STATUS["sev"]}), 0o600)
    assert "lacks snp fields" in refused(host, capsys, "sev_baseline_missing")
    host.write(host.baseline, json.dumps(STATUS), 0o666)
    refused(host, capsys, "sev_baseline_missing")


def test_sev_status_unreadable(host, capsys, monkeypatch):
    def fail():
        raise gates.GateRefusal("sev_status_unreadable", "SEV command 9 failed: [Errno 13] Permission denied")
    monkeypatch.setattr(gates, "read_sev", fail)
    assert "Permission denied" in refused(host, capsys, "sev_status_unreadable")


def test_real_reader_errors_map_to_unreadable(host, capsys, monkeypatch):
    monkeypatch.undo()  # the real read_sev, on a /dev/sev that does not exist under VM_GATES_ROOT
    monkeypatch.setenv("VM_GATES_ROOT", str(host.root))
    monkeypatch.setenv("VM_ROOT", str(host.vms))
    refused(host, capsys, "sev_status_unreadable")


def drifted(part: str, field: str) -> dict:
    now = copy.deepcopy(STATUS)
    v = now[part][field]
    now[part][field] = (v[:-1] + ("0" if v[-1] != "0" else "1")) if isinstance(v, str) else v + 1
    return now


COMPARED = [(part, f) for part, fields in sev.COMPARED.items() for f in fields]


@pytest.mark.parametrize("part,field", COMPARED)
def test_enforce_compare_any_drift_fails_with_its_reason(host, capsys, part, field):
    host.sev = drifted(part, field)
    detail = refused(host, capsys, "sev_platform_changed", "enforce")
    assert detail.startswith(f"{part}.{field}: ")
    assert json.loads(host.latch.read_text())["diff"] == [d for d in detail.split("; ")]
    assert (host.latch.stat().st_mode & 0o777) == 0o600


@pytest.mark.parametrize("part,field", COMPARED)
def test_check_any_drift_refuses_the_start(host, capsys, part, field):
    host.sev = drifted(part, field)
    assert f"{part}.{field}: " in refused(host, capsys, "sev_platform_changed")


def test_enforce_baseline_equal_passes(host, capsys):
    code, doc, err = host.run("enforce", capsys=capsys)
    assert (code, doc, err) == (0, {"ok": True, "sev": "equal"}, "")
    assert not host.latch.exists()


def test_guest_count_and_state_are_not_compared(host, capsys):
    host.sev = {"snp": sev.parse_snp(snp_bytes(guests=7)), "sev": sev.parse_sev(sev_bytes(guests=7))}
    host.sev["snp"]["state"] = 0
    assert host.run("enforce", capsys=capsys)[0] == 0
    assert host.run("check", "vm1", capsys=capsys)[0] == 0


def test_enforce_is_off_without_the_host_file(host, capsys, monkeypatch):
    host.host_path.unlink()
    monkeypatch.setattr(gates, "read_sev", lambda: pytest.fail("enforce read /dev/sev on a host that is off"))
    assert host.run("enforce", capsys=capsys)[:2] == (0, {"ok": True, "sev": "off"})


def test_enforce_without_a_baseline_alerts(host, capsys):
    host.baseline.unlink()
    refused(host, capsys, "sev_baseline_missing", "enforce")


def test_enforce_never_starts_or_stops_anything(host, capsys, monkeypatch):
    def no_process(*a, **k):
        pytest.fail(f"enforce ran a process: {a}")
    monkeypatch.setattr(subprocess, "run", no_process)
    monkeypatch.setattr(subprocess, "Popen", no_process)
    host.sev = drifted("snp", "mask_chip_key")
    refused(host, capsys, "sev_platform_changed", "enforce")


def test_change_latches_until_a_host_reboot(host, capsys):
    host.sev = drifted("snp", "vlek_en")
    refused(host, capsys, "sev_platform_changed", "enforce")
    host.sev = copy.deepcopy(STATUS)  # flipped back by a second platform command
    assert "changed earlier in this boot" in refused(host, capsys, "sev_platform_changed")
    assert "snp.vlek_en" in refused(host, capsys, "sev_platform_changed", "enforce")
    host.boot("boot-2")  # host reboot, status equal to the baseline: starts resume
    assert host.run("check", "vm1", capsys=capsys)[0] == 0
    assert host.run("enforce", capsys=capsys)[0] == 0


def test_reboot_with_the_change_still_there_refuses(host, capsys):
    host.sev = drifted("snp", "current_tcb")
    refused(host, capsys, "sev_platform_changed")
    host.boot("boot-2")
    refused(host, capsys, "sev_platform_changed")
    assert json.loads(host.latch.read_text())["boot_id"] == "boot-2"


def test_unreadable_latch_or_boot_id_fails_closed(host, capsys):
    host.write(host.latch, "{", 0o600)
    assert "unreadable" in refused(host, capsys, "sev_platform_changed")
    host.write(host.latch, json.dumps({"boot_id": "boot-0", "at": "t", "diff": ["snp.vlek_en: 0 -> 1"]}), 0o600)
    assert host.run("check", "vm1", capsys=capsys)[0] == 0  # an earlier boot's latch
    (host.root / "proc/sys/kernel/random/boot_id").unlink()
    refused(host, capsys, "sev_platform_changed")  # cannot tell the boots apart


# ---- gate 13: bundle digests ----------------------------------------------------------------

def bundle_dir(host) -> Path:
    return host.vms / "bundles" / host.bundle


def test_bundle_file_content_changed(host, capsys):
    p = bundle_dir(host) / "vmlinuz"
    p.write_bytes(b"kernax")  # same size
    assert "vmlinuz differs from its sha256" in refused(host, capsys, "vm_bundle_mismatch")


def test_bundle_file_size_changed(host, capsys):
    (bundle_dir(host) / "base-root.raw").write_bytes(b"root")
    assert "the manifest says 16384" in refused(host, capsys, "vm_bundle_mismatch")


def test_bundle_file_missing_or_a_link(host, capsys):
    p = bundle_dir(host) / "initrd.cpio.zst"
    real = host.vms / "initrd-copy"
    real.write_bytes(p.read_bytes())
    p.unlink()
    assert "initrd.cpio.zst: cannot open" in refused(host, capsys, "vm_bundle_mismatch")
    p.symlink_to(real)  # same bytes behind a link: still refused
    refused(host, capsys, "vm_bundle_mismatch")


def test_manifest_edited_or_missing(host, capsys):
    m = bundle_dir(host) / "manifest.json"
    m.write_bytes(m.read_bytes() + b" ")
    assert "is not bundle" in refused(host, capsys, "vm_bundle_mismatch")
    m.unlink()
    refused(host, capsys, "vm_bundle_mismatch")


def test_bundle_directory_missing(host, capsys):
    d = bundle_dir(host)
    d.rename(d.with_name("moved"))
    assert "is missing" in refused(host, capsys, "vm_bundle_mismatch")


@pytest.mark.parametrize("extra", [{"sha256": {}, "bytes": {}}, {"sha256": {"../x": "ab" * 32}, "bytes": {"../x": 1}},
                                   {"sha256": {"a": "ab" * 32}, "bytes": {"b": 1}},
                                   {"sha256": {"a": "AB" * 32}, "bytes": {"a": 1}}])
def test_manifest_without_valid_digests(host, capsys, extra):
    bid = host.make_bundle({"a": b"x"}, extra)
    host.make_vm("vm1", bid, 2)
    host.host_file({"bundles": [bid], "verified": {bid: [host.build([2])]}})
    refused(host, capsys, "vm_bundle_mismatch")


# ---- order --------------------------------------------------------------------------------

def test_gate_order_first_refusal_wins(host, capsys):
    (bundle_dir(host) / "vmlinuz").write_bytes(b"kernax")
    host.sev = drifted("sev", "owner")
    refused(host, capsys, "sev_platform_changed")  # SEV before the slow digest read
    host.write(host.root / "proc/sys/kernel/osrelease", "6.8.0-49-generic\n")
    refused(host, capsys, "vm_host_changed")
    host.make_vm("vm1", "cd" * 32, 2)
    refused(host, capsys, "vm_bundle_not_enabled")
    host.host_path.unlink()
    refused(host, capsys, "vm_host_not_enabled")


# ---- baseline (operator) ------------------------------------------------------------------

def test_baseline_records_sev_status_read_output(host, capsys):
    host.baseline.unlink()
    host.sev["snp"]["guest_count"] = 3
    code, doc, _ = host.run("baseline", capsys=capsys)
    assert code == 0 and doc["baseline"] == str(host.baseline)
    stored = json.loads(host.baseline.read_text())
    assert stored == host.sev and sev.differences(stored, STATUS) == []
    assert (host.baseline.stat().st_mode & 0o777) == 0o600
    assert host.run("check", "vm1", capsys=capsys)[0] == 0


def test_baseline_never_overwritten_without_replace(host, capsys):
    before = host.baseline.read_bytes()
    host.sev = drifted("snp", "build_id")
    code, doc, _ = host.run("baseline", capsys=capsys)
    assert (code, doc["error"], host.baseline.read_bytes()) == (2, "baseline_exists", before)
    assert host.run("baseline", "--replace", capsys=capsys)[0] == 0
    assert json.loads(host.baseline.read_text()) == host.sev


def test_no_new_baseline_after_a_change_in_the_same_boot(host, capsys):
    host.sev = drifted("snp", "mask_chip_id")
    refused(host, capsys, "sev_platform_changed", "enforce")
    before = host.baseline.read_bytes()
    assert "reboot the host" in refused(host, capsys, "sev_platform_changed", "baseline", "--replace")
    assert host.baseline.read_bytes() == before
    host.boot("boot-2")
    assert host.run("baseline", "--replace", capsys=capsys)[0] == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
