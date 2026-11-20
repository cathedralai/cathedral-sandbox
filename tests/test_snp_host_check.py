"""scripts/snp_host_check.py on a fake /proc and /sys tree (AB#844)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location("snp_host_check", Path("scripts/snp_host_check.py"))
check = importlib.util.module_from_spec(_SPEC)
sys.modules["snp_host_check"] = check  # dataclasses look the module up by name
_SPEC.loader.exec_module(check)

FLOOR_TCB = 0x581C00000000000C  # microcode 88, SNP 28, TEE 0, boot loader 12
PATCHED_TCB = 0x581E00000000000C  # SNP 30, the planned broker floor


def write(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


def genoa_host(root: Path, *, model: int = 0x11, family: int = 25, flags: str = "fpu sev sev_es sev_snp",
               name: str = "AMD EPYC 9254 24-Core Processor", sockets: int = 1, mem_kib: int = 400 * 1024 * 1024,
               sev_snp: str = "Y", sev_es_asids: int = 99) -> Path:
    cpus = "".join(
        f"processor\t: {i}\nvendor_id\t: AuthenticAMD\ncpu family\t: {family}\nmodel\t\t: {model}\n"
        f"model name\t: {name}\nphysical id\t: {i % sockets}\nflags\t\t: {flags}\n\n"
        for i in range(2 * sockets)
    )
    write(root, "proc/cpuinfo", cpus)
    write(root, "proc/meminfo", f"MemTotal:       {mem_kib} kB\n")
    write(root, "sys/class/iommu/ivhd0/uevent", "")
    write(root, "sys/module/kvm_amd/parameters/sev_snp", sev_snp + "\n")
    write(root, "sys/fs/cgroup/misc.capacity", f"sev 410\nsev_es {sev_es_asids}\n")
    write(root, "dev/sev", "")
    write(root, "sys/block/nvme0n1/size", str(2 * 10**12 // 512))
    write(root, "sys/block/nvme0n1/removable", "0")
    (root / "sys/block/nvme0n1/device").mkdir(parents=True)
    return root


def status(tcb: int = PATCHED_TCB, rmp: bool = True, masked: bool = False):
    return lambda: check.SnpStatus(1, 58, 1, rmp, 2, masked, tcb, tcb)


def run(root: Path, reader=None, euid: int = 0):
    items, facts = check.run_checks(root, reader or status(), euid=euid, virt="none")
    return {i.name: i.status for i in items}, facts, check.verdict(items)


def test_ready_genoa_host(tmp_path):
    by, facts, result = run(genoa_host(tmp_path))
    assert result == ("ready", 0)
    assert set(by.values()) == {"PASS"}
    assert facts["generation"] == "genoa"
    assert facts["reported_tcb_fields"] == {"boot_loader": 12, "tee": 0, "snp": 30, "microcode": 88}


@pytest.mark.parametrize("tcb", [FLOOR_TCB, 0x581D00000000000C])
def test_snp_28_and_29_warn_for_the_planned_floor(tmp_path, tcb):
    items, _ = check.run_checks(genoa_host(tmp_path), status(tcb), euid=0, virt="none")
    tcb_item = next(i for i in items if i.name == "tcb")
    assert tcb_item.status == "WARN" and "planned floor 30" in tcb_item.detail
    assert check.verdict(items) == ("ready", 0)


@pytest.mark.parametrize(
    "tcb, why",
    [
        (0x581B00000000000C, "snp 27"),
        (0x571C00000000000C, "microcode 87"),
        (0x581C00000000000B, "boot_loader 11"),
    ],
)
def test_each_tcb_component_below_floor_fails(tmp_path, tcb, why):
    items, _ = check.run_checks(genoa_host(tmp_path), status(tcb), euid=0, virt="none")
    tcb_item = next(i for i in items if i.name == "tcb")
    assert tcb_item.status == "FAIL"
    assert why.split()[0] in tcb_item.detail


def test_higher_unrelated_component_does_not_hide_low_snp(tmp_path):
    # Packed scalar 0x591b... is above the floor; SNP 27 is still below it.
    by, _, result = run(genoa_host(tmp_path), status(0x591B00000000000C))
    assert by["tcb"] == "FAIL" and result == ("not_ready", 1)


def test_snp_off_in_bios_fails(tmp_path):
    root = genoa_host(tmp_path, flags="fpu sev sev_es", sev_snp="N", sev_es_asids=0)
    by, _, result = run(root, status(rmp=False))
    assert by["cpu_flags"] == by["kvm_amd"] == by["snp_asids"] == by["rmp"] == "FAIL"
    assert result[1] == 1


def test_masked_chip_id_fails(tmp_path):
    by, _, _ = run(genoa_host(tmp_path), status(masked=True))
    assert by["chip_id"] == "FAIL"


@pytest.mark.parametrize(
    "family, model, name, gen, cpu_status",
    [
        (25, 0x01, "AMD EPYC 7763 64-Core Processor", "milan", "WARN"),
        (25, 0xA0, "AMD EPYC 9754 128-Core Processor", "genoa", "PASS"),
        (26, 0x02, "AMD EPYC 9575F 64-Core Processor", "turin", "WARN"),
        (25, 0x61, "AMD Ryzen 9 7950X 16-Core Processor", "unsupported", "FAIL"),
    ],
)
def test_generations(tmp_path, family, model, name, gen, cpu_status):
    by, facts, _ = run(genoa_host(tmp_path, family=family, model=model, name=name))
    assert facts["generation"] == gen
    assert by["cpu"] == cpu_status
    if gen in ("milan", "turin"):
        assert by["tcb"] == "INFO"  # no floor for these yet; never a false PASS


def test_turin_tcb_layout():
    raw = bytes([3, 4, 5, 6, 0, 0, 0, 7])
    assert check.tcb_fields(int.from_bytes(raw, "little"), "turin") == {
        "fmc": 3, "boot_loader": 4, "tee": 5, "snp": 6, "microcode": 7,
    }


def test_small_ram_warns(tmp_path):
    by, _, result = run(genoa_host(tmp_path, mem_kib=187 * 1024 * 1024))
    assert by["ram"] == "WARN"
    assert result == ("ready", 0)


def test_two_sockets_fail(tmp_path):
    by, _, result = run(genoa_host(tmp_path, sockets=2))
    assert by["sockets"] == "FAIL" and result == ("not_ready", 1)


def test_fail_with_unknown_exits_1(tmp_path):
    def broken():
        raise OSError("Permission denied")

    _, _, result = run(genoa_host(tmp_path, sockets=2), broken)
    assert result == ("not_ready", 1)


def test_128_gb_box_is_not_a_fail(tmp_path):
    by, _, _ = run(genoa_host(tmp_path, mem_kib=122 * 1024 * 1024))
    assert by["ram"] == "WARN"


def test_too_little_ram_fails(tmp_path):
    by, _, _ = run(genoa_host(tmp_path, mem_kib=64 * 1024 * 1024))
    assert by["ram"] == "FAIL"


def test_not_root_and_no_kvm_amd(tmp_path):
    root = genoa_host(tmp_path)
    (root / "sys/module/kvm_amd/parameters/sev_snp").unlink()
    (root / "sys/module/kvm_amd/parameters").rmdir()
    by, _, _ = run(root, euid=1000)
    assert by["root"] == by["kvm_amd"] == "FAIL"


def test_unreadable_firmware_is_unknown_not_pass(tmp_path):
    def broken():
        raise OSError("Permission denied")

    by, _, result = run(genoa_host(tmp_path), broken)
    assert by["firmware"] == "UNKNOWN"
    assert result == ("unknown", 2)


def test_no_dev_sev_fails(tmp_path):
    root = genoa_host(tmp_path)
    (root / "dev/sev").unlink()
    by, _, _ = run(root)
    assert by["firmware"] == "FAIL"


def test_virtualized_host_fails(tmp_path):
    root = genoa_host(tmp_path, flags="fpu sev sev_es sev_snp hypervisor")
    write(root, "sys/class/dmi/id/sys_vendor", "QEMU\n")
    items, facts = check.run_checks(root, status(), euid=0)
    assert facts["virtualization"] == "QEMU"
    assert next(i for i in items if i.name == "bare_metal").status == "FAIL"
