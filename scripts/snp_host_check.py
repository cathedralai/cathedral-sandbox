#!/usr/bin/env python3
"""Check whether a bare-metal AMD host is ready to bring to Cathedral (AB#844).

Run it on the host as root, before you apply:

    sudo python3 snp_host_check.py            # one line per item, then JSON
    sudo python3 snp_host_check.py --json     # JSON only

Read-only. It reads /proc, /sys and the cgroup misc controller, and asks the
AMD secure processor for its platform status (SNP_PLATFORM_STATUS on /dev/sev,
a query that changes nothing). It writes no file, loads no module, opens no
network connection and prints no key or serial number.

Exit code: 0 ready, 1 at least one FAIL, 2 no FAIL but something could not be
read (UNKNOWN). A pass here is not admission: Cathedral admits a box only after
its sealed hotel's chip-signed attestation verifies (docs/BRING_YOUR_COMPUTE.md).
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
import platform
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

SCHEMA = "cathedral_snp_host_check_v1"

# The validator's Genoa TCB floor: boot loader 12, TEE 0, SNP firmware 28,
# microcode 88 (cathedral-validator snp_production.py _tcb_meets_minimum).
GENOA_FLOOR = {"boot_loader": 12, "tee": 0, "snp": 28, "microcode": 88}
# The broker floor AB#809 plans to turn on (broker/README.md, min_genoa_snp_spl
# 30 for AMD-SB-3059). Below it a box passes today and is refused later.
PLANNED_SNP_FLOOR = 30

# MemTotal reads below the installed size (firmware and kernel reserve some),
# so a 128 GB machine shows about 122 GiB. The thresholds allow for that.
RAM_MIN_GIB = 120
RAM_IDEAL_GIB = 360

# linux/psp-sev.h: SNP_PLATFORM_STATUS is command 9; SEV_ISSUE_CMD is
# _IOWR('S', 0, struct sev_issue_cmd) with a packed 16-byte struct.
SNP_PLATFORM_STATUS = 9
SEV_ISSUE_CMD = 0xC0105300

PASS, WARN, FAIL, UNKNOWN, INFO = "PASS", "WARN", "FAIL", "UNKNOWN", "INFO"


@dataclass
class Item:
    name: str
    status: str
    detail: str


@dataclass
class SnpStatus:
    api_major: int
    api_minor: int
    state: int
    rmp_initialized: bool
    build_id: int
    mask_chip_id: bool
    current_tcb: int
    reported_tcb: int


def read(root: Path, path: str) -> str | None:
    try:
        return (root / path.lstrip("/")).read_text(errors="replace")
    except OSError:
        return None


def parse_cpuinfo(text: str) -> dict:
    first: dict[str, str] = {}
    sockets: set[str] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "physical id":
            sockets.add(value)
        first.setdefault(key, value)
    return {
        "vendor": first.get("vendor_id", ""),
        "family": int(first.get("cpu family", "0") or 0),
        "model": int(first.get("model", "0") or 0),
        "model_name": first.get("model name", ""),
        "flags": set(first.get("flags", "").split()),
        "sockets": max(len(sockets), 1),
    }


def generation(family: int, model: int, model_name: str) -> str:
    """EPYC server generation, or "" for anything Cathedral cannot admit."""
    if "EPYC" not in model_name:
        return ""
    if family == 0x19 and model <= 0x0F:
        return "milan"
    if family == 0x19 and (0x10 <= model <= 0x1F or 0xA0 <= model <= 0xAF):
        return "genoa"
    if family == 0x1A:
        return "turin"
    return ""


def tcb_fields(tcb: int, gen: str) -> dict[str, int]:
    raw = tcb.to_bytes(8, "little")
    if gen == "turin":  # Turin moves the fields and adds FMC
        return {"fmc": raw[0], "boot_loader": raw[1], "tee": raw[2], "snp": raw[3], "microcode": raw[7]}
    return {"boot_loader": raw[0], "tee": raw[1], "snp": raw[6], "microcode": raw[7]}


def snp_platform_status(device: str = "/dev/sev") -> SnpStatus:
    buf = ctypes.create_string_buffer(4096)
    cmd = ctypes.create_string_buffer(struct.pack("<IQI", SNP_PLATFORM_STATUS, ctypes.addressof(buf), 0), 16)
    fd = os.open(device, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, SEV_ISSUE_CMD, cmd, True)
    except OSError as exc:
        fw_error = struct.unpack("<IQI", cmd.raw)[2]
        raise OSError(f"{exc.strerror} (firmware error {fw_error:#x})") from exc
    finally:
        os.close(fd)
    major, minor, state, bits, build, flags, _guests, current, reported = struct.unpack("<BBBBIIIQQ", buf.raw[:32])
    return SnpStatus(major, minor, state, bool(bits & 1), build, bool(flags & 1), current, reported)


def run_checks(
    root: Path = Path("/"),
    status_reader: Callable[[], SnpStatus] = snp_platform_status,
    euid: int | None = None,
    virt: str | None = None,
) -> tuple[list[Item], dict]:
    items: list[Item] = []
    facts: dict = {}

    def add(name: str, status: str, detail: str) -> None:
        items.append(Item(name, status, detail))

    euid = os.geteuid() if euid is None else euid
    add("root", PASS if euid == 0 else FAIL, "running as root" if euid == 0 else "run with sudo")

    if virt is None:
        virt = detect_virt(root)
    facts["virtualization"] = virt
    add("bare_metal", PASS if virt == "none" else FAIL,
        "no hypervisor" if virt == "none" else f"runs under {virt}: SNP needs the bare-metal host")

    cpu = parse_cpuinfo(read(root, "/proc/cpuinfo") or "")
    gen = generation(cpu["family"], cpu["model"], cpu["model_name"])
    facts.update(cpu_model=cpu["model_name"], cpu_family=hex(cpu["family"]),
                 cpu_model_id=hex(cpu["model"]), generation=gen or "unsupported", sockets=cpu["sockets"])
    if cpu["vendor"] != "AuthenticAMD" or not gen:
        add("cpu", FAIL, f"{cpu['model_name'] or 'unknown CPU'}: needs AMD EPYC 7003, 9004 or 9005")
    elif gen == "genoa":
        add("cpu", PASS, f"{cpu['model_name']} (Genoa family): admitted today")
    elif gen == "milan":
        add("cpu", WARN, f"{cpu['model_name']} (Milan): apply; not admitted yet (no published Milan measurement)")
    else:
        add("cpu", WARN, f"{cpu['model_name']} (Turin): apply; not admitted yet (policy and broker verifier lack Turin)")

    # Validators require the SINGLE_SOCKET guest bit by default, and KVM cannot
    # launch such a guest on a host with two or more populated sockets.
    add("sockets", PASS if cpu["sockets"] == 1 else FAIL,
        "one socket" if cpu["sockets"] == 1 else f"{cpu['sockets']} sockets: needs one; validators require SINGLE_SOCKET")

    # Not "sme": the kernel hides that flag when host memory encryption is
    # off, which SNP guests do not need. The RMP check below is the real test.
    missing = [f for f in ("sev", "sev_es", "sev_snp") if f not in cpu["flags"]]
    add("cpu_flags", FAIL if missing else PASS,
        f"missing {' '.join(missing)}: turn on SMEE and SEV-SNP in BIOS" if missing else "sev sev_es sev_snp")

    iommu = root / "sys/class/iommu"
    has_iommu = iommu.is_dir() and any(iommu.iterdir())
    add("iommu", PASS if has_iommu else FAIL, "IOMMU on" if has_iommu else "no IOMMU: turn it on in BIOS")

    params = root / "sys/module/kvm_amd/parameters"
    if not params.is_dir():
        add("kvm_amd", FAIL, "kvm_amd not loaded")
    else:
        snp = (read(root, "/sys/module/kvm_amd/parameters/sev_snp") or "").strip()
        facts["kvm_amd_sev_snp"] = snp
        add("kvm_amd", PASS if snp in ("Y", "1") else FAIL,
            "kvm_amd sev_snp=Y" if snp in ("Y", "1") else f"kvm_amd sev_snp={snp or 'absent'}: host kernel or BIOS has SNP off")

    asids = parse_misc_capacity(read(root, "/sys/fs/cgroup/misc.capacity"))
    facts["asids"] = asids
    if asids is None:
        add("snp_asids", UNKNOWN, "cannot read /sys/fs/cgroup/misc.capacity")
    else:
        snp_asids = asids.get("sev_es", 0)  # SNP guests draw from the SEV-ES ASID range
        add("snp_asids", PASS if snp_asids > 0 else FAIL,
            f"{snp_asids} SNP-capable ASIDs" if snp_asids > 0 else "0 SNP ASIDs: set the SEV-ES ASID space in BIOS")

    if not (root / "dev/sev").exists():
        add("firmware", FAIL, "no /dev/sev: the ccp driver did not find the AMD secure processor")
    else:
        try:
            st = status_reader()
        except (OSError, ValueError) as exc:
            add("firmware", UNKNOWN, f"SNP_PLATFORM_STATUS failed: {exc}")
        else:
            check_firmware(st, gen, facts, add)

    mem_gib = parse_memtotal_gib(read(root, "/proc/meminfo") or "")
    facts["ram_gib"] = mem_gib
    if mem_gib < RAM_MIN_GIB:
        add("ram", FAIL, f"{mem_gib} GiB usable: needs a 128 GB machine or larger")
    elif mem_gib < RAM_IDEAL_GIB:
        add("ram", WARN, f"{mem_gib} GiB usable: 384 GB or more is ideal")
    else:
        add("ram", PASS, f"{mem_gib} GiB")

    disks = local_disks(root)
    facts["disks_gb"] = disks
    total = sum(disks.values())
    add("disk", PASS if total >= 900 else WARN,
        f"{total} GB local disk" if total >= 900 else f"{total} GB local disk: 1 TB or more for room scratch")

    facts["kernel"] = platform.release() if root == Path("/") else ""
    return items, facts


def check_firmware(st: SnpStatus, gen: str, facts: dict, add: Callable[[str, str, str], None]) -> None:
    facts["snp_api"] = f"{st.api_major}.{st.api_minor}"
    facts["snp_build"] = st.build_id
    facts["current_tcb"] = f"{st.current_tcb:#018x}"
    facts["reported_tcb"] = f"{st.reported_tcb:#018x}"
    add("rmp", PASS if st.rmp_initialized else FAIL,
        "RMP initialized" if st.rmp_initialized else "RMP not initialized: SNP is not on in BIOS or kernel")
    add("chip_id", FAIL if st.mask_chip_id else PASS,
        "CHIP_ID masked: unmask it, the verifier refuses masked reports" if st.mask_chip_id else "CHIP_ID not masked")
    if gen != "genoa":
        add("tcb", INFO, f"SNP {facts['snp_api']} build {st.build_id}; no {gen or 'admission'} floor yet")
        return
    low, planned = [], []
    for label, tcb in (("current", st.current_tcb), ("reported", st.reported_tcb)):
        fields = tcb_fields(tcb, gen)
        facts[f"{label}_tcb_fields"] = fields
        low += [f"{label} {k} {fields[k]} < {v}" for k, v in GENOA_FLOOR.items() if fields[k] < v]
        if fields["snp"] < PLANNED_SNP_FLOOR:
            planned.append(f"{label} snp {fields['snp']}")
    # Committed and launch TCB are only visible in a guest report; the
    # broker and validator check those at admission.
    if low:
        add("tcb", FAIL, "below floor: " + ", ".join(low) + ": update BIOS and SEV firmware")
    elif planned:
        add("tcb", WARN, f"meets today's floor; {', '.join(planned)} is below the planned floor "
            f"{PLANNED_SNP_FLOOR} (AB#809): update SEV firmware")
    else:
        add("tcb", PASS, f"at or above the planned floor (SNP {facts['snp_api']} build {st.build_id})")


def detect_virt(root: Path) -> str:
    cpu = parse_cpuinfo(read(root, "/proc/cpuinfo") or "")
    if "hypervisor" in cpu["flags"]:
        vendor = (read(root, "/sys/class/dmi/id/sys_vendor") or "").strip()
        return vendor or "a hypervisor"
    return "none"


def parse_misc_capacity(text: str | None) -> dict[str, int] | None:
    if text is None:
        return None
    out: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


def parse_memtotal_gib(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) // (1024 * 1024)
    return 0


def local_disks(root: Path) -> dict[str, int]:
    """Whole local disks in GB (NVMe namespaces, SCSI/SATA, virtio), no partitions."""
    sizes: dict[str, int] = {}
    block = root / "sys/block"
    if block.is_dir():
        for dev in sorted(block.iterdir()):
            name = dev.name
            if not (name.startswith(("nvme", "sd", "vd")) and (root / "sys/block" / name / "device").exists()):
                continue
            try:
                if (dev / "removable").read_text().strip() == "1":
                    continue
                sectors = int((dev / "size").read_text())
            except (OSError, ValueError):
                continue
            sizes[name] = sectors * 512 // 10**9
    return sizes


def verdict(items: list[Item]) -> tuple[str, int]:
    statuses = {i.status for i in items}
    if FAIL in statuses:
        return "not_ready", 1
    if UNKNOWN in statuses:
        return "unknown", 2
    return "ready", 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print the JSON summary only")
    args = parser.parse_args(argv)
    items, facts = run_checks()
    result, code = verdict(items)
    if not args.json:
        for i in items:
            print(f"{i.status:<8} {i.name:<11} {i.detail}")
        print(f"\nResult: {result}. Paste the JSON below into the application form.\n")
    print(json.dumps({"schema": SCHEMA, "result": result, "items": [asdict(i) for i in items], "facts": facts},
                     indent=None if args.json else 2, sort_keys=True, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
