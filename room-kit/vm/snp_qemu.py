"""The SEV-SNP lines of every Cathedral QEMU argv (dedicated spec 5.7, VM runtime spec r2 8.1).

One function builds them and one function checks them, for both unprivileged launchers:
room-kit/vm/launch-vm.py (sealed customer VMs) and ops/custom-guest/launch-custom-guest.py
(the dedicated custom guest, which reaches this file through a symlink and installs a copy
beside itself). The SNP object, policy, firmware and direct boot are those of
room-kit/sealed/launch-guest.sh.

The caller adds only its devices (drives, network, fw_cfg) between the boot lines and the
fixed tail. There is no parameter, environment name or flag that leaves out the SNP
object, the confidential machine, kernel-hashes or the policy: a launcher that wants a
plain KVM guest has to stop calling this function, and check_snp_argv then refuses it.
"""
from __future__ import annotations

import re

QEMU = "/usr/bin/qemu-system-x86_64"
POLICY = "0x30000"
MACHINE = "q35,confidential-guest-support=sev0,memory-backend=ram1"
CPU_MODELS = frozenset({"EPYC-Genoa-v1", "EPYC-v4"})
SANDBOX = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
# Options no Cathedral SNP launch may carry: host-set SMBIOS (credentials, cloud-init ds=),
# legacy drives that bypass -drive checks, and -runas (QEMU would start as root first).
FORBIDDEN = ("-smbios", "-hda", "-hdb", "-cdrom", "-fda", "-runas", "-snapshot", "-loadvm", "-incoming")
B64_RE = re.compile(r"[A-Za-z0-9+/]{43}=")


class SnpArgvError(ValueError):
    pass


def snp_argv(*, name: str, cpu_model: str, vcpus: int, mem_gib: int, host_data_b64: str,
             ovmf: str, kernel: str, initrd: str, cmdline: str, devices: list[str],
             qmp_sockets: list[str]) -> list[str]:
    """The whole argv: QEMU's SNP boot lines, then `devices`, then the fixed tail.

    -no-reboot: an SNP guest cannot be reset inside the same QEMU, so a reset ends QEMU and
    the launcher decides whether to relaunch. The cmdline is one argv element."""
    if cpu_model not in CPU_MODELS:
        raise SnpArgvError(f"cpu model {cpu_model!r} is not an SNP model")
    if not (isinstance(vcpus, int) and 1 <= vcpus <= 64 and isinstance(mem_gib, int) and 1 <= mem_gib <= 640):
        raise SnpArgvError("vcpus or mem_gib out of range")
    if not B64_RE.fullmatch(host_data_b64):
        raise SnpArgvError("host data must be 32 bytes in base64")
    if "\n" in cmdline or "\0" in cmdline:
        raise SnpArgvError("the cmdline is one line")
    argv = [QEMU, "-no-user-config", "-nodefaults", "-no-reboot", "-name", name,
            "-enable-kvm", "-cpu", cpu_model, "-smp", str(vcpus), "-m", f"{mem_gib}G",
            "-machine", MACHINE,
            "-object", f"memory-backend-memfd,id=ram1,size={mem_gib}G,share=true,prealloc=false",
            "-object", f"sev-snp-guest,id=sev0,policy={POLICY},cbitpos=51,reduced-phys-bits=1,"
                       f"kernel-hashes=on,host-data={host_data_b64}",
            "-bios", ovmf, "-kernel", kernel, "-initrd", initrd, "-append", cmdline]
    argv += devices
    for sock in qmp_sockets:
        argv += ["-qmp", f"unix:{sock},server=on,wait=off"]
    argv += ["-display", "none", "-vga", "none", "-monitor", "none",
             "-chardev", "ringbuf,id=serial0,size=1M", "-serial", "chardev:serial0",
             "-sandbox", SANDBOX]
    check_snp_argv(argv)
    return argv


def values_of(argv: list[str], option: str) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == option]


def check_snp_argv(argv: list[str]) -> None:
    """The property every launch must pass, whoever built the argv."""
    if not argv or argv[0] != QEMU:
        raise SnpArgvError("not the host QEMU")
    objs = values_of(argv, "-object")
    snp = [o for o in objs if o.startswith("sev-snp-guest,")]
    if len(snp) != 1:
        raise SnpArgvError("the argv has no single SEV-SNP guest object")
    fields = snp[0].split(",")
    if "id=sev0" not in fields or f"policy={POLICY}" not in fields or "kernel-hashes=on" not in fields \
            or not any(f.startswith("host-data=") and B64_RE.fullmatch(f[len("host-data="):]) for f in fields):
        raise SnpArgvError("the SEV-SNP object needs policy 0x30000, kernel-hashes=on and host-data")
    if any(o.startswith(("sev-guest,", "sev-common,", "tdx-guest,")) for o in objs):
        raise SnpArgvError("another confidential object")
    if values_of(argv, "-machine") != [MACHINE]:
        raise SnpArgvError("the machine must use the SNP object and the memfd backend")
    if not any(o.startswith("memory-backend-memfd,id=ram1,") for o in objs):
        raise SnpArgvError("guest memory must be the memfd backend")
    if argv.count("-no-reboot") != 1:
        raise SnpArgvError("-no-reboot is required")
    if argv.count("-append") != 1 or argv.count("-kernel") != 1 or argv.count("-initrd") != 1 \
            or argv.count("-bios") != 1:
        raise SnpArgvError("one firmware, one kernel, one initrd and one cmdline")
    if values_of(argv, "-sandbox") != [SANDBOX]:
        raise SnpArgvError("-sandbox must deny spawn and privilege changes")
    for opt in FORBIDDEN:
        if opt in argv:
            raise SnpArgvError(f"{opt} is refused in an SNP launch")
    for dev in values_of(argv, "-device"):
        if dev.startswith("virtio-") and "iommu_platform=true" not in dev.split(","):
            raise SnpArgvError("every virtio device needs iommu_platform=true")
