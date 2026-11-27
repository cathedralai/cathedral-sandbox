#!/bin/bash
# Run one customer VM in the foreground (ExecStart of cathedral-vm-<name>.service).
# Usage: launch-vm.sh vm.env
# SEV-SNP only (AB#999): this launcher refuses every VM until it can build the
# QEMU command with the sev-snp-guest object. There is no plain KVM path and no
# flag for one. No -no-reboot: a guest reboot resets the machine
# inside this QEMU process, so the unit stays up. A guest poweroff exits 0 and
# the unit (Restart=on-failure) stays down.
set -euo pipefail
# shellcheck disable=SC1090
source "$(readlink -f "${1:?vm.env}")"
[[ "${VM_NAME:-}" =~ ^[a-z0-9][a-z0-9-]{0,40}$ ]] || { echo "VM_NAME must match ^[a-z0-9][a-z0-9-]{0,40}$" >&2; exit 1; }
[[ "$VM_VCPUS" =~ ^[0-9]+$ && "$VM_MEM_GIB" =~ ^[0-9]+$ ]] || { echo "bad VM_VCPUS or VM_MEM_GIB" >&2; exit 1; }
[[ "$VM_TAP" =~ ^cvm[0-9]{1,5}$ ]] || { echo "bad VM_TAP" >&2; exit 1; }
[[ "$VM_MAC" =~ ^52:54:00(:[0-9a-f]{2}){3}$ ]] || { echo "bad VM_MAC" >&2; exit 1; }
# VM launch refused: SEV-SNP is required (AB#999). A plain KVM guest lets the host
# operator read guest memory and disk. The SNP launch (-object sev-snp-guest,
# confidential-guest-support, OVMF.amdsev.fd, as ../sealed/launch-guest.sh does)
# needs host work that has not shipped, so until it does every launch exits here.
# Do not add a QEMU command without the sev-snp-guest object below this line.
echo "VM launch refused: SEV-SNP is required (AB#999)" >&2
exit 78
