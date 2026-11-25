#!/bin/bash
# Run one customer VM in the foreground (ExecStart of cathedral-vm-<name>.service).
# Usage: launch-vm.sh vm.env
# Plain KVM, not SEV-SNP (v1). No -no-reboot: a guest reboot resets the machine
# inside this QEMU process, so the unit stays up. A guest poweroff exits 0 and
# the unit (Restart=on-failure) stays down.
set -euo pipefail
# shellcheck disable=SC1090
source "$(readlink -f "${1:?vm.env}")"
[[ "${VM_NAME:-}" =~ ^[a-z0-9][a-z0-9-]{0,40}$ ]] || { echo "VM_NAME must match ^[a-z0-9][a-z0-9-]{0,40}$" >&2; exit 1; }
[[ "$VM_VCPUS" =~ ^[0-9]+$ && "$VM_MEM_GIB" =~ ^[0-9]+$ ]] || { echo "bad VM_VCPUS or VM_MEM_GIB" >&2; exit 1; }
[[ "$VM_TAP" =~ ^cvm[0-9]{1,5}$ ]] || { echo "bad VM_TAP" >&2; exit 1; }
[[ "$VM_MAC" =~ ^52:54:00(:[0-9a-f]{2}){3}$ ]] || { echo "bad VM_MAC" >&2; exit 1; }
RUN=$VM_DIR/run
mkdir -p "$RUN"
rm -f "$RUN/qmp.sock"
# Serial console in a 1 MiB ring in QEMU memory, never a host file: the guest has root
# and could write to ttyS0 until the shared host disk is full (Reviewbot #754).
# -sandbox: seccomp filter, no exec/setuid/obsolete syscalls (QEMU runs as root).
exec "${QEMU:-/usr/bin/qemu-system-x86_64}" -no-user-config -nodefaults -name "cathedral-vm-$VM_NAME" \
  -machine q35,accel=kvm -enable-kvm -cpu host -smp "$VM_VCPUS" -m "${VM_MEM_GIB}G" \
  -drive "if=none,id=disk0,format=qcow2,file=$VM_DIR/disk.qcow2,cache=none,discard=unmap" \
  -device virtio-blk-pci,drive=disk0,bootindex=0 \
  -drive "if=none,id=seed,format=raw,file=$VM_DIR/seed.iso,readonly=on" \
  -device virtio-blk-pci,drive=seed \
  -netdev "tap,id=net0,ifname=$VM_TAP,script=no,downscript=no,vhost=on" \
  -device "virtio-net-pci,netdev=net0,mac=$VM_MAC,romfile=" \
  -qmp "unix:$RUN/qmp.sock,server=on,wait=off" \
  -display none -vga none -monitor none \
  -chardev ringbuf,id=serial0,size=1M -serial chardev:serial0 \
  -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
