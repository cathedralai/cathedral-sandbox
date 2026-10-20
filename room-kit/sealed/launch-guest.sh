#!/bin/bash
# Start the sealed guest in the foreground (systemd unit room-sealed-<name>.service).
# Usage: launch-guest.sh sealed.env
set -euo pipefail
# shellcheck disable=SC1090
source "$(readlink -f "${1:?sealed.env}")"
IMG=$(readlink -f "$SEALED_DIR/images/current")
RUN=$SEALED_DIR/run
mkdir -p "$RUN"
# HOST_DATA (in the report, chosen by the host, not measured): the manifest digest,
# so a report names the guest build it claims to be.
HOST_DATA=$(python3 -c 'import base64,hashlib,sys;print(base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode())' "$IMG/manifest.json")
[ -f "$SEALED_DIR/scratch.raw" ] || truncate -s "${SEALED_SCRATCH_GIB}G" "$SEALED_DIR/scratch.raw"
ln -sfn "$IMG" "$RUN/booted-image"
exec /usr/bin/qemu-system-x86_64 -no-user-config -nodefaults -name "sealed-$SEALED_NAME" \
  -enable-kvm -cpu "$SEALED_CPU_MODEL" -smp "$SEALED_VCPUS" -m "${SEALED_MEM_GIB}G" \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
  -object "memory-backend-memfd,id=ram1,size=${SEALED_MEM_GIB}G,share=true,prealloc=false" \
  -object "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,host-data=$HOST_DATA" \
  -bios "$IMG/OVMF.amdsev.fd" -kernel "$IMG/vmlinuz" -initrd "$IMG/initrd.cpio.zst" -append "$(cat "$IMG/cmdline")" \
  -drive "if=none,id=scratch,format=raw,file=$SEALED_DIR/scratch.raw,cache=none,aio=io_uring" \
  -device virtio-blk-pci,drive=scratch,serial=sealed-scratch,disable-legacy=on,iommu_platform=true \
  -netdev "tap,id=net0,ifname=$SEALED_TAP,script=no,downscript=no,vhost=on" \
  -device "virtio-net-pci,netdev=net0,mac=$SEALED_GUEST_MAC,disable-legacy=on,iommu_platform=true,romfile=" \
  -fw_cfg "name=opt/cathedral/room-api-key,file=$SEALED_API_KEY_FILE" \
  -display none -vga none -monitor none -serial "file:$RUN/serial.log"
