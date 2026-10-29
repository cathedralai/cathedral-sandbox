#!/bin/bash
# Start the sealed guest in the foreground (systemd unit room-sealed-<name>.service).
# Usage: launch-guest.sh sealed.env
set -euo pipefail
# shellcheck disable=SC1090
source "$(readlink -f "${1:?sealed.env}")"
IMG=$(readlink -f "$SEALED_DIR/images/current")
RUN=$SEALED_DIR/run
mkdir -p "$RUN"
# HOST_DATA (in the report, chosen by the host, not measured, fixed at launch).
# Shared machine: the manifest digest, so a report names the guest build it claims to be.
# Dedicated machine (SEALED_OWNER_PUBKEY_FILE set, 32 raw bytes of the owner's Ed25519
# public key): sha256("cathedral-dedicated-v1\0" || sha256(manifest.json) || owner key),
# so every report also names the one owner. The guest gets the key and the manifest
# digest in fw_cfg, recomputes this value and refuses to serve when its own report
# differs; it then refuses every create the owner did not sign.
OWNER_FW_CFG=()
if [ -n "${SEALED_OWNER_PUBKEY_FILE:-}" ]; then
  HOST_DATA=$(python3 - "$IMG/manifest.json" "$SEALED_OWNER_PUBKEY_FILE" "$RUN/manifest.sha256" <<'EOF'
import base64, hashlib, sys
manifest, key_file, digest_out = sys.argv[1:]
key = open(key_file, "rb").read()
if len(key) != 32:
    sys.exit(f"SEALED_OWNER_PUBKEY_FILE {key_file} has {len(key)} bytes; it must hold the 32 raw bytes of an Ed25519 public key")
digest = hashlib.sha256(open(manifest, "rb").read()).digest()
open(digest_out, "wb").write(digest)
print(base64.b64encode(hashlib.sha256(b"cathedral-dedicated-v1\0" + digest + key).digest()).decode())
EOF
)
  OWNER_FW_CFG=(-fw_cfg "name=opt/cathedral/owner-pubkey,file=$SEALED_OWNER_PUBKEY_FILE"
                -fw_cfg "name=opt/cathedral/manifest-sha256,file=$RUN/manifest.sha256")
else
  HOST_DATA=$(python3 -c 'import base64,hashlib,sys;print(base64.b64encode(hashlib.sha256(open(sys.argv[1],"rb").read()).digest()).decode())' "$IMG/manifest.json")
fi
[ -f "$SEALED_DIR/scratch.raw" ] || truncate -s "${SEALED_SCRATCH_GIB}G" "$SEALED_DIR/scratch.raw"
ln -sfn "$IMG" "$RUN/booted-image"
# Config hotel: the broker's hotel key goes in through fw_cfg. Miner hotel: the
# host holds no hotel key; the control plane installs it in the guest over the
# guest's attested TLS, and the guest would ignore a fw_cfg key anyway.
if [ "${SEALED_MINER:-0}" = 1 ]; then
  FW_CFG=()
else
  FW_CFG=(-fw_cfg "name=opt/cathedral/room-api-key,file=$SEALED_API_KEY_FILE")
fi
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
  ${FW_CFG[@]+"${FW_CFG[@]}"} ${OWNER_FW_CFG[@]+"${OWNER_FW_CFG[@]}"} \
  -display none -vga none -monitor none -serial "file:$RUN/serial.log"
