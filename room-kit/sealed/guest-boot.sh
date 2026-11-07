#!/bin/bash
# Runs INSIDE the sealed guest at every boot (sealed-hotel.service).
# 1. Encrypt the scratch disk with a fresh random key that exists only in guest
#    memory (dm-crypt plain, AES-XTS). The host sees only ciphertext.
#    Persistent workspaces (ROOM_WORKSPACES_SOURCE in the measured room.env):
#    open the data volume with sealed-data.sh (LUKS2, a key only this build on
#    this machine can make). It outlives a restart of the same build.
# 2. The API key file for the install:
#    - config hotel: the hotel API key from QEMU fw_cfg (host-provided, not measured);
#    - miner hotel (ROOM_MINER=1 in the measured room.env): a guest-internal key
#      made here from the guest's /dev/urandom. It never leaves the guest. The
#      hotel key the broker uses arrives later, only through the attested
#      POST /room/hotel-key. A key the host puts in fw_cfg is never read.
#      With the data volume open, the internal key is kept on it: workspace
#      owners are a hash of the API key, so they stay the same after a restart.
# 3. Install the room kit with the room.env that is part of the measured initrd.
set -euo pipefail
log() { echo "[sealed-hotel] $*"; }

DEV=/dev/disk/by-id/virtio-sealed-scratch
for _ in $(seq 60); do [ -b "$DEV" ] && break; sleep 1; done
[ -b "$DEV" ] || { log "no scratch disk"; exit 1; }
if [ ! -e /dev/mapper/sealed-scratch ]; then
  # No udev sync for device-mapper in this minimal guest: libdevmapper makes the node itself.
  DM_DISABLE_UDEV=1 cryptsetup open --type plain --cipher aes-xts-plain64 --key-size 512 --hash plain \
    --key-file /dev/urandom --keyfile-size 64 --sector-size 4096 "$DEV" sealed-scratch
fi
log "scratch encrypted: $(blockdev --getsize64 /dev/mapper/sealed-scratch) bytes"
if grep -q '^ROOM_WORKSPACES_SOURCE=/' /opt/room-kit/room.env; then
  # A data volume that fails must not keep the hotel down: workspaces then
  # stay on the scratch disk for this boot, and health says why.
  /usr/local/sbin/sealed-data.sh || log "sealed-data.sh failed (exit $?): workspaces stay on the scratch disk this boot"
fi

KEY=/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral/room-api-key/raw
DATA=/srv/sealed-data  # sealed-data.sh mounts the data volume here
if grep -qx 'ROOM_MINER=1' /opt/room-kit/room.env; then
  [ -e "$KEY" ] && log "miner hotel: a hotel key in fw_cfg is ignored; the control plane installs the key over attested TLS"
  install -m 0600 /dev/null /run/room-api-key
  if mountpoint -q "$DATA" && [ -d "$DATA/hotel" ]; then
    [ -s "$DATA/hotel/internal-api-key" ] || {
      install -m 0600 /dev/null "$DATA/hotel/internal-api-key.tmp"
      head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$DATA/hotel/internal-api-key.tmp"
      sync "$DATA/hotel/internal-api-key.tmp"          # on disk before the rename, so a crash never leaves it empty
      mv "$DATA/hotel/internal-api-key.tmp" "$DATA/hotel/internal-api-key"
      sync "$DATA/hotel"                               # persist the rename
    }
    cat "$DATA/hotel/internal-api-key" > /run/room-api-key
  else
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > /run/room-api-key
  fi
else
  for _ in $(seq 30); do [ -r "$KEY" ] && break; sleep 1; done
  install -m 0600 /dev/null /run/room-api-key
  cat "$KEY" > /run/room-api-key
fi

log "installing the room kit"
/opt/room-kit/install.sh /opt/room-kit/room.env
rm -f /run/room-api-key
log "ready"
