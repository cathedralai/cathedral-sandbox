#!/bin/bash
# Runs INSIDE the sealed guest at every boot, from sealed-hotel-boot.sh, before
# the room kit install. Only when the measured room.env sets ROOM_WORKSPACES_SOURCE.
#
# Opens the persistent data volume: the virtio disk with serial sealed-data, LUKS2
# (AES-XTS-512), with a key that only this guest build on this machine can make
# (sealed_data_key.py: the SNP derived key, then HOST_DATA). Mounts it at
# /srv/sealed-data with nosuid,nodev,noexec. The host sees only ciphertext.
#
# State in /run/sealed-data.status (JSON, read by room_health.py):
#   new     the disk held no volume: made one now (first boot, or a blank disk)
#   open    the volume opened: workspaces persist across restarts of this build
#   locked  a volume is there but no key slot opens with this build's key
#           (another build, another machine, another HOST_DATA): left untouched
#   broken  the volume opened but its file system did not mount: left untouched
#   absent  no data disk
#   nokey   the secure processor gave no key (not an SNP guest?)
# In every state but new and open the volume is not mounted and room-data.sh
# keeps workspaces on the scratch disk, which is gone at the next boot.
# A disk that holds a LUKS volume is never formatted.
set -euo pipefail
log() { echo "[sealed-data] $*"; }

DEV=${SEALED_DATA_DEV:-/dev/disk/by-id/virtio-sealed-data}
MNT=${SEALED_DATA_MNT:-/srv/sealed-data}
STATUS=${SEALED_DATA_STATUS:-/run/sealed-data.status}
KEYTOOL=${SEALED_DATA_KEYTOOL:-/usr/local/sbin/sealed_data_key.py}
RUNDIR=${SEALED_DATA_RUNDIR:-/run}
NAME=sealed-data
MAP=/dev/mapper/$NAME
TOKEN_TYPE=cathedral-sealed-data
# No udev sync for device-mapper in this minimal guest: libdevmapper makes the node itself.
export DM_DISABLE_UDEV=1

KEY_ID=""
status() { # status <state> <detail>
  python3 -c 'import json,sys; s,d,k=sys.argv[1:]; print(json.dumps({"state": s, "persistent": s in ("new", "open"), "key_id": k or None, "detail": d}, sort_keys=True))' \
    "$1" "$2" "$KEY_ID" > "$STATUS"
  log "$1: $2"
}

# A block device; the tests (tests/test_room_kit_sealed_data.py) use a regular file.
is_disk() { [ -b "$1" ] || { [ "${SEALED_DATA_FAKE_DISK:-0}" = 1 ] && [ -f "$1" ]; }; }
for _ in $(seq 10); do is_disk "$DEV" && break; sleep 1; done
if ! is_disk "$DEV"; then
  status absent "no data disk (virtio serial $NAME); workspaces stay on the scratch disk until the next boot"
  exit 0
fi

KEYFILE=$(mktemp "$RUNDIR/sealed-data.key.XXXXXX")  # /run is tmpfs: guest memory only
trap 'rm -f "$KEYFILE"' EXIT
INFO=$("$KEYTOOL" info 2>&1) && "$KEYTOOL" key > "$KEYFILE" || {
  status nokey "the secure processor gave no key: $(echo "$INFO" | tail -1)"
  exit 0
}
KEYLEN=$(wc -c < "$KEYFILE" | tr -d ' ')
if [ "$KEYLEN" != 32 ]; then
  status nokey "the key tool gave $KEYLEN bytes, not 32"
  exit 0
fi
KEY_ID=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["key_id"])' "$INFO")
MEASUREMENT=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["measurement"])' "$INFO")

fs_token() { # the file system token, or nothing before the first mkfs finished
  cryptsetup token export --token-id 0 "$DEV" 2>/dev/null \
    | python3 -c 'import json,sys; t=json.load(sys.stdin); print(t.get("fs","") if t.get("type")==sys.argv[1] else "")' "$TOKEN_TYPE" 2>/dev/null || true
}

luks_magic() { # a LUKS header (primary at 0, LUKS2 secondary at 16 KiB), even one cryptsetup cannot read
  [ "$(dd if="$DEV" bs=6 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')" = 4c554b53babe ] \
    || [ "$(dd if="$DEV" bs=16384 skip=1 count=1 2>/dev/null | head -c 6 | od -An -tx1 | tr -d ' \n')" = 534b554cbabe ]
}

STATE=open
if [ ! -e "$MAP" ]; then
  if ! cryptsetup isLuks "$DEV" && luks_magic; then
    status broken "the data disk has a LUKS header that cryptsetup cannot read; left untouched"
    exit 0
  fi
  if cryptsetup isLuks "$DEV"; then
    rc=0
    cryptsetup open --type luks2 --key-file "$KEYFILE" --keyfile-size 32 "$DEV" "$NAME" || rc=$?
    if [ "$rc" != 0 ]; then
      status locked "a LUKS2 volume is on the data disk but no key slot opens with this build's key (cryptsetup exit $rc); left untouched"
      exit 0
    fi
  else
    log "no volume on the data disk: making one (key_id $KEY_ID)"
    cryptsetup luksFormat --type luks2 --batch-mode --cipher aes-xts-plain64 --key-size 512 --sector-size 4096 \
      --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --hash sha256 --label cathedral-sealed-data \
      --key-file "$KEYFILE" --keyfile-size 32 "$DEV"
    cryptsetup open --type luks2 --key-file "$KEYFILE" --keyfile-size 32 "$DEV" "$NAME"
    STATE=new
  fi
fi

# mkfs only before the token says the file system exists: a first boot that
# stopped between luksFormat and mkfs. An opened volume with the token is never
# formatted again, whatever blkid says.
if [ "$(fs_token)" != xfs ]; then
  mkfs.xfs -f -q "$MAP"
  python3 -c 'import json,sys; t,m,k=sys.argv[1:]; print(json.dumps({"type": t, "keyslots": [], "fs": "xfs", "schema": "cathedral_sealed_data_v1", "slots": {"0": {"measurement": m, "key_id": k}}}))' \
    "$TOKEN_TYPE" "$MEASUREMENT" "$KEY_ID" | cryptsetup token import --token-id 0 --token-replace --json-file - "$DEV"
  STATE=new
fi

mkdir -p "$MNT"
if ! mountpoint -q "$MNT"; then
  if ! mount -t xfs -o nosuid,nodev,noexec,noatime "$MAP" "$MNT"; then
    status broken "the volume opened but its xfs file system did not mount; left untouched"
    exit 0
  fi
fi
install -d -m 0700 "$MNT/workspaces" "$MNT/hotel"
status "$STATE" "LUKS2 volume mounted at $MNT ($(df -B1 --output=size "$MNT" | tail -1 | tr -d ' ') bytes)"
