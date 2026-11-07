#!/bin/bash
# Runs INSIDE the sealed guest at every boot, from sealed-hotel-boot.sh, before
# the room kit install. Only when the measured room.env sets ROOM_WORKSPACES_SOURCE.
#
# Opens the persistent data volume: the virtio disk with serial sealed-data, LUKS2
# (AES-XTS-512), with a key that only this guest build on this machine can make
# (sealed_data_key.py: the SNP derived key, then HOST_DATA). Mounts it at
# /srv/sealed-data with nosuid,nodev,noexec.
#
# The LUKS2 header is on the host disk, so the host can edit it. The host cannot
# forge the key slot without the key, but it can edit the data segment to a null
# cipher (Trail of Bits, 2025-10-30), which cryptsetup does not refuse. So after
# open, and before any mkfs or mount, verify_header() proves the mapping is
# exactly the aes-xts-plain64 / 4096-byte-sector / 512-bit layout we make;
# otherwise the volume is closed and left untouched (status tampered). The host
# then holds only ciphertext and a header that cannot change what the guest
# writes.
#
# State in /run/sealed-data.status (JSON, read by room_health.py):
#   new       the disk held no volume: made one now (first boot, or a blank disk)
#   open      the volume opened: workspaces persist across restarts of this build
#   locked    a volume is there but no key slot opens with this build's key
#             (another build, another machine, another HOST_DATA): left untouched
#   tampered  the volume opened but its header is not our layout, or it holds a
#             file system with no cathedral token: closed, left untouched
#   broken    the volume opened but its file system did not mount: left untouched
#   absent    no data disk
#   nokey     the secure processor gave no key (not an SNP guest?)
#   error     a step failed, or cryptsetup is too old (serial log); exits non-zero
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
MAP=${SEALED_DATA_MAP:-/dev/mapper/$NAME}   # the tests point this at a regular file
TOKEN_TYPE=cathedral-sealed-data
# The layout we make and require: anything else after open is tampering.
ENC=aes-xts-plain64
SECTOR=4096
KEY_SIZE=64            # bytes (512-bit XTS key)
MIN_CRYPTSETUP=2.8.1   # 2.8.1+ refuses null ciphers on key slots (not on data segments; verify_header covers those)
# No udev sync for device-mapper in this minimal guest: libdevmapper makes the node itself.
export DM_DISABLE_UDEV=1

KEY_ID=""
KEYFILE=""
STATUS_SET=0
status() { # status <state> <detail>
  python3 -c 'import json,sys; s,d,k=sys.argv[1:]; print(json.dumps({"state": s, "persistent": s in ("new", "open"), "key_id": k or None, "detail": d}, sort_keys=True))' \
    "$1" "$2" "$KEY_ID" > "$STATUS"
  STATUS_SET=1
  log "$1: $2"
}
on_exit() {
  local rc=$?
  [ -z "$KEYFILE" ] || rm -f "$KEYFILE"
  if [ "$rc" != 0 ] && [ "$STATUS_SET" = 0 ]; then status error "a step failed (exit $rc); see [sealed-data] in the serial log"; fi
}
trap on_exit EXIT

cryptsetup_version_ok() {
  cryptsetup --version 2>/dev/null | awk 'NR==1{print $2}' \
    | python3 -c 'import sys
want=tuple(int(x) for x in sys.argv[1].split("."))
raw=sys.stdin.readline().strip().split("-")[0]
try:
    cur=tuple(int(x) for x in raw.split(".")[:3])
except ValueError:
    sys.exit(1)
cur=cur+(0,)*(3-len(cur))
sys.exit(0 if cur>=want else 1)' "$MIN_CRYPTSETUP"
}

verify_header() {
  # Prove the mapping we opened is exactly our layout, so a header edited to a
  # null cipher cannot make us write workspaces in clear. Two independent reads:
  # the active device-mapper table, and the on-disk LUKS2 metadata.
  local table cipher json
  table=$(dmsetup table "$NAME" 2>/dev/null) || return 1
  cipher=$(awk '$3=="crypt"{print $4; f=1} END{exit !f}' <<<"$table") || return 1
  [ "$cipher" = "$ENC" ] || return 1
  grep -qE "sector_size:$SECTOR($|[^0-9])" <<<"$table" || return 1
  json=$(cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null) || return 1
  printf '%s' "$json" | python3 -c 'import json,sys
m=json.load(sys.stdin); enc,sector,ksize=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
seg=m.get("segments",{})
if set(seg)!={"0"}: sys.exit(1)
s=seg["0"]
if s.get("type")!="crypt" or s.get("encryption")!=enc or int(s.get("sector_size",0))!=sector: sys.exit(1)
ks=m.get("keyslots",{})
if "0" not in ks or int(ks["0"].get("key_size",0))!=ksize: sys.exit(1)
for slot in ks.values():
    if "null" in str(slot.get("area",{}).get("encryption","")).lower(): sys.exit(1)
sys.exit(0)' "$ENC" "$SECTOR" "$KEY_SIZE"
}

close_untouched() { # close_untouched <state> <detail>
  cryptsetup close "$NAME" 2>/dev/null || true
  status "$1" "$2"
  exit 0
}

# A block device; the tests (tests/test_room_kit_sealed_data.py) use a regular file.
is_disk() { [ -b "$1" ] || { [ "${SEALED_DATA_FAKE_DISK:-0}" = 1 ] && [ -f "$1" ]; }; }
for _ in $(seq 30); do is_disk "$DEV" && break; sleep 1; done
if ! is_disk "$DEV"; then
  status absent "no data disk (virtio serial $NAME); workspaces stay on the scratch disk until the next boot"
  exit 0
fi

if ! cryptsetup_version_ok; then
  status error "cryptsetup $(cryptsetup --version 2>/dev/null | awk 'NR==1{print $2}') is older than $MIN_CRYPTSETUP: it does not refuse null-cipher key slots; not opening the data volume"
  exit 0
fi

KEYFILE=$(mktemp "$RUNDIR/sealed-data.key.XXXXXX")  # /run is tmpfs: guest memory only; mode 0600
INFO=$("$KEYTOOL" info 2>&1) && "$KEYTOOL" key > "$KEYFILE" || {
  status nokey "the secure processor gave no key: $(echo "$INFO" | tail -1)"
  exit 0
}
KEYLEN=$(wc -c < "$KEYFILE" | tr -d ' ')
if [ "$KEYLEN" != 32 ]; then
  status nokey "the key tool gave $KEYLEN bytes, not 32"
  exit 0
fi
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$INFO" "$1"; }
KEY_ID=$(field key_id)
MEASUREMENT=$(field measurement)
POLICY=$(field policy)
HOST_DATA_HEX=$(field host_data)
# The launch identity the key is bound to: measurement, policy and HOST_DATA.
# install-sealed.sh reads this from the token to decide if a new build owns the volume.
LAUNCH_ID=$(python3 -c 'import hashlib,sys; print(hashlib.sha256((":".join(sys.argv[1:4])).encode()).hexdigest())' "$MEASUREMENT" "$POLICY" "$HOST_DATA_HEX")

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
    cryptsetup luksFormat --type luks2 --batch-mode --cipher "$ENC" --key-size 512 --sector-size "$SECTOR" \
      --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --hash sha256 --label cathedral-sealed-data \
      --key-file "$KEYFILE" --keyfile-size 32 "$DEV"
    cryptsetup open --type luks2 --key-file "$KEYFILE" --keyfile-size 32 "$DEV" "$NAME"
    STATE=new
  fi
fi

# The key slot unlocked, but the header is on the host disk. Prove the mapping
# is our cipher and sector size before we trust the device (null-cipher attack).
if [ -e "$MAP" ] && ! verify_header; then
  close_untouched tampered "the opened volume is not our $ENC / ${SECTOR}-byte / 512-bit layout; the LUKS2 header was changed on the host (null-cipher attack?); closed, left untouched"
fi

# mkfs only before the token says the file system exists: a first boot that
# stopped between luksFormat and mkfs. An opened volume with the token is never
# formatted again, whatever blkid says.
if [ "$(fs_token)" != xfs ]; then
  # No cathedral token, yet a file system is already here: tamper, or a format
  # interrupted between mkfs and the token import. Never format over it.
  if blkid -p -u filesystem "$MAP" >/dev/null 2>&1; then
    close_untouched tampered "the opened volume carries a file system but no cathedral token; not formatting (tamper, or an interrupted first format: remove data.raw to start fresh)"
  fi
  mkfs.xfs -f -q "$MAP"
  python3 -c 'import json,sys
t,m,p,h,k,lid=sys.argv[1:]
print(json.dumps({"type": t, "keyslots": [], "fs": "xfs", "schema": "cathedral_sealed_data_v1",
  "slots": {"0": {"measurement": m, "policy": p, "host_data": h, "key_id": k, "launch_id": lid}}}))' \
    "$TOKEN_TYPE" "$MEASUREMENT" "$POLICY" "$HOST_DATA_HEX" "$KEY_ID" "$LAUNCH_ID" \
    | cryptsetup token import --token-id 0 --token-replace --json-file - "$DEV"
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
