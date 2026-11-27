#!/bin/bash
# Build the sealed guest: one kernel, one initrd that holds the WHOLE root file
# system (Ubuntu minbase + Docker + the room kit), and one kernel command line.
# OVMF (AmdSev build) hashes all three into the SNP launch measurement, so the
# measurement covers every file the guest boots from. Nothing is read from an
# unmeasured root disk. The scratch disk is encrypted with a key the guest makes
# at boot. With SEALED_DATA_GIB > 0 a second disk holds persistent workspaces
# (LUKS2, a key only this build on this machine can make; sealed-data.sh).
#
# Usage: build-guest.sh sealed.env   (run as root on the host)
# Output: $SEALED_DIR/images/<stamp>/{vmlinuz,initrd.cpio.zst,cmdline,manifest.json}
#         and the symlink $SEALED_DIR/images/current.
set -euo pipefail
umask 022
KIT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1090
source "$(readlink -f "${1:?usage: build-guest.sh sealed.env}")"
# shellcheck disable=SC1091
source "$(dirname "$(readlink -f "$0")")/guest-constants.sh"
log() { echo "[sealed-build] $*"; }

# >>> dedicated TUN (AB#938; checked before any build work)
TENANCY=${SEALED_HOTEL_TENANCY:-shared}
ALLOW_TUN=${SEALED_ROOM_ALLOW_TUN:-0}
case "$TENANCY" in shared|dedicated) ;; *) echo "SEALED_HOTEL_TENANCY must be shared or dedicated" >&2; exit 1 ;; esac
case "$ALLOW_TUN" in 0|1) ;; *) echo "SEALED_ROOM_ALLOW_TUN must be 0 or 1" >&2; exit 1 ;; esac
if [ "$ALLOW_TUN" = 1 ] && [ "$TENANCY" != dedicated ]; then
  echo "SEALED_ROOM_ALLOW_TUN needs SEALED_HOTEL_TENANCY=dedicated" >&2; exit 1
fi
# AB#962: required (default) adds nothing. open is measured here, never fw_cfg.
OWNER_GATE=${SEALED_OWNER_GATE:-required}
case "$OWNER_GATE" in required|open) ;; *) echo "SEALED_OWNER_GATE must be required or open" >&2; exit 1 ;; esac
if [ "$OWNER_GATE" = open ] && [ "$TENANCY" != dedicated ]; then
  echo "SEALED_OWNER_GATE=open needs SEALED_HOTEL_TENANCY=dedicated" >&2; exit 1
fi
DEDICATED_ENV=""
if [ "$TENANCY" = dedicated ]; then
  # The receipt front verifies the launch owner against SNP HOST_DATA at boot.
  # A missing owner key refuses startup; this flag alone cannot grant tenancy.
  DEDICATED_ENV="CATHEDRAL_HOTEL_TENANCY=dedicated
ROOM_ALLOW_TUN=$ALLOW_TUN"
  # Open: no owner key needed; the binding then says "owner_gate": "open".
  [ "$OWNER_GATE" != open ] || DEDICATED_ENV="$DEDICATED_ENV
CATHEDRAL_OWNER_GATE=open"
fi
# <<< dedicated TUN

# Miner hotel (SEALED_MINER=1, README "Miner hotel"): checked before the long
# build. 0 or unset builds a config hotel; the files below come out as before.
MINER=${SEALED_MINER:-0}
case "$MINER" in 0|1) ;; *) echo "SEALED_MINER must be 0 or 1" >&2; exit 1 ;; esac
if [ "$MINER" = 1 ]; then
  MINER_TLS_PORT=${SEALED_MINER_TLS_PORT:-18443}
  if ! [[ "$MINER_TLS_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$MINER_TLS_PORT" -gt 65535 ] \
     || [ "$MINER_TLS_PORT" = 18090 ] || [ "$MINER_TLS_PORT" = 18091 ]; then
    echo "SEALED_MINER_TLS_PORT must be a TCP port other than 18090 and 18091" >&2; exit 1
  fi
  # 1 to 4 base64 Ed25519 public keys (raw 32 bytes); printed back space-separated.
  MINER_SIGNERS=$(python3 -c '
import base64, sys
keys = sys.argv[1].split()
ok = 1 <= len(keys) <= 4 and all(len(base64.b64decode(k, validate=True)) == 32
                                 and base64.b64encode(base64.b64decode(k)).decode() == k for k in keys)
print(" ".join(dict.fromkeys(keys)) if ok else "")' "${SEALED_HOTEL_KEY_INSTALL_SIGNERS:-}" 2>/dev/null || true)
  [ -n "$MINER_SIGNERS" ] || { echo "SEALED_MINER=1 needs SEALED_HOTEL_KEY_INSTALL_SIGNERS: 1 to 4 base64 Ed25519 public keys" >&2; exit 1; }
fi

# Guest ingress for Preview URLs (AB#422): SEALED_ROOM_GUEST_INGRESS=1 makes the key in the
# guest. With SEALED_INGRESS_ZONE set the guest also serves HTTPS on SEALED_INGRESS_TLS_PORT
# with it, opens that port in its firewall and gets a certificate through the broker
# (SEALED_INGRESS_BROKER_URL). All of it is in the measured room.env. Checked before the long build.
# >>> guest ingress (tests/test_ab422_guest_ingress_serve.py runs this block)
GUEST_INGRESS=${SEALED_ROOM_GUEST_INGRESS:-0}
case "$GUEST_INGRESS" in 0|1) ;; *) echo "SEALED_ROOM_GUEST_INGRESS must be 0 or 1" >&2; exit 1 ;; esac
INGRESS_ZONE=""
if [ "$GUEST_INGRESS" = 1 ] && [ -n "${SEALED_INGRESS_ZONE:-}" ]; then
  INGRESS_ZONE=$SEALED_INGRESS_ZONE
  INGRESS_TLS_PORT=${SEALED_INGRESS_TLS_PORT:-8443}
  INGRESS_PUBLIC_PORT=${SEALED_INGRESS_PUBLIC_PORT:-443}
  INGRESS_BROKER_URL=${SEALED_INGRESS_BROKER_URL:-}
  ACME_DIRECTORY=${SEALED_ACME_DIRECTORY:-https://acme-v02.api.letsencrypt.org/directory}
  if ! [[ "$INGRESS_ZONE" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
    echo "SEALED_INGRESS_ZONE must be a lower-case DNS name (the broker acme_dns zone)" >&2; exit 1
  fi
  for p in "$INGRESS_TLS_PORT" "$INGRESS_PUBLIC_PORT"; do
    if ! [[ "$p" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$p" -gt 65535 ]; then
      echo "SEALED_INGRESS_TLS_PORT and SEALED_INGRESS_PUBLIC_PORT must be TCP ports" >&2; exit 1
    fi
  done
  if [ "$INGRESS_TLS_PORT" = 18090 ] || [ "$INGRESS_TLS_PORT" = 18091 ] || [ "$INGRESS_TLS_PORT" = 22 ] \
     || { [ "$MINER" = 1 ] && [ "$INGRESS_TLS_PORT" = "$MINER_TLS_PORT" ]; }; then
    echo "SEALED_INGRESS_TLS_PORT must not be 18090, 18091, 22 or the miner TLS port" >&2; exit 1
  fi
  if ! [[ "$INGRESS_BROKER_URL" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$ ]]; then
    echo "SEALED_INGRESS_ZONE needs SEALED_INGRESS_BROKER_URL: the broker https origin" >&2; exit 1
  fi
  if ! [[ "$ACME_DIRECTORY" =~ ^https://[A-Za-z0-9./:_-]+$ ]]; then
    echo "SEALED_ACME_DIRECTORY must be an https URL" >&2; exit 1
  fi
fi
# <<< guest ingress
# Hotel vCPU quota (AB#857): "pool" (the overcommitted CPU pool, default), "slots"
# (one vCPU per slot) or a whole number, never below one vCPU per slot (size.py).
# A number lets every slot hold a 2 vCPU room where the pool is smaller than 2 x slots.
# It is written into the measured room.env, so it is part of the measurement.
case "${SEALED_ROOM_QUOTA_VCPU:-pool}" in
  pool|slots) ;;
  *[!0-9]*|0*|"") echo "SEALED_ROOM_QUOTA_VCPU must be pool, slots or a whole number of vCPUs" >&2; exit 1 ;;
esac

# Docker Hub mirrors for the guest's dockerd (daemon.json registry-mirrors, AB#854). Part of
# the measured room.env. Unset keeps mirror.gcr.io, so a hotel that does not set it builds the
# same room.env bytes as before. 1 to 4 https origins (host and optional port, no path, no
# login): dockerd tries them in order, then Docker Hub; a mirror answering 404 is skipped.
# Checked before the long build.
# >>> registry mirrors (tests/test_ab854_sealed_registry_mirrors.py runs this block)
read -r -d '' -a mirror_list <<< "${SEALED_ROOM_REGISTRY_MIRRORS:-https://mirror.gcr.io}" || true
REGISTRY_MIRRORS="${mirror_list[*]}"  # one space between entries, whatever whitespace sealed.env used
mirror_count=0
for mirror in "${mirror_list[@]}"; do
  if ! [[ "$mirror" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$ ]]; then
    echo "SEALED_ROOM_REGISTRY_MIRRORS: '$mirror' is not an https origin (https://host[:port], lower case, no path or login)" >&2; exit 1
  fi
  mirror_count=$((mirror_count + 1))
done
if [ "$mirror_count" -lt 1 ] || [ "$mirror_count" -gt 4 ]; then
  echo "SEALED_ROOM_REGISTRY_MIRRORS needs 1 to 4 mirrors" >&2; exit 1
fi
# <<< registry mirrors

# Persistent data volume (docs/SEALED_DATA_VOLUME.md): checked before the long
# build. It holds workspaces only, so it needs them on.
DATA_GIB=${SEALED_DATA_GIB:-0}
[[ "$DATA_GIB" =~ ^(0|[1-9][0-9]{0,5})$ ]] || { echo "SEALED_DATA_GIB must be a whole number of GiB (0: no data disk)" >&2; exit 1; }
DATA_WS=""
if [ "$DATA_GIB" != 0 ]; then
  [ "${SEALED_ROOM_WORKSPACES:-0}" = 1 ] || { echo "SEALED_DATA_GIB > 0 needs SEALED_ROOM_WORKSPACES=1: the data disk holds workspaces only" >&2; exit 1; }
  DATA_WS=/srv/sealed-data/workspaces
fi

# Synced volumes (AB#789, docs/SEALED_DATA_VOLUME.md): SEALED_ROOM_VOLUMES=1 turns on the
# guest volume agent. The switch, the registry and gateway origins and the registry keys are
# in the measured room.env, so a guest only trusts the registry its measurement names. 0 or
# unset writes no volume line, so a hotel that does not set it builds the same room.env bytes
# as before. Checked before the long build.
# >>> synced volumes (tests/test_ab789_sealed_room_env_volumes.py runs this block)
VOLUMES=${SEALED_ROOM_VOLUMES:-0}
case "$VOLUMES" in 0|1) ;; *) echo "SEALED_ROOM_VOLUMES must be 0 or 1" >&2; exit 1 ;; esac
VOLUME_ENV=""
if [ "$VOLUMES" = 1 ]; then
  [ -n "$DATA_WS" ] || { echo "SEALED_ROOM_VOLUMES=1 needs the data volume (SEALED_DATA_GIB > 0): volumes sync its workspaces" >&2; exit 1; }
  for var in SEALED_ROOM_VOLUME_REGISTRY_URL SEALED_ROOM_VOLUME_GATEWAY_URL; do
    if ! [[ "${!var:-}" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?(/[A-Za-z0-9._~-]+)*$ ]]; then
      echo "SEALED_ROOM_VOLUMES=1 needs $var: an https URL (lower-case host, optional port and path, no login, query or trailing slash)" >&2; exit 1
    fi
  done
  # 1 to 4 base64 Ed25519 public keys (raw 32 bytes), comma-separated as volume_agent.from_env reads them.
  VOLUME_KEYS=$(python3 -c '
import base64, sys
keys = sys.argv[1].split(",")
ok = 1 <= len(keys) <= 4 and all(k and len(base64.b64decode(k, validate=True)) == 32
                                 and base64.b64encode(base64.b64decode(k)).decode() == k for k in keys)
print(",".join(dict.fromkeys(keys)) if ok else "")' "${SEALED_ROOM_VOLUME_REGISTRY_KEYS:-}" 2>/dev/null || true)
  [ -n "$VOLUME_KEYS" ] || { echo "SEALED_ROOM_VOLUMES=1 needs SEALED_ROOM_VOLUME_REGISTRY_KEYS: 1 to 4 comma-separated base64 Ed25519 public keys" >&2; exit 1; }
  COMMIT_SECONDS=${SEALED_ROOM_VOLUME_COMMIT_SECONDS:-}
  if [ -n "$COMMIT_SECONDS" ] && ! [[ "$COMMIT_SECONDS" =~ ^(0|[1-9][0-9]{1,4})$ && ( "$COMMIT_SECONDS" = 0 || ( "$COMMIT_SECONDS" -ge 30 && "$COMMIT_SECONDS" -le 86400 ) ) ]]; then
    echo "SEALED_ROOM_VOLUME_COMMIT_SECONDS must be empty, 0 or 30..86400" >&2; exit 1
  fi
  VOLUME_ENV="ROOM_VOLUMES=1
ROOM_VOLUME_REGISTRY_URL=$SEALED_ROOM_VOLUME_REGISTRY_URL
ROOM_VOLUME_GATEWAY_URL=$SEALED_ROOM_VOLUME_GATEWAY_URL
ROOM_VOLUME_REGISTRY_KEYS=$VOLUME_KEYS
ROOM_VOLUME_COMMIT_SECONDS=$COMMIT_SECONDS"
fi
# <<< synced volumes

# Pinned packages (AB#383): SEALED_SNAPSHOT=<YYYYMMDDTHHMMSSZ> builds the base from
# https://snapshot.ubuntu.com/ubuntu/<snapshot>, release pocket only, so every build of one
# snapshot gets the same packages. The resolved set (name, version, architecture, sha256)
# must equal SEALED_PACKAGES_LOCK or the build stops; SEALED_PACKAGES_LOCK_UPDATE=1 builds
# anyway and leaves the new lock next to the image. Unset: the mirror build as before
# (SEALED_MIRROR, newest kernel, same base cache key, same manifest). Checked before the long build.
# >>> pinned snapshot (tests/test_ab383_pinned_snapshot.py runs this block)
SNAPSHOT=${SEALED_SNAPSHOT:-}
if [ -n "$SNAPSHOT" ]; then
  LOCK_TOOL=$KIT/sealed/packages_lock.py
  SNAPSHOT_EPOCH=$(python3 "$LOCK_TOOL" snapshot-epoch "$SNAPSHOT") \
    || { echo "SEALED_SNAPSHOT must be a snapshot.ubuntu.com id such as 20261101T000000Z" >&2; exit 1; }
  LOCK_UPDATE=${SEALED_PACKAGES_LOCK_UPDATE:-0}
  case "$LOCK_UPDATE" in 0|1) ;; *) echo "SEALED_PACKAGES_LOCK_UPDATE must be 0 or 1" >&2; exit 1 ;; esac
  LOCK_FILE=${SEALED_PACKAGES_LOCK:-}
  if [ "$LOCK_UPDATE" = 0 ] && [ ! -f "$LOCK_FILE" ]; then
    echo "SEALED_SNAPSHOT needs SEALED_PACKAGES_LOCK (the expected packages.lock), or SEALED_PACKAGES_LOCK_UPDATE=1 to make one" >&2; exit 1
  fi
  # The initrd and the shadow day use the kit commit time; a pinned build with no commit time is not reproducible.
  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$KIT" log -1 --format=%ct 2>/dev/null || echo 0)}
  [[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || { echo "SEALED_SNAPSHOT needs the kit commit time: build from a git checkout or set SOURCE_DATE_EPOCH" >&2; exit 1; }
fi
# <<< pinned snapshot

B=$SEALED_DIR/build
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$SEALED_DIR/images/$STAMP
mkdir -p "$B" "$OUT"

# ---------------------------------------------------------------- 1. base root file system (cached)
PKGS=systemd,systemd-sysv,udev,kmod,iproute2,nftables,iptables,conntrack,docker.io,containerd,xfsprogs,cryptsetup-bin,curl,ca-certificates,bzip2,python3,procps,util-linux,iputils-ping,linux-image-virtual,openssh-server,less,tar,gzip,zstd,passwd,dmsetup
BASE_ID=$(echo "$SEALED_SUITE $SEALED_MIRROR $PKGS" | sha256sum | cut -c1-12)
# >>> pinned base (tests/test_ab383_pinned_snapshot.py runs this block)
# A pinned base is keyed by the snapshot, not the mirror URL; its lock is cached next to it.
BASE_MIRROR=$SEALED_MIRROR
if [ -n "$SNAPSHOT" ]; then
  BASE_MIRROR=https://snapshot.ubuntu.com/ubuntu/$SNAPSHOT
  BASE_ID=$(echo "snapshot $SNAPSHOT $SEALED_SUITE $PKGS" | sha256sum | cut -c1-12)
fi
if [ ! -d "$B/base-$BASE_ID" ]; then
  log "mmdebstrap $SEALED_SUITE (base $BASE_ID)"
  rm -rf "$B/base-$BASE_ID.tmp" "$B/base-$BASE_ID.packages.lock"
  LOCK_HOOK=()
  if [ -n "$SNAPSHOT" ]; then
    # The hook runs on the build host before mmdebstrap removes the apt lists, which hold
    # the sha256 of every .deb. The base's own dates come from the snapshot time.
    LOCK_HOOK=(--customize-hook="python3 $(printf '%q' "$LOCK_TOOL") emit \"\$1\" > $(printf '%q' "$B/base-$BASE_ID.packages.lock.tmp")")
  fi
  ( [ -z "$SNAPSHOT" ] || export SOURCE_DATE_EPOCH=$SNAPSHOT_EPOCH
    mmdebstrap --variant=minbase --aptopt='APT::Install-Recommends "false"' --components=main,universe \
      "${LOCK_HOOK[@]}" --include="$PKGS" "$SEALED_SUITE" "$B/base-$BASE_ID.tmp" "$BASE_MIRROR" )
  [ -z "$SNAPSHOT" ] || mv "$B/base-$BASE_ID.packages.lock.tmp" "$B/base-$BASE_ID.packages.lock"
  mv "$B/base-$BASE_ID.tmp" "$B/base-$BASE_ID"
fi
R=$B/rootfs
rm -rf "$R"
cp -a "$B/base-$BASE_ID" "$R"
BASE_ROOTFS=$BASE_ID
if [ -n "$SNAPSHOT" ]; then
  BASE_LOCK=$B/base-$BASE_ID.packages.lock
  [ -s "$BASE_LOCK" ] || { echo "base $BASE_ID has no packages.lock; remove $B/base-$BASE_ID to rebuild it" >&2; exit 1; }
  python3 "$LOCK_TOOL" check "$R" "$BASE_LOCK" || { echo "base $BASE_ID does not match its packages.lock; remove it to rebuild" >&2; exit 1; }
  install -m 0644 "$BASE_LOCK" "$OUT/packages.lock"
  if [ "$LOCK_UPDATE" = 1 ]; then
    log "SEALED_PACKAGES_LOCK_UPDATE=1: new lock at $OUT/packages.lock"
  elif ! cmp -s "$BASE_LOCK" "$LOCK_FILE"; then
    diff -u "$LOCK_FILE" "$BASE_LOCK" | head -40 >&2 || true
    echo "resolved packages differ from $LOCK_FILE; set SEALED_PACKAGES_LOCK_UPDATE=1 to accept a new lock" >&2; exit 1
  fi
  # The manifest names the lock, not the mirror URL it was fetched from.
  BASE_ROOTFS=$(sha256sum < "$OUT/packages.lock" | cut -d' ' -f1)
fi
# <<< pinned base

# The data volume's header is verified at boot, but a cryptsetup older than 2.8.1
# would still open a null-cipher key slot, so refuse to ship one with the volume on.
if [ "$DATA_GIB" != 0 ]; then
  CRYPTVER=$(chroot "$R" cryptsetup --version 2>/dev/null | awk 'NR==1{print $2}')
  python3 -c 'import sys
raw=sys.argv[1].split("-")[0]
cur=tuple(int(x) for x in raw.split(".")[:3]) if raw else ()
cur=cur+(0,)*(3-len(cur))
sys.exit(0 if cur>=(2,8,1) else 1)' "$CRYPTVER" \
    || { echo "cryptsetup ${CRYPTVER:-unknown} in the base rootfs is older than 2.8.1; use a newer suite or pin cryptsetup (SEALED_DATA_GIB needs it)" >&2; exit 1; }
fi

# ---------------------------------------------------------------- 2. kernel out, boot files gone
KVER=$(ls "$R/lib/modules" | sort -V | tail -1)
# A pinned build boots the kernel its lock names, not whichever is newest in the root.
[ -z "$SNAPSHOT" ] || KVER=$(python3 "$LOCK_TOOL" kernel "$OUT/packages.lock")
install -m 0644 "$R/boot/vmlinuz-$KVER" "$OUT/vmlinuz"
rm -rf "${R:?}/boot"/* "$R/var/cache/apt/archives"/*.deb "$R/var/lib/apt/lists"/* 2>/dev/null || true

# ---------------------------------------------------------------- 3. guest configuration
ln -sfn usr/lib/systemd/systemd "$R/init"
# The hotel name is not in the image: guest-boot.sh sets the hostname from fw_cfg.
echo "room-sealed" > "$R/etc/hostname"
: > "$R/etc/machine-id"
: > "$R/etc/fstab"
rm -f "$R/etc/resolv.conf"
for d in $SEALED_DNS; do echo "nameserver $d"; done > "$R/etc/resolv.conf"
# A pinned build ships the same apt sources whatever mirror or snapshot it was fetched from,
# so the URL is not in the measurement. The guest never runs apt (timers masked below).
if [ -n "$SNAPSHOT" ]; then
  rm -f "$R"/etc/apt/sources.list.d/*
  printf 'deb http://archive.ubuntu.com/ubuntu %s main universe\n' "$SEALED_SUITE" > "$R/etc/apt/sources.list"
fi

# The link (host IP, guest IP) is per hotel and NOT in the image (AB#432): the host
# passes it in fw_cfg (opt/cathedral/link) and sealed-link.sh checks it and writes
# the .network file, the guard and the listen addresses under /run at boot. The
# only NIC is the virtio one (QEMU -nodefaults), so the .link matches the driver,
# not the per-hotel MAC.
cat > "$R/etc/systemd/network/10-uplink.link" <<EOF
[Match]
Driver=virtio_net
[Link]
Name=uplink
EOF
cat > "$R/etc/modules-load.d/sealed.conf" <<'EOF'
sev-guest
tsm_report
qemu_fw_cfg
dm-crypt
xfs
overlay
br_netfilter
EOF
[ "$ALLOW_TUN" != 1 ] || echo tun >> "$R/etc/modules-load.d/sealed.conf"

DEBUG=0; [ -n "${SEALED_DEBUG_SSH_PUBKEY:-}" ] && DEBUG=1
# Guest firewall on the uplink: replies, the hotel API from the host, nothing else.
# A miner hotel adds its attested HTTPS port from any source: the host forwards
# one public port to it, and only the guest holds that TLS key. @SEALED_HOST_IP@
# is filled in at boot by sealed-link.sh from the checked fw_cfg link; with no
# valid link it loads the guard without those lines (uplink closed).
SSH_RULE=""; [ $DEBUG = 1 ] && SSH_RULE='iifname "uplink" ip saddr @SEALED_HOST_IP@ tcp dport 22 accept'
INPUT_RULES=$SSH_RULE
if [ "$MINER" = 1 ]; then
  INPUT_RULES="${SSH_RULE:+$SSH_RULE
    }iifname \"uplink\" tcp dport $MINER_TLS_PORT accept"
fi
if [ -n "$INGRESS_ZONE" ]; then
  # Preview URL ingress (AB#422): from any source, like the miner port. Only the guest holds the key.
  INPUT_RULES="${INPUT_RULES:+$INPUT_RULES
    }iifname \"uplink\" tcp dport $INGRESS_TLS_PORT accept"
fi
cat > "$R/etc/sealed-guard.nft" <<EOF
table inet sealed_guard {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "uplink" ct state established,related accept
    iifname "uplink" ip saddr @SEALED_HOST_IP@ tcp dport 18090 accept
    $INPUT_RULES
    iifname "uplink" drop
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "uplink" ct state established,related accept
    iifname "uplink" drop
  }
}
EOF
cat > "$R/etc/systemd/system/sealed-guard.service" <<'EOF'
[Unit]
Description=Sealed hotel: guest firewall on the uplink
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=systemd-modules-load.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/sealed-link.sh
[Install]
WantedBy=sysinit.target
EOF

install -m 0755 "$KIT/sealed/guest-boot.sh" "$R/usr/local/sbin/sealed-hotel-boot.sh"
install -m 0755 "$KIT/sealed/guest-link.sh" "$R/usr/local/sbin/sealed-link.sh"
install -m 0755 "$KIT/sealed/sealed-data.sh" "$R/usr/local/sbin/sealed-data.sh"
install -m 0755 "$KIT/sealed/sealed_data_key.py" "$R/usr/local/sbin/sealed_data_key.py"
cat > "$R/etc/systemd/system/sealed-hotel.service" <<'EOF'
[Unit]
Description=Sealed hotel: encrypt scratch, then install the room kit
Wants=network-online.target sealed-guard.service
After=network-online.target sealed-guard.service systemd-modules-load.service containerd.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/sealed-hotel-boot.sh
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=1800
[Install]
WantedBy=multi-user.target
EOF

# The room kit, exactly as for unsealed hotels, plus the guest's room.env.
mkdir -p "$R/opt/room-kit"
# Only tracked kit files and the pinned API tarball go into the measured
# initrd. A stray sealed.env, editor swap file or __pycache__ in the checkout
# changed the measurement and shipped into the guest.
# shellcheck disable=SC1091
source "$KIT/versions.lock"
if git -C "$KIT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$KIT" ls-files -z | grep -zv '^sealed/work/' | tar -C "$KIT" --null -T - -cf - | tar -C "$R/opt/room-kit" -xf -
else
  tar -C "$KIT" --exclude=./sealed/work --exclude='*.swp' --exclude='__pycache__' --exclude=./sealed/sealed.env \
    --exclude=./room.env --exclude=./dist -cf - . | tar -C "$R/opt/room-kit" -xf -
fi
mkdir -p "$R/opt/room-kit/dist"
install -m 0644 "$KIT/$CATHEDRAL_TARBALL" "$R/opt/room-kit/dist/"
{ cat "$KIT/KIT_COMMIT" 2>/dev/null || ( cd "$KIT" && git rev-parse HEAD 2>/dev/null ) || echo unknown; } > "$R/opt/room-kit/KIT_COMMIT"
cat > "$R/opt/room-kit/room.env" <<EOF
# Sealed hotel: written by sealed/build-guest.sh, part of the measured initrd.
ROOM_ID=room-sealed
ROOM_HOSTNAME=room-sealed.local
ROOM_ACME_EMAIL=
ROOM_CUSTOMER=broker
ROOM_REGION=EU
API_PROFILE=v1
ROOM_API_KEY_FILE=/run/room-api-key
ROOM_API_PORT=18090
ROOM_HEALTH_PORT=18091
ROOM_PUBLIC_PORT=443
ROOM_TLS=off
ROOM_REGISTRY_MIRRORS="$REGISTRY_MIRRORS"
ROOM_DATA_DIR=/srv/room-sealed
ROOM_DATA_DEVICE=/dev/mapper/sealed-scratch
ROOM_DATA_DEVICE_WIPE=yes
ROOM_DATA_IMG=
ROOM_DATA_SIZE_GB=0
ROOM_BRIDGE=rmbr0
ROOM_BRIDGE_CIDR=10.213.0.1/21
ROOM_DNS="$SEALED_DNS"
# Dedicated and shared both keep the default emulated-only character devices: no
# room opens /dev/sev-guest; a dedicated room gets its SNP report from its socket.
if [ "$TENANCY" = dedicated ]; then
  # --host-uds=open: the room reaches its report socket (AB#1001) on a bind mount.
  ROOM_RUNSC_FLAGS="--platform=systrap --overlay2=none --net-raw --host-uds=open"
else
  ROOM_RUNSC_FLAGS="--platform=systrap --overlay2=none --net-raw"
fi
ROOM_ALLOW_DIND=1
SHAPE_VCPU=1
SHAPE_MEM_GIB=4
SHAPE_DISK_GIB=10
RESERVE_RAM_PCT=12
RESERVE_THREADS=2
DISK_MAX_FILL_PCT=80
CPU_OVERCOMMIT=16
MEM_OVERCOMMIT=20
DISK_OVERCOMMIT=1000
ROOM_MAX_SLOTS=$SEALED_ROOM_MAX_SLOTS
ROOM_QUOTA_VCPU=${SEALED_ROOM_QUOTA_VCPU:-pool}
ROOM_CREATES_PER_MINUTE=6000
ROOM_GC_PARALLELISM=16
ROOM_DIND_DOCKERD_ARGS="--iptables=false --ip6tables=false --bridge=none --default-network-opt bridge=com.docker.network.advertise_addr_nmsgs=0 --default-address-pool base=10.200.0.0/14,size=24"
ROOM_DIND_ENV="PATH=/usr/local/sbin/.iptables-legacy:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ROOM_NETS="$SEALED_ROOM_NETS"
ROOM_NET_SIZE=1000
ROOM_NET_BRIDGE_PREFIX=rmnet
ROOM_RECEIPTS=1
ROOM_RECEIPTS_LISTEN=\${SEALED_LINK_GUEST_IP:?}:18090
ROOM_SECRETS_PERSIST=0
ROOM_SECRETS_PER_OWNER=4096
ROOM_WORKSPACES=${SEALED_ROOM_WORKSPACES:-0}
ROOM_WORKSPACES_SOURCE=$DATA_WS
ROOM_ESCAPE=${SEALED_ROOM_ESCAPE:-0}
ROOM_ESCAPE_ALLOW_PLAINTEXT=${SEALED_ROOM_ESCAPE_ALLOW_PLAINTEXT:-0}
ROOM_SEALED_SECRETS=${SEALED_ROOM_SEALED_SECRETS:-0}
ROOM_SEALED_EXEC=${SEALED_ROOM_SEALED_EXEC:-0}
ROOM_GUEST_INGRESS=${SEALED_ROOM_GUEST_INGRESS:-0}
# ROOM_HOTEL_NAME is not set here: guest-boot.sh exports it from fw_cfg (opt/cathedral/hotel-name).
# SEALED_LINK_GUEST_IP is not set here either: guest-boot.sh exports it from the link
# sealed-link.sh checked (fw_cfg opt/cathedral/link). install.sh sources this file,
# so the listen addresses resolve then; unset, the install stops.
EOF
[ -z "$DEDICATED_ENV" ] || { echo; echo "$DEDICATED_ENV"; } >> "$R/opt/room-kit/room.env"
# AB#1001: the in-room report call is on for dedicated images only. It sits outside the
# measured dedicated TUN block above, whose output is pinned by its own tests.
[ "$TENANCY" != dedicated ] || echo "ROOM_IN_ROOM_ATTEST=1" >> "$R/opt/room-kit/room.env"
if [ -n "$VOLUME_ENV" ]; then
  { echo "# Synced volumes (AB#789): install.sh fetches the pinned restic and the receipts front runs the"
    echo "# guest volume agent against this registry and gateway, trusting only these registry keys."
    echo "$VOLUME_ENV"; } >> "$R/opt/room-kit/room.env"
fi
if [ -n "$INGRESS_ZONE" ]; then
  cat >> "$R/opt/room-kit/room.env" <<EOF
# Preview URL ingress (AB#422): the front serves HTTPS here with the guest-made key,
# certificate from the ACME directory over DNS-01 through the broker. The listen IP and
# the public port are per hotel (two ingress hotels on one host forward two public
# ports), so they come from fw_cfg through guest-boot.sh (AB#432).
ROOM_INGRESS_ZONE=$INGRESS_ZONE
ROOM_INGRESS_BROKER_URL=$INGRESS_BROKER_URL
ROOM_INGRESS_TLS_LISTEN=\${SEALED_LINK_GUEST_IP:?}:$INGRESS_TLS_PORT
ROOM_INGRESS_PUBLIC_PORT=\${SEALED_LINK_INGRESS_PUBLIC_PORT:?}
ROOM_ACME_DIRECTORY=$ACME_DIRECTORY
EOF
fi
if [ "$MINER" = 1 ]; then
  cat >> "$R/opt/room-kit/room.env" <<EOF
# Miner hotel: guest TLS on its own key, plain HTTP for /room/attestation only,
# the hotel key only through POST /room/hotel-key signed by one of these keys.
ROOM_MINER=1
ROOM_RECEIPTS_TLS_LISTEN=\${SEALED_LINK_GUEST_IP:?}:$MINER_TLS_PORT
ROOM_HOTEL_KEY_INSTALL_SIGNERS="$MINER_SIGNERS"
EOF
fi

# Units: no logins, no host Docker daemon, no apt timers; the hotel and the guard on.
in_root() { chroot "$R" "$@"; }
in_root systemctl mask -q docker.service docker.socket serial-getty@ttyS0.service getty@tty1.service \
  console-getty.service getty.target apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
in_root systemctl enable -q systemd-networkd.service sealed-guard.service sealed-hotel.service containerd.service
in_root passwd -l root >/dev/null
if [ $DEBUG = 1 ]; then
  install -d -m 0700 "$R/root/.ssh"
  echo "$SEALED_DEBUG_SSH_PUBKEY" > "$R/root/.ssh/authorized_keys"
  chmod 0600 "$R/root/.ssh/authorized_keys"
  printf 'PasswordAuthentication no\nPermitRootLogin prohibit-password\n' > "$R/etc/ssh/sshd_config.d/10-sealed-debug.conf"
  # ListenAddress is the per-hotel guest IP: sealed-link.sh writes it at boot.
  ln -sfn /run/sealed-link/sshd-listen.conf "$R/etc/ssh/sshd_config.d/11-sealed-listen.conf"
  mkdir -p "$R/etc/systemd/system/ssh.service.d"
  # Ubuntu's unit runs "sshd -t" first and the build removes host keys, so
  # reset the list: make keys, then check the config.
  printf '[Service]\nExecStartPre=\nExecStartPre=/usr/bin/ssh-keygen -A\nExecStartPre=/usr/sbin/sshd -t\n' > "$R/etc/systemd/system/ssh.service.d/10-hostkeys.conf"
  in_root systemctl enable -q ssh.service
  in_root systemctl mask -q ssh.socket 2>/dev/null || true
else
  in_root systemctl mask -q ssh.service ssh.socket 2>/dev/null || true
  rm -f "$R"/etc/ssh/ssh_host_*
fi
# Host keys made at build time would be in the measured initrd; make them at boot instead.
rm -f "$R"/etc/ssh/ssh_host_*

# SOURCE_DATE_EPOCH: the kit commit time, so the same kit gives the same bytes on any host.
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$KIT" log -1 --format=%ct 2>/dev/null || echo 0)}
# >>> shadow day (tests/test_ab432_hotel_name_off_the_measurement.py runs this block)
# /etc/shadow field 3 is the day each account was made: the day THIS host cached its base
# rootfs (base-*), so two hosts of one kit measured differently (AB#432: nc-sealed-2 20749,
# nc-sealed-3 20753). Pin it to the kit commit day. 0 would mean "change the password at
# the next login", so an unknown commit time leaves the file as it is.
SHADOW_DAY=$(( SOURCE_DATE_EPOCH / 86400 ))
if [ "$SHADOW_DAY" -gt 0 ]; then
  for f in "$R/etc/shadow" "$R/etc/shadow-"; do
    [ -f "$f" ] || continue
    awk -F: -v OFS=: -v d="$SHADOW_DAY" '$3 != "" { $3 = d } { print }' "$f" > "$f.tmp"
    cat "$f.tmp" > "$f"  # keeps the file's owner and mode
    rm -f "$f.tmp"
  done
fi
# <<< shadow day

# ---------------------------------------------------------------- 4. initrd = whole root, cmdline
log "packing initrd"
# shellcheck disable=SC1091
source "$KIT/sealed/pack-initrd.sh"
pack_initrd "$R" "$OUT/initrd.cpio.zst" "$SOURCE_DATE_EPOCH"
# systemd.import_credentials=no: systemd would otherwise import credentials from QEMU fw_cfg
# and SMBIOS, which the host sets and nothing measures (a systemd.extra-unit.* credential is
# root code in the guest with the measurement unchanged). Its confidential-VM detection is not
# relied on. The guest reads its own fw_cfg keys (opt/cathedral/*) from sysfs, not as credentials.
CMDLINE="console=ttyS0 loglevel=7 systemd.show_status=error panic=-1 rdinit=/init systemd.import_credentials=no cathedral.debug=$DEBUG"
printf '%s' "$CMDLINE" > "$OUT/cmdline"
install -m 0644 "$SEALED_OVMF" "$OUT/OVMF.amdsev.fd"

python3 - "$OUT" "$SEALED_VCPUS" "$SEALED_CPU_MODEL" "$KVER" "$DEBUG" "$BASE_ROOTFS" \
  "$MINER" "${MINER_TLS_PORT:-}" "${MINER_SIGNERS:-}" "$DATA_WS" <<'EOF'
import hashlib, json, os, sys
out, vcpus, cpu, kver, debug, base, miner, tls_port, signers, data_ws = sys.argv[1:]
def sha(p):
    h = hashlib.sha256()
    with open(os.path.join(out, p), "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
m = {"schema": "cathedral_sealed_hotel_guest_v1", "vcpus": int(vcpus), "cpu_model": cpu,
     "kernel_release": kver, "debug": debug == "1", "base_rootfs": base,
     "cmdline": open(os.path.join(out, "cmdline")).read(),
     "sha256": {p: sha(p) for p in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst", "cmdline")},
     "bytes": {p: os.path.getsize(os.path.join(out, p)) for p in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst")}}
if miner == "1":  # a config hotel's manifest keeps its old fields only
    m["miner"] = {"tls_port": int(tls_port), "hotel_key_install_signers_ed25519_b64": signers.split()}
if data_ws:  # likewise: only a build with the persistent data volume names it
    m["data_volume"] = {"format": "luks2", "cipher": "aes-xts-plain64", "key": "snp-derived",
                        "root_key": "vcek", "guest_field_select": 9, "mixes_host_data": True, "holds": ["workspaces"]}
json.dump(m, open(os.path.join(out, "manifest.json"), "w"), indent=1, sort_keys=True)
EOF
ln -sfn "$STAMP" "$SEALED_DIR/images/current"
log "guest $STAMP: $(du -h "$OUT/initrd.cpio.zst" | cut -f1) initrd, kernel $KVER, debug $DEBUG"
