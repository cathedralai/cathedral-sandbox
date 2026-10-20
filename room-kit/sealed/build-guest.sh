#!/bin/bash
# Build the sealed guest: one kernel, one initrd that holds the WHOLE root file
# system (Ubuntu minbase + Docker + the room kit), and one kernel command line.
# OVMF (AmdSev build) hashes all three into the SNP launch measurement, so the
# measurement covers every file the guest boots from. Nothing is read from an
# unmeasured root disk. The only disk is the scratch disk, which the guest
# encrypts with a key it makes at boot.
#
# Usage: build-guest.sh sealed.env   (run as root on the host)
# Output: $SEALED_DIR/images/<stamp>/{vmlinuz,initrd.cpio.zst,cmdline,manifest.json}
#         and the symlink $SEALED_DIR/images/current.
set -euo pipefail
umask 022
KIT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1090
source "$(readlink -f "${1:?usage: build-guest.sh sealed.env}")"
log() { echo "[sealed-build] $*"; }

B=$SEALED_DIR/build
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$SEALED_DIR/images/$STAMP
mkdir -p "$B" "$OUT"

# ---------------------------------------------------------------- 1. base root file system (cached)
PKGS=systemd,systemd-sysv,udev,kmod,iproute2,nftables,iptables,docker.io,containerd,xfsprogs,cryptsetup-bin,curl,ca-certificates,bzip2,python3,procps,util-linux,iputils-ping,linux-image-virtual,openssh-server,less,tar,gzip,zstd,passwd,dmsetup
BASE_ID=$(echo "$SEALED_SUITE $SEALED_MIRROR $PKGS" | sha256sum | cut -c1-12)
if [ ! -d "$B/base-$BASE_ID" ]; then
  log "mmdebstrap $SEALED_SUITE (base $BASE_ID)"
  rm -rf "$B/base-$BASE_ID.tmp"
  mmdebstrap --variant=minbase --aptopt='APT::Install-Recommends "false"' --components=main,universe \
    --include="$PKGS" "$SEALED_SUITE" "$B/base-$BASE_ID.tmp" "$SEALED_MIRROR"
  mv "$B/base-$BASE_ID.tmp" "$B/base-$BASE_ID"
fi
R=$B/rootfs
rm -rf "$R"
cp -a "$B/base-$BASE_ID" "$R"

# ---------------------------------------------------------------- 2. kernel out, boot files gone
KVER=$(ls "$R/lib/modules" | sort -V | tail -1)
install -m 0644 "$R/boot/vmlinuz-$KVER" "$OUT/vmlinuz"
rm -rf "${R:?}/boot"/* "$R/var/cache/apt/archives"/*.deb "$R/var/lib/apt/lists"/* 2>/dev/null || true

# ---------------------------------------------------------------- 3. guest configuration
ln -sfn usr/lib/systemd/systemd "$R/init"
echo "room-$SEALED_NAME" > "$R/etc/hostname"
: > "$R/etc/machine-id"
: > "$R/etc/fstab"
rm -f "$R/etc/resolv.conf"
for d in $SEALED_DNS; do echo "nameserver $d"; done > "$R/etc/resolv.conf"

cat > "$R/etc/systemd/network/10-uplink.link" <<EOF
[Match]
MACAddress=$SEALED_GUEST_MAC
[Link]
Name=uplink
EOF
cat > "$R/etc/systemd/network/10-uplink.network" <<EOF
[Match]
Name=uplink
[Network]
Address=$SEALED_GUEST_IP/30
Gateway=$SEALED_HOST_IP
LinkLocalAddressing=no
IPv6AcceptRA=no
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

DEBUG=0; [ -n "${SEALED_DEBUG_SSH_PUBKEY:-}" ] && DEBUG=1
# Guest firewall on the uplink: replies, the hotel API from the host, nothing else.
SSH_RULE=""; [ $DEBUG = 1 ] && SSH_RULE="iifname \"uplink\" ip saddr $SEALED_HOST_IP tcp dport 22 accept"
cat > "$R/etc/sealed-guard.nft" <<EOF
table inet sealed_guard {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "uplink" ct state established,related accept
    iifname "uplink" ip saddr $SEALED_HOST_IP tcp dport 18090 accept
    $SSH_RULE
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
ExecStart=/usr/sbin/nft -f /etc/sealed-guard.nft
[Install]
WantedBy=sysinit.target
EOF

install -m 0755 "$KIT/sealed/guest-boot.sh" "$R/usr/local/sbin/sealed-hotel-boot.sh"
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
tar -C "$KIT" --exclude=./sealed/work -cf - . | tar -C "$R/opt/room-kit" -xf -
{ cat "$KIT/KIT_COMMIT" 2>/dev/null || ( cd "$KIT" && git rev-parse HEAD 2>/dev/null ) || echo unknown; } > "$R/opt/room-kit/KIT_COMMIT"
cat > "$R/opt/room-kit/room.env" <<EOF
# Sealed hotel $SEALED_NAME: written by sealed/build-guest.sh, part of the measured initrd.
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
ROOM_REGISTRY_MIRRORS="https://mirror.gcr.io"
ROOM_DATA_DIR=/srv/room-sealed
ROOM_DATA_DEVICE=/dev/mapper/sealed-scratch
ROOM_DATA_DEVICE_WIPE=yes
ROOM_DATA_IMG=
ROOM_DATA_SIZE_GB=0
ROOM_BRIDGE=rmbr0
ROOM_BRIDGE_CIDR=10.213.0.1/21
ROOM_DNS="$SEALED_DNS"
ROOM_RUNSC_FLAGS="--platform=systrap --overlay2=none --net-raw"
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
ROOM_CREATES_PER_MINUTE=6000
ROOM_GC_PARALLELISM=16
ROOM_DIND_DOCKERD_ARGS="--iptables=false --ip6tables=false --bridge=none --default-network-opt bridge=com.docker.network.advertise_addr_nmsgs=0 --default-address-pool base=10.200.0.0/14,size=24"
ROOM_DIND_ENV="PATH=/usr/local/sbin/.iptables-legacy:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ROOM_NETS="$SEALED_ROOM_NETS"
ROOM_NET_SIZE=1000
ROOM_NET_BRIDGE_PREFIX=rmnet
ROOM_RECEIPTS=1
ROOM_RECEIPTS_LISTEN=$SEALED_GUEST_IP:18090
ROOM_HOTEL_NAME=$SEALED_NAME
EOF

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
  printf 'ListenAddress %s\nPasswordAuthentication no\nPermitRootLogin prohibit-password\n' "$SEALED_GUEST_IP" \
    > "$R/etc/ssh/sshd_config.d/10-sealed-debug.conf"
  mkdir -p "$R/etc/systemd/system/ssh.service.d"
  printf '[Service]\nExecStartPre=/usr/bin/ssh-keygen -A\n' > "$R/etc/systemd/system/ssh.service.d/10-hostkeys.conf"
  in_root systemctl enable -q ssh.service
else
  in_root systemctl mask -q ssh.service ssh.socket 2>/dev/null || true
  rm -f "$R"/etc/ssh/ssh_host_*
fi
# Host keys made at build time would be in the measured initrd; make them at boot instead.
rm -f "$R"/etc/ssh/ssh_host_*

# ---------------------------------------------------------------- 4. initrd = whole root, cmdline
log "packing initrd"
( cd "$R" && find . -mindepth 1 \( -path './proc/*' -o -path './sys/*' -o -path './dev/*' \) -prune -o -print0 \
  | LC_ALL=C sort -z | cpio --null -o -H newc --reproducible --quiet ) | zstd -q -T0 -10 > "$OUT/initrd.cpio.zst"
CMDLINE="console=ttyS0 loglevel=7 systemd.show_status=error panic=-1 rdinit=/init cathedral.hotel=$SEALED_NAME cathedral.debug=$DEBUG"
printf '%s' "$CMDLINE" > "$OUT/cmdline"
install -m 0644 "$SEALED_OVMF" "$OUT/OVMF.amdsev.fd"

python3 - "$OUT" "$SEALED_NAME" "$SEALED_VCPUS" "$SEALED_CPU_MODEL" "$KVER" "$DEBUG" "$BASE_ID" <<'EOF'
import hashlib, json, os, sys
out, name, vcpus, cpu, kver, debug, base = sys.argv[1:]
def sha(p):
    h = hashlib.sha256()
    with open(os.path.join(out, p), "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
m = {"schema": "cathedral_sealed_hotel_guest_v1", "hotel": name, "vcpus": int(vcpus), "cpu_model": cpu,
     "kernel_release": kver, "debug": debug == "1", "base_rootfs": base,
     "cmdline": open(os.path.join(out, "cmdline")).read(),
     "sha256": {p: sha(p) for p in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst", "cmdline")},
     "bytes": {p: os.path.getsize(os.path.join(out, p)) for p in ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst")}}
json.dump(m, open(os.path.join(out, "manifest.json"), "w"), indent=1, sort_keys=True)
EOF
ln -sfn "$STAMP" "$SEALED_DIR/images/current"
log "guest $STAMP: $(du -h "$OUT/initrd.cpio.zst" | cut -f1) initrd, kernel $KVER, debug $DEBUG"
