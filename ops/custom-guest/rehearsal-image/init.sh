#!/bin/sh
# /init of the REHEARSAL-ONLY test initrd for the dedicated custom SNP guest
# (AB#1008, rehearsal B). Never offered to customers. It does not switch_root: sshd
# runs from the initrd. It boots the #776 reference kernel, which has every driver
# built in (no modules), so nothing here loads a module.
# Order (spec-r9 5.6 and 8.7): documents and HOST_DATA first, then network, then sshd.
# Any failure powers the guest off; with -no-reboot QEMU then exits.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
# The initramfs root starts as mode 1777, and sshd StrictModes refuses keys under
# a world-writable "/" (first rehearsal boot, 27 Nov 11:04Z). The cpio "." entry sets
# 0755 too; this keeps the guest right if an archive ever lacks that entry.
chown 0:0 /
chmod 0755 /

mount -t devtmpfs -o mode=0755,nosuid devtmpfs /dev
exec </dev/console >/dev/console 2>&1
log() { echo "rehearsal-init: $*"; }
fail() {
  log "FAIL: $*"
  log "powering off"
  sync
  poweroff -f
  echo o > /proc/sysrq-trigger
  exit 1
}

mount -t proc -o nosuid,nodev,noexec proc /proc || fail "mount proc"
mount -t sysfs -o nosuid,nodev,noexec sysfs /sys || fail "mount sysfs"
mkdir -p /dev/pts /run /tmp
mount -t devpts -o mode=0620,ptmxmode=0666,nosuid,noexec devpts /dev/pts || fail "mount devpts"
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run || fail "mount /run"
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /tmp || fail "mount /tmp"
log "REHEARSAL-ONLY test image, not for customers; kernel $(uname -r)"
log "root $(ls -ldn /)"

# The reference kernel has TSM_REPORTS, SEV_GUEST, FW_CFG_SYSFS and configfs built in.
mount -t configfs configfs /sys/kernel/config 2>/dev/null || true
# Root-only reports (spec-r9 5.6 step 2).
chmod 0700 /sys/kernel/config 2>/dev/null || true

FW=/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral
i=0
while [ ! -r "$FW/bootstrap.sig/raw" ]; do
  i=$((i + 1)); [ $i -le 20 ] || fail "fw_cfg launch documents missing"; sleep 1
done

# 8.7 items 1, 2, 4: documents, signature, cmdline owner, guest-observed state.
/usr/lib/cathedral/cathedral-rehearsal-bootcheck > /run/rehearsal-boot.env || fail "launch documents refused"
# shellcheck disable=SC1091
. /run/rehearsal-boot.env
log "documents ok: launch $SMOKE_LAUNCH_ID, expected HOST_DATA $SMOKE_HOST_DATA"

# The built-in sev-guest driver makes /dev/sev-guest only in an SEV-SNP guest.
i=0
while [ ! -c /dev/sev-guest ]; do
  i=$((i + 1)); [ $i -le 20 ] || fail "no /dev/sev-guest: not an SEV-SNP guest"; sleep 1
done
chown 0:0 /dev/sev-guest && chmod 0600 /dev/sev-guest || fail "chmod /dev/sev-guest"
# 8.7 item 3: HOST_DATA in a native report under the boot-check tag (#776).
/usr/lib/cathedral/cathedral-attest --boot-host-data "$SMOKE_HOST_DATA" > /run/rehearsal-bootcheck.json \
  || { cat /run/rehearsal-bootcheck.json; fail "HOST_DATA check"; }
grep -q '"local_boot_binding":"checked"' /run/rehearsal-bootcheck.json || fail "HOST_DATA check not confirmed"
log "launch $SMOKE_LAUNCH_ID on $SMOKE_HOTEL: documents, owner signature and HOST_DATA $SMOKE_HOST_DATA checked"

hostname "rehearsal-$SMOKE_LAUNCH_ID"
ip link set lo up || fail "lo up"
ip link set "$SMOKE_IFACE" up || fail "link up"
ip addr add "$SMOKE_GUEST_IP/$SMOKE_PREFIX" dev "$SMOKE_IFACE" || fail "address"
ip route add default via "$SMOKE_HOST_IP" dev "$SMOKE_IFACE" || fail "route"
log "network $SMOKE_IFACE $SMOKE_GUEST_IP/$SMOKE_PREFIX via $SMOKE_HOST_IP"

# SSH host key: one ed25519 key, made now in RAM (spec-r9 5.6 step 5).
ssh-keygen -q -t ed25519 -N '' -C "rehearsal-$SMOKE_LAUNCH_ID" -f /run/cathedral/ssh_host_ed25519_key || fail "host key"
chmod 0600 /run/cathedral/ssh_host_ed25519_key
chmod 0644 /run/cathedral/ssh_host_ed25519_key.pub
log "ssh host key $(ssh-keygen -l -f /run/cathedral/ssh_host_ed25519_key.pub)"
/usr/sbin/sshd -t -f /etc/ssh/sshd_config || fail "sshd config"

# PID 1 stays here: run sshd in the foreground and restart it if it exits.
while :; do
  log "sshd listening on $SMOKE_GUEST_IP:22"
  /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
  log "sshd exited with $?; restarting in 2 s"
  sleep 2
done
