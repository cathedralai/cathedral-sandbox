#!/bin/bash
# Boot a REHEARSAL-ONLY root under plain QEMU (no SNP) and check its systemd over SSH
# (AB#1008, AB#1027). The static check (check_stock_root.py) cannot see boot-time waits, such
# as networkd leaving a link pending udev; this boot can.
#
# A test-only shim initrd (busybox) stands in for reference initrd v2's hand-off, as far as
# the root can see it:
# - the squashfs root, read-only, from the first virtio disk (no dm-verity: this tests the
#   root's userland, not the initrd);
# - /run a tmpfs with nosuid, nodev and noexec, and /run/cathedral 0700 holding the four 0600
#   files the measured init writes (throwaway keys; network.env for QEMU's user network);
# - /proc and /sys left for systemd to mount read-write, as v2 leaves them.
# cathedral-init's own verity mount and hand-off are proven live, not here.
#
# Usage: boot-smoke.sh VMLINUZ ROOT_RAW VARIANT NEW_WORK_DIR
#   VARIANT stock-systemd: dbus, udevd, networkd and cathedral-sshd active, eth0 routable and
#     configured with network.env's address.
#   VARIANT v1 (negative control): SSH answers (its ip unit), dbus and networkd are not active.
# Needs qemu-system-x86_64, busybox (static), cpio, ssh and ssh-keygen. Never on a hotel host.
set -euo pipefail
kernel=$(readlink -f "${1:?vmlinuz}")
image=$(readlink -f "${2:?root.raw}")
variant=${3:?v1 or stock-systemd}
work=$(readlink -m "${4:?new work directory}")
case "$variant" in v1|stock-systemd) ;; *) echo "variant is v1 or stock-systemd" >&2; exit 1 ;; esac
[ ! -e "$work" ] || { echo "$work exists" >&2; exit 1; }
busybox=$(command -v busybox)
file -L "$busybox" | grep -q 'statically linked' || { echo "$busybox is not static" >&2; exit 1; }

# QEMU's user network defaults: the guest is 10.0.2.15/24, the gateway 10.0.2.2.
GUEST_CIDR=10.0.2.15/24
GATEWAY=10.0.2.2
PORT=${SMOKE_SSH_PORT:-2222}

mkdir -p "$work/shim/bin" "$work/shim/dev" "$work/shim/proc" "$work/shim/sys" "$work/shim/newroot" "$work/shim/keys"
cp "$busybox" "$work/shim/bin/busybox"
ssh-keygen -q -t ed25519 -N '' -C smoke-client -f "$work/client"
ssh-keygen -q -t ed25519 -N '' -C smoke-host -f "$work/shim/keys/ssh_host_ed25519_key"
cp "$work/client.pub" "$work/shim/keys/authorized_keys"
printf 'CATHEDRAL_INTERFACE=eth0\nCATHEDRAL_GUEST_CIDR=%s\nCATHEDRAL_GATEWAY=%s\n' "$GUEST_CIDR" "$GATEWAY" > "$work/shim/keys/network.env"
printf '[127.0.0.1]:%s %s\n' "$PORT" "$(cut -d ' ' -f 1,2 "$work/shim/keys/ssh_host_ed25519_key.pub")" > "$work/known_hosts"
cat > "$work/shim/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t squashfs -o ro /dev/vda /newroot || { echo "SMOKE-SHIM: no squashfs root on /dev/vda"; poweroff -f; }
mount -t tmpfs -o nosuid,nodev,noexec,mode=0755 tmpfs /newroot/run
mkdir -m 0700 /newroot/run/cathedral
for f in ssh_host_ed25519_key ssh_host_ed25519_key.pub authorized_keys network.env; do
  cp /keys/$f /newroot/run/cathedral/$f
  chmod 0600 /newroot/run/cathedral/$f
done
umount /proc
mount --move /dev /newroot/dev
echo "SMOKE-SHIM: switch_root to /sbin/init"
exec switch_root /newroot /sbin/init
EOF
chmod 0755 "$work/shim/init"
(cd "$work/shim" && find . | LC_ALL=C sort | cpio --quiet -o -H newc -R 0:0) > "$work/shim.cpio"

accel=(-accel tcg -cpu max)
if [ -e /dev/kvm ] && [ -w /dev/kvm ]; then accel=(-accel kvm -cpu host); fi
echo "accelerator: ${accel[*]}"
timeout 900 qemu-system-x86_64 -machine q35 -m 2048 -smp 2 "${accel[@]}" -nodefaults -no-reboot -display none \
  -serial "file:$work/serial.log" -kernel "$kernel" -initrd "$work/shim.cpio" \
  -append "console=ttyS0 panic=-1 rdinit=/init systemd.show_status=1" \
  -drive "file=$image,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" -device virtio-net-pci,netdev=n0 &
qemu=$!
trap 'kill "$qemu" 2>/dev/null || true; tr -d "\r" < "$work/serial.log" | tail -n 80 || true' EXIT

guest() {
  ssh -q -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$work/known_hosts" \
    -i "$work/client" -p "$PORT" root@127.0.0.1 "$@"
}
deadline=$((SECONDS + 600))
until guest true 2>/dev/null; do
  kill -0 "$qemu" 2>/dev/null || { echo "SMOKE: FAIL the guest stopped before SSH answered" >&2; exit 1; }
  [ "$SECONDS" -lt "$deadline" ] || { echo "SMOKE: FAIL no SSH within 600 s" >&2; exit 1; }
  sleep 5
done
echo "SMOKE: SSH answered after ${SECONDS} s (the host key is the one /run/cathedral holds)"

# Let the boot settle, then read the units, the link and the address.
guest 'timeout 180 systemctl is-system-running --wait >/dev/null 2>&1 || true' || true
for unit in dbus.service systemd-udevd.service systemd-networkd.service cathedral-sshd.service; do
  printf '%s %s\n' "$unit" "$(guest systemctl is-active "$unit" || true)"
done | tee "$work/active.txt"
guest 'networkctl status eth0 --no-pager 2>&1 || true' | tee "$work/networkctl.txt"
guest 'ip -4 -o address show dev eth0' | tee "$work/address.txt"
guest 'systemctl --failed --no-legend --plain || true' | tee "$work/failed.txt"
guest 'systemctl is-system-running || true' | tee "$work/system-state.txt"

active() { grep -qx "$1 active" "$work/active.txt"; }
fails=0
fail() { echo "SMOKE: FAIL $*"; fails=$((fails + 1)); }
if [ "$variant" = stock-systemd ]; then
  for unit in dbus.service systemd-udevd.service systemd-networkd.service cathedral-sshd.service; do
    active "$unit" || fail "$unit is not active"
  done
  grep -Eq 'State: routable \(configured\)' "$work/networkctl.txt" || fail "eth0 is not routable (configured)"
  grep -q "inet $GUEST_CIDR " "$work/address.txt" || fail "eth0 does not have $GUEST_CIDR"
  [ "$fails" = 0 ] && echo "SMOKE: PASS stock-systemd: dbus, udevd, networkd and cathedral-sshd active; eth0 routable (configured) with $GUEST_CIDR"
else
  active cathedral-sshd.service || fail "cathedral-sshd.service is not active"
  active dbus.service && fail "dbus.service is active on the v1 root"
  active systemd-networkd.service && fail "systemd-networkd.service is active on the v1 root"
  [ "$fails" = 0 ] && echo "SMOKE: PASS v1 (negative control): SSH answers through its ip unit; dbus and networkd not active"
fi
[ "$fails" = 0 ]
