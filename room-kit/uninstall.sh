#!/bin/bash
# Room kit uninstaller. Run as root: ./uninstall.sh [--keep-runtime] [--keep-data]
# Removes what install.sh added: room units, room containers and images, the
# room daemon, its bridge and iptables rules, the data volume, Caddy, Python,
# the service user and /etc/pool-room. The host Docker daemon is not touched.
# --keep-runtime keeps /opt/pool-room/gvisor* (runsc).
# --keep-data keeps the loop image file (the volume is still unmounted).
set -uo pipefail
KEEP_RUNTIME=0; KEEP_DATA=0
for a in "$@"; do case $a in --keep-runtime) KEEP_RUNTIME=1;; --keep-data) KEEP_DATA=1;; esac; done
ROOM_ETC=/etc/pool-room; ROOM_OPT=/opt/pool-room; SOCK=/run/pool-room/docker.sock
[ -f $ROOM_ETC/room.env ] || { echo "no room installed ($ROOM_ETC/room.env missing)"; exit 0; }
# shellcheck disable=SC1091
source $ROOM_ETC/room.env
STATE=$ROOM_ETC/install-state
log() { echo "[room-kit] $*"; }

# One unit at a time: a unit that is missing (e.g. Caddy with ROOM_TLS=off) must not stop the others.
for u in "$ROOM_ID-receipts.service" "$ROOM_ID-reaper.timer" "$ROOM_ID-caddy.service" "$ROOM_ID-health.service" "$ROOM_ID.service"; do
  systemctl disable --now "$u" 2>/dev/null || systemctl stop "$u" 2>/dev/null || true
done
if [ -S $SOCK ]; then
  ids=$(docker -H unix://$SOCK ps -aq)
  [ -z "$ids" ] || docker -H unix://$SOCK rm -f $ids >/dev/null
  log "removed $(echo $ids | wc -w) room containers"
fi
systemctl disable --now "$ROOM_ID-docker.service" 2>/dev/null
$ROOM_OPT/bin/room-net.sh down $ROOM_ETC/room.env 2>/dev/null || true
# The containerd namespace of the room daemon (metadata only).
if command -v ctr >/dev/null; then
  for ns in "pool-room-$ROOM_ID" "pool-room-$ROOM_ID-plugins"; do
    for c in $(ctr -n "$ns" containers ls -q 2>/dev/null); do ctr -n "$ns" containers rm "$c" >/dev/null 2>&1; done
    for i in $(ctr -n "$ns" images ls -q 2>/dev/null); do ctr -n "$ns" images rm "$i" >/dev/null 2>&1; done
    for l in $(ctr -n "$ns" leases ls -q 2>/dev/null); do ctr -n "$ns" leases rm "$l" >/dev/null 2>&1; done
    for c in $(ctr -n "$ns" content ls -q 2>/dev/null); do ctr -n "$ns" content rm "$c" >/dev/null 2>&1; done
    ctr namespaces rm "$ns" >/dev/null 2>&1 || true
  done
fi
systemctl disable --now "$ROOM_ID-data.service" 2>/dev/null
if mountpoint -q "$ROOM_DATA_DIR"; then umount "$ROOM_DATA_DIR"; fi
if [ -z "${ROOM_DATA_DEVICE:-}" ]; then
  for d in $(losetup -j "$ROOM_DATA_IMG" | cut -d: -f1); do losetup -d "$d"; done
  if [ $KEEP_DATA = 0 ] && grep -qxF "file:$ROOM_DATA_IMG" "$STATE"; then rm -f "$ROOM_DATA_IMG"; log "deleted $ROOM_DATA_IMG"; fi
fi
rmdir "$ROOM_DATA_DIR" 2>/dev/null || true
for u in "$ROOM_ID-receipts.service" "$ROOM_ID.service" "$ROOM_ID-health.service" "$ROOM_ID-caddy.service" "$ROOM_ID-reaper.service" "$ROOM_ID-reaper.timer" "$ROOM_ID-docker.service" "$ROOM_ID-data.service"; do
  rm -f "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true
grep -q '^ufw:' "$STATE" 2>/dev/null && ufw delete allow "$ROOM_PUBLIC_PORT/tcp" >/dev/null
grep -q '^iptables:' "$STATE" 2>/dev/null && iptables -D INPUT -p tcp --dport "$ROOM_PUBLIC_PORT" -j ACCEPT -m comment --comment "pool-room:$ROOM_ID" 2>/dev/null
grep -q '^masked:docker' "$STATE" 2>/dev/null && systemctl unmask docker.service docker.socket >/dev/null 2>&1
grep -q '^user:poolroom' "$STATE" 2>/dev/null && userdel poolroom 2>/dev/null
# dockerd leaves an nsfs bind mount under its exec root; unmount before delete.
for m in $(grep " /run/pool-room" /proc/mounts | cut -d" " -f2 | sort -r); do umount "$m" 2>/dev/null; done
rm -rf /var/lib/pool-room /var/lib/private/pool-room-caddy /var/lib/pool-room-caddy /run/pool-room
if [ $KEEP_RUNTIME = 1 ]; then
  find $ROOM_OPT -mindepth 1 -maxdepth 1 ! -name 'gvisor*' -exec rm -rf {} +
  log "kept $ROOM_OPT/gvisor (runsc)"
else
  rm -rf $ROOM_OPT
fi
rm -rf $ROOM_ETC
log "apt packages added by install (left in place): $(grep '^apt:' "$STATE" 2>/dev/null | tr '\n' ' ')"
log "uninstalled room $ROOM_ID"
