#!/bin/bash
# Room data volume. Usage: room-data.sh up|down /etc/pool-room/room.env
# xfs with project quota (Docker --storage-opt size=), mounted WITHOUT nodev
# (Docker disables overlay2 quota on a nodev mount).
# With ROOM_WORKSPACES=1, $ROOM_DATA_DIR/workspaces is a bind mount of itself
# with nosuid,nodev,noexec (#305). Rooms write there; the host never runs or
# opens a device from it. The API refuses workspaces without these options.
# ROOM_WORKSPACES_SOURCE: bind that directory instead, when it is on a mount of
# its own (a sealed guest's persistent data volume). When it is missing or on
# the root file system, workspaces stay on the data volume, as without it.
set -euo pipefail
# shellcheck disable=SC1090
source "${2:?room.env}"
case "${1:?up|down}" in
  up)
    mkdir -p "$ROOM_DATA_DIR"
    if ! mountpoint -q "$ROOM_DATA_DIR"; then
      if [ -n "${ROOM_DATA_DEVICE:-}" ]; then
        SRC=$ROOM_DATA_DEVICE
      else
        SRC=$(losetup -j "$ROOM_DATA_IMG" | cut -d: -f1 | head -1)
        [ -n "$SRC" ] || SRC=$(losetup --direct-io=on --show -f "$ROOM_DATA_IMG")
      fi
      mount -o prjquota,noatime "$SRC" "$ROOM_DATA_DIR"
    fi
    if [ "${ROOM_WORKSPACES:-0}" = 1 ]; then
      WS=$ROOM_DATA_DIR/workspaces
      mkdir -p "$WS"
      SRC=${ROOM_WORKSPACES_SOURCE:-}
      if [ -n "$SRC" ] && { [ ! -d "$SRC" ] || [ "$(findmnt -n -o TARGET --target "$SRC")" = / ]; }; then
        echo "room-data: $SRC is not on a volume of its own; workspaces stay on $ROOM_DATA_DIR" >&2
        SRC=""
      fi
      mountpoint -q "$WS" || mount --bind "${SRC:-$WS}" "$WS"
      mount -o remount,bind,nosuid,nodev,noexec "$WS"
    fi
    ;;
  down)
    if mountpoint -q "$ROOM_DATA_DIR/workspaces"; then umount "$ROOM_DATA_DIR/workspaces"; fi
    if mountpoint -q "$ROOM_DATA_DIR"; then umount "$ROOM_DATA_DIR"; fi
    if [ -z "${ROOM_DATA_DEVICE:-}" ]; then
      for d in $(losetup -j "$ROOM_DATA_IMG" | cut -d: -f1); do losetup -d "$d"; done
    fi
    ;;
esac
