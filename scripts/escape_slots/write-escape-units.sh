#!/bin/bash
# Wire ONE AB#683 fresh slot on its host, beside the units of
# room-kit/sealed/write-units.sh:
#   room-sealed-<name>-escape.service              the #496 supervisor (stop, confirm
#                                                  QEMU gone, delete scratch, relaunch
#                                                  on a new REPORT_ID)
#   room-sealed-<name>-net.service.d/50-escape-retire.conf
#                                                  the broker retire channel, run by
#                                                  the existing every-minute link check
# Then daemon-reload. Never starts, stops, enables or restarts anything: the
# roll enables room-sealed-<name>-escape.service after the slot is drained.
#
# The retire channel is the net-check unit's (leader decision on AB#683, card
# comment 33000587): no new host agent and no new port. The host calls the
# broker's own listener with the slot's hotel key (GET and POST
# /v1/broker/hotels/<name>/escape-retire); the broker never connects to the
# host. A drop-in, so the measured guest kit (room-kit/, copied into the
# initrd by build-guest.sh) is unchanged and the guest measurement stays.
#
# sealed.env of a fresh slot must also set:
#   SEALED_ESCAPE_SLOT=1
#   SEALED_BROKER_URL=https://<the broker this slot is joined to>
# and on a guest TLS slot (SEALED_MINER=1):
#   SEALED_API_KEY_FILE=<root-only copy of the broker's hotel key for this slot>
set -euo pipefail
ENV_FILE=$(readlink -f "${1:?usage: write-escape-units.sh sealed.env}")
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ "${SEALED_NAME:-}" =~ ^[a-z0-9][a-z0-9-]{0,58}$ ]] || { echo "SEALED_NAME must match ^[a-z0-9][a-z0-9-]{0,58}$" >&2; exit 1; }
[ -n "${SEALED_DIR:-}" ] || { echo "SEALED_DIR is not set" >&2; exit 1; }
[ "${SEALED_ESCAPE_SLOT:-0}" = 1 ] || { echo "SEALED_ESCAPE_SLOT=1 is not set: not a fresh slot, nothing written" >&2; exit 1; }
[[ "${SEALED_BROKER_URL:-}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "SEALED_BROKER_URL must be an https origin" >&2; exit 1; }
# A guest TLS slot (SEALED_MINER=1) gets its hotel key only from the broker, in
# the guest. The host half needs a copy of that key in SEALED_API_KEY_FILE: the
# supervisor reads the guest's TLS port with it and the retire channel signs in
# to the broker with it.
case "${SEALED_MINER:-0}" in
  0) ;;
  1) [ -n "${SEALED_API_KEY_FILE:-}" ] && [ -s "${ROOM_DESTDIR:-}$SEALED_API_KEY_FILE" ] || {
       echo "SEALED_MINER=1 slot needs SEALED_API_KEY_FILE: a copy of the broker's hotel key for $SEALED_NAME" >&2; exit 1; } ;;
  *) echo "SEALED_MINER must be 0 or 1 on a fresh slot" >&2; exit 1 ;;
esac
[ "${SEALED_DATA_GIB:-0}" = 0 ] || { echo "SEALED_DATA_GIB must be 0 on a fresh slot: a data volume outlives the guest" >&2; exit 1; }
UNIT=room-sealed-$SEALED_NAME
ETC=${ROOM_DESTDIR:-}/etc/systemd/system
TOOL_DIR=$SEALED_DIR/escape-slot
TOOL=$TOOL_DIR/supervise_escape_slot.py
install -d -m 0700 "${ROOM_DESTDIR:-}$TOOL_DIR"
install -m 0755 "$HERE/supervise_escape_slot.py" "${ROOM_DESTDIR:-}$TOOL"
mkdir -p "$ETC/$UNIT-net.service.d"
# ExecStartPre with "-": the channel runs first each minute and its failure
# never stops the link check. It waits up to 150 s for the supervisor's stop.
cat > "$ETC/$UNIT-net.service.d/50-escape-retire.conf" <<UNITEOF
# AB#683 fresh slot: broker retire channel (write-escape-units.sh)
[Service]
ExecStartPre=-/usr/bin/python3 -I $TOOL --sealed-env $SEALED_DIR/sealed.env --retire-channel
TimeoutStartSec=300
UNITEOF
cat > "$ETC/$UNIT-escape.service" <<UNITEOF
[Unit]
Description=Escape fresh slot $SEALED_NAME supervisor (AB#683, #496)
After=$UNIT.service
ConditionPathExists=$SEALED_DIR/sealed.env
[Service]
Type=simple
# The live gate of supervise_escape_slot.py: set only in this unit, which the
# roll enables once the slot is drained and the owner agreed.
Environment=CATHEDRAL_ESCAPE_SLOT_LIVE_OK=yes
ExecStart=/usr/bin/python3 -I $TOOL --sealed-env $SEALED_DIR/sealed.env
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNITEOF
if [ -z "${ROOM_DESTDIR:-}" ]; then
  systemctl daemon-reload
fi
echo "[escape-slot] units written for $SEALED_NAME (no start)"
