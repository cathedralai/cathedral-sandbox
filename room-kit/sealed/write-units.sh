#!/bin/bash
# Write the systemd units of ONE sealed hotel from its sealed.env (AB#824):
#   room-sealed-<name>.service       host link + QEMU
#   room-sealed-<name>-net.service   host link check, and its every-minute timer
# Then daemon-reload. Never starts, stops or restarts anything, so it is safe on a
# live hotel: the unit text is host-side and not part of the measured guest.
# Used by install-sealed.sh (step 4), by a roll that only updates the units, and by the
# custom guest return (spec r9 11.6 R6).
#
# Host lock and hold marker (AB#999; spec r9 5.3, 5.10, host-lock.sh): run directly, this script
# takes the host lock; under a holder (install-sealed.sh, a roll, a custom guest phase) it checks
# the inherited lock instead. While a custom guest holds the hotel (SEALED_DIR/custom-guest.hold)
# it refuses, unless the caller is that launch's return phase. The kit unit's first ExecStartPre is
# the guard: any start while the marker says "held" fails, whoever asks for it (roll, conveyor, a
# person, a host boot). With no marker the guard passes and the unit behaves as before.
#
# After a host reboot the guest must come back by itself. On 19 Nov 2026 a SEV
# firmware upload at boot delayed kvm_amd about 14 s, every sealed unit started
# before /dev/kvm existed, QEMU failed "Could not access KVM" and, with Restart=no,
# the hotels stayed down 28 min. So the unit loads kvm_amd, waits up to 120 s for
# /dev/kvm, and restarts on failure (a clean stop or a guest poweroff exits 0 and
# is not restarted). dev-kvm.device is not tagged for systemd on these hosts, so
# the wait is an ExecStartPre, not an After=.
set -euo pipefail
ENV_FILE=$(readlink -f "${1:?usage: write-units.sh sealed.env}")
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ "${SEALED_NAME:-}" =~ ^[a-z0-9][a-z0-9-]{0,58}$ ]] || { echo "SEALED_NAME must match ^[a-z0-9][a-z0-9-]{0,58}$" >&2; exit 1; }
[ -n "${SEALED_DIR:-}" ] || { echo "SEALED_DIR is not set" >&2; exit 1; }
# The guard below names the marker inside a quoted sh -c line: no quote, space, $, % or backslash
# may reach it (systemd expands $ and % and unescapes backslashes in command lines).
[[ "$SEALED_DIR" =~ ^/[A-Za-z0-9/._-]*$ ]] || { echo "SEALED_DIR must be an absolute path of [A-Za-z0-9/._-]" >&2; exit 1; }
UNIT=room-sealed-$SEALED_NAME.service
# shellcheck disable=SC1091
source "$(dirname "$(readlink -f "$0")")/host-lock.sh"
snp_lock_take write-units write-units "$SEALED_NAME" - - || exit 1
trap snp_lock_release EXIT
if HOLD=$(snp_hold_marker "$SEALED_DIR"); then
  if [ "$SNP_LOCK_PHASE" = return-kit ] && [ "${HOLD#* }" != - ] && [ "${HOLD#* }" = "$SNP_LOCK_LAUNCH" ]; then
    echo "[sealed] custom guest ${HOLD#* } is returning the kit (marker ${HOLD%% *}): writing the units under its lock"
  else
    echo "custom_guest_held: launch=${HOLD#* } state=${HOLD%% *}: a custom guest holds $SEALED_NAME ($SEALED_DIR/custom-guest.hold); only that launch's return phase rewrites the units. Nothing was changed." >&2
    exit 1
  fi
fi
ETC=${ROOM_DESTDIR:-}/etc/systemd/system
mkdir -p "$ETC"
# The host link rules are set by ExecStartPre only; a host firewall reload
# (ufw) removes them and every room loses the internet while health stays
# green. A timer checks them each minute and puts them back.
cat > "$ETC/${UNIT%.service}-net.service" <<UNITEOF
[Unit]
Description=Sealed hotel $SEALED_NAME host link check
ConditionPathExists=$SEALED_DIR/sealed.env
[Service]
Type=oneshot
ExecStart=$SEALED_DIR/host-net.sh check $SEALED_DIR/sealed.env
UNITEOF
cat > "$ETC/${UNIT%.service}-net.timer" <<UNITEOF
[Unit]
Description=Sealed hotel $SEALED_NAME host link check (every minute)
[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
UNITEOF
cat > "$ETC/$UNIT" <<UNITEOF
[Unit]
Description=Sealed hotel $SEALED_NAME (AMD SEV-SNP guest with the room kit)
After=network-online.target systemd-modules-load.service
Wants=network-online.target
# At most 5 starts in 15 min, then the unit stays failed for a person to look at.
StartLimitIntervalSec=900
StartLimitBurst=5
[Service]
Type=simple
# Custom guest hold guard (spec r9 5.10): no start while the hold marker says held; none without it.
ExecStartPre=/bin/sh -c '[ ! -e $SEALED_DIR/custom-guest.hold ] || grep -q "[{,] *.state. *: *.kit_start." $SEALED_DIR/custom-guest.hold'
ExecStartPre=-/sbin/modprobe -q kvm_amd
ExecStartPre=/bin/sh -c 'for i in \$\$(seq 1 120); do [ -c /dev/kvm ] && exit 0; sleep 1; done; echo "no /dev/kvm after 120 s" >&2; exit 1'
ExecStartPre=$SEALED_DIR/host-net.sh up $SEALED_DIR/sealed.env
ExecStart=$SEALED_DIR/launch-guest.sh $SEALED_DIR/sealed.env
ExecStopPost=$SEALED_DIR/host-net.sh down $SEALED_DIR/sealed.env
KillSignal=SIGTERM
TimeoutStopSec=60
# The /dev/kvm wait alone may take 120 s; the default 90 s start timeout would cut it short.
TimeoutStartSec=180
Restart=on-failure
RestartSec=15
LimitMEMLOCK=infinity
[Install]
WantedBy=multi-user.target
UNITEOF
if [ -z "${ROOM_DESTDIR:-}" ]; then
  systemctl daemon-reload
fi
echo "[sealed] units written for $SEALED_NAME (no restart)"
