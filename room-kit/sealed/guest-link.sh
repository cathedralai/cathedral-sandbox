#!/bin/bash
# Runs INSIDE the sealed guest before the network (sealed-guard.service, AB#432).
# The link (host IP and guest IP of the hotel's /30) is per hotel, so it is not in
# the measured image: the host passes it in QEMU fw_cfg (opt/cathedral/link,
# "<host ip> <guest ip>"), and, for a guest-ingress build, the public port of its
# Preview URLs (opt/cathedral/ingress-public-port). Two hotels of one build on one host then share one
# measurement. This script checks the pair with the same rules the host used
# (guest-constants.sh, in the measured kit) and writes, under /run:
#   systemd/network/10-uplink.network   the static /30 and gateway
#   sealed-link/guard.nft               the uplink guard with the host IP
#   sealed-link/link.env                SEALED_LINK_HOST_IP, SEALED_LINK_GUEST_IP (and
#                                       SEALED_LINK_INGRESS_PUBLIC_PORT) for guest-boot.sh
#   sealed-link/sshd-listen.conf        ListenAddress for a debug build
# Then it loads the guard. A missing or bad link loads the guard WITHOUT the
# host-IP lines (the uplink takes nothing new), writes no address and exits 1;
# guest-boot.sh then refuses to install the hotel.
# The host could always choose what reaches the uplink; choosing the IP gives it
# nothing new. The measured parts stay: the guard rules, the ports, the checks.
set -euo pipefail
log() { echo "[sealed-link] $*"; }
FW=${SEALED_LINK_FW_CFG:-/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral/link/raw}
FW_PORT=${SEALED_LINK_FW_CFG_PORT:-/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral/ingress-public-port/raw}
GUARD=${SEALED_LINK_GUARD:-/etc/sealed-guard.nft}
ROOM_ENV=${SEALED_LINK_ROOM_ENV:-/opt/room-kit/room.env}
CONSTANTS=${SEALED_LINK_CONSTANTS:-/opt/room-kit/sealed/guest-constants.sh}
RUN=${SEALED_LINK_RUN:-/run}
NFT=${SEALED_LINK_NFT:-/usr/sbin/nft}
OUT=$RUN/sealed-link
mkdir -p "$OUT" "$RUN/systemd/network"

closed() {
  log "$1; uplink stays closed, the hotel will not start"
  grep -v '@SEALED_HOST_IP@' "$GUARD" > "$OUT/guard.nft"
  "$NFT" -f "$OUT/guard.nft"
  exit 1
}

for _ in $(seq 30); do [ -r "$FW" ] && break; sleep 1; done
[ -r "$FW" ] || closed "no link in fw_cfg (opt/cathedral/link)"
raw=$(head -c 64 "$FW")
[[ "$raw" =~ ^([0-9.]{7,15})\ ([0-9.]{7,15})$ ]] || closed "link in fw_cfg is not '<host ip> <guest ip>'"
host_ip=${BASH_REMATCH[1]} guest_ip=${BASH_REMATCH[2]}
# Same checks as on the host: one private /30, host first, no overlap with a
# network inside the guest (the room networks come from the measured room.env).
nets=$(sed -n 's/^ROOM_NETS="\(.*\)"$/\1/p' "$ROOM_ENV")
err=$(SEALED_HOST_IP=$host_ip SEALED_GUEST_IP=$guest_ip SEALED_ROOM_NETS=$nets \
  bash -c 'set -euo pipefail; unset SEALED_GUEST_MAC; source "$1"' _ "$CONSTANTS" 2>&1 >/dev/null) \
  || closed "link $host_ip $guest_ip refused: ${err:-check failed}"
port_line=""
if grep -q '^ROOM_INGRESS_ZONE=.' "$ROOM_ENV"; then
  [ -r "$FW_PORT" ] || closed "guest ingress build, no public port in fw_cfg (opt/cathedral/ingress-public-port)"
  port=$(head -c 16 "$FW_PORT")
  { [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$port" -le 65535 ]; } || closed "ingress public port in fw_cfg is not a TCP port"
  port_line="SEALED_LINK_INGRESS_PUBLIC_PORT=$port"
fi

cat > "$RUN/systemd/network/10-uplink.network" <<EOF
[Match]
Name=uplink
[Network]
Address=$guest_ip/30
Gateway=$host_ip
LinkLocalAddressing=no
IPv6AcceptRA=no
EOF
sed "s/@SEALED_HOST_IP@/$host_ip/g" "$GUARD" > "$OUT/guard.nft"
{ printf 'SEALED_LINK_HOST_IP=%s\nSEALED_LINK_GUEST_IP=%s\n' "$host_ip" "$guest_ip"
  [ -z "$port_line" ] || printf '%s\n' "$port_line"; } > "$OUT/link.env"
printf 'ListenAddress %s\n' "$guest_ip" > "$OUT/sshd-listen.conf"
"$NFT" -f "$OUT/guard.nft"
log "link $host_ip/30 -> guest $guest_ip${port_line:+, ingress public port ${port_line#*=}}"
