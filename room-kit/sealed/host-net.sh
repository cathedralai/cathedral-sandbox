#!/bin/bash
# Host side of the sealed guest link. Usage: host-net.sh up|down|check|clash sealed.env
# A tap device with a /30, NAT to the internet for the guest, and nothing else:
# - the guest cannot reach private ranges or this host's services,
# - nothing on the host side (other bridges, containers) can open a connection
#   into the guest; only this host (the broker) reaches the hotel API port.
# Own chains only (SEALED-<TAP>-FWD, SEALED-<TAP>-IN, one MASQUERADE rule).
# Miner hotel (SEALED_MINER=1): one more way in, SEALED_MINER_PUBLIC_PORT on
# this host forwarded (DNAT) to the guest's attested HTTPS port, and nothing
# else. TLS ends inside the guest; this host only moves the bytes.
set -euo pipefail
# shellcheck disable=SC1090
source "${2:?sealed.env}"
# A bad link stops every action but "down", which must still remove the tap.
# shellcheck disable=SC1091
source "$(dirname "$(readlink -f "$0")")/guest-constants.sh" || [ "${1:-}" = down ] || exit 1
ENV=$2
TAP=$SEALED_TAP
FWD=SEALED-${TAP^^}-FWD
IN=SEALED-${TAP^^}-IN
TAG="sealed-hotel:$SEALED_NAME"
PRIVATE="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16"
MINER=${SEALED_MINER:-0}
TLS_PORT=${SEALED_MINER_TLS_PORT:-18443}
PUBLIC_PORT=${SEALED_MINER_PUBLIC_PORT:-9443}
DNAT=(-p tcp --dport "$PUBLIC_PORT" -m addrtype --dst-type LOCAL -m comment --comment "$TAG" -j DNAT --to-destination "$SEALED_GUEST_IP:$TLS_PORT")
RULES=5; [ "$MINER" = 1 ] && RULES=7

# Several guests on one host (AB#432). Refuse, before anything changes:
# - a /30 another interface holds or overlaps (two guests on one connected
#   route: the broker reaches the wrong one or none),
# - a /30 another sealed hotel unit on this host is set to use (stopped or not),
# - a move of this hotel's own link while its guest runs (its tap holds another
#   address): the running guest would lose its NAT. Drain, stop the unit (its
#   stop removes the old link; "check" leaves a stopped guest's link down),
#   retarget any broker tunnel, then install.
link_clash() {
  local net dev cidr a p unit env other
  net=$(( $(sealed_ip_int "$SEALED_HOST_IP") - 1 ))
  while read -r _ dev _ cidr _; do
    a=$(sealed_ip_int "${cidr%/*}") || continue
    p=${cidr#*/}
    if [ "$dev" = "$TAP" ]; then
      [ "$cidr" = "$SEALED_HOST_IP/30" ] && continue
      echo "sealed-hotel: $TAP holds $cidr but sealed.env names $SEALED_HOST_IP/30: the running guest uses the old link. Drain $SEALED_NAME, stop room-sealed-$SEALED_NAME.service, retarget any broker tunnel to $SEALED_GUEST_IP:18090, then start it" >&2
      return 1
    fi
    if sealed_cidr_overlap "$net" 30 "$a" "$p"; then
      echo "sealed-hotel: $dev already holds $cidr, which overlaps this hotel's link $SEALED_HOST_IP/30; give $SEALED_NAME its own SEALED_HOST_IP and SEALED_GUEST_IP in sealed.env" >&2
      return 1
    fi
  done < <(ip -4 -o addr show)
  # Only guest units (ExecStart launch-guest.sh), not the -net check units, and
  # not this hotel's own (same unit name or the same sealed.env).
  for unit in "${ROOM_DESTDIR:-}"/etc/systemd/system/room-sealed-*.service; do
    [ -f "$unit" ] && [ "$unit" != "${ROOM_DESTDIR:-}/etc/systemd/system/room-sealed-$SEALED_NAME.service" ] || continue
    env=$(sed -n 's/^ExecStart=[^ ]*\/launch-guest\.sh \([^ ]*\)$/\1/p' "$unit" | head -1)
    [ -n "$env" ] && [ -r "$env" ] && ! [ "$env" -ef "$ENV" ] || continue
    other=$(bash -c 'set +eu; source "$1" >/dev/null 2>&1; echo "${SEALED_HOST_IP:-10.215.0.1}"' _ "$env")
    a=$(sealed_ip_int "$other") || continue
    if sealed_cidr_overlap "$net" 30 "$(( a - 1 ))" 30; then
      echo "sealed-hotel: $(basename "$unit") is set to $other/30, which overlaps this hotel's link $SEALED_HOST_IP/30; give $SEALED_NAME its own SEALED_HOST_IP and SEALED_GUEST_IP in sealed.env" >&2
      return 1
    fi
  done
  return 0
}

case "${1:?up|down|check|clash}" in
clash)
  link_clash
  ;;
up)
  link_clash || exit 1
  ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add dev "$TAP" mode tap
  ip addr replace "$SEALED_HOST_IP/30" dev "$TAP"
  ip link set "$TAP" up
  sysctl -qw net.ipv4.ip_forward=1
  iptables -N "$FWD" 2>/dev/null || iptables -F "$FWD"
  if [ "$MINER" = 1 ]; then
    # Answers from the guest's HTTPS port on a connection a client opened, to
    # a private-range client too. The guest still cannot open one there.
    iptables -A "$FWD" -i "$TAP" -s "$SEALED_GUEST_IP" -p tcp --sport "$TLS_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT
  fi
  iptables -A "$FWD" -i "$TAP" -d "$PRIVATE" -j DROP
  iptables -A "$FWD" -i "$TAP" -s "$SEALED_GUEST_IP" -j ACCEPT
  iptables -A "$FWD" -i "$TAP" -j DROP
  iptables -A "$FWD" -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  if [ "$MINER" = 1 ]; then
    iptables -A "$FWD" -o "$TAP" -d "$SEALED_GUEST_IP" -p tcp --dport "$TLS_PORT" -m conntrack --ctstate NEW -j ACCEPT
  fi
  iptables -A "$FWD" -o "$TAP" -j DROP
  iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || iptables -I FORWARD 1 -m comment --comment "$TAG" -j "$FWD"
  iptables -N "$IN" 2>/dev/null || iptables -F "$IN"
  iptables -A "$IN" -i "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$IN" -i "$TAP" -j DROP
  iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || iptables -I INPUT 1 -m comment --comment "$TAG" -j "$IN"
  iptables -t nat -C POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE
  if [ "$MINER" = 1 ]; then
    iptables -t nat -C PREROUTING "${DNAT[@]}" 2>/dev/null || iptables -t nat -A PREROUTING "${DNAT[@]}"
  fi
  ;;
check)
  # A stopped guest needs no link: do not bring its tap back (a link move is
  # drain, stop, edit sealed.env, install). Only the timer runs "check".
  if command -v systemctl >/dev/null && ! systemctl is-active -q "room-sealed-$SEALED_NAME.service"; then
    exit 0
  fi
  # Put the rules back when a firewall reload took them (idempotent "up").
  if iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null \
     && iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null \
     && iptables -t nat -C POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null \
     && { [ "$MINER" != 1 ] || iptables -t nat -C PREROUTING "${DNAT[@]}" 2>/dev/null; } \
     && [ "$(iptables -S "$FWD" 2>/dev/null | grep -c -- '-A')" -ge "$RULES" ]; then
    exit 0
  fi
  echo "sealed-hotel: host link rules for $TAP were missing; restoring" >&2
  exec "$0" up "$2"
  ;;
down)
  iptables -D FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || true
  iptables -D INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null || true
  if [ "$MINER" = 1 ]; then
    iptables -t nat -D PREROUTING "${DNAT[@]}" 2>/dev/null || true
  fi
  iptables -F "$FWD" 2>/dev/null && iptables -X "$FWD" 2>/dev/null || true
  iptables -F "$IN" 2>/dev/null && iptables -X "$IN" 2>/dev/null || true
  ip link del "$TAP" 2>/dev/null || true
  ;;
esac
