#!/bin/bash
# Host side of the sealed guest link. Usage: host-net.sh up|down sealed.env
# A tap device with a /30, NAT to the internet for the guest, and nothing else:
# - the guest cannot reach private ranges or this host's services,
# - nothing on the host side (other bridges, containers) can open a connection
#   into the guest; only this host (the broker) reaches the hotel API port.
# Own chains only (SEALED-<TAP>-FWD, SEALED-<TAP>-IN, one MASQUERADE rule).
set -euo pipefail
# shellcheck disable=SC1090
source "${2:?sealed.env}"
TAP=$SEALED_TAP
FWD=SEALED-${TAP^^}-FWD
IN=SEALED-${TAP^^}-IN
TAG="sealed-hotel:$SEALED_NAME"
PRIVATE="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16"

case "${1:?up|down}" in
up)
  ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add dev "$TAP" mode tap
  ip addr replace "$SEALED_HOST_IP/30" dev "$TAP"
  ip link set "$TAP" up
  sysctl -qw net.ipv4.ip_forward=1
  iptables -N "$FWD" 2>/dev/null || iptables -F "$FWD"
  iptables -A "$FWD" -i "$TAP" -d "$PRIVATE" -j DROP
  iptables -A "$FWD" -i "$TAP" -s "$SEALED_GUEST_IP" -j ACCEPT
  iptables -A "$FWD" -i "$TAP" -j DROP
  iptables -A "$FWD" -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$FWD" -o "$TAP" -j DROP
  iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || iptables -I FORWARD 1 -m comment --comment "$TAG" -j "$FWD"
  iptables -N "$IN" 2>/dev/null || iptables -F "$IN"
  iptables -A "$IN" -i "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$IN" -i "$TAP" -j DROP
  iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || iptables -I INPUT 1 -m comment --comment "$TAG" -j "$IN"
  iptables -t nat -C POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE
  ;;
down)
  iptables -D FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || true
  iptables -D INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null || true
  iptables -F "$FWD" 2>/dev/null && iptables -X "$FWD" 2>/dev/null || true
  iptables -F "$IN" 2>/dev/null && iptables -X "$IN" 2>/dev/null || true
  ip link del "$TAP" 2>/dev/null || true
  ;;
esac
