#!/bin/bash
# Host side of the sealed guest link. Usage: host-net.sh up|down sealed.env
# A tap device with a /30, NAT to the internet for the guest, and nothing else:
# - the guest cannot reach private ranges or this host's services,
# - nothing on the host side (other bridges, containers) can open a connection
#   into the guest; only this host (the broker) reaches the hotel API port.
# Own chains only (SEALED-<TAP>-FWD, SEALED-<TAP>-IN, one MASQUERADE rule).
# Miner hotel (SEALED_MINER=1): one more way in, SEALED_MINER_PUBLIC_PORT on
# this host forwarded (DNAT) to the guest's attested HTTPS port, and nothing
# else. TLS ends inside the guest; this host only moves the bytes.
# Preview URL ingress (SEALED_GUEST_INGRESS=1, AB#423): the same shape again,
# SEALED_INGRESS_PUBLIC_PORT (default 443) to the guest's ingress port
# SEALED_INGRESS_TLS_PORT (default 8443). The guest holds the TLS key.
set -euo pipefail
# shellcheck disable=SC1090
source "${2:?sealed.env}"
# shellcheck disable=SC1091
source "$(dirname "$(readlink -f "$0")")/guest-constants.sh"
TAP=$SEALED_TAP
FWD=SEALED-${TAP^^}-FWD
IN=SEALED-${TAP^^}-IN
TAG="sealed-hotel:$SEALED_NAME"
PRIVATE="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16"
MINER=${SEALED_MINER:-0}
TLS_PORT=${SEALED_MINER_TLS_PORT:-18443}
PUBLIC_PORT=${SEALED_MINER_PUBLIC_PORT:-9443}
DNAT=(-p tcp --dport "$PUBLIC_PORT" -m addrtype --dst-type LOCAL -m comment --comment "$TAG" -j DNAT --to-destination "$SEALED_GUEST_IP:$TLS_PORT")
INGRESS=${SEALED_GUEST_INGRESS:-0}
INGRESS_TLS_PORT=${SEALED_INGRESS_TLS_PORT:-8443}
INGRESS_PUBLIC_PORT=${SEALED_INGRESS_PUBLIC_PORT:-443}
INGRESS_DNAT=(-p tcp --dport "$INGRESS_PUBLIC_PORT" -m addrtype --dst-type LOCAL -m comment --comment "$TAG" -j DNAT --to-destination "$SEALED_GUEST_IP:$INGRESS_TLS_PORT")
# Two more FWD rules per way in (answers out, new connections in).
RULES=5
[ "$MINER" = 1 ] && RULES=$((RULES + 2))
[ "$INGRESS" = 1 ] && RULES=$((RULES + 2))

port_ok() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]; }
if [ "$INGRESS" = 1 ] && [ "${1:-}" != down ]; then
  # Checked on up and check only: a bad edit must not keep "down" from removing rules.
  if ! port_ok "$INGRESS_TLS_PORT" || ! port_ok "$INGRESS_PUBLIC_PORT" \
     || [ "$INGRESS_TLS_PORT" = 18090 ] || [ "$INGRESS_TLS_PORT" = 18091 ] \
     || { [ "$MINER" = 1 ] && { [ "$INGRESS_TLS_PORT" = "$TLS_PORT" ] || [ "$INGRESS_PUBLIC_PORT" = "$PUBLIC_PORT" ]; }; }; then
    echo "sealed-hotel: SEALED_INGRESS_TLS_PORT and SEALED_INGRESS_PUBLIC_PORT must be TCP ports; the guest port not 18090, 18091 or the miner port, the public port not the miner public port" >&2
    exit 1
  fi
fi

case "${1:?up|down|check}" in
up)
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
  if [ "$INGRESS" = 1 ]; then
    iptables -A "$FWD" -i "$TAP" -s "$SEALED_GUEST_IP" -p tcp --sport "$INGRESS_TLS_PORT" -m conntrack --ctstate ESTABLISHED -j ACCEPT
  fi
  iptables -A "$FWD" -i "$TAP" -d "$PRIVATE" -j DROP
  iptables -A "$FWD" -i "$TAP" -s "$SEALED_GUEST_IP" -j ACCEPT
  iptables -A "$FWD" -i "$TAP" -j DROP
  iptables -A "$FWD" -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  if [ "$MINER" = 1 ]; then
    iptables -A "$FWD" -o "$TAP" -d "$SEALED_GUEST_IP" -p tcp --dport "$TLS_PORT" -m conntrack --ctstate NEW -j ACCEPT
  fi
  if [ "$INGRESS" = 1 ]; then
    iptables -A "$FWD" -o "$TAP" -d "$SEALED_GUEST_IP" -p tcp --dport "$INGRESS_TLS_PORT" -m conntrack --ctstate NEW -j ACCEPT
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
  if [ "$INGRESS" = 1 ]; then
    iptables -t nat -C PREROUTING "${INGRESS_DNAT[@]}" 2>/dev/null || iptables -t nat -A PREROUTING "${INGRESS_DNAT[@]}"
  fi
  ;;
check)
  # Put the rules back when a firewall reload took them (idempotent "up").
  if iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null \
     && iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null \
     && iptables -t nat -C POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null \
     && { [ "$MINER" != 1 ] || iptables -t nat -C PREROUTING "${DNAT[@]}" 2>/dev/null; } \
     && { [ "$INGRESS" != 1 ] || iptables -t nat -C PREROUTING "${INGRESS_DNAT[@]}" 2>/dev/null; } \
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
  if [ "$INGRESS" = 1 ]; then
    iptables -t nat -D PREROUTING "${INGRESS_DNAT[@]}" 2>/dev/null || true
  fi
  iptables -F "$FWD" 2>/dev/null && iptables -X "$FWD" 2>/dev/null || true
  iptables -F "$IN" 2>/dev/null && iptables -X "$IN" 2>/dev/null || true
  ip link del "$TAP" 2>/dev/null || true
  ;;
esac
