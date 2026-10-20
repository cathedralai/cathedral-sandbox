#!/bin/bash
# Room guest network. Usage: room-net.sh up|down|status /etc/pool-room/room.env
# The room Docker daemon runs with iptables=false, so it never rewrites the
# host's Docker chains. This script owns the room's rules, and only those:
#   filter: chain $CHAIN, jumped to from FORWARD and INPUT (first position)
#   nat:    one MASQUERADE rule for the room CIDR
set -euo pipefail
ACTION=${1:?up|down|status}
# shellcheck disable=SC1090
source "${2:?room.env}"
BR=$ROOM_BRIDGE
CIDR_GW=$ROOM_BRIDGE_CIDR                       # e.g. 10.213.0.1/24
NET=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_interface(sys.argv[1]).network)" "$CIDR_GW")
CHAIN="ROOM-$(echo "$ROOM_ID" | tr 'a-z' 'A-Z' | tr -c 'A-Z0-9\n' '-' | cut -c1-20)"
CHAIN_IN="${CHAIN}-IN"
TAG="pool-room:$ROOM_ID"
NFT_TABLE="pool_room_$(echo "$ROOM_ID" | tr -c 'a-zA-Z0-9\n' '_')"

del_all() { while iptables "$@" 2>/dev/null; do :; done; }

down() {
  # Delete every rule that carries the room tag, whatever CIDR it was made with.
  for t in filter nat; do
    { iptables -t $t -S | grep -F -- "--comment \"$TAG\"" || true; } | sed 's/^-A /-D /' | while read -r rule; do
      eval "iptables -t $t $rule" 2>/dev/null || true
    done
  done
  for c in "$CHAIN" "$CHAIN_IN"; do iptables -F "$c" 2>/dev/null || true; iptables -X "$c" 2>/dev/null || true; done
  nft delete table bridge "$NFT_TABLE" 2>/dev/null || true
  if ip link show "$BR" >/dev/null 2>&1; then ip link set "$BR" down || true; ip link del "$BR" || true; fi
}

up() {
  down
  if ip route show "$NET" | grep -q .; then echo "room CIDR $NET already routed on this host; pick another ROOM_BRIDGE_CIDR" >&2; exit 1; fi
  # dockerd stores the default bridge subnet in its network DB; drop it so a
  # changed ROOM_BRIDGE_CIDR takes effect (the room daemon has no other networks).
  rm -f "$ROOM_DATA_DIR/docker/network/files/local-kv.db"
  ip link add "$BR" type bridge
  ip addr add "$CIDR_GW" dev "$BR"
  ip link set "$BR" up
  sysctl -q -w net.ipv4.ip_forward=1
  iptables -N "$CHAIN"
  # Guests may not reach link-local (cloud metadata), private ranges (host LANs,
  # other Docker bridges, other tenants), or the host itself.
  for d in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10; do
    iptables -A "$CHAIN" -i "$BR" -d "$d" -j DROP
  done
  # runsc --net-raw (needed for Docker in the guest) lets a guest forge packets:
  # only the room CIDR may leave the bridge.
  iptables -A "$CHAIN" -i "$BR" ! -s "$NET" -j DROP
  iptables -A "$CHAIN" -i "$BR" ! -o "$BR" -j ACCEPT
  iptables -A "$CHAIN" -o "$BR" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$CHAIN" -o "$BR" -j DROP
  iptables -A "$CHAIN" -i "$BR" -j DROP
  iptables -I FORWARD 1 -j "$CHAIN" -m comment --comment "$TAG"
  iptables -N "$CHAIN_IN"
  iptables -A "$CHAIN_IN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$CHAIN_IN" -j DROP
  iptables -I INPUT 1 -i "$BR" -j "$CHAIN_IN" -m comment --comment "$TAG"
  iptables -t nat -A POSTROUTING -s "$NET" ! -o "$BR" -j MASQUERADE -m comment --comment "$TAG"
  # Guest to guest on the same bridge is layer 2 and skips iptables unless
  # br_netfilter is loaded (a host-wide change). An nftables bridge-family
  # rule drops frames bridged between two ports of this bridge only.
  nft add table bridge "$NFT_TABLE"
  nft add chain bridge "$NFT_TABLE" forward '{ type filter hook forward priority 0; policy accept; }'
  nft add rule bridge "$NFT_TABLE" forward meta ibrname "$BR" drop
}

case "$ACTION" in
  up) up ;;
  down) down ;;
  status) ip -br addr show "$BR" || true; iptables -S "$CHAIN" || true; iptables -S "$CHAIN_IN" || true; iptables -t nat -S POSTROUTING | grep -F "$TAG" || true; nft list table bridge "$NFT_TABLE" || true ;;
  *) echo "usage: $0 up|down|status room.env" >&2; exit 2 ;;
esac
