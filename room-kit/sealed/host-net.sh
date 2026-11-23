#!/bin/bash
# Host side of the sealed guest link. Usage: host-net.sh up|down|check|clash sealed.env
# A tap device with a /30, NAT to the internet for the guest, and nothing else:
# - the guest cannot reach private ranges or this host's services,
# - nothing on the host side (other bridges, containers) can open a connection
#   into the guest; only this host (the broker) reaches the hotel API port.
# Own chains only (SEALED-<TAP>-FWD, SEALED-<TAP>-IN, one MASQUERADE rule).
# Miner hotel (SEALED_MINER=1): one more way in, SEALED_MINER_PUBLIC_PORT on
# this host forwarded (DNAT) to the guest's attested HTTPS port, and nothing
# else. TLS ends inside the guest; this host only moves the bytes. The same
# DNAT sits in nat OUTPUT too (AB#822): Linux runs PREROUTING only for packets
# that arrive, so a broker on this host would never reach its own miner hotel's
# public address:port without it.
# Preview URL ingress (SEALED_GUEST_INGRESS=1, AB#423): one more PREROUTING
# forward, SEALED_INGRESS_PUBLIC_PORT (default 443) to the guest's ingress port
# SEALED_INGRESS_TLS_PORT (default 8443). The guest holds the TLS key.
# It also lets the guest open TCP to the broker URL's own address on its port
# (SEALED_INGRESS_BROKER_URL, default port 443) when that address is one of this
# host's, and nothing else on the host: when the broker runs on this host, the
# broker name resolves here, and the guest's DNS-01 PUT for its certificate
# (room_acme.py) must reach it. Other host addresses (bridges, tailscale) stay shut.
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
INGRESS=${SEALED_GUEST_INGRESS:-0}
INGRESS_TLS_PORT=${SEALED_INGRESS_TLS_PORT:-8443}
INGRESS_PUBLIC_PORT=${SEALED_INGRESS_PUBLIC_PORT:-443}
BROKER_PORT=$(sed -nE 's#^https://[^/:]+:([0-9]{1,5})/?$#\1#p' <<< "${SEALED_INGRESS_BROKER_URL:-}")
BROKER_PORT=${BROKER_PORT:-443}
BROKER_HOST=$(sed -nE 's#^https://([^/:]+)(:[0-9]{1,5})?/?$#\1#p' <<< "${SEALED_INGRESS_BROKER_URL:-}")
# The broker's IPv4 addresses that belong to this host (empty when the broker is elsewhere).
broker_local_addrs() {
  [ -n "$BROKER_HOST" ] || return 0
  local mine a
  mine=" $(ip -4 -o addr show | awk '{sub(/\/.*/, "", $4); printf "%s ", $4}') "
  for a in $(getent ahostsv4 "$BROKER_HOST" 2>/dev/null | awk '{print $1}' | sort -u); do
    [[ "$mine" == *" $a "* ]] && echo "$a"
  done
  return 0
}
INGRESS_DNAT=(-p tcp --dport "$INGRESS_PUBLIC_PORT" -m addrtype --dst-type LOCAL -m comment --comment "$TAG" -j DNAT --to-destination "$SEALED_GUEST_IP:$INGRESS_TLS_PORT")
# Two more FWD rules per way in (answers out, new connections in).
RULES=5
[ "$MINER" = 1 ] && RULES=$((RULES + 2))
[ "$INGRESS" = 1 ] && RULES=$((RULES + 2))

# Every PREROUTING and nat OUTPUT rule this hotel owns carries $TAG. Find them by tag, not by the
# current flags and ports: sealed.env may have changed since "up" (ingress
# turned off, a public port edited), and the old forward must still go.
tagged_dnat() { { iptables -t nat -S 2>/dev/null | grep -F -- "--comment \"$TAG\"" | grep -E -- '^-A (PREROUTING|OUTPUT) ' || true; }; }
# Fails when the rules cannot be listed or a delete fails, so "down" can say so.
purge_dnat() {
  local rules rule rc=0
  rules=$(iptables -t nat -S 2>/dev/null) || return 1
  while read -r rule; do
    [ -n "$rule" ] || continue
    eval "iptables -t nat ${rule/#-A /-D }" 2>/dev/null || rc=1
  done < <(printf '%s\n' "$rules" | grep -F -- "--comment \"$TAG\"" | grep -E -- '^-A (PREROUTING|OUTPUT) ' || true)
  return $rc
}
# A public port forward matches every local address, so two hotels on one
# host cannot share one: the first rule would take the other hotel's traffic.
# Unlisted rules are not "no clash": refuse rather than add a forward blind.
dnat_port_clash() {
  local rules port
  [ "$WANT_DNAT" -gt 0 ] || return 0
  if ! rules=$(iptables -t nat -S 2>/dev/null); then
    echo "sealed-hotel: could not list the nat rules to check $SEALED_NAME's public ports against other sealed hotels; not adding a forward" >&2
    return 1
  fi
  for port in $([ "$MINER" = 1 ] && echo "$PUBLIC_PORT") $([ "$INGRESS" = 1 ] && echo "$INGRESS_PUBLIC_PORT"); do
    if printf '%s\n' "$rules" | grep -- '^-A PREROUTING ' | grep -F -- '--comment "sealed-hotel:' \
       | grep -vF -- "--comment \"$TAG\"" | grep -qE -- "--dport $port( |\$)"; then
      echo "sealed-hotel: another sealed hotel on this host already forwards public port $port; give $SEALED_NAME its own port (SEALED_INGRESS_PUBLIC_PORT or SEALED_MINER_PUBLIC_PORT) or host" >&2
      return 1
    fi
  done
  return 0
}
# Host-wide lock held from the port clash check until "up" has added its
# forwards (and released when the script exits): two hotel units starting
# together would otherwise both pass the check and both forward one port.
lock_dnat() {
  [ "$WANT_DNAT" -gt 0 ] || return 0
  take_dnat_lock
}
take_dnat_lock() {
  local dir="${ROOM_DESTDIR:-}/run/lock"
  mkdir -p "$dir" 2>/dev/null && exec 9>"$dir/sealed-hotel-dnat.lock" && flock -w "${SEALED_DNAT_LOCK_WAIT:-60}" 9 && return 0
  echo "sealed-hotel: could not take $dir/sealed-hotel-dnat.lock, which another sealed hotel's start holds; not adding a forward" >&2
  return 1
}
# Tagged forwards "up" adds: the miner port in PREROUTING and OUTPUT, ingress in PREROUTING.
WANT_DNAT=0
[ "$MINER" = 1 ] && WANT_DNAT=$((WANT_DNAT + 2))
[ "$INGRESS" = 1 ] && WANT_DNAT=$((WANT_DNAT + 1))

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

# The miner hotel's public port: dnat -A|-C|-D PREROUTING|OUTPUT. PREROUTING
# takes connections from other hosts, OUTPUT the ones this host opens itself.
DNAT_CHAINS="PREROUTING OUTPUT"
dnat() {
  iptables -t nat "$1" "$2" -p tcp --dport "$PUBLIC_PORT" -m addrtype --dst-type LOCAL -m comment --comment "$TAG" \
    -j DNAT --to-destination "$SEALED_GUEST_IP:$TLS_PORT"
}

# Several guests on one host (AB#432). Refuse, before anything changes:
# - a /30 another interface holds or overlaps (two guests on one connected
#   route: the broker reaches the wrong one or none),
# - a /30 another sealed hotel unit on this host is set to use (stopped or not),
# - a tap name (SEALED_TAP) another sealed hotel unit on this host is set to use,
# - a move of this hotel's own link while its guest runs (its tap holds another
#   address): the running guest would lose its NAT. Drain, stop the unit (its
#   stop removes the old link; "check" leaves a stopped guest's link down),
#   retarget any broker tunnel, then install.
link_clash() {
  local net dev cidr a p unit env other other_tap
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
    read -r other other_tap < <(bash -c 'set +eu; source "$1" >/dev/null 2>&1; echo "${SEALED_HOST_IP:-10.215.0.1} ${SEALED_TAP:-}"' _ "$env")
    # Same tap name, any /30 (AB#432): both guests would open one tap device, and this hotel's
    # "up" would readdress the sibling's link or its "down" would delete it.
    if [ -n "${other_tap:-}" ] && [ "$other_tap" = "$TAP" ]; then
      echo "sealed-hotel: $(basename "$unit") is set to tap $other_tap, the same SEALED_TAP as this hotel; give $SEALED_NAME its own SEALED_TAP in sealed.env" >&2
      return 1
    fi
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
  link_clash && lock_dnat && dnat_port_clash
  ;;
up)
  link_clash || exit 1
  lock_dnat || exit 1
  dnat_port_clash || exit 1
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
  if [ "$INGRESS" = 1 ]; then
    for a in $(broker_local_addrs); do
      iptables -A "$IN" -i "$TAP" -s "$SEALED_GUEST_IP" -d "$a" -p tcp --dport "$BROKER_PORT" -m conntrack --ctstate NEW -j ACCEPT
    done
  fi
  iptables -A "$IN" -i "$TAP" -j DROP
  iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || iptables -I INPUT 1 -m comment --comment "$TAG" -j "$IN"
  iptables -t nat -C POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE
  purge_dnat  # drop forwards a previous config left (feature off, port edited) before adding the current ones
  if [ "$MINER" = 1 ]; then
    for chain in $DNAT_CHAINS; do
      dnat -C "$chain" 2>/dev/null || dnat -A "$chain"
    done
  fi
  if [ "$INGRESS" = 1 ]; then
    iptables -t nat -C PREROUTING "${INGRESS_DNAT[@]}" 2>/dev/null || iptables -t nat -A PREROUTING "${INGRESS_DNAT[@]}"
  fi
  ;;
check)
  # A stopped guest needs no link: do not bring its tap back (a link move is
  # drain, stop, edit sealed.env, install). Only the timer runs "check".
  if command -v systemctl >/dev/null && ! systemctl is-active -q "room-sealed-$SEALED_NAME.service"; then
    # But a public forward must not outlive its guest (a "down" that could not
    # delete it). Only once the unit has settled stopped: while it is
    # activating its ExecStartPre "up" is adding the forwards, while it is
    # deactivating "down" is removing them, and an unanswered query proves
    # nothing. Leave those to the next check.
    state=$(systemctl show -p ActiveState --value "room-sealed-$SEALED_NAME.service" 2>/dev/null) || state=unknown
    case "$state" in
      inactive|failed) ;;
      *) exit 0 ;;
    esac
    # Under the same lock as "up", so a start that begins now waits for this purge.
    take_dnat_lock || exit 1
    # Fail when it still cannot, so the timer unit shows it.
    if ! purge_dnat; then
      echo "sealed-hotel: $SEALED_NAME is stopped but its public port forwards tagged $TAG could not be listed or deleted; check 'iptables -t nat -S'" >&2
      exit 1
    fi
    exit 0
  fi
  # Put the rules back when a firewall reload took them (idempotent "up").
  if iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null \
     && iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null \
     && iptables -t nat -C POSTROUTING -s "$SEALED_GUEST_IP/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE 2>/dev/null \
     && { [ "$MINER" != 1 ] || { dnat -C PREROUTING 2>/dev/null && dnat -C OUTPUT 2>/dev/null; }; } \
     && { [ "$INGRESS" != 1 ] || iptables -t nat -C PREROUTING "${INGRESS_DNAT[@]}" 2>/dev/null; } \
     && [ "$(tagged_dnat | grep -c -- '-A')" = "$WANT_DNAT" ] \
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
    for chain in $DNAT_CHAINS; do
      dnat -D "$chain" 2>/dev/null || true
    done
  fi
  if [ "$INGRESS" = 1 ]; then
    iptables -t nat -D PREROUTING "${INGRESS_DNAT[@]}" 2>/dev/null || true
  fi
  dnat_left=0
  purge_dnat || dnat_left=1  # whatever the flags say now
  iptables -F "$FWD" 2>/dev/null && iptables -X "$FWD" 2>/dev/null || true
  iptables -F "$IN" 2>/dev/null && iptables -X "$IN" 2>/dev/null || true
  ip link del "$TAP" 2>/dev/null || true
  if [ "$dnat_left" = 1 ]; then
    # Everything else is down; say so loudly rather than leave a public forward silently.
    echo "sealed-hotel: could not list or delete the public port forwards tagged $TAG; check 'iptables -t nat -S PREROUTING'" >&2
    exit 1
  fi
  ;;
esac
