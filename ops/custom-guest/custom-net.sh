#!/bin/bash
# Host side of one custom SNP guest link (spec-r9 6). Usage:
#   custom-net.sh up|down|check|purge <hotel> <launch_id>
# Copied in shape from room-kit/vm/vm-net.sh. Own identity: tap cgst<n>, link
# 10.217.<n>.0/30 (host .1, guest .2), MAC 52:54:00:c7:xx:xx, tag
# custom-guest:<hotel>:<launch_id>, chains CGST-<TAP>-FWD and CGST-<TAP>-IN.
# The link and the ports come from the root-owned images/bootstrap.json of the
# launch (the owner signed it), never from a file the guest user can write.
# - In: per declared pair, nat PREROUTING DNAT of the public TCP port to the
#   guest port, no nat OUTPUT rule; FWD takes NEW only with that DNAT's
#   original port. No inbound UDP.
# - Out: only from the guest address; private, link-local, CGNAT, multicast,
#   class E and TCP 25 dropped; MASQUERADE.
# - This host: the guest reaches no host service (IN takes answers only), and no
#   host process opens a connection into the guest but the uid cg-probe.
# - IPv6: disable_ipv6 on the tap before link up AND tagged ip6tables DROP
#   rules; up fails (custom_guest_ipv6_not_shut) unless both hold.
# Every rule in a built-in chain carries the tag, so down and purge find them
# whatever the bootstrap says now, and down fails while any tagged rule is left.
set -euo pipefail
export PATH=${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin
ROOT=${CG_ROOT:-}
ACTION=${1:?up|down|check|purge}
HOTEL=${2:?hotel}
LAUNCH=${3:?launch_id}
[[ "$HOTEL" =~ ^[a-z0-9][a-z0-9-]{0,58}$ ]] || { echo "custom-net: bad hotel" >&2; exit 2; }
[[ "$LAUNCH" =~ ^cg-[0-9a-f]{12}$ ]] || { echo "custom-net: bad launch id" >&2; exit 2; }
D=$ROOT/srv/custom-guest/$HOTEL/$LAUNCH
TAG="custom-guest:$HOTEL:$LAUNCH"
UNIT=custom-guest-$LAUNCH.service
BLOCKED="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4"
V6_CONF=${CG_IPV6_CONF_DIR:-/proc/sys/net/ipv6/conf}
fail() { echo "ERROR $1: $2" >&2; exit 1; }

# The link and ports from bootstrap.json: "<n> <guest_ip> <host_ip>" then "<public> <guest>" per pair.
read_bootstrap() {
  python3 -I - "$D/images/bootstrap.json" <<'PY'
import json, re, sys
b = json.load(open(sys.argv[1]))
net = b["network"]
m = re.fullmatch(r"10\.217\.([0-9]{1,3})\.2", net["guest_ip"])
assert m and int(m.group(1)) <= 255 and net["host_ip"] == f"10.217.{m.group(1)}.1" and net["prefix"] == 30
print(int(m.group(1)), net["guest_ip"], net["host_ip"])
for p in b["ports"]:
    assert p["proto"] == "tcp" and 20000 <= p["public"] <= 29999 and 1 <= p["guest"] <= 65535
    print(p["public"], p["guest"])
PY
}

# Tagged rules in one table's built-in chains, as -S lines.
tagged() { { "$1" -t "$2" -S 2>/dev/null | grep -E -- "--comment \"?$TAG\"?( |\$)" | grep -E '^-A ' || true; }; }
# Delete every tagged rule of one table. Fails when the rules cannot be listed or a delete fails.
purge_table() {
  local tool=$1 table=$2 rules rule rc=0
  rules=$("$tool" -t "$table" -S 2>/dev/null) || return 1
  while read -r rule; do
    [ -n "$rule" ] || continue
    read -ra words <<< "${rule/#-A /-D }"
    local args=() i=0
    while [ $i -lt ${#words[@]} ]; do
      if [ "${words[$i]}" = --comment ]; then args+=(--comment "$TAG"); i=$((i + 2)); continue; fi
      args+=("${words[$i]}"); i=$((i + 1))
    done
    "$tool" -t "$table" "${args[@]}" 2>/dev/null || rc=1
  done < <(printf '%s\n' "$rules" | grep -E -- "--comment \"?$TAG\"?( |\$)" | grep -E '^-A ' || true)
  return $rc
}
# Taps named by this launch's tagged jumps (the bootstrap may already be wiped).
tagged_taps() {
  { iptables -t filter -S 2>/dev/null | grep -E -- "--comment \"?$TAG\"?( |\$)" \
      | sed -nE 's/.* -j CGST-CGST([0-9]{1,3})-(FWD|IN)$/cgst\1/p' | sort -u; } || true
}
remove_all() {
  local left=0 taps tap n
  taps=$(tagged_taps)
  [ -n "${TAP:-}" ] && taps=$(printf '%s\n%s\n' "$taps" "$TAP" | sort -u)
  purge_table iptables filter || left=1
  purge_table iptables nat || left=1
  if command -v ip6tables >/dev/null 2>&1; then purge_table ip6tables filter || left=1; fi
  for tap in $taps; do
    [[ "$tap" =~ ^cgst([0-9]{1,3})$ ]] || continue
    n=${BASH_REMATCH[1]}
    iptables -F "CGST-CGST$n-FWD" 2>/dev/null && iptables -X "CGST-CGST$n-FWD" 2>/dev/null || true
    iptables -F "CGST-CGST$n-IN" 2>/dev/null && iptables -X "CGST-CGST$n-IN" 2>/dev/null || true
    ip link del "$tap" 2>/dev/null || true
  done
  # Nothing may carry the tag afterwards.
  if [ -n "$(tagged iptables filter)$(tagged iptables nat)" ] \
     || { command -v ip6tables >/dev/null 2>&1 && [ -n "$(tagged ip6tables filter)" ]; }; then
    left=1
  fi
  return $left
}

dnat() { # dnat -A|-C|-D <public> <guest>
  iptables -t nat "$1" PREROUTING -p tcp --dport "$2" -m addrtype --dst-type LOCAL \
    -m comment --comment "$TAG" -j DNAT --to-destination "$GUEST:$3"
}
masq() { iptables -t nat "$1" POSTROUTING -s "$GUEST/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE; }
out_rules() { # out_rules -A|-C|-D: host processes open nothing into the guest but cg-probe
  if [ "$1" = -A ]; then
    iptables -A OUTPUT -o "$TAP" -m owner --uid-owner cg-probe -m conntrack --ctstate NEW -m comment --comment "$TAG" -j ACCEPT
    iptables -A OUTPUT -o "$TAP" -m conntrack --ctstate NEW -m comment --comment "$TAG" -j DROP
  else
    iptables "$1" OUTPUT -o "$TAP" -m owner --uid-owner cg-probe -m conntrack --ctstate NEW -m comment --comment "$TAG" -j ACCEPT \
      && iptables "$1" OUTPUT -o "$TAP" -m conntrack --ctstate NEW -m comment --comment "$TAG" -j DROP
  fi
}
v6_rules() { echo "INPUT -i $TAP"; echo "FORWARD -i $TAP"; echo "FORWARD -o $TAP"; }
v6_off() { [ "$(cat "$V6_CONF/$TAP/disable_ipv6" 2>/dev/null)" = 1 ]; }
v6_rules_in() {
  command -v ip6tables >/dev/null 2>&1 || return 1
  local c m
  while read -r c m; do
    # shellcheck disable=SC2086
    ip6tables -C "$c" $m -m comment --comment "$TAG" -j DROP 2>/dev/null || return 1
  done < <(v6_rules)
}
rules_present() {
  v6_off && v6_rules_in || return 1
  iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null \
    && iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null \
    && out_rules -C 2>/dev/null && masq -C 2>/dev/null || return 1
  local p g
  while read -r p g; do dnat -C "$p" "$g" 2>/dev/null || return 1; done <<< "$PAIRS"
  [ "$(iptables -S "$FWD" 2>/dev/null | grep -c -- '^-A')" -ge "$((6 + 2 * $(wc -l <<< "$PAIRS")))" ]
}

# The dnat lock of room-kit/sealed/host-net.sh: a sibling kit's start (rehearsal A host) and this
# "up" never pass their port checks together.
take_dnat_lock() {
  local dir=$ROOT/run/lock
  mkdir -p "$dir" && exec 8>"$dir/sealed-hotel-dnat.lock" && flock -w 60 8 && return 0
  fail custom_guest_port_unavailable "could not take $dir/sealed-hotel-dnat.lock"
}
port_clash() {
  local rules p g kit_ports
  rules=$(iptables -t nat -S 2>/dev/null) || fail custom_guest_port_unavailable "cannot list the nat rules"
  kit_ports=" 22 443 9443 "
  for env in "$ROOT"/srv/sealed-hotel-*/sealed.env; do
    [ -r "$env" ] || continue
    kit_ports+="$(sed -nE 's/^SEALED_(MINER|INGRESS)_PUBLIC_PORT=([0-9]+).*/\2/p' "$env" | tr '\n' ' ')"
  done
  while read -r p g; do
    [[ "$kit_ports" == *" $p "* ]] && fail custom_guest_port_unavailable "port $p is a kit or SSH port"
    if printf '%s\n' "$rules" | grep -E -- '^-A (PREROUTING|OUTPUT) ' | grep -E -- '-j DNAT' \
        | grep -vE -- "--comment \"?$TAG\"?( |\$)" | grep -qE -- "--dport $p( |\$)"; then
      fail custom_guest_port_unavailable "another rule on this host already forwards port $p"
    fi
    if command -v ss >/dev/null 2>&1 && [ -n "$(ss -Htln "sport = :$p" 2>/dev/null)" ]; then
      fail custom_guest_port_unavailable "a host service listens on port $p"
    fi
  done <<< "$PAIRS"
}
link_clash() {
  local dev cidr
  while read -r _ dev _ cidr _; do
    [ "$dev" = "$TAP" ] && [ "$cidr" = "$HOST/30" ] && continue
    case "$cidr" in
      10.217.$N.*) fail custom_guest_port_unavailable "$dev already holds $cidr, inside this launch's /30" ;;
    esac
    if [ "$dev" = "$TAP" ]; then
      fail custom_guest_port_unavailable "$TAP holds $cidr, not $HOST/30"
    fi
  done < <(ip -4 -o addr show 2>/dev/null || true)
  # Without this, a loop whose last address is not the tap returns the false test's 1, and set -e
  # ends "up" with no message (rehearsal B, 27 Nov: every real host lists lo and its uplink).
  return 0
}

load() {
  local first
  BOOT=$(read_bootstrap) || fail custom_guest_isolation_failed "cannot read $D/images/bootstrap.json"
  first=$(head -1 <<< "$BOOT")
  read -r N GUEST HOST <<< "$first"
  PAIRS=$(tail -n +2 <<< "$BOOT")
  TAP=cgst$N
  FWD=CGST-CGST$N-FWD
  IN=CGST-CGST$N-IN
}

case "$ACTION" in
up)
  load
  take_dnat_lock
  link_clash
  port_clash
  ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add dev "$TAP" mode tap user "cg-$HOTEL" group "cg-$HOTEL"
  # IPv6 first: shut before the link is up, and the ip6tables backstop.
  sysctl -qw "net.ipv6.conf.$TAP.disable_ipv6=1" 2>/dev/null || true
  if command -v ip6tables >/dev/null 2>&1; then
    while read -r c m; do
      # shellcheck disable=SC2086
      ip6tables -C "$c" $m -m comment --comment "$TAG" -j DROP 2>/dev/null \
        || ip6tables -I "$c" 1 $m -m comment --comment "$TAG" -j DROP 2>/dev/null || true
    done < <(v6_rules)
  fi
  if ! { v6_off && v6_rules_in; }; then
    remove_all || true
    fail custom_guest_ipv6_not_shut "disable_ipv6 and the ip6tables DROP rules must both hold on $TAP"
  fi
  ip addr replace "$HOST/30" dev "$TAP"
  ip link set "$TAP" up
  sysctl -qw net.ipv4.ip_forward=1
  iptables -N "$FWD" 2>/dev/null || iptables -F "$FWD"
  while read -r p g; do
    # Answers of a declared guest port to any client, a private-range one too.
    iptables -A "$FWD" -i "$TAP" -s "$GUEST" -p tcp --sport "$g" -m conntrack --ctstate ESTABLISHED -j ACCEPT
  done <<< "$PAIRS"
  iptables -A "$FWD" -i "$TAP" -d "$BLOCKED" -j DROP
  iptables -A "$FWD" -i "$TAP" -p tcp --dport 25 -j DROP
  iptables -A "$FWD" -i "$TAP" -s "$GUEST" -j ACCEPT
  iptables -A "$FWD" -i "$TAP" -j DROP
  while read -r p g; do
    # New connections in: only those that came through this launch's own DNAT of port p.
    iptables -A "$FWD" -o "$TAP" -d "$GUEST" -p tcp --dport "$g" -m conntrack --ctstate NEW \
      -m conntrack --ctstate DNAT --ctorigdstport "$p" -j ACCEPT
  done <<< "$PAIRS"
  iptables -A "$FWD" -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$FWD" -o "$TAP" -j DROP
  iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || iptables -I FORWARD 1 -m comment --comment "$TAG" -j "$FWD"
  iptables -N "$IN" 2>/dev/null || iptables -F "$IN"
  iptables -A "$IN" -i "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$IN" -i "$TAP" -j DROP
  iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || iptables -I INPUT 1 -m comment --comment "$TAG" -j "$IN"
  out_rules -C 2>/dev/null || out_rules -A
  masq -C 2>/dev/null || masq -A
  # Forwards an older run left (another port) go before the current ones are added.
  while read -r rule; do
    [ -n "$rule" ] || continue
    p=$(sed -nE 's/.*--dport ([0-9]+) .*/\1/p' <<< "$rule")
    grep -qE "^$p " <<< "$PAIRS" || { read -ra w <<< "${rule/#-A /-D }"; a=(); i=0
      while [ $i -lt ${#w[@]} ]; do if [ "${w[$i]}" = --comment ]; then a+=(--comment "$TAG"); i=$((i + 2)); continue; fi; a+=("${w[$i]}"); i=$((i + 1)); done
      iptables -t nat "${a[@]}" 2>/dev/null || true; }
  done < <(tagged iptables nat | grep -E '^-A PREROUTING ' || true)
  while read -r p g; do dnat -C "$p" "$g" 2>/dev/null || dnat -A "$p" "$g"; done <<< "$PAIRS"
  rules_present || fail custom_guest_isolation_failed "the link rules did not read back after up"
  ;;
check)
  # Custom timer: while the guest unit runs, put back rules a firewall reload took. Once it has
  # settled stopped, no tagged rule may outlive it.
  state=$(systemctl show -p ActiveState --value "$UNIT" 2>/dev/null) || state=unknown
  case "$state" in
    active)
      load
      rules_present && exit 0
      echo "custom-net: link rules for $LAUNCH were missing; restoring" >&2
      exec "$BASH" "$0" up "$HOTEL" "$LAUNCH"
      ;;
    inactive|failed)
      if [ -r "$D/images/bootstrap.json" ]; then load; fi
      if [ -z "$(tagged iptables filter)$(tagged iptables nat)" ] \
         && { [ -z "${TAP:-}" ] || ! ip link show "$TAP" >/dev/null 2>&1; }; then
        exit 0
      fi
      remove_all || fail custom_guest_isolation_failed "rules tagged $TAG are left after the guest stopped"
      ;;
    *) exit 0 ;;
  esac
  ;;
down|purge)
  if [ -r "$D/images/bootstrap.json" ]; then load; fi
  remove_all || fail custom_guest_isolation_failed "could not delete every rule tagged $TAG; check iptables-save"
  ;;
*)
  echo "usage: custom-net.sh up|down|check|purge <hotel> <launch_id>" >&2; exit 2 ;;
esac
