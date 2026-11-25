#!/bin/bash
# Host side of one customer VM link (AB#991). Usage: vm-net.sh up|down|check vm.env
# Copied from room-kit/sealed/host-net.sh, smaller: a tap with a /30, NAT out,
# and one way in, the VM's public SSH port on this host forwarded (DNAT) to the
# guest's port 22. Nothing else:
# - the guest cannot reach private ranges or any service of this host,
# - nothing on the host side can open a connection into the guest but SSH.
# Own chains only (CVM-<TAP>-FWD, CVM-<TAP>-IN), and every rule in a built-in
# chain carries the comment "cathedral-vm:<name>", so "down" finds them by tag.
set -euo pipefail
export PATH=${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin
# shellcheck disable=SC1090
source "$(readlink -f "${2:?vm.env}")"
[[ "${VM_NAME:-}" =~ ^[a-z0-9][a-z0-9-]{0,40}$ ]] || { echo "cathedral-vm: bad VM_NAME" >&2; exit 1; }
[[ "${VM_TAP:-}" =~ ^cvm[0-9]{1,5}$ ]] || { echo "cathedral-vm: bad VM_TAP" >&2; exit 1; }
IP_RE='^10\.216\.[0-9]{1,3}\.[0-9]{1,3}$'
[[ "${VM_HOST_IP:-}" =~ $IP_RE && "${VM_GUEST_IP:-}" =~ $IP_RE ]] || { echo "cathedral-vm: bad VM_HOST_IP or VM_GUEST_IP" >&2; exit 1; }
[[ "${VM_SSH_PORT:-}" =~ ^[1-9][0-9]{3,4}$ ]] && [ "$VM_SSH_PORT" -le 65535 ] || { echo "cathedral-vm: bad VM_SSH_PORT" >&2; exit 1; }
TAP=$VM_TAP
GUEST=$VM_GUEST_IP
FWD=CVM-${TAP^^}-FWD
IN=CVM-${TAP^^}-IN
TAG="cathedral-vm:$VM_NAME"
PRIVATE="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,224.0.0.0/4,240.0.0.0/4"
# PREROUTING takes connections from other hosts, OUTPUT the ones this host opens itself.
dnat() {
  iptables -t nat "$1" "$2" -p tcp --dport "$VM_SSH_PORT" -m addrtype --dst-type LOCAL \
    -m comment --comment "$TAG" -j DNAT --to-destination "$GUEST:22"
}
masq() {
  iptables -t nat "$1" POSTROUTING -s "$GUEST/32" ! -o "$TAP" -m comment --comment "$TAG" -j MASQUERADE
}
# Every nat rule this VM owns, by tag, whatever vm.env says now.
purge_nat() {
  local rules rule rc=0
  rules=$(iptables -t nat -S 2>/dev/null) || return 1
  while read -r rule; do
    [ -n "$rule" ] || continue
    read -ra words <<< "${rule/#-A /-D }"
    # The comment is listed quoted; pass it as one word without the quotes.
    local args=() i=0
    while [ $i -lt ${#words[@]} ]; do
      if [ "${words[$i]}" = --comment ]; then args+=(--comment "$TAG"); i=$((i + 2)); continue; fi
      args+=("${words[$i]}"); i=$((i + 1))
    done
    iptables -t nat "${args[@]}" 2>/dev/null || rc=1
  done < <(printf '%s\n' "$rules" | grep -F -- "--comment \"$TAG\"" || true)
  return $rc
}
# Host-wide lock from the port check until the forward is in.
lock() {
  local dir="${VM_LOCK_DIR:-/run/lock}"
  mkdir -p "$dir" && exec 9>"$dir/cathedral-vm-net.lock" && flock -w 60 9 && return 0
  echo "cathedral-vm: could not take $dir/cathedral-vm-net.lock" >&2
  return 1
}
# A public port forward matches every local address: refuse one any other rule already forwards.
port_clash() {
  local rules
  rules=$(iptables -t nat -S PREROUTING 2>/dev/null) || { echo "cathedral-vm: cannot list nat rules; not adding a forward" >&2; return 1; }
  if printf '%s\n' "$rules" | grep -- '-j DNAT' | grep -vF -- "--comment \"$TAG\"" | grep -qE -- "--dport $VM_SSH_PORT( |\$)"; then
    echo "cathedral-vm: another rule on this host already forwards port $VM_SSH_PORT" >&2
    return 1
  fi
}
rules_present() {
  iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null \
    && iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null \
    && masq -C 2>/dev/null && dnat -C PREROUTING 2>/dev/null && dnat -C OUTPUT 2>/dev/null \
    && [ "$(iptables -S "$FWD" 2>/dev/null | grep -c -- '^-A')" -ge 7 ]
}

case "${1:?up|down|check}" in
up)
  lock
  port_clash
  ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add dev "$TAP" mode tap
  ip addr replace "$VM_HOST_IP/30" dev "$TAP"
  ip link set "$TAP" up
  sysctl -qw net.ipv4.ip_forward=1
  iptables -N "$FWD" 2>/dev/null || iptables -F "$FWD"
  # Answers of the guest's sshd to any client, a private-range one too.
  iptables -A "$FWD" -i "$TAP" -s "$GUEST" -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
  iptables -A "$FWD" -i "$TAP" -d "$PRIVATE" -j DROP
  iptables -A "$FWD" -i "$TAP" -s "$GUEST" -j ACCEPT
  iptables -A "$FWD" -i "$TAP" -j DROP
  iptables -A "$FWD" -o "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$FWD" -o "$TAP" -d "$GUEST" -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
  iptables -A "$FWD" -o "$TAP" -j DROP
  iptables -C FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || iptables -I FORWARD 1 -m comment --comment "$TAG" -j "$FWD"
  # This host's own services: closed to the guest (only answers to connections the host opened).
  iptables -N "$IN" 2>/dev/null || iptables -F "$IN"
  iptables -A "$IN" -i "$TAP" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A "$IN" -i "$TAP" -j DROP
  iptables -C INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || iptables -I INPUT 1 -m comment --comment "$TAG" -j "$IN"
  purge_nat || true  # a forward an older vm.env left (port edited)
  masq -A
  dnat -A PREROUTING
  dnat -A OUTPUT
  ;;
check)
  # Run by "vm-ctl.sh enforce" for running VMs: put the rules back when a
  # firewall reload took them.
  if rules_present; then exit 0; fi
  echo "cathedral-vm: link rules for $TAP were missing; restoring" >&2
  exec "$0" up "$2"
  ;;
down)
  iptables -D FORWARD -m comment --comment "$TAG" -j "$FWD" 2>/dev/null || true
  iptables -D INPUT -m comment --comment "$TAG" -j "$IN" 2>/dev/null || true
  left=0
  purge_nat || left=1
  iptables -F "$FWD" 2>/dev/null && iptables -X "$FWD" 2>/dev/null || true
  iptables -F "$IN" 2>/dev/null && iptables -X "$IN" 2>/dev/null || true
  ip link del "$TAP" 2>/dev/null || true
  if [ "$left" = 1 ]; then
    echo "cathedral-vm: could not delete the nat rules tagged $TAG; check 'iptables -t nat -S'" >&2
    exit 1
  fi
  ;;
*)
  echo "usage: vm-net.sh up|down|check vm.env" >&2; exit 2 ;;
esac
