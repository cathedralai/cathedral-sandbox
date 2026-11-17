# Link settings of the sealed guest image (sourced by build-guest.sh,
# launch-guest.sh, host-net.sh and install-sealed.sh AFTER sealed.env).
# They are inside the measured initrd. The hotel name is NOT here; it reaches
# the guest through fw_cfg (opt/cathedral/hotel-name), unmeasured.
#
# Host IP, guest IP and guest MAC: per hotel (AB#432). Several guests on one
# host need one /30 each, so SEALED_HOST_IP, SEALED_GUEST_IP and
# SEALED_GUEST_MAC in sealed.env win; unset, they are 10.215.0.1, 10.215.0.2
# and 52:54:00:5e:a1:ed. A hotel's measurement depends on them, so it is stable
# per hotel (same kit, same sealed.env, same measurement), and hotels on the
# defaults share one measurement per build. The MAC follows sealed.env as
# before #467, so an older image started by a newer launch-guest.sh (a
# rollback) still finds its uplink. DNS stays an image constant.
SEALED_LINK_HALF=0
if [ -n "${SEALED_HOST_IP:-}" ] && [ -z "${SEALED_GUEST_IP:-}" ]; then SEALED_LINK_HALF=1; fi
if [ -z "${SEALED_HOST_IP:-}" ] && [ -n "${SEALED_GUEST_IP:-}" ]; then SEALED_LINK_HALF=1; fi
# Defaults first, so a caller that goes on after a refusal (host-net.sh down) has values.
SEALED_HOST_IP=${SEALED_HOST_IP:-10.215.0.1}
SEALED_GUEST_IP=${SEALED_GUEST_IP:-10.215.0.2}
SEALED_GUEST_MAC=${SEALED_GUEST_MAC:-52:54:00:5e:a1:ed}
SEALED_DNS="1.1.1.1 8.8.8.8"
if [ "$SEALED_LINK_HALF" = 1 ]; then
  echo "sealed: set both SEALED_HOST_IP and SEALED_GUEST_IP in sealed.env, or neither (default 10.215.0.1 and 10.215.0.2)" >&2
  return 1
fi

# The pair must be the two usable addresses of one private /30 (host first),
# and the /30 must not overlap a network the guest uses inside: the Docker
# pool 10.200.0.0/14, the room bridge 10.213.0.0/21 and SEALED_ROOM_NETS
# (auto: its pool 10.214.0.0/16). The MAC must be a unicast MAC.
sealed_ip_int() {
  local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])' a b c d
  [[ "$1" =~ ^$o\.$o\.$o\.$o$ ]] || return 1
  IFS=. read -r a b c d <<< "$1"
  echo $(( (a << 24) | (b << 16) | (c << 8) | d ))
}
# 0 when two prefixes overlap: sealed_cidr_overlap <int> <bits> <int> <bits>
sealed_cidr_overlap() {
  local bits=$2; (( $4 < bits )) && bits=$4
  (( bits == 0 || $1 >> (32 - bits) == $3 >> (32 - bits) ))
}
sealed_link_check() {
  local h g cidr nets base
  h=$(sealed_ip_int "$SEALED_HOST_IP") && g=$(sealed_ip_int "$SEALED_GUEST_IP") \
    || { echo "sealed: SEALED_HOST_IP and SEALED_GUEST_IP must be IPv4 addresses" >&2; return 1; }
  (( h % 4 == 1 && g == h + 1 )) \
    || { echo "sealed: SEALED_HOST_IP and SEALED_GUEST_IP must be the first and second address of one /30 (for example 10.215.0.5 and 10.215.0.6)" >&2; return 1; }
  (( h >> 24 == 10 || h >> 20 == (172 << 4 | 1) || h >> 16 == (192 << 8 | 168) )) \
    || { echo "sealed: the guest link must be in 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16" >&2; return 1; }
  [[ "$SEALED_GUEST_MAC" =~ ^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$ ]] \
    || { echo "sealed: SEALED_GUEST_MAC must be a unicast MAC in lower case (for example 52:54:00:5e:a1:ee)" >&2; return 1; }
  nets=${SEALED_ROOM_NETS:-}
  [ "$nets" = auto ] && nets=10.214.0.0/16
  for cidr in 10.200.0.0/14 10.213.0.0/21 $nets; do
    [[ "$cidr" =~ ^([0-9.]+)/([0-9]|[12][0-9]|3[0-2])$ ]] || continue
    base=$(sealed_ip_int "${BASH_REMATCH[1]}") || continue
    if sealed_cidr_overlap $((h - 1)) 30 "$base" "${BASH_REMATCH[2]}"; then
      echo "sealed: the guest link $SEALED_HOST_IP/30 overlaps $cidr, a network inside the guest" >&2; return 1
    fi
  done
  return 0
}
sealed_link_check || return 1

# CPU model: QEMU -cpu, sev-snp-measure --vcpu-type and the manifest all read this one
# variable, so the measured vCPU type cannot drift from the one the guest runs. Unlike
# DNS above, a value in sealed.env wins: set SEALED_CPU_MODEL=EPYC-v4 there
# for a baseline hotel. EPYC-Genoa-v1 shows AVX-512 to the guest (EPYC-v4 hides it) and
# needs a Zen 4 host. The CPUID signature is measured, so changing it changes the measurement.
SEALED_CPU_MODEL=${SEALED_CPU_MODEL:-EPYC-Genoa-v1}
