#!/bin/bash
# up|down: a netns with a veth to the host, the shape Docker's bridge gives a room.
set -e
if [ "$1" = up ]; then
  ip netns add ckspike
  ip link add ckspkh type veth peer name ckspkg
  ip link set ckspkg netns ckspike
  ip addr add 10.231.0.1/30 dev ckspkh; ip link set ckspkh up
  ip -n ckspike addr add 10.231.0.2/30 dev ckspkg; ip -n ckspike link set ckspkg up; ip -n ckspike link set lo up
  ip -n ckspike route add default via 10.231.0.1
else
  ip link del ckspkh 2>/dev/null || true; ip netns del ckspike 2>/dev/null || true
fi
