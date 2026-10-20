#!/usr/bin/env python3
"""Room kit: guests with a network that the room's bridges can hold.

Usage: net_capacity.py <ROOM_BRIDGE_CIDR> <ROOM_BRIDGE_PORT_CAP> <ROOM_NET_SIZE> [ROOM_NETS CIDR ...]
A Linux bridge takes at most 1,024 ports. Without ROOM_NETS every guest with
a network is on the main bridge. With ROOM_NETS the API puts guests with a
network on those bridges only, ROOM_NET_SIZE (max 1,023) on each.
"""
import ipaddress
import sys

main, port_cap, size, nets = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]
if nets:
    size = max(1, min(size, 1023))
    print(sum(min(size, ipaddress.ip_network(n).num_addresses - 3) for n in nets))
else:
    n = ipaddress.ip_interface(main).network.num_addresses - 3
    print(min(n, port_cap) if port_cap > 0 else n)
