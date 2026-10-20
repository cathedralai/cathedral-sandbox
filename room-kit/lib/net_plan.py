#!/usr/bin/env python3
"""Room kit: plan room networks from the host size (#291).

Usage: net_plan.py <slots> <ROOM_BRIDGE_PORT_CAP> <ROOM_NET_SIZE> <ROOM_NETS_POOL> [routed CIDR ...]

<slots> is the room count that CPU, memory and disk allow (size.py with no
bridge limit). When the main bridge holds them all (slots <= port cap, or a
cap of 0), the plan is empty. Otherwise the plan is one network for each
ROOM_NET_SIZE rooms, cut from ROOM_NETS_POOL in the smallest block that
holds ROOM_NET_SIZE guests. Blocks that overlap a routed CIDR (from
"ip route") are skipped. Prints the CIDRs on one line, space separated.
If the pool is too small, prints the networks that fit and a warning on
stderr.
"""
from __future__ import annotations

import ipaddress
import math
import sys

BRIDGE_MAX = 1023  # a Linux bridge takes at most 1,024 ports


def block_prefix(size: int) -> int:
    """Smallest prefix length whose block holds *size* guests (network, gateway, broadcast excluded)."""
    for prefix in range(30, 0, -1):
        if 2 ** (32 - prefix) - 3 >= size:
            return prefix
    raise ValueError("network size too large")


def plan(slots: int, port_cap: int, size: int, pool: str, routed: list[str]) -> tuple[list[str], str | None]:
    size = max(1, min(size, BRIDGE_MAX))
    if port_cap <= 0 or slots <= port_cap:
        return [], None
    want = math.ceil(slots / size)
    pool_net = ipaddress.ip_network(pool, strict=False)
    prefix = block_prefix(size)
    if prefix < pool_net.prefixlen:
        raise ValueError(f"pool {pool} is smaller than one network of {size} guests")
    taken = [ipaddress.ip_network(r, strict=False) for r in routed]
    out: list[str] = []
    for block in pool_net.subnets(new_prefix=prefix):
        if any(block.overlaps(t) for t in taken):
            continue
        out.append(str(block))
        if len(out) == want:
            return out, None
    return out, f"pool {pool} holds {len(out)} free networks of /{prefix}; {want} wanted for {slots} rooms"


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    nets, warning = plan(int(argv[0]), int(argv[1]), int(argv[2]), argv[3], argv[4:])
    if warning:
        print(f"net_plan: {warning}", file=sys.stderr)
    print(" ".join(nets))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
