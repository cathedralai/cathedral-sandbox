#!/usr/bin/env python3
"""Room kit: the room daemon's runsc runtimes, with the per-room tunable variants.

Usage: tunable_runtimes.py <RUNSC path> <ROOM_RUNSC_FLAGS>
Prints the daemon.json "runtimes" object: "runsc" with the hotel's flags, plus
16 entries runsc-tun-<d1|d0>-<root|all>-n<1..4>. Each variant is the hotel's
runsc entry without --directfs, --overlay2 and --num-network-channels, then
exactly those three set explicitly. A create with "tunables" starts its room
under one variant (cathedral/room_tunables.py builds the same names and checks
the args against the daemon); every other room keeps "runsc".
Bounds are the TEE box tunables' (cathedral/tee_box/tunables.py).
"""
import json
import sys

TUNABLE = ("--directfs", "--overlay2", "--num-network-channels")


def runtimes(runsc: str, flags: str) -> dict:
    base = flags.split()
    kept = [a for a in base if not any(a == p or a.startswith(p + "=") for p in TUNABLE)]
    out = {"runsc": {"path": runsc, "runtimeArgs": base}}
    for directfs in (True, False):
        for overlay in ("root:self", "all:self"):
            for channels in range(1, 5):
                name = f"runsc-tun-{'d1' if directfs else 'd0'}-{overlay.split(':')[0]}-n{channels}"
                args = kept + [f"--directfs={str(directfs).lower()}", f"--overlay2={overlay}",
                               f"--num-network-channels={channels}"]
                out[name] = {"path": runsc, "runtimeArgs": args}
    return out


if __name__ == "__main__":
    print(json.dumps(runtimes(sys.argv[1], sys.argv[2])))
